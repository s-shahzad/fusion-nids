from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .layout import CloudStorageLayout


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp_now() -> str:
    return _utc_now().strftime("%Y%m%d-%H%M%S")


def _load_manifest(bundle_dir: Path) -> dict[str, Any]:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Bundle manifest not found: {manifest_path}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not bool(payload.get("lab_generated")):
        raise ValueError(f"Bundle is not marked lab_generated: {manifest_path}")
    return payload


def _find_first(bundle_dir: Path, pattern: str) -> Path:
    matches = sorted(bundle_dir.glob(pattern))
    if not matches:
        raise FileNotFoundError(f"Expected {pattern} under {bundle_dir}")
    return matches[0]


def stage_validation_bundle(
    *,
    bundle_dir: str | Path,
    layout: CloudStorageLayout,
    config_path: str = "config/nids_cloud_single_node.yml",
    rules_path: str = "rules/rules.yml",
    sensor_id: str = "cloud-validation",
    run_stamp: str | None = None,
) -> dict[str, Any]:
    source = Path(bundle_dir).resolve()
    manifest = _load_manifest(source)
    stamp = run_stamp or _stamp_now()

    canonical_dir = layout.lab_generated_bundles_dir / source.name
    if not canonical_dir.exists():
        shutil.copytree(source, canonical_dir)

    staged_dir = layout.replay_staging_dir / f"{source.name}-{stamp}"
    shutil.copytree(canonical_dir, staged_dir)

    pcap_path = _find_first(staged_dir, "*.pcap")
    labels_path = staged_dir / "labels.csv"
    run_name = f"{source.name}-{stamp}"
    runtime_output_dir = layout.runtime_output_dir / run_name
    reports_dir = layout.runtime_reports_dir / run_name
    archive_dir = layout.archived_outputs_dir / run_name
    runtime_log_path = layout.runtime_logs_dir / f"{run_name}.stdout.log"
    runtime_err_path = layout.runtime_logs_dir / f"{run_name}.stderr.log"
    plan = {
        "generated_at": _utc_now().isoformat(timespec="seconds"),
        "bundle_source": str(source),
        "bundle_manifest": manifest,
        "canonical_bundle_dir": str(canonical_dir),
        "staged_bundle_dir": str(staged_dir),
        "pcap_path": str(pcap_path),
        "labels_path": str(labels_path),
        "runtime_output_dir": str(runtime_output_dir),
        "reports_dir": str(reports_dir),
        "archive_dir": str(archive_dir),
        "runtime_stdout_log": str(runtime_log_path),
        "runtime_stderr_log": str(runtime_err_path),
        "commands": {
            "host_python": (
                f"python -m nids run --pcap-dir \"{pcap_path}\" --labels \"{labels_path}\" "
                f"--config {config_path} --rules {rules_path} --output-dir \"{runtime_output_dir}\" "
                f"--sensor-id {sensor_id}-{stamp} > \"{runtime_log_path}\" 2> \"{runtime_err_path}\""
            ),
            "docker_compose_runtime": (
                "docker compose -f docker-compose.cloud-single-node.yml run --rm "
                f"-e NIDS_PCAP_DIR=/data/replay/staging/{staged_dir.name}/{pcap_path.name} "
                f"-e NIDS_LABELS_PATH=/data/replay/staging/{staged_dir.name}/labels.csv "
                f"-e NIDS_OUTPUT_DIR=/data/runtime/output/{run_name} "
                f"-e NIDS_SENSOR_ID={sensor_id}-{stamp} nids-runtime"
            ),
            "report": (
                f"python -m nids report --from-db \"{runtime_output_dir / 'nids.db'}\" "
                f"--out \"{reports_dir / 'summary.md'}\""
            ),
            "visualize": (
                f"python -m nids visualize --from-db \"{runtime_output_dir / 'nids.db'}\" "
                f"--out \"{reports_dir / 'graphs'}\""
            )
        },
    }
    plan_path = layout.manifests_dir / f"cloud_validation_plan_{run_name}.json"
    plan_path.write_text(json.dumps(plan, indent=2, ensure_ascii=True), encoding="utf-8")
    plan["plan_path"] = str(plan_path)
    return plan


def cleanup_staged_replay(
    *,
    layout: CloudStorageLayout,
    older_than_hours: int = 24,
    apply: bool = False,
) -> dict[str, Any]:
    cutoff = _utc_now().timestamp() - (max(1, int(older_than_hours)) * 3600)
    candidates: list[dict[str, Any]] = []
    removed: list[str] = []
    for path in sorted(layout.replay_staging_dir.iterdir()) if layout.replay_staging_dir.exists() else []:
        try:
            modified = path.stat().st_mtime
        except FileNotFoundError:
            continue
        if modified >= cutoff:
            continue
        entry = {
            "path": str(path),
            "modified_epoch": modified,
            "apply": bool(apply),
        }
        candidates.append(entry)
        if apply:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
            removed.append(str(path))
    return {
        "older_than_hours": max(1, int(older_than_hours)),
        "candidates": candidates,
        "removed": removed,
        "apply": bool(apply),
    }
