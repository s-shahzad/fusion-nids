from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CloudStorageLayout:
    root: Path
    runtime_output_dir: Path
    runtime_logs_dir: Path
    runtime_reports_dir: Path
    runtime_artifacts_incoming_dir: Path
    runtime_artifacts_processed_dir: Path
    runtime_artifacts_quarantine_dir: Path
    lab_generated_bundles_dir: Path
    lab_generated_archive_dir: Path
    replay_staging_dir: Path
    archived_outputs_dir: Path
    manifests_dir: Path

    def as_dict(self) -> dict[str, str]:
        return {
            "root": str(self.root),
            "runtime_output_dir": str(self.runtime_output_dir),
            "runtime_logs_dir": str(self.runtime_logs_dir),
            "runtime_reports_dir": str(self.runtime_reports_dir),
            "runtime_artifacts_incoming_dir": str(self.runtime_artifacts_incoming_dir),
            "runtime_artifacts_processed_dir": str(self.runtime_artifacts_processed_dir),
            "runtime_artifacts_quarantine_dir": str(self.runtime_artifacts_quarantine_dir),
            "lab_generated_bundles_dir": str(self.lab_generated_bundles_dir),
            "lab_generated_archive_dir": str(self.lab_generated_archive_dir),
            "replay_staging_dir": str(self.replay_staging_dir),
            "archived_outputs_dir": str(self.archived_outputs_dir),
            "manifests_dir": str(self.manifests_dir),
        }


def build_cloud_storage_layout(root: str | Path) -> CloudStorageLayout:
    base = Path(root).resolve()
    return CloudStorageLayout(
        root=base,
        runtime_output_dir=base / "runtime" / "output",
        runtime_logs_dir=base / "runtime" / "logs",
        runtime_reports_dir=base / "runtime" / "reports",
        runtime_artifacts_incoming_dir=base / "runtime" / "artifacts" / "incoming",
        runtime_artifacts_processed_dir=base / "runtime" / "artifacts" / "processed",
        runtime_artifacts_quarantine_dir=base / "runtime" / "artifacts" / "quarantine",
        lab_generated_bundles_dir=base / "lab_generated" / "bundles",
        lab_generated_archive_dir=base / "lab_generated" / "archive",
        replay_staging_dir=base / "replay" / "staging",
        archived_outputs_dir=base / "archive" / "output_bundles",
        manifests_dir=base / "manifests",
    )


def ensure_cloud_storage_layout(layout: CloudStorageLayout) -> CloudStorageLayout:
    for path in (
        layout.runtime_output_dir,
        layout.runtime_logs_dir,
        layout.runtime_reports_dir,
        layout.runtime_artifacts_incoming_dir,
        layout.runtime_artifacts_processed_dir,
        layout.runtime_artifacts_quarantine_dir,
        layout.lab_generated_bundles_dir,
        layout.lab_generated_archive_dir,
        layout.replay_staging_dir,
        layout.archived_outputs_dir,
        layout.manifests_dir,
    ):
        path.mkdir(parents=True, exist_ok=True)
    return layout


def capacity_guidance(total_gb: int) -> dict[str, int | str]:
    total = max(10, int(total_gb))
    os_and_margin_gb = max(6, int(round(total * 0.2)))
    runtime_output_gb = max(6, int(round(total * 0.35)))
    reports_gb = max(2, int(round(total * 0.1)))
    replay_gb = max(2, int(round(total * 0.1)))
    archive_gb = max(2, total - (os_and_margin_gb + runtime_output_gb + reports_gb + replay_gb))
    return {
        "total_gb": total,
        "os_and_margin_gb": os_and_margin_gb,
        "runtime_output_gb": runtime_output_gb,
        "reports_gb": reports_gb,
        "replay_gb": replay_gb,
        "archive_gb": archive_gb,
        "note": "Single-node guidance only. Keep free headroom available for SQLite growth, JSONL writes, and temporary replay staging.",
    }
