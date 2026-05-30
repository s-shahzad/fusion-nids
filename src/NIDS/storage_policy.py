from __future__ import annotations

import gzip
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


RUNTIME_ROOTS = (
    "output",
    "realtime_lab/output",
    "NIDS_TestLab/results",
    "artifacts/portfolio_bundles",
)

COMPRESSIBLE_SUFFIXES = {".json", ".jsonl", ".md", ".txt", ".csv"}


@dataclass(frozen=True)
class RetentionPolicy:
    keep_full_detail_days: int = 14
    compress_after_days: int = 7
    archive_after_days: int = 30
    max_active_runs: int = 25
    preserve_named_baselines: tuple[str, ...] = ()


@dataclass(frozen=True)
class BundleCandidate:
    root_name: str
    path: Path
    age_days: float
    size_bytes: int
    preserved: bool
    has_details: bool
    has_compressed_details: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def _dir_size(path: Path) -> int:
    total = 0
    for child in path.rglob("*"):
        if child.is_file():
            try:
                total += child.stat().st_size
            except OSError:
                continue
    return total


def _is_bundle_dir(path: Path) -> bool:
    if not path.is_dir():
        return False
    markers = ("nids.db", "alerts.jsonl", "summary.md", "metrics.json", "fusion_trace.json")
    return any((path / marker).exists() for marker in markers)


def _is_preserved(name: str, preserve: tuple[str, ...]) -> bool:
    lowered = name.lower()
    return any(token.lower() in lowered for token in preserve if token)


def _compressible_files(bundle_path: Path) -> list[Path]:
    files: list[Path] = []
    for child in bundle_path.rglob("*"):
        if not child.is_file():
            continue
        if child.suffix.lower() not in COMPRESSIBLE_SUFFIXES:
            continue
        if child.name.endswith(".gz"):
            continue
        files.append(child)
    return sorted(files)


def bundle_candidates(repo_root: Path, policy: RetentionPolicy, *, now: datetime | None = None) -> list[BundleCandidate]:
    now_dt = now or _utc_now()
    items: list[BundleCandidate] = []
    for root_name in RUNTIME_ROOTS:
        root = (repo_root / root_name).resolve()
        if not root.exists():
            continue
        for child in root.iterdir():
            if not _is_bundle_dir(child):
                continue
            age_days = max(0.0, (now_dt - _safe_mtime(child)).total_seconds() / 86400.0)
            compressible = _compressible_files(child)
            items.append(
                BundleCandidate(
                    root_name=root_name,
                    path=child,
                    age_days=age_days,
                    size_bytes=_dir_size(child),
                    preserved=_is_preserved(child.name, policy.preserve_named_baselines),
                    has_details=bool(compressible),
                    has_compressed_details=any(file.name.endswith(".gz") for file in child.rglob("*.gz")),
                )
            )
    items.sort(key=lambda item: (item.root_name, item.path.name))
    return items


def plan_retention(repo_root: Path, policy: RetentionPolicy, *, now: datetime | None = None) -> dict[str, Any]:
    now_dt = now or _utc_now()
    archive_root = (repo_root / "runtime_data" / "archive").resolve()
    active_root = (repo_root / "runtime_data" / "active").resolve()
    tmp_root = (repo_root / "runtime_data" / "tmp").resolve()
    candidates = bundle_candidates(repo_root, policy, now=now_dt)

    by_root: dict[str, list[BundleCandidate]] = {}
    for candidate in candidates:
        by_root.setdefault(candidate.root_name, []).append(candidate)

    compress: list[dict[str, Any]] = []
    archive: list[dict[str, Any]] = []
    for root_name, root_candidates in by_root.items():
        sorted_by_age = sorted(root_candidates, key=lambda item: _safe_mtime(item.path), reverse=True)
        active_keep = max(0, int(policy.max_active_runs))
        for idx, candidate in enumerate(sorted_by_age):
            if candidate.preserved:
                continue
            if candidate.age_days >= float(policy.archive_after_days) or idx >= active_keep:
                archive.append(
                    {
                        "root_name": root_name,
                        "bundle_path": str(candidate.path),
                        "target_path": str((archive_root / root_name.replace("/", "_") / candidate.path.name).resolve()),
                        "age_days": round(candidate.age_days, 2),
                        "size_bytes": candidate.size_bytes,
                    }
                )
                continue
            if candidate.age_days >= float(policy.compress_after_days) and candidate.has_details:
                compress.append(
                    {
                        "root_name": root_name,
                        "bundle_path": str(candidate.path),
                        "files": [str(path) for path in _compressible_files(candidate.path)],
                        "age_days": round(candidate.age_days, 2),
                        "size_bytes": candidate.size_bytes,
                    }
                )

    return {
        "generated_at": now_dt.isoformat(timespec="seconds"),
        "runtime_layout": {
            "active_root": str(active_root),
            "archive_root": str(archive_root),
            "tmp_root": str(tmp_root),
        },
        "policy": {
            "keep_full_detail_days": int(policy.keep_full_detail_days),
            "compress_after_days": int(policy.compress_after_days),
            "archive_after_days": int(policy.archive_after_days),
            "max_active_runs": int(policy.max_active_runs),
            "preserve_named_baselines": list(policy.preserve_named_baselines),
        },
        "bundle_count": len(candidates),
        "compress_actions": compress,
        "archive_actions": archive,
    }


def ensure_storage_layout(repo_root: Path) -> dict[str, str]:
    runtime_root = (repo_root / "runtime_data").resolve()
    active_root = (runtime_root / "active").resolve()
    archive_root = (runtime_root / "archive").resolve()
    tmp_root = (runtime_root / "tmp").resolve()
    for path in (runtime_root, active_root, archive_root, tmp_root):
        path.mkdir(parents=True, exist_ok=True)
        keep = path / ".gitkeep"
        if not keep.exists():
            keep.write_text("", encoding="utf-8")
    return {
        "runtime_root": str(runtime_root),
        "active_root": str(active_root),
        "archive_root": str(archive_root),
        "tmp_root": str(tmp_root),
    }


def execute_retention_plan(plan: dict[str, Any], *, apply_changes: bool = False) -> dict[str, Any]:
    summary = {
        "applied": bool(apply_changes),
        "compressed_files": 0,
        "archived_bundles": 0,
        "errors": [],
    }
    if not apply_changes:
        return summary

    for action in plan.get("compress_actions", []):
        for raw_path in action.get("files", []):
            path = Path(raw_path)
            target = path.with_suffix(path.suffix + ".gz")
            if target.exists():
                continue
            try:
                with path.open("rb") as src, gzip.open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                summary["compressed_files"] += 1
            except OSError as exc:
                summary["errors"].append(f"compress:{path}:{exc}")

    for action in plan.get("archive_actions", []):
        src = Path(str(action.get("bundle_path") or ""))
        dst = Path(str(action.get("target_path") or ""))
        if not src.exists() or dst.exists():
            continue
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst)
            summary["archived_bundles"] += 1
        except OSError as exc:
            summary["errors"].append(f"archive:{src}:{exc}")
    return summary


def build_storage_profile(repo_root: Path, policy: RetentionPolicy, *, now: datetime | None = None) -> dict[str, Any]:
    ensure_storage_layout(repo_root)
    now_dt = now or _utc_now()
    directories: list[dict[str, Any]] = []
    categories: dict[str, int] = {}
    for root_name in RUNTIME_ROOTS:
        root = (repo_root / root_name).resolve()
        if not root.exists():
            continue
        size = _dir_size(root)
        directories.append({"path": str(root), "size_bytes": size})
        for child in root.rglob("*"):
            if not child.is_file():
                continue
            suffix = child.suffix.lower() or "<none>"
            categories[suffix] = categories.get(suffix, 0) + child.stat().st_size

    directories.sort(key=lambda item: (-int(item["size_bytes"]), item["path"]))
    category_rows = [
        {"category": key, "size_bytes": value}
        for key, value in sorted(categories.items(), key=lambda item: (-item[1], item[0]))
    ]
    plan = plan_retention(repo_root, policy, now=now_dt)
    estimated_reduction = 0
    for action in plan.get("compress_actions", []):
        estimated_reduction += int(action.get("size_bytes", 0) * 0.35)
    for action in plan.get("archive_actions", []):
        estimated_reduction += int(action.get("size_bytes", 0))
    return {
        "generated_at": now_dt.isoformat(timespec="seconds"),
        "largest_directories": directories[:10],
        "largest_file_categories": category_rows[:10],
        "retention_plan": plan,
        "estimated_cleanup_impact_bytes": estimated_reduction,
    }


def write_storage_profile(repo_root: Path, policy: RetentionPolicy, out_md: Path, out_json: Path) -> tuple[Path, Path]:
    profile = build_storage_profile(repo_root, policy)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(profile, indent=2, ensure_ascii=True), encoding="utf-8")

    lines = [
        "# Storage Profile",
        "",
        f"Generated: {profile['generated_at']}",
        "",
        "## Largest Directories",
        "",
    ]
    for item in profile["largest_directories"]:
        size_mb = round(int(item["size_bytes"]) / (1024 * 1024), 2)
        lines.append(f"- `{item['path']}`: `{size_mb} MB`")
    lines.extend(["", "## Largest File Categories", ""])
    for item in profile["largest_file_categories"]:
        size_mb = round(int(item["size_bytes"]) / (1024 * 1024), 2)
        lines.append(f"- `{item['category']}`: `{size_mb} MB`")
    lines.extend(
        [
            "",
            "## Recommended Cleanup Impact",
            "",
            f"- Compress candidates: `{len(profile['retention_plan']['compress_actions'])}`",
            f"- Archive candidates: `{len(profile['retention_plan']['archive_actions'])}`",
            f"- Estimated cleanup impact: `{round(int(profile['estimated_cleanup_impact_bytes']) / (1024 * 1024), 2)} MB`",
            "",
            "## Notes",
            "",
            "- Compression candidates are JSON/JSONL/Markdown-style artifacts only.",
            "- Archive candidates are copied into `runtime_data/archive/`; no destructive deletion is performed by default.",
        ]
    )
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_md, out_json


def retention_policy_from_mapping(payload: dict[str, Any]) -> RetentionPolicy:
    source = dict(payload or {})
    preserve = tuple(str(item) for item in source.get("preserve_named_baselines", ()) if str(item).strip())
    return RetentionPolicy(
        keep_full_detail_days=max(1, int(source.get("keep_full_detail_days", 14))),
        compress_after_days=max(1, int(source.get("compress_after_days", 7))),
        archive_after_days=max(1, int(source.get("archive_after_days", 30))),
        max_active_runs=max(1, int(source.get("max_active_runs", 25))),
        preserve_named_baselines=preserve,
    )
