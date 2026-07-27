from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analyzer import analyze_artifact, compute_hashes, detect_mime_type
from .storage import ArtifactStore


@dataclass
class ArtifactScanSummary:
    scanned: int = 0
    inserted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    processed: int = 0
    errors: int = 0


@dataclass
class ArtifactPaths:
    incoming: Path
    processed: Path
    quarantine: Path
    db_path: Path
    jsonl_path: Path


def _ensure_dirs(paths: ArtifactPaths) -> None:
    paths.incoming.mkdir(parents=True, exist_ok=True)
    paths.processed.mkdir(parents=True, exist_ok=True)
    paths.quarantine.mkdir(parents=True, exist_ok=True)
    paths.db_path.parent.mkdir(parents=True, exist_ok=True)
    paths.jsonl_path.parent.mkdir(parents=True, exist_ok=True)


def _iter_files(target: Path, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target]

    if not target.exists():
        return []

    if recursive:
        return sorted([path for path in target.rglob("*") if path.is_file()])
    return sorted([path for path in target.glob("*") if path.is_file()])


def _unique_destination(base_dir: Path, original_name: str, sha256: str) -> Path:
    candidate = base_dir / original_name
    if not candidate.exists():
        return candidate

    stem = Path(original_name).stem
    suffix = Path(original_name).suffix
    short_hash = sha256[:10]
    candidate = base_dir / f"{stem}_{short_hash}{suffix}"

    index = 1
    while candidate.exists():
        candidate = base_dir / f"{stem}_{short_hash}_{index}{suffix}"
        index += 1

    return candidate


def _duplicate_record(
    file_path: Path,
    sha256: str,
    md5_hash: str,
    existing: dict[str, Any],
) -> dict[str, Any]:
    reasons = [f"duplicate_of_id:{existing.get('id', 'unknown')}"]
    metadata = {
        "duplicate": True,
        "duplicate_of_id": existing.get("id"),
        "duplicate_of_path": existing.get("stored_path") or existing.get("source_path"),
    }
    tags = list(existing.get("tags", [])) if isinstance(existing.get("tags"), list) else []
    tags.append("duplicate")

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_path": str(file_path.resolve()),
        "stored_path": "",
        "filename": file_path.name,
        "extension": file_path.suffix.lower(),
        "mime_type": detect_mime_type(file_path),
        "size_bytes": int(file_path.stat().st_size),
        "sha256": sha256,
        "md5": md5_hash,
        "tags": sorted(set(tags)),
        "risk_level": str(existing.get("risk_level") or "low"),
        "reasons": reasons,
        "extracted_text": "",
        "extracted_metadata": metadata,
    }


def _process_file(
    file_path: Path,
    store: ArtifactStore,
    processed_dir: Path,
    quarantine_dir: Path,
    max_text_chars: int,
    zip_limits: dict[str, int],
) -> tuple[dict[str, Any] | None, bool]:
    sha256, md5_hash = compute_hashes(file_path)
    existing = store.find_by_sha256(sha256)
    duplicate = existing is not None

    if duplicate:
        record = _duplicate_record(file_path=file_path, sha256=sha256, md5_hash=md5_hash, existing=existing)
    else:
        record = analyze_artifact(
            file_path,
            max_text_chars=max_text_chars,
            zip_limits=zip_limits,
        )

    target_root = quarantine_dir if str(record.get("risk_level", "")).lower() == "high" else processed_dir
    destination = _unique_destination(target_root, file_path.name, sha256)

    shutil.move(str(file_path), str(destination))
    record["stored_path"] = str(destination.resolve())

    store.insert_artifact(record)
    return record, duplicate


def run_artifact_scan(
    path: str | Path,
    recursive: bool = False,
    db_path: str | Path = "output/nids.db",
    jsonl_path: str | Path = "output/artifacts.jsonl",
    processed_dir: str | Path = "artifacts/processed",
    quarantine_dir: str | Path = "artifacts/quarantine",
    max_text_chars: int = 20000,
    zip_limits: dict[str, int] | None = None,
) -> ArtifactScanSummary:
    """One-shot scan for artifacts from an incoming path."""
    if zip_limits is None:
        zip_limits = {}

    incoming = Path(path).resolve()
    paths = ArtifactPaths(
        incoming=incoming,
        processed=Path(processed_dir).resolve(),
        quarantine=Path(quarantine_dir).resolve(),
        db_path=Path(db_path).resolve(),
        jsonl_path=Path(jsonl_path).resolve(),
    )

    _ensure_dirs(paths)

    summary = ArtifactScanSummary()
    store = ArtifactStore(db_path=paths.db_path, jsonl_path=paths.jsonl_path)

    try:
        files = _iter_files(paths.incoming, recursive=recursive)
        for file_path in files:
            summary.scanned += 1
            try:
                record, duplicate = _process_file(
                    file_path=file_path,
                    store=store,
                    processed_dir=paths.processed,
                    quarantine_dir=paths.quarantine,
                    max_text_chars=max_text_chars,
                    zip_limits=zip_limits,
                )
                if record is None:
                    summary.errors += 1
                    continue

                summary.inserted += 1
                if duplicate:
                    summary.duplicates += 1

                if str(record.get("risk_level", "")).lower() == "high":
                    summary.quarantined += 1
                else:
                    summary.processed += 1
            except Exception:
                summary.errors += 1
    finally:
        store.close()

    return summary


def run_artifact_watch(
    path: str | Path,
    recursive: bool = False,
    db_path: str | Path = "output/nids.db",
    jsonl_path: str | Path = "output/artifacts.jsonl",
    processed_dir: str | Path = "artifacts/processed",
    quarantine_dir: str | Path = "artifacts/quarantine",
    interval_sec: int = 5,
    max_text_chars: int = 20000,
    zip_limits: dict[str, int] | None = None,
) -> None:
    """Polling watcher for continuous artifact intake from incoming directory."""
    print(f"Watching artifacts at {Path(path).resolve()} (interval={interval_sec}s)")
    try:
        while True:
            summary = run_artifact_scan(
                path=path,
                recursive=recursive,
                db_path=db_path,
                jsonl_path=jsonl_path,
                processed_dir=processed_dir,
                quarantine_dir=quarantine_dir,
                max_text_chars=max_text_chars,
                zip_limits=zip_limits,
            )
            if summary.inserted > 0 or summary.errors > 0:
                print(
                    "artifact-watch: "
                    f"scanned={summary.scanned} inserted={summary.inserted} "
                    f"duplicates={summary.duplicates} quarantined={summary.quarantined} errors={summary.errors}"
                )
            time.sleep(max(1, int(interval_sec)))
    except KeyboardInterrupt:
        print("Artifact watch stopped.")
