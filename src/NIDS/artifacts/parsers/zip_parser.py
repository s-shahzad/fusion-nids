from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Any

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".scr",
}

NESTED_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".rar",
    ".7z",
}


def _ext(name: str) -> str:
    return Path(name.lower()).suffix


def parse_zip(
    path: Path,
    max_files: int = 5000,
    max_uncompressed_bytes: int = 1_000_000_000,
) -> dict[str, Any]:
    """Parse ZIP structure only, with zip-bomb safeguards."""
    reasons: list[str] = []

    try:
        data = path.read_bytes()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [entry for entry in archive.infolist() if not entry.is_dir()]
            member_names = [entry.filename for entry in members]
            dangerous_inside = [name for name in member_names if _ext(name) in DANGEROUS_EXTENSIONS]
            nested_archives = [name for name in member_names if _ext(name) in NESTED_ARCHIVE_EXTENSIONS]

            total_uncompressed = int(sum(int(entry.file_size) for entry in members))
            compressed_total = int(sum(int(entry.compress_size) for entry in members))
            compression_ratio = float(total_uncompressed / max(1, compressed_total))

            traversal_entries = [
                name
                for name in member_names
                if "../" in name.replace("\\", "/") or name.startswith("/")
            ]

            if len(members) > max_files:
                reasons.append("zip_exceeds_max_files")
            if total_uncompressed > max_uncompressed_bytes:
                reasons.append("zip_exceeds_uncompressed_limit")
            if compression_ratio > 80.0 and total_uncompressed > 25_000_000:
                reasons.append("zip_high_compression_ratio")
            if dangerous_inside:
                reasons.append("zip_contains_dangerous_extensions")
            if nested_archives:
                reasons.append("zip_contains_nested_archives")
            if traversal_entries:
                reasons.append("zip_path_traversal_indicator")

            metadata = {
                "file_count": len(members),
                "total_uncompressed_bytes": total_uncompressed,
                "total_compressed_bytes": compressed_total,
                "compression_ratio": round(compression_ratio, 2),
                "dangerous_entries": dangerous_inside[:300],
                "nested_archives": nested_archives[:300],
                "traversal_entries": traversal_entries[:100],
                "sample_entries": member_names[:100],
            }

            text = "\n".join(member_names[:500])[:20000]
            return {
                "metadata": metadata,
                "text": text,
                "tags": ["zip", "archive"],
                "reasons": reasons,
            }
    except Exception as exc:
        return {
            "metadata": {"error": f"zip_parse_failed: {exc}"},
            "text": "",
            "tags": ["zip", "parse_error"],
            "reasons": ["zip_parse_failed"],
        }
