from __future__ import annotations

import hashlib
import json
import mimetypes
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .parsers.csv_parser import parse_csv
from .parsers.docx_parser import parse_docx
from .parsers.exe_parser import parse_exe
from .parsers.html_parser import parse_html
from .parsers.json_parser import parse_json
from .parsers.pdf_parser import parse_pdf
from .parsers.py_parser import parse_python
from .parsers.xlsx_parser import parse_xlsx
from .parsers.zip_parser import parse_zip

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".msi",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
    ".com",
}

SUSPICIOUS_TEXT_TOKENS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "wget http",
    "curl http",
    "mimikatz",
    "reverse shell",
    "frombase64string",
]

YARA_LITE_RULES: list[tuple[str, list[str]]] = [
    ("credential_theft_pattern", ["token=", "api_key", "private key", "password="]),
    ("command_exec_pattern", ["os.system", "subprocess", "exec(", "eval("]),
    ("remote_payload_pattern", ["downloadstring", "invoke-webrequest", "bitsadmin", "certutil -urlcache"]),
]

ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{32,}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compute_hashes(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return sha256.hexdigest(), md5.hexdigest()


def detect_mime_type(path: Path) -> str:
    try:
        import magic  # type: ignore

        result = magic.from_file(str(path), mime=True)
        if result:
            return str(result)
    except Exception:
        pass

    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


def _has_high_entropy_segments(text: str) -> bool:
    for match in ENTROPY_TOKEN_RE.finditer(text):
        token = match.group(0)
        unique_ratio = len(set(token)) / max(1, len(token))
        if len(token) >= 48 and unique_ratio >= 0.45:
            return True
    return False


def _match_yara_lite(text: str) -> list[str]:
    lower = text.lower()
    matches: list[str] = []
    for name, patterns in YARA_LITE_RULES:
        if any(pattern.lower() in lower for pattern in patterns):
            matches.append(name)
    return matches


def _run_parser(path: Path, ext: str, max_text_chars: int, zip_limits: dict[str, int]) -> dict[str, Any]:
    if ext == ".pdf":
        return parse_pdf(path, text_limit=max_text_chars)
    if ext == ".docx":
        return parse_docx(path, text_limit=max_text_chars)
    if ext == ".xlsx":
        return parse_xlsx(path)
    if ext == ".csv":
        return parse_csv(path)
    if ext == ".json":
        return parse_json(path, text_limit=max_text_chars)
    if ext in {".html", ".htm"}:
        return parse_html(path, text_limit=max_text_chars)
    if ext == ".py":
        return parse_python(path, text_limit=max_text_chars)
    if ext in {".exe", ".dll", ".msi", ".scr", ".bin"}:
        return parse_exe(path, text_limit=max_text_chars)
    if ext == ".zip":
        return parse_zip(
            path,
            max_files=int(zip_limits.get("max_files", 5000)),
            max_uncompressed_bytes=int(zip_limits.get("max_uncompressed_bytes", 1_000_000_000)),
        )

    metadata = {
        "note": "generic_static_scan",
        "preview_bytes": min(path.stat().st_size, max_text_chars),
    }
    text = ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")[:max_text_chars]
    except Exception:
        text = ""

    return {
        "metadata": metadata,
        "text": text,
        "tags": ["generic"],
        "reasons": [],
    }


def _score_risk(ext: str, reasons: list[str], text: str) -> tuple[str, list[str]]:
    scored_reasons = list(reasons)
    lower_text = text.lower()

    contains_suspicious_strings = any(token in lower_text for token in SUSPICIOUS_TEXT_TOKENS)
    if contains_suspicious_strings:
        scored_reasons.append("contains_suspicious_strings")

    yara_hits = _match_yara_lite(text)
    for hit in yara_hits:
        scored_reasons.append(f"yara_lite:{hit}")

    high = False
    medium = False

    if ext in EXECUTABLE_EXTENSIONS and contains_suspicious_strings:
        high = True
        scored_reasons.append("executable_with_suspicious_strings")

    if ext == ".bin" and "executable_contains_suspicious_strings" in scored_reasons:
        medium = True
        scored_reasons.append("binary_with_suspicious_strings")

    high_indicators = {
        "zip_contains_dangerous_extensions",
        "zip_path_traversal_indicator",
        "html_many_inline_scripts",
        "html_suspicious_domains",
        "python_contains_suspicious_function_calls",
        "executable_suspicious_imports",
    }
    if any(reason in scored_reasons for reason in high_indicators):
        high = True

    medium_indicators = {
        "docx_vba_macro_indicator",
        "docx_embedded_object_indicator",
        "xlsx_vba_macro_indicator",
        "xlsx_external_link_indicator",
        "zip_contains_nested_archives",
        "zip_high_compression_ratio",
        "zip_exceeds_uncompressed_limit",
        "json_contains_sensitive_or_execution_keys",
    }
    if ext in {".docm", ".xlsm", ".pptm"}:
        medium = True
        scored_reasons.append("macro_enabled_document_indicator")
    if any(reason in scored_reasons for reason in medium_indicators):
        medium = True

    if _has_high_entropy_segments(text):
        medium = True
        scored_reasons.append("high_entropy_content_segments")

    if yara_hits:
        medium = True

    unique_reasons = sorted(set(scored_reasons))
    if high:
        return "high", unique_reasons
    if medium:
        return "medium", unique_reasons
    return "low", unique_reasons


def analyze_artifact(
    path: Path,
    max_text_chars: int = 20000,
    zip_limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Perform static artifact analysis and return a normalized record."""
    if zip_limits is None:
        zip_limits = {}

    resolved = path.resolve()
    ext = resolved.suffix.lower()
    size_bytes = int(resolved.stat().st_size)
    sha256, md5_hash = compute_hashes(resolved)
    mime_type = detect_mime_type(resolved)

    parser_output = _run_parser(resolved, ext, max_text_chars=max_text_chars, zip_limits=zip_limits)
    metadata = parser_output.get("metadata", {}) or {}
    extracted_text = str(parser_output.get("text", ""))[:max_text_chars]
    tags = [str(tag) for tag in (parser_output.get("tags", []) or [])]
    reasons = [str(reason) for reason in (parser_output.get("reasons", []) or [])]

    risk_level, scored_reasons = _score_risk(ext=ext, reasons=reasons, text=extracted_text)

    return {
        "timestamp": _now_iso(),
        "source_path": str(resolved),
        "stored_path": "",
        "filename": resolved.name,
        "extension": ext,
        "mime_type": mime_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "md5": md5_hash,
        "tags": tags,
        "risk_level": risk_level,
        "reasons": scored_reasons,
        "extracted_text": extracted_text,
        "extracted_metadata": metadata,
    }


def record_to_json(record: dict[str, Any]) -> str:
    """Serialize record safely for JSONL output."""
    payload = dict(record)
    for key in ("tags", "reasons", "extracted_metadata"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            continue
        if value is None:
            if key == "extracted_metadata":
                payload[key] = {}
            else:
                payload[key] = []
        else:
            payload[key] = [str(value)] if key in {"tags", "reasons"} else {"value": str(value)}
    return json.dumps(payload, ensure_ascii=True)
