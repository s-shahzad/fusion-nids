from __future__ import annotations

import re
from pathlib import Path
from typing import Any

PRINTABLE_RE = re.compile(rb"[ -~]{4,}")
SUSPICIOUS_STRING_PATTERNS = [
    "powershell",
    "cmd.exe",
    "http://",
    "https://",
    "mimikatz",
    "regsvr32",
    "rundll32",
    "shellcode",
    "keylogger",
]

SUSPICIOUS_IMPORTS = {
    "ws2_32.dll",
    "wininet.dll",
    "urlmon.dll",
    "advapi32.dll",
    "crypt32.dll",
}


def parse_exe(path: Path, text_limit: int = 20000, string_limit: int = 4000) -> dict[str, Any]:
    """Static EXE parser (PE headers if available + string extraction)."""
    metadata: dict[str, Any] = {}
    reasons: list[str] = []

    raw = path.read_bytes()
    strings = [
        match.group(0).decode("utf-8", errors="ignore")
        for match in PRINTABLE_RE.finditer(raw)
    ]
    strings = strings[:string_limit]

    suspicious_hits: list[str] = []
    for token in SUSPICIOUS_STRING_PATTERNS:
        for text in strings:
            if token in text.lower():
                suspicious_hits.append(token)
                break

    if suspicious_hits:
        reasons.append("executable_contains_suspicious_strings")

    metadata["strings_count"] = len(strings)
    metadata["suspicious_string_hits"] = sorted(set(suspicious_hits))

    try:
        import pefile  # type: ignore

        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        imports: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown"
            imports.append(dll.lower())

        suspicious_import_hits = sorted(set(imports) & SUSPICIOUS_IMPORTS)
        if suspicious_import_hits:
            reasons.append("executable_suspicious_imports")

        metadata["pe_timestamp"] = int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0))
        metadata["pe_machine"] = int(getattr(pe.FILE_HEADER, "Machine", 0))
        metadata["imports"] = sorted(set(imports))[:200]
        metadata["suspicious_import_hits"] = suspicious_import_hits
    except Exception as exc:
        metadata["pe_parse"] = f"unavailable_or_failed: {exc}"

    text = "\n".join(strings)[:text_limit]
    return {
        "metadata": metadata,
        "text": text,
        "tags": ["exe", "binary"],
        "reasons": reasons,
    }
