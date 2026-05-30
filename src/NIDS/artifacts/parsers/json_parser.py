from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SUSPICIOUS_KEYS = {
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "cmd",
    "command",
    "exec",
    "powershell",
}


def parse_json(path: Path, text_limit: int = 20000) -> dict[str, Any]:
    """Parse JSON payload and inspect top-level structure and key risk hints."""
    reasons: list[str] = []

    try:
        raw_text = path.read_text(encoding="utf-8-sig", errors="ignore")
        payload = json.loads(raw_text)

        metadata: dict[str, Any] = {
            "top_level_type": type(payload).__name__,
            "size_chars": len(raw_text),
        }

        suspicious_keys: list[str] = []
        if isinstance(payload, dict):
            keys = [str(key) for key in payload.keys()]
            metadata["top_level_keys"] = keys[:200]
            for key in keys:
                if key.lower() in SUSPICIOUS_KEYS:
                    suspicious_keys.append(key)

        if isinstance(payload, list):
            metadata["list_length"] = len(payload)

        if suspicious_keys:
            metadata["suspicious_keys"] = suspicious_keys
            reasons.append("json_contains_sensitive_or_execution_keys")

        preview = raw_text[:text_limit]
        return {
            "metadata": metadata,
            "text": preview,
            "tags": ["json"],
            "reasons": reasons,
        }
    except Exception as exc:
        return {
            "metadata": {"error": f"json_parse_failed: {exc}"},
            "text": "",
            "tags": ["json", "parse_error"],
            "reasons": ["json_parse_failed"],
        }

