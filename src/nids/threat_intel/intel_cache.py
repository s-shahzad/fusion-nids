from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class IntelCache:
    """Small TTL cache for local threat-intelligence lookups."""

    def __init__(self, cache_path: Path | None = None, ttl_sec: int = 3600) -> None:
        self.cache_path = cache_path
        self.ttl_sec = max(1, int(ttl_sec))
        self._entries: dict[str, dict[str, Any]] = {}
        if self.cache_path is not None and self.cache_path.exists():
            self._load()

    def _load(self) -> None:
        if self.cache_path is None:
            return
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        self._entries = {str(key): value for key, value in payload.items() if isinstance(value, dict)}

    def _save(self) -> None:
        if self.cache_path is None:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self._entries, indent=2, sort_keys=True), encoding="utf-8")

    def get(self, key: str) -> dict[str, Any] | None:
        entry = self._entries.get(key)
        if not entry:
            return None
        expires_at = float(entry.get("expires_at", 0))
        if expires_at < time.time():
            self._entries.pop(key, None)
            self._save()
            return None
        value = entry.get("value")
        if isinstance(value, dict):
            return dict(value)
        return None

    def set(self, key: str, value: dict[str, Any]) -> None:
        self._entries[key] = {
            "expires_at": time.time() + self.ttl_sec,
            "value": dict(value),
        }
        self._save()
