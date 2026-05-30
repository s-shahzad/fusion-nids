from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def _normalize_indicator(item: dict[str, Any]) -> dict[str, Any] | None:
    ip_value = str(item.get("ip") or item.get("indicator") or "").strip()
    if not ip_value:
        return None
    normalized = dict(item)
    normalized["ip"] = ip_value
    return normalized


class IPReputationProvider:
    """Local indicator provider for IP reputation matches."""

    def __init__(
        self,
        *,
        indicators_path: str | Path | None = None,
        inline_indicators: list[dict[str, Any]] | None = None,
    ) -> None:
        self._indicators: dict[str, dict[str, Any]] = {}
        for indicator in inline_indicators or []:
            normalized = _normalize_indicator(indicator)
            if normalized is not None:
                self._indicators[normalized["ip"]] = normalized

        if indicators_path:
            self._load_from_path(Path(indicators_path))

    def _load_from_path(self, path: Path) -> None:
        if not path.exists():
            return
        raw_text = path.read_text(encoding="utf-8")
        payload: Any
        if path.suffix.lower() == ".json":
            payload = json.loads(raw_text)
        else:
            payload = yaml.safe_load(raw_text)

        if isinstance(payload, dict) and isinstance(payload.get("indicators"), list):
            records = payload["indicators"]
        elif isinstance(payload, list):
            records = payload
        else:
            records = []

        for indicator in records:
            if not isinstance(indicator, dict):
                continue
            normalized = _normalize_indicator(indicator)
            if normalized is not None:
                self._indicators[normalized["ip"]] = normalized

    def lookup(self, ip_address: str | None) -> dict[str, Any] | None:
        if not ip_address:
            return None
        match = self._indicators.get(str(ip_address).strip())
        return dict(match) if match is not None else None
