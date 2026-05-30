from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .intel_cache import IntelCache
from .ip_reputation import IPReputationProvider


def _to_epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


def _severity_rank(value: str) -> int:
    token = value.lower()
    if token in {"critical"}:
        return 4
    if token in {"high", "alert"}:
        return 3
    if token in {"medium", "warning"}:
        return 2
    return 1


class ThreatIntelEnricher:
    """Optional alert enrichment and match alerting using local indicators."""

    def __init__(self, cfg: dict[str, Any] | None = None) -> None:
        data = dict(cfg or {})
        self.enabled = bool(data.get("enabled", False))
        self.emit_match_alerts = bool(data.get("emit_match_alerts", True))
        self.src_enabled = bool(data.get("src_enabled", True))
        self.dst_enabled = bool(data.get("dst_enabled", True))
        self.cooldown_sec = max(1, int(data.get("cooldown_sec", 300)))
        self.default_severity = str(data.get("severity", "high"))
        cache_path_raw = str(data.get("cache_path") or "").strip()
        cache_path = Path(cache_path_raw).resolve() if cache_path_raw else None
        self.cache = IntelCache(cache_path=cache_path, ttl_sec=int(data.get("cache_ttl_sec", 3600)))
        self.provider = IPReputationProvider(
            indicators_path=data.get("indicators_path"),
            inline_indicators=list(data.get("inline_indicators", []) or []),
        )
        self._last_alert_epoch: dict[str, float] = {}

    def _lookup(self, role: str, ip_address: str) -> dict[str, Any] | None:
        cache_key = f"{role}:{ip_address}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if bool(cached.get("found")):
                result = dict(cached.get("indicator", {}) or {})
                result["matched_role"] = role
                return result
            return None

        indicator = self.provider.lookup(ip_address)
        payload = {"found": bool(indicator), "indicator": indicator or {}}
        self.cache.set(cache_key, payload)
        if indicator is None:
            return None

        result = dict(indicator)
        result["matched_role"] = role
        return result

    def _should_emit(self, key: str, now_epoch: float) -> bool:
        last = self._last_alert_epoch.get(key)
        if last is not None and now_epoch - last < self.cooldown_sec:
            return False
        self._last_alert_epoch[key] = now_epoch
        return True

    def process(self, flow_record: dict[str, Any], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self.enabled:
            return list(alerts)

        matches: list[dict[str, Any]] = []
        src_ip = str(flow_record.get("src_ip") or "").strip()
        dst_ip = str(flow_record.get("dst_ip") or "").strip()
        if self.src_enabled and src_ip:
            match = self._lookup("src_ip", src_ip)
            if match is not None:
                matches.append(match)
        if self.dst_enabled and dst_ip:
            match = self._lookup("dst_ip", dst_ip)
            if match is not None:
                matches.append(match)

        if not matches:
            return list(alerts)

        enriched: list[dict[str, Any]] = []
        for alert in alerts:
            cloned = dict(alert)
            extra = dict(alert.get("extra", {}) or {})
            extra["threat_intel"] = {"matches": [dict(item) for item in matches]}
            cloned["extra"] = extra
            enriched.append(cloned)

        if not self.emit_match_alerts:
            return enriched

        now_epoch = _to_epoch(str(flow_record.get("timestamp") or ""))
        dedupe_key = "|".join(sorted(f"{item['matched_role']}:{item['ip']}" for item in matches if item.get("ip")))
        if not dedupe_key or not self._should_emit(dedupe_key, now_epoch):
            return enriched

        severity = self.default_severity
        if matches:
            severity = max(
                (str(item.get("severity", self.default_severity)) for item in matches),
                key=_severity_rank,
            )

        enriched.append(
            {
                "engine": "threat_intel",
                "severity": severity,
                "rule_name": "Threat Intel Reputation Match",
                "summary": "Traffic matched locally configured threat-intelligence indicators.",
                "extra": {
                    "threat_intel": {
                        "matches": [dict(item) for item in matches],
                    }
                },
            }
        )
        return enriched
