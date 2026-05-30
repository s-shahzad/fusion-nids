from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone


def _to_epoch(timestamp: str) -> float:
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


class AlertSuppressor:
    """Suppress duplicate alerts within a time window to reduce noise."""

    def __init__(self, window_sec: int = 15) -> None:
        self.window_sec = max(1, int(window_sec))
        self.last_seen: dict[str, float] = defaultdict(float)

    def should_emit(self, alert: dict[str, object], timestamp: str) -> bool:
        ts = _to_epoch(timestamp)
        key = "|".join(
            [
                str(alert.get("engine", "")),
                str(alert.get("rule_name", "")),
                str(alert.get("src_ip", "")),
                str(alert.get("dst_ip", "")),
                str(alert.get("dst_port", "")),
                str(alert.get("severity", "")),
            ]
        )

        previous = self.last_seen.get(key, 0.0)
        if ts - previous < self.window_sec:
            return False

        self.last_seen[key] = ts
        return True
