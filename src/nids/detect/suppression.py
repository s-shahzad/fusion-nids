from __future__ import annotations

from collections import defaultdict

from ..utils.time import now_ts, parse_epoch


class AlertSuppressor:
    """Suppress duplicate alerts within a time window to reduce noise."""

    def __init__(self, window_sec: int = 15) -> None:
        self.window_sec = max(1, int(window_sec))
        self.last_seen: dict[str, float] = defaultdict(float)

    def should_emit(self, alert: dict[str, object], timestamp: str) -> bool:
        ts = parse_epoch(timestamp)
        if ts is None:
            ts = now_ts()
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
        # Use the absolute gap, not the signed one. The old "ts - previous"
        # check meant any out-of-order/backdated ts (ts < previous) produced a
        # negative delta that is *always* < window_sec, so it always suppressed
        # -- no matter how far in the past ts actually was. Once a single bad
        # timestamp got stored as `previous` (e.g. a clock jump or malformed
        # value parsed far in the future), every subsequent normal-timed alert
        # for that key would be permanently suppressed, since last_seen is only
        # advanced when an alert actually emits. Comparing on magnitude means a
        # large gap in either direction is correctly treated as "not a
        # duplicate" and lets the key recover.
        should_emit = abs(ts - previous) >= self.window_sec
        if should_emit:
            self.last_seen[key] = ts
        return should_emit
