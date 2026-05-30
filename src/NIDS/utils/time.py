from __future__ import annotations

from datetime import datetime, timezone


def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def to_iso(ts: float | None = None) -> str:
    if ts is None:
        current = datetime.now(timezone.utc)
    else:
        current = datetime.fromtimestamp(ts, tz=timezone.utc)
    return current.isoformat(timespec="seconds")
