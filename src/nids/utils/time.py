from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def to_iso(ts: float | None = None) -> str:
    if ts is None:
        current = datetime.now(timezone.utc)
    else:
        current = datetime.fromtimestamp(ts, tz=timezone.utc)
    return current.isoformat(timespec="seconds")


def parse_epoch(value: Any) -> float | None:
    """Parse a timestamp into a UTC epoch float.

    Accepts an ISO-8601 string (with optional trailing "Z"), a numeric string,
    or an int/float already in epoch seconds. Returns ``None`` when ``value``
    is missing, blank, or unparsable -- it never silently substitutes the
    current time for a bad timestamp. Callers that want a "fall back to now"
    behavior must do so explicitly, e.g. ``parse_epoch(x) if parse_epoch(x)
    is not None else now_ts()``, so that failure handling is visible at each
    call site instead of buried here.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)

    token = str(value).strip()
    if not token:
        return None

    try:
        return float(token)
    except (TypeError, ValueError):
        pass

    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None
