from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import json
import logging
import threading
import uuid
from typing import Any

from fastapi import Request
from pydantic import BaseModel


logger = logging.getLogger("nids.api")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


class ApiErrorPayload(BaseModel):
    error: str
    detail: str
    status_code: int
    path: str
    timestamp: str
    request_id: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def request_id_from_headers(request: Request) -> str:
    token = str(request.headers.get("x-request-id", "") or "").strip()
    if token and len(token) <= 128:
        return token
    return uuid.uuid4().hex


def request_id(request: Request) -> str:
    token = getattr(request.state, "request_id", None)
    if token:
        return str(token)
    token = request_id_from_headers(request)
    request.state.request_id = token
    return token


def error_payload(request: Request, *, status_code: int, error: str, detail: str) -> ApiErrorPayload:
    return ApiErrorPayload(
        error=error,
        detail=detail,
        status_code=status_code,
        path=str(request.url.path),
        timestamp=utc_now_iso(),
        request_id=request_id(request),
    )


def log_api_event(level: int, event: str, *, request: Request | None = None, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "event": event,
    }
    if request is not None:
        payload["path"] = str(request.url.path)
        payload["request_id"] = request_id(request)
        if request.client and request.client.host:
            payload["client"] = request.client.host
    payload.update(fields)
    logger.log(level, json.dumps(payload, sort_keys=True))


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, *, limit: int, window_sec: int, now: float) -> bool:
        with self._lock:
            bucket = self._buckets[key]
            cutoff = now - float(window_sec)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= int(limit):
                return False
            bucket.append(now)
            return True
