from __future__ import annotations

import hmac
import os
import time
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from ..platform.errors import RouteDisabledError
from ..platform.settings import PlatformSettings


def get_settings(request: Request) -> PlatformSettings:
    return request.app.state.settings


def _client_host(request: Request) -> str:
    client = request.client
    return client.host if client else ""


def require_read_access(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
) -> None:
    settings = get_settings(request)
    host = _client_host(request)
    if not settings.allow_remote_api and host not in {"127.0.0.1", "::1", "localhost"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="remote access disabled")
    if settings.api_token:
        supplied = x_api_token
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization.split(" ", 1)[1].strip()
        if supplied != settings.api_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api token")


def require_write_access(
    request: Request,
    authorization: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> None:
    require_read_access(request, authorization=authorization)
    settings = get_settings(request)
    if not settings.allow_mutating_routes:
        raise RouteDisabledError("mutating routes are disabled")
    if settings.action_token:
        supplied = x_action_token
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization.split(" ", 1)[1].strip()
        if supplied != settings.action_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid action token")


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_universal_nids_api_key(provided_api_key: str | None = Depends(api_key_header)) -> None:
    expected = str(os.getenv("UNIVERSAL_NIDS_API_KEY", "") or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Protected endpoints are disabled until UNIVERSAL_NIDS_API_KEY is configured.",
        )
    provided = str(provided_api_key or "").strip()
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


def enforce_rate_limit(*, limit: int, window_sec: int) -> Callable[[Request], None]:
    def dependency(request: Request) -> None:
        limiter = getattr(request.app.state, "rate_limiter", None)
        clock = getattr(request.app.state, "rate_limit_clock", time.monotonic)
        if limiter is None:
            return
        route = request.scope.get("route")
        route_path = getattr(route, "path", request.url.path)
        client = request.client
        client_host = client.host if client and client.host else "local"
        bucket_key = f"{request.method.upper()}:{route_path}:{client_host}"
        if not limiter.allow(bucket_key, limit=limit, window_sec=window_sec, now=float(clock())):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests for this route. Try again later.",
            )

    return dependency
