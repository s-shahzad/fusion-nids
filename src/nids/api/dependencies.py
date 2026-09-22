from __future__ import annotations

import hmac
import time
from collections.abc import Callable

from fastapi import Header, HTTPException, Request, status

from ..platform.settings import PlatformSettings


def get_settings(request: Request) -> PlatformSettings:
    return request.app.state.settings


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _client_host(request: Request) -> str:
    client = request.client
    return client.host if client else ""


def _is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS


def _header_value(value: object) -> str | None:
    """Return ``value`` only when it is a real header string.

    These dependencies are also called directly -- ``require_write_access``
    delegates to ``require_read_access`` -- and a direct call leaves unpassed
    parameters holding their ``Header(default=None)`` sentinel rather than
    ``None``. Comparing that sentinel against a token silently misbehaves, so
    anything that is not a string is treated as "no header supplied".
    """
    return value if isinstance(value, str) else None


def require_read_access(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
) -> None:
    settings = get_settings(request)
    host = _client_host(request)
    if not settings.allow_remote_api and not _is_loopback(host):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="remote access disabled")

    if not settings.api_token:
        raise HTTPException(status_code=503, detail="NIDS_API_TOKEN is not configured")

    supplied = _header_value(x_api_token)
    auth = _header_value(authorization)
    if auth is not None:
        scheme, separator, token = auth.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not separator or not token:
            raise HTTPException(status_code=401, detail="invalid api token")
        if supplied is not None and not _tokens_equal(supplied, token):
            raise HTTPException(status_code=401, detail="conflicting api credentials")
        supplied = token
    if not supplied or not _tokens_equal(supplied, settings.api_token):
        raise HTTPException(status_code=401, detail="invalid api token")


def _tokens_equal(supplied: str, expected: str) -> bool:
    # Byte comparison also handles non-ASCII input without raising TypeError.
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def require_write_access(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
    x_action_token: str | None = Header(default=None),
) -> None:
    require_read_access(request, authorization=authorization, x_api_token=x_api_token)
    settings = get_settings(request)
    if not settings.allow_mutating_routes:
        raise HTTPException(status_code=403, detail="mutating routes are disabled")
    if not settings.action_token:
        raise HTTPException(status_code=503, detail="NIDS_ACTION_TOKEN is not configured")
    supplied = _header_value(x_action_token)
    if not supplied or not _tokens_equal(supplied, settings.action_token):
        raise HTTPException(status_code=401, detail="invalid action token")


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
