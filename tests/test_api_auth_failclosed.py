"""Auth dependencies must fail closed, not open. See issue #9.

The original defect: both token checks were guarded by ``if settings.api_token:``
/ ``if settings.action_token:``. With no token configured the check was skipped
and the request proceeded. Enabling remote access without also setting a token
therefore served an unauthenticated API, while the sibling dependency in the
same module (``get_universal_nids_api_key``) correctly refused when unconfigured.

Policy pinned here, matching scripts/run_dashboard_container.sh: loopback is
always allowed, any other client must present a token, and a missing token
configuration makes the route unavailable rather than unguarded.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.nids.api.dependencies import require_read_access, require_write_access
from src.nids.platform.errors import RouteDisabledError


def _request(
    host: str,
    *,
    api_token: str | None = None,
    action_token: str | None = None,
    allow_remote_api: bool = False,
    allow_mutating_routes: bool = False,
):
    """Minimal stand-in exposing only what the dependencies read."""
    settings = SimpleNamespace(
        api_token=api_token,
        action_token=action_token,
        allow_remote_api=allow_remote_api,
        allow_mutating_routes=allow_mutating_routes,
    )
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        app=SimpleNamespace(state=SimpleNamespace(settings=settings)),
    )


# --------------------------------------------------------------------------
# read access
# --------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_loopback_without_token_is_allowed(host):
    """Local development must keep working without configuring tokens."""
    require_read_access(_request(host), authorization=None, x_api_token=None)


def test_remote_client_is_refused_when_remote_access_disabled():
    with pytest.raises(HTTPException) as exc:
        require_read_access(_request("10.0.0.5"), authorization=None, x_api_token=None)
    assert exc.value.status_code == 403


def test_remote_access_enabled_without_token_fails_closed():
    """The regression this issue is about: enabled + unconfigured must refuse."""
    request = _request("10.0.0.5", allow_remote_api=True, api_token=None)

    with pytest.raises(HTTPException) as exc:
        require_read_access(request, authorization=None, x_api_token=None)

    assert exc.value.status_code == 503
    assert "NIDS_API_TOKEN" in exc.value.detail


def test_remote_access_with_correct_token_is_allowed():
    request = _request("10.0.0.5", allow_remote_api=True, api_token="s3cret")
    require_read_access(request, authorization=None, x_api_token="s3cret")


def test_remote_access_accepts_bearer_header():
    request = _request("10.0.0.5", allow_remote_api=True, api_token="s3cret")
    require_read_access(request, authorization="Bearer s3cret", x_api_token=None)


def test_remote_access_with_wrong_token_is_rejected():
    request = _request("10.0.0.5", allow_remote_api=True, api_token="s3cret")

    with pytest.raises(HTTPException) as exc:
        require_read_access(request, authorization=None, x_api_token="wrong")

    assert exc.value.status_code == 401


def test_missing_token_when_configured_is_rejected():
    """Absent header must not pass a configured token check."""
    request = _request("10.0.0.5", allow_remote_api=True, api_token="s3cret")

    with pytest.raises(HTTPException) as exc:
        require_read_access(request, authorization=None, x_api_token=None)

    assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# write access
# --------------------------------------------------------------------------


def test_mutating_routes_disabled_raises_route_disabled():
    request = _request("127.0.0.1", allow_mutating_routes=False)

    with pytest.raises(RouteDisabledError):
        require_write_access(request, authorization=None, x_action_token=None)


def test_loopback_write_without_action_token_is_allowed():
    request = _request("127.0.0.1", allow_mutating_routes=True)
    require_write_access(request, authorization=None, x_action_token=None)


def test_remote_write_without_action_token_fails_closed():
    request = _request(
        "10.0.0.5",
        allow_remote_api=True,
        api_token="s3cret",
        allow_mutating_routes=True,
        action_token=None,
    )

    with pytest.raises(HTTPException) as exc:
        require_write_access(request, authorization="Bearer s3cret", x_action_token=None)

    assert exc.value.status_code == 503
    assert "NIDS_ACTION_TOKEN" in exc.value.detail


def test_remote_write_with_correct_action_token_is_allowed():
    request = _request(
        "10.0.0.5",
        allow_remote_api=True,
        api_token="s3cret",
        allow_mutating_routes=True,
        action_token="act",
    )
    require_write_access(
        request, authorization=None, x_api_token="s3cret", x_action_token="act"
    )


def test_remote_write_with_wrong_action_token_is_rejected():
    request = _request(
        "10.0.0.5",
        allow_remote_api=True,
        api_token="s3cret",
        allow_mutating_routes=True,
        action_token="act",
    )

    with pytest.raises(HTTPException) as exc:
        require_write_access(
            request, authorization=None, x_api_token="s3cret", x_action_token="nope"
        )

    assert exc.value.status_code == 401


def test_write_forwards_api_token_to_read_check():
    """Regression: write routes dropped X-API-Token when delegating.

    `require_write_access` called `require_read_access` without passing
    `x_api_token`, so the read check saw the `Header(default=None)` sentinel
    instead of the caller's token and rejected every X-API-Token authenticated
    write, even with a correct token. Bearer auth masked it.
    """
    request = _request(
        "10.0.0.5",
        allow_remote_api=True,
        api_token="s3cret",
        allow_mutating_routes=True,
        action_token="act",
    )

    # No Authorization header at all: the token arrives only via X-API-Token.
    require_write_access(
        request, authorization=None, x_api_token="s3cret", x_action_token="act"
    )


def test_write_still_rejects_wrong_api_token():
    request = _request(
        "10.0.0.5",
        allow_remote_api=True,
        api_token="s3cret",
        allow_mutating_routes=True,
        action_token="act",
    )

    with pytest.raises(HTTPException) as exc:
        require_write_access(
            request, authorization=None, x_api_token="wrong", x_action_token="act"
        )

    assert exc.value.status_code == 401
