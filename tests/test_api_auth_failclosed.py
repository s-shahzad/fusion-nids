"""The canonical dependencies fail closed for local and remote callers."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.nids.api.dependencies import require_read_access, require_write_access


def _request(host="127.0.0.1", **overrides):
    settings = dict(api_token="read", action_token="write", allow_remote_api=True,
                    allow_mutating_routes=True)
    settings.update(overrides)
    return SimpleNamespace(client=SimpleNamespace(host=host),
                           app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(**settings))))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "10.0.0.5"])
@pytest.mark.parametrize("token, supplied, expected", [(None, None, 503), ("read", None, 401),
                                                       ("read", "wrong", 401)])
def test_read_fails_closed_everywhere(host, token, supplied, expected):
    with pytest.raises(HTTPException) as exc:
        require_read_access(_request(host, api_token=token), authorization=None, x_api_token=supplied)
    assert exc.value.status_code == expected


def test_remote_policy_precedes_token_configuration():
    with pytest.raises(HTTPException) as exc:
        require_read_access(_request("10.0.0.5", allow_remote_api=False, api_token=None))
    assert exc.value.status_code == 403


@pytest.mark.parametrize("authorization, token", [("Bearer read", None), (None, "read"),
                                                   ("Bearer read", "read")])
def test_read_credentials(authorization, token):
    require_read_access(_request(), authorization=authorization, x_api_token=token)


@pytest.mark.parametrize("authorization, token", [("Basic read", "read"), ("Bearer", "read"),
    ("", "read"), ("Bearer read", "wrong"), ("Bearer wrong", "read"),
    ("Bearer read extra", "read"), ("Bearer ", "read"), ("Bearer räad", None)])
def test_invalid_or_conflicting_headers_reject(authorization, token):
    with pytest.raises(HTTPException) as exc:
        require_read_access(_request(), authorization=authorization, x_api_token=token)
    assert exc.value.status_code == 401


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "10.0.0.5"])
def test_action_configuration_required_locally_and_remotely(host):
    with pytest.raises(HTTPException) as exc:
        require_write_access(_request(host, action_token=None), authorization="Bearer read",
                             x_api_token=None, x_action_token=None)
    assert exc.value.status_code == 503
    assert "NIDS_ACTION_TOKEN" in exc.value.detail


def test_mutations_disabled_returns_http_403():
    with pytest.raises(HTTPException) as exc:
        require_write_access(_request(allow_mutating_routes=False), authorization="Bearer read",
                             x_api_token=None, x_action_token="write")
    assert exc.value.status_code == 403


@pytest.mark.parametrize("authorization, token", [("Bearer read", None), (None, "read")])
def test_write_accepts_separate_read_and_action_credentials(authorization, token):
    require_write_access(_request(), authorization=authorization, x_api_token=token,
                         x_action_token="write")


@pytest.mark.parametrize("authorization, token, action", [("Bearer read", None, None),
    ("Bearer read", None, "wrong"), ("Bearer read", None, "wrïte"),
    ("Bearer write", "read", "write"), (None, "wrong", "write"), (None, None, "write")])
def test_write_rejects_invalid_credentials(authorization, token, action):
    with pytest.raises(HTTPException) as exc:
        require_write_access(_request(), authorization=authorization, x_api_token=token,
                             x_action_token=action)
    assert exc.value.status_code == 401


def test_bearer_cannot_substitute_for_action_header_even_with_same_tokens():
    with pytest.raises(HTTPException) as exc:
        require_write_access(_request(action_token="read"), authorization="Bearer read",
                             x_api_token=None, x_action_token=None)
    assert exc.value.status_code == 401
