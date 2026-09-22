"""Request-level authentication contract shared by both API factories."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from unittest.mock import Mock

import pytest

import importlib
from src.nids.api import production_app
control = importlib.import_module("src.nids.api.app")
from src.nids.services.report_service import ReportService
from test_control_layer_api import _asgi_request


READ_PATHS = [("control", path) for path in ["/runs", "/status", "/runs/example/summary",
    "/runs/example/alerts", "/runs/example/metrics"]] + [
    ("production", "/v1/alerts/recent"), ("production", "/health/ready")]
WRITE_PATHS = [("control", path) for path in ["/run-local", "/runs/example/explain",
    "/exports/portfolio-bundle", "/llm/summarize-run", "/llm/explain-alert",
    "/llm/analyze-alerts"]] + [("production", "/v1/reports/incident")]


@pytest.fixture
def make_app(monkeypatch, tmp_path):
    monkeypatch.setenv("NIDS_API_TOKEN", "read")
    monkeypatch.setenv("NIDS_ACTION_TOKEN", "write")
    monkeypatch.setenv("NIDS_ALLOW_REMOTE_API", "false")
    monkeypatch.setenv("NIDS_ALLOW_MUTATING_ROUTES", "true")
    monkeypatch.setenv("NIDS_TRUSTED_HOSTS", "testserver")
    monkeypatch.setenv("NIDS_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setenv("NIDS_SQLITE_PATH", str(tmp_path / "output" / "nids.db"))
    monkeypatch.delenv("UNIVERSAL_NIDS_API_KEY", raising=False)
    monkeypatch.setattr(control, "_repo_root", lambda: tmp_path)

    def create(kind, **settings):
        app = (control if kind == "control" else production_app).create_app()
        app.state.settings = replace(app.state.settings, **settings)
        return app
    return create


def request(app, method, path, headers=None, body=None, host="127.0.0.1"):
    # Reuse the existing dependency-free ASGI transport; wrap only client IP.
    async def with_client(scope, receive, send):
        scope = dict(scope, client=(host, 50000))
        await app(scope, receive, send)
    return asyncio.run(_asgi_request(with_client, method, path, headers=headers, json_body=body))[0]


@pytest.mark.parametrize("kind,path", READ_PATHS)
@pytest.mark.parametrize("headers", [None, {"X-API-Key": "read"}, {"X-API-Token": "wrong"},
    {"Authorization": "Basic read", "X-API-Token": "read"},
    {"Authorization": "Bearer read", "X-API-Token": "wrong"},
    {"Authorization": "Bearer räad"}])
def test_every_protected_read_rejects_invalid_auth(make_app, kind, path, headers):
    assert request(make_app(kind), "GET", path, headers) == 401


@pytest.mark.parametrize("kind,path", READ_PATHS)
def test_every_read_fails_closed_without_configuration(make_app, monkeypatch, kind, path):
    monkeypatch.setenv("UNIVERSAL_NIDS_API_KEY", "legacy")
    app = make_app(kind, api_token=None)
    assert request(app, "GET", path, {"X-API-Key": "legacy"}) == 503


@pytest.mark.parametrize("kind,path", READ_PATHS)
def test_remote_disabled_precedes_configuration(make_app, kind, path):
    assert request(make_app(kind, api_token=None), "GET", path, host="10.0.0.5") == 403


@pytest.mark.parametrize("kind,path", READ_PATHS)
def test_authenticated_read_reaches_handler(make_app, monkeypatch, kind, path):
    monkeypatch.setattr(ReportService, "recent_alerts", lambda *args, **kwargs: [])
    status = request(make_app(kind), "GET", path, {"Authorization": "Bearer read"})
    assert status == (404 if "/runs/example/" in path else 200)


@pytest.mark.parametrize("kind,path", WRITE_PATHS)
@pytest.mark.parametrize("settings,headers,expected", [
    ({}, {}, 401),
    ({}, {"X-API-Key": "read"}, 401),
    ({}, {"X-Action-Token": "write"}, 401),
    ({}, {"Authorization": "Bearer read"}, 401),
    ({}, {"Authorization": "Bearer read", "X-Action-Token": "wrong"}, 401),
    ({}, {"Authorization": "Bearer write", "X-API-Token": "read", "X-Action-Token": "write"}, 401),
    ({"action_token": None}, {"Authorization": "Bearer read"}, 503),
    ({"allow_mutating_routes": False}, {"Authorization": "Bearer read", "X-Action-Token": "write"}, 403),
])
def test_every_write_denies_before_side_effects(make_app, tmp_path, kind, path, settings, headers, expected):
    app = make_app(kind, **settings)
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert request(app, "POST", path, headers, {}) == expected
    after = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert after == before


@pytest.mark.parametrize("kind", ["control", "production"])
@pytest.mark.parametrize("read_headers", [{"Authorization": "Bearer read"}, {"X-API-Token": "read"}])
def test_authenticated_write_calls_service_once(make_app, monkeypatch, tmp_path, kind, read_headers):
    if kind == "control":
        service = Mock(return_value=object())
        monkeypatch.setattr(control, "_run_local_request", service)
        # The endpoint logs pipeline result attributes before serializing.
        from types import SimpleNamespace
        service.return_value = SimpleNamespace(output_dir=tmp_path, flow_count=0, alert_count=0)
        monkeypatch.setattr(control, "_success_response", lambda result: dict(status="ok", output_dir=str(tmp_path),
            flows=0, alerts=0, report_path=None, visuals_path=None))
        path = "/run-local"
        body = {"pcap_path": "sample.pcap", "output_dir": str(tmp_path)}
    else:
        service = Mock(return_value=tmp_path / "report.md")
        monkeypatch.setattr(ReportService, "generate_incident_markdown", service)
        path = "/v1/reports/incident"
        body = {"out_path": str(tmp_path / "report.md")}
    app = make_app(kind)
    assert request(app, "POST", path, read_headers, body) == 401
    service.assert_not_called()
    assert request(app, "POST", path, dict(read_headers, **{"X-Action-Token": "write"}), body) == 200
    service.assert_called_once()


@pytest.mark.parametrize("kind,path", [("control", "/runs"), ("production", "/health/ready")])
def test_app_settings_are_snapshot_not_live_environment(make_app, monkeypatch, kind, path):
    app = make_app(kind)
    monkeypatch.setenv("NIDS_API_TOKEN", "changed")
    assert request(app, "GET", path, {"X-API-Token": "read"}) == 200
    assert request(app, "GET", path, {"X-API-Token": "changed"}) == 401


@pytest.mark.parametrize("kind,path", [("control", "/runs"), ("production", "/health/ready")])
def test_remote_enabled_still_requires_token(make_app, kind, path):
    app = make_app(kind, allow_remote_api=True)
    assert request(app, "GET", path, host="10.0.0.5") == 401
    assert request(app, "GET", path, {"X-API-Token": "read"}, host="10.0.0.5") == 200


