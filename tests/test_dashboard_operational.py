from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from src.NIDS.storage.sqlite_store import SQLiteStore
from src.NIDS.visuals.dashboard import create_dashboard_app, run_dashboard


def _route_endpoint(app: Any, path: str, method: str):
    for route in app.routes:
        route_path = getattr(route, "path", None)
        route_methods = getattr(route, "methods", set())
        if route_path == path and method.upper() in route_methods:
            return route.endpoint
    raise AssertionError(f"Route not found: {method} {path}")


def _websocket_endpoint(app: Any, path: str):
    for route in app.routes:
        if getattr(route, "path", None) == path:
            return route.endpoint
    raise AssertionError(f"WebSocket route not found: {path}")


def _request(
    method: str,
    path: str,
    *,
    query_string: str = "",
    headers: dict[str, str] | None = None,
    json_payload: dict[str, Any] | None = None,
):
    from starlette.requests import Request

    body = b""
    header_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if json_payload is not None:
        body = json.dumps(json_payload).encode("utf-8")
        header_map.setdefault("content-type", "application/json")
    if body:
        header_map.setdefault("content-length", str(len(body)))

    raw_headers = [(name.encode("latin-1"), value.encode("latin-1")) for name, value in header_map.items()]
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query_string.encode("utf-8"),
        "headers": raw_headers,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope, receive)


def _seed_dashboard_db(db_path: Path) -> int:
    store = SQLiteStore(db_path)
    try:
        alert_id = store.insert_alert(
            {
                "timestamp": "2026-03-08T15:00:00+00:00",
                "sensor_id": "sensor-dashboard",
                "dataset_source": "pcap:test-dashboard.pcap",
                "src_ip": "10.0.0.10",
                "dst_ip": "192.0.2.10",
                "src_port": 55000,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "high",
                "engine": "signature",
                "rule_name": "TLS Suspicion",
                "summary": "dashboard alert",
                "is_labeled": 0,
            }
        )
        store.insert_metric("2026-03-08T15:00:00+00:00", "sensor-dashboard", "events_per_sec", 18.2)
        store.insert_metric("2026-03-08T15:00:00+00:00", "sensor-dashboard", "alerts_per_min", 4.0)
        store.insert_metric("2026-03-08T15:00:00+00:00", "sensor-dashboard", "queue_size", 2.0)
        store.insert_metric("2026-03-08T15:00:00+00:00", "sensor-dashboard", "ingest_lag_sec", 0.4)
        store.insert_flow(
            {
                "timestamp": "2026-03-08T15:00:00+00:00",
                "sensor_id": "sensor-dashboard",
                "dataset_source": "pcap:test-dashboard.pcap",
                "src_ip": "10.0.0.10",
                "dst_ip": "192.0.2.10",
                "src_port": 55000,
                "dst_port": 443,
                "proto": "TCP",
                "packet_len": 128,
                "packet_count": 2,
            }
        )
        store.acknowledge_alert(alert_id, actor="analyst-1", actor_role="analyst", reason="triage")
        store.create_suppression_rule_from_alert(
            alert_id,
            actor="admin-1",
            actor_role="admin",
            ttl_minutes=30,
            reason="known maintenance noise",
        )
        return alert_id
    finally:
        store.close()


def test_dashboard_readyz_reports_degraded_when_core_tables_are_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.db"
    app = create_dashboard_app(db_path)
    ready_endpoint = _route_endpoint(app, "/readyz", "GET")

    response = asyncio.run(ready_endpoint())
    payload = json.loads(response.body)

    assert response.status_code == 200
    assert payload["status"] == "degraded"
    assert payload["db_exists"] is True
    assert "alerts" in payload["missing_tables"]


def test_dashboard_figures_audit_and_suppression_paths_return_data(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    alert_id = _seed_dashboard_db(db_path)
    app = create_dashboard_app(db_path, api_token="view-token", action_token="action-token")

    figures_endpoint = _route_endpoint(app, "/api/figures", "GET")
    audit_endpoint = _route_endpoint(app, "/api/audit", "GET")
    suppressions_endpoint = _route_endpoint(app, "/api/suppressions", "GET")

    request = _request("GET", "/api/figures", query_string="token=view-token")
    figures_response = asyncio.run(
        figures_endpoint(
            request,
            lookback=5,
            severity="high",
            engine="signature",
            sensor_id="sensor-dashboard",
        )
    )
    figures_payload = json.loads(figures_response.body)
    assert figures_response.status_code == 200
    assert len(figures_payload["charts"]) == 10
    assert any(chart["slug"] == "time_series_alerts_traffic" for chart in figures_payload["charts"])

    audit_response = asyncio.run(audit_endpoint(_request("GET", "/api/audit", query_string="token=view-token"), limit=10))
    audit_payload = json.loads(audit_response.body)
    assert audit_response.status_code == 200
    assert any(str(item["action"]) == "ack" for item in audit_payload["actions"])

    suppressions_response = asyncio.run(
        suppressions_endpoint(_request("GET", "/api/suppressions", query_string="token=view-token"), limit=10)
    )
    suppressions_payload = json.loads(suppressions_response.body)
    assert suppressions_response.status_code == 200
    assert len(suppressions_payload["rules"]) >= 1
    assert int(suppressions_payload["rules"][0]["source_alert_id"]) == alert_id


def test_dashboard_websocket_rejects_missing_token(tmp_path: Path) -> None:
    class FakeWebSocket:
        def __init__(self) -> None:
            self.query_params: dict[str, str] = {}
            self.headers: dict[str, str] = {}
            self.accepted = False
            self.closed_code: int | None = None

        async def accept(self) -> None:
            self.accepted = True

        async def send_json(self, _payload: dict[str, Any]) -> None:
            raise AssertionError("send_json should not be called for unauthorized clients")

        async def close(self, code: int = 1000) -> None:
            self.closed_code = code

    app = create_dashboard_app(tmp_path / "nids.db", api_token="view-token")
    ws_endpoint = _websocket_endpoint(app, "/ws/realtime")
    websocket = FakeWebSocket()

    asyncio.run(ws_endpoint(websocket))

    assert websocket.accepted is False
    assert websocket.closed_code == 4401


def test_dashboard_websocket_streams_one_payload_then_exits_on_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeWebSocket:
        def __init__(self) -> None:
            self.query_params = {"token": "view-token", "lookback": "5", "sensor_id": "sensor-dashboard"}
            self.headers: dict[str, str] = {}
            self.accepted = False
            self.closed_code: int | None = None
            self.sent: list[dict[str, Any]] = []

        async def accept(self) -> None:
            self.accepted = True

        async def send_json(self, payload: dict[str, Any]) -> None:
            self.sent.append(payload)

        async def close(self, code: int = 1000) -> None:
            self.closed_code = code

    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    import src.NIDS.visuals.dashboard as dashboard_module

    async def fake_sleep(_seconds: float) -> None:
        raise RuntimeError("test-stop")

    monkeypatch.setattr(
        dashboard_module,
        "_build_realtime_payload",
        lambda *_args, **_kwargs: {"generated_at": "2026-03-08T15:00:00Z", "summary": {"alerts_per_min": 4.0}},
    )
    monkeypatch.setattr(dashboard_module.asyncio, "sleep", fake_sleep)

    app = create_dashboard_app(db_path, api_token="view-token")
    ws_endpoint = _websocket_endpoint(app, "/ws/realtime")
    websocket = FakeWebSocket()

    asyncio.run(ws_endpoint(websocket))

    assert websocket.accepted is True
    assert len(websocket.sent) == 1
    assert websocket.sent[0]["summary"]["alerts_per_min"] == 4.0
    assert websocket.closed_code is None


def test_run_dashboard_delegates_to_uvicorn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(app: Any, *, host: str, port: int) -> None:
        captured["app"] = app
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setitem(sys.modules, "uvicorn", types.SimpleNamespace(run=fake_run))

    run_dashboard(tmp_path / "nids.db", host="0.0.0.0", port=9000, api_token="view-token")

    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9000
    assert getattr(captured["app"], "title", "") == "Universal NIDS Analytics Dashboard"
