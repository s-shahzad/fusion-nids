from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from starlette.requests import Request
import pytest

from src.NIDS.storage.sqlite_store import SQLiteStore
from src.NIDS.visuals.dashboard import (
    _build_realtime_payload,
    _dashboard_html,
    _is_authorized_token,
    create_dashboard_app,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _seed_dashboard_db(db_path: Path) -> None:
    store = SQLiteStore(db_path)
    try:
        timestamp = _now_iso()

        sensor_a_metrics = [
            ("runtime_heartbeat", 1.0),
            ("events_per_sec", 12.5),
            ("alerts_per_min", 7.0),
            ("queue_size", 4.0),
            ("ingest_lag_sec", 0.35),
            ("total_alerts", 20.0),
            ("suppressed_alerts", 2.0),
        ]
        sensor_b_metrics = [
            ("runtime_heartbeat", 1.0),
            ("events_per_sec", 88.0),
            ("alerts_per_min", 1.0),
            ("queue_size", 80.0),
            ("ingest_lag_sec", 5.0),
            ("total_alerts", 3.0),
            ("suppressed_alerts", 0.0),
        ]

        for metric_name, metric_value in sensor_a_metrics:
            store.insert_metric(timestamp, "sensor-a", metric_name, metric_value)
        for metric_name, metric_value in sensor_b_metrics:
            store.insert_metric(timestamp, "sensor-b", metric_name, metric_value)

        store.insert_alert(
            {
                "timestamp": timestamp,
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:test-a.pcap",
                "src_ip": "10.0.0.5",
                "dst_ip": "192.168.1.10",
                "src_port": 51000,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "high",
                "engine": "signature",
                "rule_name": "Suspicious TLS",
                "summary": "A alert",
                "is_labeled": 0,
            }
        )
        store.insert_alert(
            {
                "timestamp": timestamp,
                "sensor_id": "sensor-b",
                "dataset_source": "pcap:test-b.pcap",
                "src_ip": "10.1.1.8",
                "dst_ip": "172.16.2.40",
                "src_port": 52000,
                "dst_port": 53,
                "proto": "UDP",
                "severity": "low",
                "engine": "anomaly",
                "rule_name": "DNS Burst",
                "summary": "B alert",
                "is_labeled": 0,
            }
        )
    finally:
        store.close()


def _route_endpoint(app: Any, path: str, method: str):
    for route in app.routes:
        route_path = getattr(route, 'path', None)
        route_methods = getattr(route, 'methods', set())
        if route_path == path and method.upper() in route_methods:
            return route.endpoint
    raise AssertionError(f'Route not found: {method} {path}')


def _build_request(
    method: str,
    path: str,
    *,
    query_string: str = '',
    headers: dict[str, str] | None = None,
    json_payload: dict[str, Any] | None = None,
) -> Request:
    body = b''
    header_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}

    if json_payload is not None:
        body = json.dumps(json_payload).encode('utf-8')
        header_map.setdefault('content-type', 'application/json')
    if body:
        header_map.setdefault('content-length', str(len(body)))

    raw_headers = [
        (name.encode('latin-1'), value.encode('latin-1'))
        for name, value in header_map.items()
    ]

    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {'type': 'http.request', 'body': b'', 'more_body': False}
        sent = True
        return {'type': 'http.request', 'body': body, 'more_body': False}

    scope = {
        'type': 'http',
        'http_version': '1.1',
        'method': method.upper(),
        'scheme': 'http',
        'path': path,
        'raw_path': path.encode('utf-8'),
        'query_string': query_string.encode('utf-8'),
        'headers': raw_headers,
        'client': ('testclient', 50000),
        'server': ('testserver', 80),
    }
    return Request(scope, receive)


def _call_app_http(
    app: Any,
    method: str,
    path: str,
    *,
    query_string: str = "",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    payload = body or b""
    header_map = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    if payload:
        header_map.setdefault("content-length", str(len(payload)))

    raw_headers = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in header_map.items()
    ]

    sent = False
    messages: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

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

    asyncio.run(app(scope, receive, send))

    status_code = 0
    header_result: dict[str, str] = {}
    body_chunks: list[bytes] = []

    for message in messages:
        msg_type = str(message.get("type") or "")
        if msg_type == "http.response.start":
            status_code = int(message.get("status") or 0)
            raw = message.get("headers") or []
            for item in raw:
                name = bytes(item[0]).decode("latin-1").lower()
                value = bytes(item[1]).decode("latin-1")
                header_result[name] = value
        elif msg_type == "http.response.body":
            body_chunks.append(bytes(message.get("body") or b""))

    return status_code, header_result, b"".join(body_chunks)


def test_dashboard_html_contains_advanced_sections() -> None:
    html = _dashboard_html()
    assert "Realtime Status" in html
    assert "Latest Alerts" in html
    assert "Sensor Comparison" in html
    assert "Drift Alerts" in html
    assert "Incident Audit" in html
    assert "Incident Queue" in html
    assert "incident-queue-filter" in html
    assert "incident-status-filter" in html
    assert "incident-owner-filter" in html
    assert "Active Suppressions" in html
    assert "Anomaly Trend Bands" in html
    assert "history.replaceState" in html
    assert "filter-sensor" in html
    assert "/api/realtime" in html
    assert "/api/audit" in html
    assert "/api/suppressions" in html
    assert "/api/incidents" in html
    assert "fetchIncidents" in html
    assert "postIncidentAssign" in html
    assert "postIncidentStatus" in html
    assert "postAlertAction" in html
    assert "postSuppressionRevoke" in html
    assert "new WebSocket" in html
    assert "/ws/realtime" in html


def test_realtime_payload_filters_and_sensor_summary(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    payload = _build_realtime_payload(
        db_path,
        lookback_minutes=5,
        max_alerts=10,
        sensor_id="sensor-a",
        severity="high",
        engine="signature",
    )

    assert payload["summary"]["events_per_sec"] == 12.5
    assert payload["summary"]["ingest_lag_sec"] == 0.35

    assert len(payload["series"]["events_per_sec"]) >= 1
    assert len(payload["recent_alerts"]) == 1

    first_alert = payload["recent_alerts"][0]
    assert first_alert["sensor_id"] == "sensor-a"
    assert int(first_alert["alert_id"]) >= 1
    assert first_alert["ack_status"] in {"new", "acknowledged"}
    assert first_alert["severity"].lower() == "high"
    assert first_alert["engine"].lower() == "signature"

    assert "sensor-a" in payload["available_sensors"]
    assert "sensor-b" in payload["available_sensors"]

    assert len(payload["sensor_summary"]) >= 1
    first_sensor = payload["sensor_summary"][0]
    assert first_sensor["sensor_id"] == "sensor-a"
    assert first_sensor["alert_count"] >= 1
    assert "anomaly_trend" in payload
    assert "drift_alerts" in payload


def test_realtime_payload_reports_drift_and_trend(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    payload = _build_realtime_payload(
        db_path,
        lookback_minutes=5,
        max_alerts=10,
        sensor_id=None,
        severity=None,
        engine=None,
    )

    assert len(payload.get("anomaly_trend", [])) >= 1
    drift_rows = payload.get("drift_alerts", [])
    assert isinstance(drift_rows, list)
    assert any(str(item.get("sensor_id")) == "sensor-b" for item in drift_rows)


def test_dashboard_app_has_realtime_routes(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path)
    paths = {route.path for route in app.routes}

    assert "/" in paths
    assert "/healthz" in paths
    assert "/readyz" in paths
    assert "/api/figures" in paths
    assert "/api/realtime" in paths
    assert "/api/audit" in paths
    assert "/api/incidents" in paths
    assert "/api/incidents/{incident_id}/assign" in paths
    assert "/api/incidents/{incident_id}/status" in paths
    assert "/api/incidents/bulk" in paths
    assert "/api/alerts/{alert_id}/ack" in paths
    assert "/api/alerts/{alert_id}/suppress" in paths
    assert "/api/suppressions" in paths
    assert "/api/suppressions/{rule_id}/revoke" in paths
    assert "/ws/realtime" in paths


def test_dashboard_health_and_ready_handlers(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path)
    route_map = {route.path: route for route in app.routes if hasattr(route, "endpoint")}

    health_response = asyncio.run(route_map["/healthz"].endpoint())
    assert health_response.status_code == 200
    health_payload = json.loads(health_response.body)
    assert health_payload["status"] == "ok"
    assert health_payload["db_exists"] is True

    ready_response = asyncio.run(route_map["/readyz"].endpoint())
    assert ready_response.status_code == 200
    ready_payload = json.loads(ready_response.body)
    assert ready_payload["status"] in {"ready", "degraded"}
    assert isinstance(ready_payload["missing_tables"], list)
    notifications_payload = ready_payload.get("notifications", {})
    assert "dead_letter_max_bytes" in notifications_payload
    assert "dead_letter_backup_count" in notifications_payload


def test_dashboard_token_auth_helper() -> None:
    assert _is_authorized_token(None, query_token=None, header_token=None, authorization_header=None) is True

    assert _is_authorized_token(
        "secret-token",
        query_token="secret-token",
        header_token=None,
        authorization_header=None,
    ) is True
    assert _is_authorized_token(
        "secret-token",
        query_token=None,
        header_token="secret-token",
        authorization_header=None,
    ) is True
    assert _is_authorized_token(
        "secret-token",
        query_token=None,
        header_token=None,
        authorization_header="Bearer secret-token",
    ) is True
    assert _is_authorized_token(
        "secret-token",
        query_token="wrong",
        header_token=None,
        authorization_header="Bearer wrong",
    ) is False


def test_dashboard_incident_api_assign_and_status(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path, api_token="view-token", action_token="action-token")

    incidents_endpoint = _route_endpoint(app, "/api/incidents", "GET")
    incidents_request = _build_request(
        "GET",
        "/api/incidents",
        query_string="token=view-token",
    )
    incidents_response = asyncio.run(
        incidents_endpoint(
            incidents_request,
            limit=25,
            queue="open",
            status_filter=None,
            owner=None,
            priority=None,
            sensor_id=None,
            severity=None,
            engine=None,
        )
    )
    assert incidents_response.status_code == 200

    incidents_payload = json.loads(incidents_response.body)
    incidents = incidents_payload.get("incidents", [])
    assert len(incidents) >= 1

    incident_id = int(incidents[0].get("incident_id") or incidents[0].get("id") or 0)
    assert incident_id > 0

    action_headers = {
        "x-nids-token": "action-token",
        "x-nids-actor": "analyst-1",
        "x-nids-role": "analyst",
    }

    assign_endpoint = _route_endpoint(app, "/api/incidents/{incident_id}/assign", "POST")
    assign_request = _build_request(
        "POST",
        f"/api/incidents/{incident_id}/assign",
        query_string="token=view-token",
        headers=action_headers,
        json_payload={"owner": "analyst-1", "reason": "take ownership"},
    )
    assign_response = asyncio.run(assign_endpoint(incident_id, assign_request))
    assert assign_response.status_code == 200

    assign_payload = json.loads(assign_response.body)
    assert str(assign_payload["incident"]["owner"]) == "analyst-1"

    status_endpoint = _route_endpoint(app, "/api/incidents/{incident_id}/status", "POST")
    status_request = _build_request(
        "POST",
        f"/api/incidents/{incident_id}/status",
        query_string="token=view-token",
        headers=action_headers,
        json_payload={"status": "investigating", "reason": "analysis started"},
    )
    status_response = asyncio.run(status_endpoint(incident_id, status_request))
    assert status_response.status_code == 200

    status_payload = json.loads(status_response.body)
    assert str(status_payload["incident"]["status"]) == "investigating"


def test_dashboard_incident_bulk_api_rbac_and_validation(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path, api_token="view-token", action_token="action-token")

    incidents_endpoint = _route_endpoint(app, "/api/incidents", "GET")
    incidents_request = _build_request(
        "GET",
        "/api/incidents",
        query_string="token=view-token",
    )
    incidents_response = asyncio.run(
        incidents_endpoint(
            incidents_request,
            limit=25,
            queue="open",
            status_filter=None,
            owner=None,
            priority=None,
            sensor_id=None,
            severity=None,
            engine=None,
        )
    )
    assert incidents_response.status_code == 200

    incidents_payload = json.loads(incidents_response.body)
    incidents = incidents_payload.get("incidents", [])
    assert len(incidents) >= 2

    incident_ids = [int(row.get("incident_id") or row.get("id") or 0) for row in incidents]
    incident_ids = [value for value in incident_ids if value > 0]
    assert len(incident_ids) >= 2

    bulk_endpoint = _route_endpoint(app, "/api/incidents/bulk", "POST")

    invalid_action_token_request = _build_request(
        "POST",
        "/api/incidents/bulk",
        query_string="token=view-token",
        headers={
            "x-nids-token": "view-token",
            "x-nids-actor": "analyst-2",
            "x-nids-role": "analyst",
        },
        json_payload={
            "incident_ids": incident_ids[:2],
            "status": "triage",
            "reason": "bulk triage",
        },
    )
    with pytest.raises(HTTPException) as invalid_action_token_exc:
        asyncio.run(bulk_endpoint(invalid_action_token_request))
    assert int(invalid_action_token_exc.value.status_code) == 401

    forbidden_role_request = _build_request(
        "POST",
        "/api/incidents/bulk",
        query_string="token=view-token",
        headers={
            "x-nids-token": "action-token",
            "x-nids-actor": "viewer-1",
            "x-nids-role": "viewer",
        },
        json_payload={
            "incident_ids": incident_ids[:2],
            "status": "triage",
            "reason": "bulk triage",
        },
    )
    with pytest.raises(HTTPException) as forbidden_role_exc:
        asyncio.run(bulk_endpoint(forbidden_role_request))
    assert int(forbidden_role_exc.value.status_code) == 403

    invalid_priority_request = _build_request(
        "POST",
        "/api/incidents/bulk",
        query_string="token=view-token",
        headers={
            "x-nids-token": "action-token",
            "x-nids-actor": "analyst-2",
            "x-nids-role": "analyst",
        },
        json_payload={
            "incident_ids": incident_ids[:2],
            "priority": "urgent",
        },
    )
    with pytest.raises(HTTPException) as invalid_priority_exc:
        asyncio.run(bulk_endpoint(invalid_priority_request))
    assert int(invalid_priority_exc.value.status_code) == 422

    bulk_update_request = _build_request(
        "POST",
        "/api/incidents/bulk",
        query_string="token=view-token",
        headers={
            "x-nids-token": "action-token",
            "x-nids-actor": "analyst-2",
            "x-nids-role": "analyst",
        },
        json_payload={
            "incident_ids": incident_ids[:2],
            "owner": "analyst-2",
            "status": "triage",
            "reason": "bulk triage",
        },
    )
    bulk_update_response = asyncio.run(bulk_endpoint(bulk_update_request))
    assert bulk_update_response.status_code == 200

    payload = json.loads(bulk_update_response.body)
    assert int(payload.get("updated_count") or 0) == 2
    updated = payload.get("incidents", [])
    assert len(updated) == 2
    assert all(str(item.get("owner") or "") == "analyst-2" for item in updated)
    assert all(str(item.get("status") or "") == "triage" for item in updated)



def test_dashboard_read_api_rejects_missing_token(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path, api_token="view-token")
    incidents_endpoint = _route_endpoint(app, "/api/incidents", "GET")
    incidents_request = _build_request("GET", "/api/incidents")

    with pytest.raises(HTTPException) as unauthorized_exc:
        asyncio.run(
            incidents_endpoint(
                incidents_request,
                limit=25,
                queue="open",
                status_filter=None,
                owner=None,
                priority=None,
                sensor_id=None,
                severity=None,
                engine=None,
            )
        )
    assert int(unauthorized_exc.value.status_code) == 401


def test_dashboard_status_api_enforces_action_token_and_role(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path, api_token="view-token", action_token="action-token")

    incidents_endpoint = _route_endpoint(app, "/api/incidents", "GET")
    incidents_request = _build_request(
        "GET",
        "/api/incidents",
        query_string="token=view-token",
    )
    incidents_response = asyncio.run(
        incidents_endpoint(
            incidents_request,
            limit=25,
            queue="open",
            status_filter=None,
            owner=None,
            priority=None,
            sensor_id=None,
            severity=None,
            engine=None,
        )
    )
    assert incidents_response.status_code == 200

    incidents_payload = json.loads(incidents_response.body)
    incidents = incidents_payload.get("incidents", [])
    assert len(incidents) >= 1

    incident_id = int(incidents[0].get("incident_id") or incidents[0].get("id") or 0)
    assert incident_id > 0

    status_endpoint = _route_endpoint(app, "/api/incidents/{incident_id}/status", "POST")

    wrong_action_token_request = _build_request(
        "POST",
        f"/api/incidents/{incident_id}/status",
        query_string="token=view-token",
        headers={
            "x-nids-token": "view-token",
            "x-nids-actor": "analyst-3",
            "x-nids-role": "analyst",
        },
        json_payload={"status": "triage", "reason": "auth smoke"},
    )
    with pytest.raises(HTTPException) as wrong_action_token_exc:
        asyncio.run(status_endpoint(incident_id, wrong_action_token_request))
    assert int(wrong_action_token_exc.value.status_code) == 401

    forbidden_role_request = _build_request(
        "POST",
        f"/api/incidents/{incident_id}/status",
        query_string="token=view-token",
        headers={
            "x-nids-token": "action-token",
            "x-nids-actor": "viewer-2",
            "x-nids-role": "viewer",
        },
        json_payload={"status": "triage", "reason": "rbac smoke"},
    )
    with pytest.raises(HTTPException) as forbidden_role_exc:
        asyncio.run(status_endpoint(incident_id, forbidden_role_request))
    assert int(forbidden_role_exc.value.status_code) == 403

def test_dashboard_http_security_headers_present(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path, api_token="view-token", action_token="action-token")

    status_code, response_headers, _ = _call_app_http(
        app,
        "GET",
        "/api/realtime",
        query_string="token=view-token",
    )

    assert status_code == 200
    assert response_headers.get("x-content-type-options") == "nosniff"
    assert response_headers.get("x-frame-options") == "DENY"
    assert response_headers.get("referrer-policy") == "no-referrer"
    assert response_headers.get("permissions-policy") == "geolocation=(), microphone=(), camera=()"
    csp = str(response_headers.get("content-security-policy") or "")
    assert "frame-ancestors 'none'" in csp


def test_dashboard_action_endpoints_require_header_or_bearer_action_token(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_dashboard_db(db_path)

    app = create_dashboard_app(db_path, api_token="view-token", action_token="action-token")

    incidents_endpoint = _route_endpoint(app, "/api/incidents", "GET")
    incidents_request = _build_request(
        "GET",
        "/api/incidents",
        query_string="token=view-token",
    )
    incidents_response = asyncio.run(
        incidents_endpoint(
            incidents_request,
            limit=25,
            queue="open",
            status_filter=None,
            owner=None,
            priority=None,
            sensor_id=None,
            severity=None,
            engine=None,
        )
    )
    assert incidents_response.status_code == 200

    incidents_payload = json.loads(incidents_response.body)
    incidents = incidents_payload.get("incidents", [])
    assert len(incidents) >= 1

    incident_id = int(incidents[0].get("incident_id") or incidents[0].get("id") or 0)
    assert incident_id > 0

    status_endpoint = _route_endpoint(app, "/api/incidents/{incident_id}/status", "POST")

    request_missing_action_header = _build_request(
        "POST",
        f"/api/incidents/{incident_id}/status",
        query_string="token=view-token",
        headers={
            "x-nids-actor": "analyst-4",
            "x-nids-role": "analyst",
        },
        json_payload={"status": "triage", "reason": "header required"},
    )

    with pytest.raises(HTTPException) as missing_action_header_exc:
        asyncio.run(status_endpoint(incident_id, request_missing_action_header))
    assert int(missing_action_header_exc.value.status_code) == 401
