from __future__ import annotations

import asyncio
import importlib
import json
from pathlib import Path

from src.NIDS.ai.providers.ollama_provider import OllamaProvider
from src.NIDS.ai.services.explainer_service import ExplainerService
from src.NIDS.pipeline.runtime import LocalPipelineResult
from src.NIDS.services.export_service import ExportService
from src.NIDS.services.run_inspection_service import RunInspectionService
from src.NIDS.storage.sqlite_store import SQLiteStore
from starlette.requests import Request


app_module = importlib.import_module("src.NIDS.api.app")


def _alert_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "timestamp": "2026-03-08T10:15:00+00:00",
        "sensor_id": "sensor-a",
        "dataset_source": "pcap:unit-test.pcap",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.0.2.10",
        "src_port": 50505,
        "dst_port": 443,
        "proto": "TCP",
        "severity": "high",
        "engine": "fusion",
        "rule_name": "Suspicious TLS Session",
        "summary": "unit-test alert",
        "anomaly_score": 0.74,
        "predicted_label": "attack",
        "prediction_score": 0.92,
        "supervised_score": 0.88,
        "unsupervised_score": 0.63,
        "unsupervised_isolation_score": 0.61,
        "unsupervised_autoencoder_score": 0.65,
        "fusion_score": 0.9,
        "fusion_label": "malicious",
        "fusion_agreement_count": 3,
        "label": "attack",
        "attack_type": "credential-access",
        "is_labeled": 1,
        "extra": {"baseline_snapshot_path": "C:/private/unsupervised_baseline.pkl"},
    }
    payload.update(overrides)
    return payload


def _flow_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "timestamp": "2026-03-08T10:15:01+00:00",
        "sensor_id": "sensor-a",
        "dataset_source": "pcap:unit-test.pcap",
        "src_ip": "10.0.0.10",
        "dst_ip": "192.0.2.10",
        "src_port": 50505,
        "dst_port": 443,
        "proto": "TCP",
        "packet_len": 512,
        "packet_count": 4,
    }
    payload.update(overrides)
    return payload


def _seed_run(repo_root: Path, run_name: str = "run-a") -> None:
    run_dir = repo_root / "output" / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(run_dir / "nids.db")
    try:
        store.insert_alert(_alert_payload())
        store.insert_alert(_alert_payload(severity="medium", engine="signature", rule_name="HTTP Suspicious Keyword"))
        store.insert_flow(_flow_payload())
        store.insert_flow(_flow_payload(dst_port=22, packet_len=128))
    finally:
        store.close()
    (run_dir / "summary.md").write_text("# Summary\n", encoding="utf-8")
    (run_dir / "graphs").mkdir(exist_ok=True)
    (run_dir / "graphs" / "index.html").write_text("<html></html>", encoding="utf-8")
    with (run_dir / "alerts.jsonl").open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(_alert_payload()) + "\n")
        handle.write(json.dumps(_alert_payload(severity="medium", engine="signature", rule_name="HTTP Suspicious Keyword")) + "\n")


def _seed_baseline_profile(repo_root: Path) -> None:
    profile_path = repo_root / "NIDS_TestLab" / "config" / "offline_replay_profile.yml"
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(
        "ml:\n  unsupervised_confirmation_hits: 2\nfusion:\n  min_agreement_count: 3\n",
        encoding="utf-8",
    )


class FakeClock:
    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _route_endpoint(app, path: str, method: str):
    for route in app.routes:
        if getattr(route, "path", None) == path and method.upper() in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError(f"Route not found: {method} {path}")


def _request(method: str, path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope, receive)


async def _asgi_request(
    app,
    method: str,
    path: str,
    *,
    json_body: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], object]:
    body = b""
    request_headers: list[tuple[bytes, bytes]] = [(b"host", b"testserver")]
    if headers:
        request_headers.extend((key.lower().encode("utf-8"), value.encode("utf-8")) for key, value in headers.items())
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        request_headers.append((b"content-type", b"application/json"))
        request_headers.append((b"content-length", str(len(body)).encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": request_headers,
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }

    request_sent = False
    response_status = 500
    response_headers: dict[str, str] = {}
    response_body = bytearray()

    async def receive():
        nonlocal request_sent
        if request_sent:
            return {"type": "http.disconnect"}
        request_sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        nonlocal response_status, response_headers
        if message["type"] == "http.response.start":
            response_status = int(message["status"])
            response_headers = {
                key.decode("utf-8"): value.decode("utf-8")
                for key, value in message.get("headers", [])
            }
        elif message["type"] == "http.response.body":
            response_body.extend(message.get("body", b""))

    await app(scope, receive, send)
    raw_text = response_body.decode("utf-8")
    try:
        payload: object = json.loads(raw_text)
    except json.JSONDecodeError:
        payload = raw_text
    return response_status, response_headers, payload


def test_run_summary_alerts_and_metrics_endpoints(tmp_path: Path, monkeypatch) -> None:
    _seed_run(tmp_path, "run-a")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    app = app_module.create_app()

    summary_endpoint = _route_endpoint(app, "/runs/{run_name}/summary", "GET")
    alerts_endpoint = _route_endpoint(app, "/runs/{run_name}/alerts", "GET")
    metrics_endpoint = _route_endpoint(app, "/runs/{run_name}/metrics", "GET")

    summary_payload = asyncio.run(summary_endpoint("run-a", _request("GET", "/runs/run-a/summary")))
    assert summary_payload.run_name == "run-a"
    assert int(summary_payload.flows) == 2

    alerts_payload = asyncio.run(alerts_endpoint("run-a", _request("GET", "/runs/run-a/alerts"), 5))
    assert alerts_payload.count == 2
    assert alerts_payload.alerts[0].rule_name == "Suspicious TLS Session"

    metrics_payload = asyncio.run(metrics_endpoint("run-a", _request("GET", "/runs/run-a/metrics")))
    assert metrics_payload.engine_distribution["fusion"] == 1
    assert metrics_payload.severity_distribution["high"] == 1


def test_run_alerts_apply_privacy_filter_when_enabled(tmp_path: Path, monkeypatch) -> None:
    _seed_run(tmp_path, "run-private")
    monkeypatch.setenv("NIDS_PRIVACY_MODE", "review")
    monkeypatch.setenv("NIDS_REDACT_IP_ADDRESSES", "true")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    app = app_module.create_app()

    alerts_endpoint = _route_endpoint(app, "/runs/{run_name}/alerts", "GET")
    alerts_payload = asyncio.run(alerts_endpoint("run-private", _request("GET", "/runs/run-private/alerts"), 5))
    assert alerts_payload.alerts[0].src_ip == "10.0.0.x"
    assert alerts_payload.alerts[0].dst_ip == "192.0.2.x"
    assert alerts_payload.alerts[0].privacy_metadata["privacy_mode"] == "review"


def test_portfolio_bundle_generation_writes_sanitized_files(tmp_path: Path) -> None:
    _seed_run(tmp_path, "run-export")
    service = RunInspectionService(tmp_path)
    exporter = ExportService(tmp_path, service)

    payload = exporter.export_portfolio_bundle(run_name="run-export")
    output_dir = Path(payload["output_dir"])

    assert (output_dir / "nids-summary.json").exists()
    assert (output_dir / "nids-metrics.json").exists()
    assert (output_dir / "nids-alerts-sample.json").exists()
    assert (output_dir / "nids-case-study-summary.md").exists()

    alerts_sample = json.loads((output_dir / "nids-alerts-sample.json").read_text(encoding="utf-8"))
    assert alerts_sample["alerts"][0]["evidence_reference"] == "unsupervised_baseline.pkl"


def test_explainer_service_falls_back_when_ollama_is_unavailable(monkeypatch) -> None:
    service = ExplainerService.from_env()
    monkeypatch.setattr(OllamaProvider, "available", lambda self: False)

    payload = service.explain_run(
        summary={"run_name": "run-a", "flows": 509, "alerts": 10, "status": "ready"},
        metrics={
            "engine_distribution": {"fusion": 2, "signature": 1},
            "severity_distribution": {"critical": 1, "high": 1},
            "baseline_comparison": {"matches_validated_result": True, "delta": {"flows": 0, "alerts": 0, "alert_ratio": 0.0}},
        },
        alerts=[{"rule_name": "Hybrid Fusion Decision", "engine": "fusion", "severity": "critical"}],
        compare_summary=None,
    )

    assert payload["fallback_used"] is True
    assert payload["provider"] == "deterministic-fallback"
    assert "matches the validated baseline" in payload["summary"]


def test_run_local_requires_configured_api_key(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    monkeypatch.delenv("UNIVERSAL_NIDS_API_KEY", raising=False)
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    app = app_module.create_app()
    status_code, _, payload = asyncio.run(
        _asgi_request(
            app,
            "POST",
            "/run-local",
            json_body={
                "pcap_path": "NIDS_TestLab/pcaps/sample.pcap",
                "output_dir": "output/api-test-run",
            },
        )
    )

    assert status_code == 503
    assert "UNIVERSAL_NIDS_API_KEY" in str(payload["detail"])


def test_run_local_requires_valid_api_key(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    monkeypatch.setenv("UNIVERSAL_NIDS_API_KEY", "expected-key")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    app = app_module.create_app()
    payload = {
        "pcap_path": "NIDS_TestLab/pcaps/sample.pcap",
        "output_dir": "output/api-test-run",
    }

    missing_status, _, missing_payload = asyncio.run(_asgi_request(app, "POST", "/run-local", json_body=payload))
    assert missing_status == 401
    assert missing_payload["detail"] == "Invalid or missing API key."

    wrong_status, _, wrong_payload = asyncio.run(
        _asgi_request(app, "POST", "/run-local", json_body=payload, headers={"X-API-Key": "wrong-key"})
    )
    assert wrong_status == 401
    assert wrong_payload["detail"] == "Invalid or missing API key."


def test_run_local_accepts_correct_api_key(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    monkeypatch.setenv("UNIVERSAL_NIDS_API_KEY", "expected-key")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)

    def fake_run_local(request) -> LocalPipelineResult:
        output_dir = (tmp_path / "output" / "api-test-run").resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "summary.md"
        visuals_dir = output_dir / "graphs"
        visuals_dir.mkdir(exist_ok=True)
        visual_index = visuals_dir / "index.html"
        report_path.write_text("# Summary\n", encoding="utf-8")
        visual_index.write_text("<html></html>", encoding="utf-8")
        return LocalPipelineResult(
            output_dir=output_dir,
            db_path=output_dir / "nids.db",
            flows_jsonl_path=output_dir / "flows.jsonl",
            alerts_jsonl_path=output_dir / "alerts.jsonl",
            metrics_jsonl_path=output_dir / "metrics.jsonl",
            report_path=report_path,
            visual_dir=visuals_dir,
            visual_index_path=visual_index,
            chart_count=1,
            flow_count=4,
            alert_count=2,
            metric_count=1,
        )

    monkeypatch.setattr(app_module, "_run_local_request", fake_run_local)
    app = app_module.create_app()
    status_code, _, payload = asyncio.run(
        _asgi_request(
            app,
            "POST",
            "/run-local",
            headers={"X-API-Key": "expected-key"},
            json_body={
                "pcap_path": "NIDS_TestLab/pcaps/sample.pcap",
                "output_dir": "output/api-test-run",
            },
        )
    )

    assert status_code == 200
    assert payload["status"] == "ok"
    assert payload["flows"] == 4
    assert payload["alerts"] == 2


def test_read_only_endpoints_remain_open_without_auth(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    _seed_run(tmp_path, "run-open")
    monkeypatch.delenv("UNIVERSAL_NIDS_API_KEY", raising=False)
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    app = app_module.create_app()
    health_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/health"))
    version_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/version"))
    baseline_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/baseline"))
    summary_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/runs/run-open/summary"))
    alerts_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/runs/run-open/alerts"))

    assert health_status == 200
    assert version_status == 200
    assert baseline_status == 200
    assert summary_status == 200
    assert alerts_status == 200


def test_status_endpoint_reports_operating_profile(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    _seed_run(tmp_path, "run-status")
    monkeypatch.setenv("NIDS_PRIVACY_MODE", "review")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "config" / "nids.yml").write_text(
        "pipeline:\n  enable_hot_cold_pipeline: true\n  cold_worker_enabled: true\n",
        encoding="utf-8",
    )
    app = app_module.create_app()
    status_code, _, payload = asyncio.run(_asgi_request(app, "GET", "/status"))
    assert status_code == 200
    assert payload["api_health"] == "ok"
    assert payload["privacy_mode"] == "review"
    assert payload["hot_cold_enabled"] is True
    assert payload["cold_worker_enabled"] is True


def test_run_local_rate_limit_returns_429(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    monkeypatch.setenv("UNIVERSAL_NIDS_API_KEY", "expected-key")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(app_module, "_run_local_request", lambda request: LocalPipelineResult(
        output_dir=(tmp_path / "output" / "limited-run").resolve(),
        db_path=tmp_path / "output" / "limited-run" / "nids.db",
        flows_jsonl_path=tmp_path / "output" / "limited-run" / "flows.jsonl",
        alerts_jsonl_path=tmp_path / "output" / "limited-run" / "alerts.jsonl",
        metrics_jsonl_path=tmp_path / "output" / "limited-run" / "metrics.jsonl",
        report_path=tmp_path / "output" / "limited-run" / "summary.md",
        visual_dir=tmp_path / "output" / "limited-run" / "graphs",
        visual_index_path=tmp_path / "output" / "limited-run" / "graphs" / "index.html",
        chart_count=1,
        flow_count=1,
        alert_count=1,
        metric_count=1,
    ))
    app = app_module.create_app()
    clock = FakeClock()
    app.state.rate_limit_clock = clock
    payload = {"pcap_path": "NIDS_TestLab/pcaps/sample.pcap", "output_dir": "output/limited-run"}
    headers = {"X-API-Key": "expected-key"}

    first_status, _, _ = asyncio.run(_asgi_request(app, "POST", "/run-local", headers=headers, json_body=payload))
    second_status, _, _ = asyncio.run(_asgi_request(app, "POST", "/run-local", headers=headers, json_body=payload))
    third_status, _, third_payload = asyncio.run(_asgi_request(app, "POST", "/run-local", headers=headers, json_body=payload))

    assert first_status == 200
    assert second_status == 200
    assert third_status == 429
    assert third_payload["detail"] == "Too many requests for this route. Try again later."


def test_summary_rate_limit_resets_after_window_expiry(tmp_path: Path, monkeypatch) -> None:
    _seed_baseline_profile(tmp_path)
    _seed_run(tmp_path, "run-rate")
    monkeypatch.setattr(app_module, "_repo_root", lambda: tmp_path)
    app = app_module.create_app()
    clock = FakeClock()
    app.state.rate_limit_clock = clock

    for _ in range(30):
        response_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/runs/run-rate/summary"))
        assert response_status == 200

    limited_status, _, limited_payload = asyncio.run(_asgi_request(app, "GET", "/runs/run-rate/summary"))
    assert limited_status == 429
    assert limited_payload["detail"] == "Too many requests for this route. Try again later."

    clock.advance(61.0)
    recovered_status, _, _ = asyncio.run(_asgi_request(app, "GET", "/runs/run-rate/summary"))
    assert recovered_status == 200
