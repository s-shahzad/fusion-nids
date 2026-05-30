from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import yaml

from src.NIDS.config import RuntimeConfig
from src.NIDS.runtime_live import LiveCaptureController, process_packet_batch, start_live_capture, stop_live_capture, validate_interface
from realtime_lab.monitor.system_monitor import run_system_monitor
from realtime_lab.runner.run_realtime_lab import run_realtime_lab
from realtime_lab.traffic.traffic_generator import run_traffic_generator


def test_system_monitor_writes_log(tmp_path: Path) -> None:
    stop_event = threading.Event()
    output_path = tmp_path / "monitor_log.json"
    monitor = run_system_monitor(output_path=output_path, interval_seconds=0.1, stop_event=stop_event)
    stop_event.wait(0.25)
    samples = monitor.stop()
    assert output_path.exists()
    assert len(samples) >= 1
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert "cpu_percent" in payload[0]


def test_runtime_live_start_stop_without_crash(tmp_path: Path, monkeypatch) -> None:
    class _FakeRuntime:
        def __init__(self, cfg, sensor_id) -> None:
            self.cfg = cfg
            self.sensor_id = sensor_id
            self.stop_event = threading.Event()
            self.queue = type("Queue", (), {"qsize": staticmethod(lambda: 0)})()
            self.stats = type("Stats", (), {"events_seen": 2, "alerts_emitted": 1})()
            self.live_capture_telemetry = type(
                "Telemetry",
                (),
                {"snapshot": staticmethod(lambda backend=None: {"packets_processed": 2, "packets_enqueued": 2})},
            )()

        async def run(self) -> None:
            while not self.stop_event.is_set():
                await __import__("asyncio").sleep(0.05)

    rules_path = tmp_path / "rules.yml"
    rules_path.write_text("- name: test\n  match: {}\n  action: alert\n", encoding="utf-8")
    cfg = RuntimeConfig(
        interface=None,
        pcap_dir=None,
        rules_path=rules_path,
        output_dir=tmp_path / "output",
        pipeline={},
        detection={},
        ml={},
        adapters={},
    )

    monkeypatch.setattr("src.NIDS.runtime_live.NIDSRuntime", _FakeRuntime)
    monkeypatch.setattr("src.NIDS.runtime_live.list_available_interfaces", lambda: ["lo"])

    controller = start_live_capture("lo", cfg=cfg, duration=None, batch_size=4)
    snapshot = process_packet_batch(controller)
    assert snapshot["batch_size"] == 4
    stop_live_capture()
    assert controller.thread.is_alive() is False


def test_runtime_live_latency_calculation() -> None:
    runtime = type(
        "Runtime",
        (),
        {
            "stop_event": threading.Event(),
            "queue": type("Queue", (), {"qsize": staticmethod(lambda: 0)})(),
            "stats": type("Stats", (), {"events_seen": 1, "alerts_emitted": 1})(),
            "live_capture_telemetry": type(
                "Telemetry",
                (),
                {
                    "snapshot": staticmethod(
                        lambda backend=None: {
                            "packets_received": 2,
                            "packets_processed": 2,
                            "total_dropped_packets": 0,
                        }
                    )
                },
            )(),
            "cfg": type("Cfg", (), {"pipeline": {"live_capture_backend": "scapy"}})(),
        },
    )()
    controller = LiveCaptureController(
        runtime=runtime,
        thread=threading.Thread(target=lambda: None),
        interface="lo",
        batch_size=5,
        available_interfaces=["lo"],
    )
    capture_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))
    controller.record_event_metrics(
        queue_depth=2,
        processing_time_ms=3.5,
        event_timestamp=capture_ts,
        new_alerts=1,
    )
    metrics = controller.build_metrics()
    assert metrics.avg_latency_ms >= 0.0
    assert metrics.max_batch_processing_time_ms == 3.5
    assert metrics.queue_depth_peak == 2
    assert len(metrics.alert_latency_samples) == 1


def test_validate_interface_rejects_unknown_interface(monkeypatch) -> None:
    monkeypatch.setattr("src.NIDS.runtime_live.list_available_interfaces", lambda: ["lo", "eth0"])
    try:
        validate_interface("missing0")
    except ValueError as exc:
        assert "available interfaces" in str(exc)
    else:
        raise AssertionError("validate_interface should reject unknown interfaces")


def test_traffic_generator_runs_and_records_stats(tmp_path: Path) -> None:
    stop_event = threading.Event()
    output_path = tmp_path / "traffic_log.json"
    generator = run_traffic_generator(mode="mixed", duration=0.5, output_path=output_path, stop_event=stop_event)
    stats = generator.stop()
    assert output_path.exists()
    assert stats["mode"] == "mixed"
    assert stats["http_requests"] >= 0


def test_realtime_lab_runner_creates_expected_outputs(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "lab_config.yml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "interface": "auto",
                "duration": 1,
                "traffic_mode": "mixed",
                "batch_size": 5,
                "enable_fusion_trace": True,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    class _FakeController:
        def __init__(self) -> None:
            self.runtime = type(
                "Runtime",
                (),
                {
                    "stop_event": threading.Event(),
                    "queue": type("Queue", (), {"qsize": staticmethod(lambda: 0)})(),
                    "stats": type("Stats", (), {"events_seen": 4, "alerts_emitted": 1})(),
                    "live_capture_telemetry": type(
                        "Telemetry",
                        (),
                        {"snapshot": staticmethod(lambda backend=None: {"packets_processed": 4, "packets_enqueued": 4})},
                    )(),
                    "cfg": type("Cfg", (), {"pipeline": {"live_capture_backend": "scapy"}})(),
                },
            )()

        def build_metrics(self):
            return SimpleNamespace(
                total_packets=4,
                processed_packets=4,
                dropped_packets=0,
                avg_latency_ms=12.5,
                max_latency_ms=20.0,
                alerts_generated=1,
                runtime_duration=1.0,
                avg_batch_processing_time_ms=2.0,
                max_batch_processing_time_ms=4.0,
                queue_depth_peak=1,
                packets_captured=4,
                packets_processed_runtime=4,
                packets_dropped_detectable=0,
                privilege_ok=True,
                privilege_warning="",
                interface="lo",
                available_interfaces=["lo"],
                alert_latency_samples=[],
            )

    def fake_start_live_capture(*_args, **_kwargs):
        output_dir = Path(_kwargs["cfg"].output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        db_path = output_dir / "nids.db"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE alerts(
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    engine TEXT,
                    severity TEXT,
                    rule_name TEXT,
                    summary TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    proto TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO alerts(timestamp, engine, severity, rule_name, summary, src_ip, dst_ip, src_port, dst_port, proto)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("2026-03-28T12:00:00Z", "signature", "high", "Lab Alert", "Synthetic alert", "127.0.0.1", "127.0.0.1", 5000, 8080, "TCP"),
            )
        return _FakeController()

    def fake_generate_incident_report(from_db, out):
        del from_db
        path = Path(out)
        path.write_text("# Incident Report\n", encoding="utf-8")
        return path

    monkeypatch.setattr("realtime_lab.runner.run_realtime_lab.REPO_ROOT", tmp_path)
    monkeypatch.setattr("realtime_lab.runner.run_realtime_lab.validate_interface", lambda raw: "lo")
    monkeypatch.setattr("realtime_lab.runner.run_realtime_lab.start_live_capture", fake_start_live_capture)
    monkeypatch.setattr("realtime_lab.runner.run_realtime_lab.stop_live_capture", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "realtime_lab.runner.run_realtime_lab.process_packet_batch",
        lambda *_args, **_kwargs: {"telemetry": {"packets_processed": 4, "packets_enqueued": 4}},
    )
    monkeypatch.setattr("realtime_lab.runner.run_realtime_lab.generate_incident_report", fake_generate_incident_report)

    result = run_realtime_lab(config_path=config_path)
    output_dir = Path(result["output_dir"])
    assert output_dir.exists()
    assert (output_dir / "alerts.json").exists()
    assert (output_dir / "monitor_log.json").exists()
    assert (output_dir / "realtime_metrics.json").exists()
    assert (output_dir / "realtime_summary.md").exists()
    alerts = json.loads((output_dir / "alerts.json").read_text(encoding="utf-8"))
    assert len(alerts) == 1
    assert "Realtime Lab Summary" in (output_dir / "realtime_summary.md").read_text(encoding="utf-8")
    metrics_payload = json.loads((output_dir / "realtime_metrics.json").read_text(encoding="utf-8"))
    assert metrics_payload["avg_latency_ms"] == 12.5
