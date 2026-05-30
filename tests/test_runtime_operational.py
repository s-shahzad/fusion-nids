from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import src.NIDS.detect.ml as ml_module
import src.NIDS.runtime as runtime_module
from src.NIDS.config import build_runtime_config, RuntimeConfig
from src.NIDS.runtime import NIDSRuntime, run_runtime


def _rules_file(tmp_path: Path) -> Path:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: HTTP Evil Payload
  match:
    proto: TCP
    dst_ports: [80]
    payload_contains: ["evil"]
  action: alert
  severity: high
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return rules_path


def _runtime_config(
    tmp_path: Path,
    *,
    interface: str | None = None,
    pcap_dir: Path | None = None,
    adapters: dict[str, Any] | None = None,
    ml: dict[str, Any] | None = None,
) -> RuntimeConfig:
    return RuntimeConfig(
        interface=interface,
        pcap_dir=pcap_dir,
        rules_path=_rules_file(tmp_path),
        output_dir=tmp_path / "output",
        pipeline={"queue_max_size": 64, "metrics_interval_sec": 1, "replay_delay_ms": 0},
        detection={
            "dos_packets_per_sec_threshold": 10,
            "scan_ports_threshold": 2,
            "scan_window_sec": 12,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "suppress_window_sec": 0,
            "dns_unique_threshold": 10,
        },
        ml=ml or {"model_path": str(tmp_path / "missing-model.pkl"), "unsupervised": False},
        adapters=adapters or {},
        fusion={"enabled": True},
        maintenance={"enabled": False},
        notifications={"enabled": False},
    )


def test_build_runtime_config_applies_cli_precedence_over_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        """
pipeline:
  replay_delay_ms: 99
  metrics_interval_sec: 77
ml:
  model_path: models/from-yaml.pkl
  unsupervised: false
  unsupervised_alert_threshold: 0.25
adapters:
  suricata:
    enabled: false
    path: logs/eve.json
maintenance:
  enabled: false
notifications:
  enabled: false
""".strip()
        + "\n",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        config=str(config_path),
        replay_delay_ms=5,
        metrics_interval=3,
        model="models/from-cli.pkl",
        model_path=None,
        unsupervised=True,
        unsupervised_threshold=0.71,
        suricata_log=str(tmp_path / "eve-from-cli.json"),
        zeek_log=None,
        enable_suricata=False,
        enable_zeek=False,
        maintenance_enabled=True,
        maintenance_retention_days=14,
        maintenance_interval_hours=6,
        maintenance_include_artifacts=True,
        maintenance_vacuum=True,
        notify_webhook="https://hooks.slack.test/example",
        notify_min_severity="medium",
        notify_timeout_sec=6.0,
        notify_max_retries=5,
        notify_backoff_sec=0.3,
        notify_max_backoff_sec=1.4,
        notify_min_interval_sec=0.2,
        notify_dead_letter=str(tmp_path / "notify.jsonl"),
        notify_dead_letter_max_bytes=4096,
        notify_dead_letter_backup_count=2,
        interface="eth0",
        pcap_dir=str(tmp_path / "pcaps"),
        rules=str(_rules_file(tmp_path)),
        output_dir=str(tmp_path / "output"),
    )

    cfg = build_runtime_config(args)

    assert cfg.interface == "eth0"
    assert cfg.pipeline["replay_delay_ms"] == 5
    assert cfg.pipeline["metrics_interval_sec"] == 3
    assert cfg.ml["model_path"] == "models/from-cli.pkl"
    assert cfg.ml["unsupervised"] is True
    assert float(cfg.ml["unsupervised_alert_threshold"]) == 0.71
    assert cfg.adapters["suricata"]["enabled"] is True
    assert Path(str(cfg.adapters["suricata"]["path"])).is_absolute()
    assert cfg.maintenance["enabled"] is True
    assert cfg.maintenance["retention_days"] == 14
    assert cfg.maintenance["include_artifacts"] is True
    assert cfg.notifications["enabled"] is True
    assert cfg.notifications["slack_webhook"] == "https://hooks.slack.test/example"


def test_runtime_initialization_loads_rules_and_ml_engines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"fixture")
    captured: dict[str, Any] = {}

    class FakeSupervisedMLEngine:
        def __init__(self, model_path: Path, score_threshold: float) -> None:
            captured["model_path"] = str(model_path)
            captured["score_threshold"] = float(score_threshold)
            self.available = True

        def detect(self, *_args: object, **_kwargs: object) -> tuple[list[dict[str, Any]], dict[str, Any]]:
            return [], {}

    class FakeUnsupervisedMLEngine:
        def __init__(self, **kwargs: Any) -> None:
            captured["snapshot_path"] = kwargs.get("snapshot_path")

        def detect(self, *_args: object, **_kwargs: object) -> tuple[list[dict[str, Any]], dict[str, Any]]:
            return [], {}

        def save_snapshot(self) -> Path | None:
            return None

    monkeypatch.setattr(ml_module, "SupervisedMLEngine", FakeSupervisedMLEngine)
    monkeypatch.setattr(ml_module, "UnsupervisedMLEngine", FakeUnsupervisedMLEngine)

    cfg = _runtime_config(
        tmp_path,
        ml={
            "model_path": str(model_path),
            "score_threshold": 0.93,
            "unsupervised": True,
            "unsupervised_persist_baseline": True,
            "unsupervised_baseline_path": "",
        },
    )

    runtime = NIDSRuntime(cfg=cfg, sensor_id="sensor-init")
    try:
        assert runtime.signature.rules[0]["name"] == "HTTP Evil Payload"
        assert runtime.ml.supervised is not None
        assert captured["model_path"] == str(model_path)
        assert captured["score_threshold"] == 0.93
        assert str(captured["snapshot_path"]).endswith("unsupervised_baseline.pkl")
    finally:
        runtime.sqlite.close()


def test_runtime_run_assembles_producers_and_closes_resources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    eve_path = tmp_path / "eve.json"
    zeek_path = tmp_path / "conn.json"
    eve_path.write_text("", encoding="utf-8")
    zeek_path.write_text("", encoding="utf-8")

    cfg = _runtime_config(
        tmp_path,
        interface="eth0",
        pcap_dir=pcap_dir,
        adapters={
            "suricata": {"enabled": True, "path": str(eve_path)},
            "zeek": {"enabled": True, "path": str(zeek_path)},
        },
    )
    runtime = NIDSRuntime(cfg=cfg, sensor_id="sensor-run")

    calls: list[tuple[str, str]] = []
    closed: dict[str, bool] = {"sqlite": False, "ml": False}

    async def fake_live_capture(*, interface: str, queue: Any, stop_event: Any, sensor_id: str, **_kwargs: Any) -> None:
        del queue, stop_event
        calls.append(("live", f"{interface}:{sensor_id}"))

    async def fake_offline_pcaps(*, pcap_dir: Path, queue: Any, stop_event: Any, sensor_id: str, **_kwargs: Any) -> None:
        del queue, stop_event
        calls.append(("offline", f"{Path(pcap_dir).name}:{sensor_id}"))

    async def fake_suricata(*, eve_path: str, queue: Any, stop_event: Any, sensor_id: str) -> None:
        del queue, stop_event
        calls.append(("suricata", f"{Path(eve_path).name}:{sensor_id}"))

    async def fake_zeek(*, zeek_path: str, queue: Any, stop_event: Any, sensor_id: str) -> None:
        del queue, stop_event
        calls.append(("zeek", f"{Path(zeek_path).name}:{sensor_id}"))

    async def fake_metrics_loop() -> None:
        await runtime.stop_event.wait()

    monkeypatch.setattr(runtime_module, "run_live_capture", fake_live_capture)
    monkeypatch.setattr(runtime_module, "run_offline_pcaps", fake_offline_pcaps)
    monkeypatch.setattr(runtime_module, "run_suricata_eve", fake_suricata)
    monkeypatch.setattr(runtime_module, "run_zeek_json", fake_zeek)
    monkeypatch.setattr(runtime, "_metrics_loop", fake_metrics_loop)
    monkeypatch.setattr(runtime.sqlite, "close", lambda: closed.__setitem__("sqlite", True))
    monkeypatch.setattr(runtime.ml, "close", lambda: closed.__setitem__("ml", True) or None)

    asyncio.run(runtime.run())

    assert sorted(calls) == sorted(
        [
            ("live", "eth0:sensor-run"),
            ("offline", "pcaps:sensor-run"),
            ("suricata", "eve.json:sensor-run-suricata"),
            ("zeek", "conn.json:sensor-run-zeek"),
        ]
    )
    assert closed["sqlite"] is True
    assert closed["ml"] is True


def test_runtime_run_requires_at_least_one_ingest_source(tmp_path: Path) -> None:
    runtime = NIDSRuntime(cfg=_runtime_config(tmp_path), sensor_id="sensor-none")
    try:
        with pytest.raises(ValueError, match="No ingest source configured"):
            asyncio.run(runtime.run())
    finally:
        runtime.sqlite.close()


def test_producer_wrapper_logs_error_and_emits_sentinel(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = NIDSRuntime(cfg=_runtime_config(tmp_path), sensor_id="sensor-wrap")

    async def failing_producer() -> None:
        raise RuntimeError("synthetic failure")

    try:
        asyncio.run(runtime._producer_wrapper("live", failing_producer()))
        sentinel = runtime.queue.get_nowait()
    finally:
        runtime.sqlite.close()

    assert sentinel is None
    assert "producer[live] error: synthetic failure" in capsys.readouterr().out


def test_run_runtime_handles_keyboard_interrupt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    cfg = _runtime_config(tmp_path, interface="eth0")

    def fake_asyncio_run(coro: Any) -> None:
        coro.close()
        raise KeyboardInterrupt()

    monkeypatch.setattr(runtime_module.asyncio, "run", fake_asyncio_run)
    run_runtime(cfg)

    assert "runtime: stopped by user" in capsys.readouterr().out
