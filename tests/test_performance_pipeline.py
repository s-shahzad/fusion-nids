from __future__ import annotations

import asyncio
import time
import tracemalloc
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from src.NIDS.config import RuntimeConfig
from src.NIDS.ingest.offline import run_offline_pcaps
from src.NIDS.runtime import NIDSRuntime
from src.NIDS.storage.jsonl_store import JSONLStore
from src.NIDS.storage.sqlite_store import SQLiteStore


pytestmark = [pytest.mark.slow, pytest.mark.integration]


def _rules_file(tmp_path: Path) -> Path:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Performance Signature
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


def _runtime(tmp_path: Path) -> NIDSRuntime:
    cfg = RuntimeConfig(
        interface=None,
        pcap_dir=None,
        rules_path=_rules_file(tmp_path),
        output_dir=tmp_path / "output",
        pipeline={"queue_max_size": 4096, "metrics_interval_sec": 5, "replay_delay_ms": 0},
        detection={
            "dos_packets_per_sec_threshold": 20,
            "scan_ports_threshold": 5,
            "scan_window_sec": 12,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "suppress_window_sec": 0,
            "dns_unique_threshold": 10,
        },
        ml={"model_path": str(tmp_path / "missing-model.pkl"), "unsupervised": False},
        adapters={},
        fusion={"enabled": True},
        maintenance={"enabled": False},
        notifications={"enabled": False},
    )
    return NIDSRuntime(cfg=cfg, sensor_id="perf-sensor")


def _event(index: int) -> dict[str, object]:
    return {
        "timestamp": f"2026-03-08T16:00:{index % 60:02d}+00:00",
        "sensor_id": "perf-sensor",
        "dataset_source": "pcap:perf.pcap",
        "src_ip": f"10.0.0.{(index % 40) + 1}",
        "dst_ip": "192.0.2.80",
        "src_port": 50000 + (index % 200),
        "dst_port": 80,
        "proto": "TCP",
        "packet_len": 180,
        "tcp_flags": "PA",
        "payload": b"GET /evil HTTP/1.1\r\nHost: perf.local\r\n\r\n",
        "label": None,
        "attack_type": None,
        "is_labeled": 0,
    }


def test_offline_pcap_replay_throughput_smoke(tmp_path: Path) -> None:
    pcap_path = tmp_path / "perf.pcap"
    packets = [
        IP(src=f"10.0.0.{(index % 40) + 1}", dst="192.0.2.80") / TCP(sport=50000 + index, dport=80) / Raw(load=b"evil")
        for index in range(200)
    ]
    wrpcap(str(pcap_path), packets)

    async def exercise() -> tuple[int, float]:
        queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()
        stop_event = asyncio.Event()
        started = time.perf_counter()
        await run_offline_pcaps(pcap_dir=pcap_path, queue=queue, stop_event=stop_event, sensor_id="perf-sensor")
        duration = time.perf_counter() - started
        count = queue.qsize()
        return count, duration

    count, duration = asyncio.run(exercise())
    throughput = count / max(duration, 0.001)

    assert count == 200
    assert duration < 20.0
    assert throughput >= 10.0


def test_runtime_detection_latency_smoke(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    started = time.perf_counter()
    try:
        for index in range(120):
            runtime._process_event(_event(index))
    finally:
        duration = time.perf_counter() - started
        runtime.sqlite.close()

    avg_latency_ms = (duration / 120.0) * 1000.0
    assert runtime.stats.events_seen == 120
    assert runtime.stats.alerts_emitted >= 1
    assert avg_latency_ms < 100.0


def test_storage_write_pressure_smoke(tmp_path: Path) -> None:
    sqlite_store = SQLiteStore(tmp_path / "perf.db")
    jsonl_store = JSONLStore(tmp_path / "jsonl")
    started = time.perf_counter()
    try:
        for index in range(500):
            sqlite_store.insert_alert(
                {
                    "timestamp": f"2026-03-08T16:10:{index % 60:02d}+00:00",
                    "sensor_id": "perf-sensor",
                    "dataset_source": "pcap:perf.pcap",
                    "src_ip": f"10.0.1.{(index % 40) + 1}",
                    "dst_ip": "192.0.2.90",
                    "src_port": 51000 + index,
                    "dst_port": 443,
                    "proto": "TCP",
                    "severity": "medium",
                    "engine": "signature",
                    "rule_name": "Write Pressure",
                    "summary": "perf alert",
                    "is_labeled": 0,
                }
            )
            jsonl_store.append_flow(
                {
                    "timestamp": f"2026-03-08T16:10:{index % 60:02d}+00:00",
                    "sensor_id": "perf-sensor",
                    "src_ip": f"10.0.1.{(index % 40) + 1}",
                    "dst_ip": "192.0.2.90",
                    "packet_len": 128,
                }
            )
    finally:
        duration = time.perf_counter() - started
        sqlite_store.close()

    assert duration < 15.0
    assert sum(1 for _ in (tmp_path / "jsonl" / "flows.jsonl").open("r", encoding="utf-8")) == 500


def test_memory_growth_during_replay_is_bounded(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    tracemalloc.start()
    try:
        for index in range(200):
            runtime._process_event(_event(index))
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
        runtime.sqlite.close()

    assert peak < 40 * 1024 * 1024
