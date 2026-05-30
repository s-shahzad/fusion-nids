from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.config import RuntimeConfig
from src.NIDS.runtime import NIDSRuntime


def _ts(days_offset: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days_offset)).isoformat(timespec="seconds")


def _build_runtime(tmp_path: Path) -> NIDSRuntime:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Integration Signature Match
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

    cfg = RuntimeConfig(
        interface=None,
        pcap_dir=None,
        rules_path=rules_path,
        output_dir=tmp_path / "output",
        pipeline={"queue_max_size": 128, "metrics_interval_sec": 5, "replay_delay_ms": 0},
        detection={
            "dos_packets_per_sec_threshold": 1,
            "scan_ports_threshold": 1,
            "scan_window_sec": 12,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "suppress_window_sec": 0,
            "dns_unique_threshold": 10,
        },
        ml={"unsupervised": False, "model_path": str(tmp_path / "missing_model.pkl")},
        adapters={},
        maintenance={
            "enabled": True,
            "retention_days": 1,
            "interval_sec": 300,
            "include_artifacts": False,
            "vacuum": False,
        },
    )
    return NIDSRuntime(cfg=cfg, sensor_id="test-sensor")


def test_runtime_scheduled_maintenance_prunes_old_rows(tmp_path: Path) -> None:
    runtime = _build_runtime(tmp_path)
    try:
        runtime.sqlite.insert_alert(
            {
                "timestamp": _ts(-10),
                "sensor_id": "test-sensor",
                "dataset_source": "pcap:test",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 80,
                "proto": "TCP",
                "severity": "low",
                "engine": "signature",
                "rule_name": "old-rule",
                "summary": "old",
                "is_labeled": 0,
            }
        )
        runtime.sqlite.insert_alert(
            {
                "timestamp": _ts(0),
                "sensor_id": "test-sensor",
                "dataset_source": "pcap:test",
                "src_ip": "10.0.0.2",
                "dst_ip": "1.1.1.1",
                "src_port": 50001,
                "dst_port": 80,
                "proto": "TCP",
                "severity": "low",
                "engine": "signature",
                "rule_name": "new-rule",
                "summary": "new",
                "is_labeled": 0,
            }
        )

        runtime._run_maintenance_if_due(datetime.now(timezone.utc).timestamp())

        db_path = tmp_path / "output" / "nids.db"
        with sqlite3.connect(str(db_path)) as conn:
            remaining = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            assert remaining == 1

            metric_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM metrics WHERE metric_name='maintenance_deleted_total'"
                ).fetchone()[0]
            )
            assert metric_count >= 1
    finally:
        runtime.sqlite.close()
