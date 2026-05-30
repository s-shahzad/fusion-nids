from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from src.NIDS.config import RuntimeConfig
from src.NIDS.reporting import generate_incident_report
from src.NIDS.runtime import NIDSRuntime
from src.NIDS.visuals.export import run_visual_export


def _ts() -> str:
    return datetime(2026, 3, 6, tzinfo=timezone.utc).isoformat()


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
    )
    return NIDSRuntime(cfg=cfg, sensor_id="test-sensor")


def test_runtime_pipeline_persists_flows_and_alerts(tmp_path: Path) -> None:
    runtime = _build_runtime(tmp_path)
    try:
        runtime._process_event(
            {
                "timestamp": _ts(),
                "dataset_source": "pcap:test.pcap",
                "src_ip": "10.10.10.10",
                "dst_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 220,
                "tcp_flags": "S",
                "payload": b"evil command",
                "label": "attack",
                "attack_type": "test",
                "is_labeled": 1,
            }
        )

        db_path = tmp_path / "output" / "nids.db"
        assert db_path.exists()

        with sqlite3.connect(str(db_path)) as conn:
            flow_count = int(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
            alert_count = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            assert flow_count == 1
            assert alert_count >= 1

            engines = {row[0] for row in conn.execute("SELECT DISTINCT engine FROM alerts").fetchall()}
            assert "signature" in engines

            flow_row = conn.execute(
                """
                SELECT supervised_label, unsupervised_label, fusion_label, fusion_score, fusion_agreement_count
                FROM flows
                ORDER BY id ASC
                LIMIT 1
                """
            ).fetchone()
            assert flow_row is not None
            assert flow_row[2] in {"attack", "benign"}
            assert flow_row[3] is not None
            assert int(flow_row[4]) >= 0

            alert_row = conn.execute("SELECT extra FROM alerts ORDER BY id ASC LIMIT 1").fetchone()
            assert alert_row is not None
            extra = json.loads(alert_row[0] or "{}")
            assert set(extra["fusion_components"]).issuperset({"signature", "statistical", "supervised", "unsupervised"})

        flows_jsonl = (tmp_path / "output" / "flows.jsonl").read_text(encoding="utf-8").strip().splitlines()
        alerts_jsonl = (tmp_path / "output" / "alerts.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert len(flows_jsonl) == 1
        assert len(alerts_jsonl) >= 1
    finally:
        runtime.sqlite.close()


def test_runtime_outputs_support_report_and_visuals(tmp_path: Path) -> None:
    runtime = _build_runtime(tmp_path)
    try:
        runtime._process_event(
            {
                "timestamp": _ts(),
                "dataset_source": "pcap:test2.pcap",
                "src_ip": "172.16.0.5",
                "dst_ip": "8.8.8.8",
                "src_port": 40000,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 180,
                "tcp_flags": "SA",
                "payload": b"evil traffic",
            }
        )

        db_path = tmp_path / "output" / "nids.db"
        report_path = generate_incident_report(db_path, tmp_path / "reports" / "summary.md")
        assert report_path.exists()

        report_text = report_path.read_text(encoding="utf-8")
        assert "NIDS Incident Report" in report_text
        assert "Total alerts:" in report_text

        index_path, charts = run_visual_export(db_path=db_path, output_dir=tmp_path / "reports" / "graphs")
        assert index_path.exists()
        assert len(charts) >= 1
        assert (tmp_path / "reports" / "graphs" / "time_series_alerts_traffic.html").exists()
    finally:
        runtime.sqlite.close()


def test_runtime_forces_ml_on_existing_signature_or_anomaly_signal(tmp_path: Path) -> None:
    runtime = _build_runtime(tmp_path)

    class _StubMLRouter:
        def __init__(self) -> None:
            self.force_values: list[bool] = []

        def detect(self, event, features, *, force: bool = False):
            self.force_values.append(bool(force))
            return [], {
                "predicted_label": None,
                "predicted_attack_type": None,
                "prediction_score": None,
                "supervised_label": None,
                "supervised_score": None,
                "unsupervised_label": None,
                "unsupervised_score": None,
            }

        def persist_state(self):
            return None

        def close(self):
            return None

    runtime.ml = _StubMLRouter()
    runtime.anomaly.dos_threshold = 999999
    runtime.anomaly.scan_ports_threshold = 999999

    try:
        runtime._process_event(
            {
                "timestamp": _ts(),
                "dataset_source": "pcap:test-force-signature.pcap",
                "src_ip": "10.10.10.10",
                "dst_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 220,
                "tcp_flags": "S",
                "payload": b"evil command",
            }
        )
        runtime._process_event(
            {
                "timestamp": _ts(),
                "dataset_source": "pcap:test-force-benign.pcap",
                "src_ip": "10.10.10.11",
                "dst_ip": "192.168.1.2",
                "src_port": 54322,
                "dst_port": 81,
                "proto": "TCP",
                "packet_len": 180,
                "tcp_flags": "A",
                "payload": b"benign",
            }
        )

        assert runtime.ml.force_values == [True, False]
    finally:
        runtime.sqlite.close()


def test_runtime_policy_suppression_blocks_future_matching_alerts(tmp_path: Path) -> None:
    runtime = _build_runtime(tmp_path)
    runtime.anomaly.dos_threshold = 999999
    runtime.anomaly.scan_ports_threshold = 999999

    try:
        first_ts = datetime(2026, 3, 6, 0, 0, 0, tzinfo=timezone.utc).isoformat()
        runtime._process_event(
            {
                "timestamp": first_ts,
                "dataset_source": "pcap:policy-test-1.pcap",
                "src_ip": "10.20.30.40",
                "dst_ip": "192.168.100.10",
                "src_port": 54000,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 210,
                "tcp_flags": "S",
                "payload": b"evil payload one",
            }
        )

        db_path = tmp_path / "output" / "nids.db"
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute("SELECT id FROM alerts ORDER BY id ASC LIMIT 1").fetchone()
            assert row is not None
            alert_id = int(row[0])
            first_count = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            assert first_count >= 1

        rule = runtime.sqlite.create_suppression_rule_from_alert(
            alert_id,
            actor="admin-user",
            actor_role="admin",
            ttl_minutes=60,
            reason="policy test",
            metadata={"test": "policy-suppression"},
        )
        assert rule is not None

        second_ts = datetime(2026, 3, 6, 0, 0, 5, tzinfo=timezone.utc).isoformat()
        runtime._process_event(
            {
                "timestamp": second_ts,
                "dataset_source": "pcap:policy-test-2.pcap",
                "src_ip": "10.20.30.40",
                "dst_ip": "192.168.100.10",
                "src_port": 54001,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 215,
                "tcp_flags": "S",
                "payload": b"evil payload two",
            }
        )

        with sqlite3.connect(str(db_path)) as conn:
            final_count = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])

        assert final_count == first_count
        assert runtime.stats.policy_suppressed_alerts >= 1
    finally:
        runtime.sqlite.close()

