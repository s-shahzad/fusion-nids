from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from src.NIDS.storage.jsonl_store import JSONLStore
from src.NIDS.storage.sqlite_store import SQLiteStore


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
        "predicted_attack_type": "credential-access",
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
        "extra": {"case_id": "storage-direct"},
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
        "tcp_flags": "PA",
        "packet_count": 4,
        "packet_rate_dst": 12.5,
        "unique_dst_ports_src_window": 3.0,
        "unique_dst_hosts_src_window": 2.0,
        "label": "attack",
        "attack_type": "credential-access",
        "is_labeled": 1,
        "anomaly_score": 0.41,
        "predicted_label": "attack",
        "predicted_attack_type": "credential-access",
        "prediction_score": 0.82,
        "supervised_label": "attack",
        "supervised_score": 0.79,
        "unsupervised_label": "suspicious",
        "unsupervised_score": 0.54,
        "unsupervised_isolation_score": 0.51,
        "unsupervised_autoencoder_score": 0.57,
        "fusion_label": "malicious",
        "fusion_score": 0.77,
        "fusion_agreement_count": 2,
        "payload_preview": "GET /login HTTP/1.1",
    }
    payload.update(overrides)
    return payload


def test_sqlite_store_persists_ml_fields_and_fetches_labeled_flows(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    store = SQLiteStore(db_path)
    try:
        alert_id = store.insert_alert(_alert_payload())
        store.insert_flow(_flow_payload())
        store.insert_metric("2026-03-08T10:15:02+00:00", "sensor-a", "events_per_sec", 18.5)

        alert = store.fetch_alert(alert_id)
        assert alert is not None
        assert alert["engine"] == "fusion"
        assert float(alert["fusion_score"]) == 0.9
        assert str(alert["predicted_attack_type"]) == "credential-access"
        assert json.loads(str(alert["extra"]))["case_id"] == "storage-direct"

        labeled_flows = store.fetch_labeled_flows()
        assert len(labeled_flows) == 1
        assert str(labeled_flows[0]["fusion_label"]) == "malicious"
        assert float(labeled_flows[0]["packet_rate_dst"]) == 12.5

        health = store.health_snapshot()
        assert health["ok"] is True
        assert health["row_counts"]["alerts"] == 1
        assert health["row_counts"]["flows"] == 1
        assert health["row_counts"]["metrics"] == 1
    finally:
        store.close()


def test_sqlite_store_migrates_legacy_schema_and_supports_two_handles(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE alerts(id INTEGER PRIMARY KEY, timestamp TEXT, sensor_id TEXT)")
        conn.execute("CREATE TABLE flows(id INTEGER PRIMARY KEY, timestamp TEXT, sensor_id TEXT, label TEXT)")
        conn.commit()

    store_a = SQLiteStore(db_path)
    store_b = SQLiteStore(db_path)
    try:
        alert_columns = store_a._table_columns("alerts")
        flow_columns = store_a._table_columns("flows")
        assert "fusion_score" in alert_columns
        assert "predicted_attack_type" in alert_columns
        assert "payload_preview" in flow_columns
        assert "unsupervised_autoencoder_score" in flow_columns

        first_id = store_a.insert_alert(_alert_payload(sensor_id="sensor-a"))
        second_id = store_b.insert_alert(_alert_payload(sensor_id="sensor-b", src_ip="10.0.0.11"))
        store_a.insert_flow(_flow_payload(sensor_id="sensor-a"))
        store_b.insert_flow(_flow_payload(sensor_id="sensor-b", src_ip="10.0.0.11"))

        assert store_a.fetch_alert(first_id) is not None
        assert store_b.fetch_alert(second_id) is not None

        snapshot = store_a.health_snapshot()
        assert snapshot["row_counts"]["alerts"] == 2
        assert snapshot["row_counts"]["flows"] == 2
    finally:
        store_a.close()
        store_b.close()


def test_sqlite_store_persists_incident_actions_and_suppression_rules(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    store = SQLiteStore(db_path)
    try:
        alert_id = store.insert_alert(_alert_payload())

        acknowledged = store.acknowledge_alert(
            alert_id,
            actor="analyst-1",
            actor_role="analyst",
            reason="triage acknowledged",
            metadata={"ticket": "INC-1001"},
        )
        assert acknowledged is True

        rule = store.create_suppression_rule_from_alert(
            alert_id,
            actor="analyst-1",
            actor_role="analyst",
            ttl_minutes=30,
            reason="known noisy test case",
            metadata={"ticket": "INC-1001"},
        )
        assert rule is not None
        assert int(rule["is_active"]) == 1
        assert rule["metadata"]["source"] == "manual"

        matched = store.match_active_suppression(store.fetch_alert(alert_id) or {})
        assert matched is not None
        assert int(matched["id"]) == int(rule["id"])

        revoked = store.revoke_suppression_rule(
            int(rule["id"]),
            actor="lead-analyst",
            actor_role="lead",
            reason="suppression window complete",
            metadata={"ticket": "INC-1001"},
        )
        assert revoked is True

        actions = store.fetch_incident_actions(limit=10)
        action_names = [str(item["action"]) for item in actions]
        assert "ack" in action_names
        assert "suppress" in action_names
        assert "revoke_suppress" in action_names
    finally:
        store.close()


def test_sqlite_store_health_snapshot_reports_connection_failure(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    store = SQLiteStore(db_path)
    real_conn = store.conn

    class BrokenConnection:
        def execute(self, *_args: object, **_kwargs: object) -> None:
            raise sqlite3.DatabaseError("disk image is malformed")

    try:
        store.conn = BrokenConnection()  # type: ignore[assignment]
        snapshot = store.health_snapshot()
        assert snapshot["ok"] is False
        assert snapshot["db_path"] == str(db_path)
    finally:
        real_conn.close()


def test_jsonl_store_appends_parseable_records_from_multiple_handles(tmp_path: Path) -> None:
    output_dir = tmp_path / "jsonl"
    store_a = JSONLStore(output_dir)
    store_b = JSONLStore(output_dir)

    store_a.append_alert({"id": 1, "summary": "first"})
    store_b.append_alert({"id": 2, "summary": "second"})
    store_a.append_flow({"id": 10, "src_ip": "10.0.0.1"})
    store_b.append_metric({"sensor_id": "sensor-a", "metric_name": "events_per_sec", "metric_value": 19.2})

    alert_lines = [json.loads(line) for line in store_a.alerts_path.read_text(encoding="utf-8").splitlines()]
    flow_lines = [json.loads(line) for line in store_a.flows_path.read_text(encoding="utf-8").splitlines()]
    metric_lines = [json.loads(line) for line in store_a.metrics_path.read_text(encoding="utf-8").splitlines()]

    assert [line["id"] for line in alert_lines] == [1, 2]
    assert flow_lines[0]["src_ip"] == "10.0.0.1"
    assert float(metric_lines[0]["metric_value"]) == 19.2


def test_sqlite_store_flushes_batched_writes_on_close(tmp_path: Path) -> None:
    db_path = tmp_path / "batched.db"
    store = SQLiteStore(db_path, commit_batch_size=32)
    try:
        store.insert_flow(_flow_payload())
        with sqlite3.connect(str(db_path)) as conn:
            assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0
    finally:
        store.close()

    with sqlite3.connect(str(db_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 1
