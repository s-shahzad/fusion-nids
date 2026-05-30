from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.NIDS.storage.sqlite_store import SQLiteStore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _insert_sample_alert(store: SQLiteStore) -> int:
    return store.insert_alert(
        {
            "timestamp": _now_iso(),
            "sensor_id": "sensor-a",
            "dataset_source": "pcap:test.pcap",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "src_port": 50001,
            "dst_port": 443,
            "proto": "TCP",
            "severity": "high",
            "engine": "signature",
            "rule_name": "Test Rule",
            "summary": "test alert",
            "is_labeled": 0,
        }
    )


def test_incident_ack_and_suppress_audit(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    store = SQLiteStore(db_path)
    try:
        alert_id = _insert_sample_alert(store)

        ack_changed = store.acknowledge_alert(
            alert_id,
            actor="analyst-user",
            actor_role="analyst",
            reason="triaged",
            metadata={"ticket": "INC-1"},
        )
        assert ack_changed is True

        suppress_changed = store.suppress_alert(
            alert_id,
            actor="admin-user",
            actor_role="admin",
            ttl_minutes=45,
            reason="maintenance window",
            metadata={"ticket": "INC-1"},
        )
        assert suppress_changed is True

        alert = store.fetch_alert(alert_id)
        assert alert is not None
        assert str(alert.get("ack_status")) == "acknowledged"
        assert str(alert.get("acknowledged_by")) == "analyst-user"
        assert int(alert.get("is_suppressed") or 0) == 1
        assert str(alert.get("suppressed_by")) == "admin-user"
        assert int(alert.get("suppressed_ttl_minutes") or 0) == 45

        rules = store.fetch_suppression_rules(active_only=True, limit=10)
        assert len(rules) == 1
        assert str(rules[0].get("rule_name")) == "Test Rule"

        actions = store.fetch_incident_actions(limit=10)
        action_names = {str(item.get("action")) for item in actions}
        assert "ack" in action_names
        assert "suppress" in action_names
    finally:
        store.close()


def test_suppression_rule_match_and_revoke(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    store = SQLiteStore(db_path)
    try:
        alert_id = _insert_sample_alert(store)
        rule = store.create_suppression_rule_from_alert(
            alert_id,
            actor="admin-user",
            actor_role="admin",
            ttl_minutes=30,
            reason="active response",
            metadata={"ticket": "INC-2"},
        )
        assert rule is not None

        matched = store.match_active_suppression(
            {
                "sensor_id": "sensor-a",
                "engine": "signature",
                "rule_name": "Test Rule",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "dst_port": 443,
                "proto": "TCP",
            }
        )
        assert matched is not None
        rule_id = int(matched.get("id") or 0)
        assert rule_id > 0

        revoked = store.revoke_suppression_rule(
            rule_id,
            actor="admin-user",
            actor_role="admin",
            reason="false positive",
            metadata={"ticket": "INC-2"},
        )
        assert revoked is True

        active_rules = store.fetch_suppression_rules(active_only=True, limit=10)
        assert active_rules == []

        post_match = store.match_active_suppression(
            {
                "sensor_id": "sensor-a",
                "engine": "signature",
                "rule_name": "Test Rule",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "dst_port": 443,
                "proto": "TCP",
            }
        )
        assert post_match is None

        actions = store.fetch_incident_actions(limit=20)
        action_names = {str(item.get("action")) for item in actions}
        assert "revoke_suppress" in action_names
    finally:
        store.close()

