from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.storage.incident_store import IncidentStore
from src.NIDS.storage.sqlite_store import SQLiteStore


def test_incident_store_graceful_without_alerts_table(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS placeholder(id INTEGER PRIMARY KEY)")
        conn.commit()

    store = IncidentStore(db_path)
    try:
        assert store.ensure_recent_incidents(limit=100) == 0
        assert store.ensure_incident_for_alert(1, emit_action=False) is None
        assert store.list_incidents(limit=20) == []
    finally:
        store.close()


def test_incident_store_creates_and_updates_incident(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    sql_store = SQLiteStore(db_path)
    try:
        alert_id = sql_store.insert_alert(
            {
                "timestamp": "2026-03-07T12:00:00+00:00",
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
    finally:
        sql_store.close()

    incident_store = IncidentStore(db_path)
    try:
        incident = incident_store.ensure_incident_for_alert(alert_id, emit_action=False)
        assert incident is not None
        assert int(incident.get("alert_id") or 0) == int(alert_id)
        assert str(incident.get("status") or "") == "open"

        updated = incident_store.assign_incident(
            int(incident.get("incident_id") or 0),
            actor="analyst-1",
            actor_role="analyst",
            owner="analyst-1",
            reason="take ownership",
        )
        assert updated is not None
        assert str(updated.get("owner") or "") == "analyst-1"

        resolved = incident_store.set_incident_status(
            int(updated.get("incident_id") or 0),
            actor="analyst-1",
            actor_role="analyst",
            status="resolved",
            reason="closed",
        )
        assert resolved is not None
        assert str(resolved.get("status") or "") == "resolved"

        summary = incident_store.incident_summary()
        assert int(summary.get("total") or 0) >= 1
    finally:
        incident_store.close()


def test_incident_store_sla_policy_escalates_response_and_overdue(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    sql_store = SQLiteStore(db_path)
    try:
        alert_id = sql_store.insert_alert(
            {
                "timestamp": "2026-03-07T12:00:00+00:00",
                "sensor_id": "sensor-sla",
                "dataset_source": "pcap:sla.pcap",
                "src_ip": "10.2.0.1",
                "dst_ip": "8.8.4.4",
                "src_port": 51002,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "low",
                "engine": "anomaly",
                "rule_name": "SLA Rule",
                "summary": "sla candidate",
                "is_labeled": 0,
            }
        )
    finally:
        sql_store.close()

    incident_store = IncidentStore(db_path)
    try:
        incident = incident_store.ensure_incident_for_alert(alert_id, emit_action=False)
        assert incident is not None
        incident_id = int(incident.get("incident_id") or 0)
        assert incident_id > 0

        now_dt = datetime.now(timezone.utc)
        created_at = (now_dt - timedelta(hours=4)).isoformat(timespec="seconds")
        due_at = (now_dt - timedelta(hours=2, minutes=5)).isoformat(timespec="seconds")

        incident_store.conn.execute(
            """
            UPDATE incidents
            SET created_at = ?,
                timestamp = ?,
                status = 'open',
                owner = NULL,
                priority = 'low',
                due_at = ?,
                metadata = '{}'
            WHERE id = ?
            """,
            (created_at, created_at, due_at, incident_id),
        )
        incident_store.conn.commit()

        stats = incident_store.apply_sla_policies(
            now=now_dt,
            response_sla_minutes=30,
            overdue_escalation_minutes=60,
            max_overdue_stage=3,
        )
        assert int(stats.get("updated") or 0) >= 1
        assert int(stats.get("response_breaches") or 0) >= 1
        assert int(stats.get("overdue_escalations") or 0) >= 1

        updated = incident_store.fetch_incident(incident_id)
        assert updated is not None
        assert str(updated.get("status") or "") == "investigating"
        assert str(updated.get("priority") or "") == "critical"
        assert int(updated.get("sla_response_breached") or 0) == 1
        assert int(updated.get("sla_overdue_stage") or 0) >= 2

        actions = incident_store.conn.execute(
            "SELECT action FROM incident_actions WHERE alert_id = ? ORDER BY id ASC",
            (alert_id,),
        ).fetchall()
        action_names = {str(row[0]) for row in actions}
        assert "incident_sla_response_breach" in action_names
        assert any(name.startswith("incident_sla_overdue_stage_") for name in action_names)

        rerun = incident_store.apply_sla_policies(
            now=now_dt,
            response_sla_minutes=30,
            overdue_escalation_minutes=60,
            max_overdue_stage=3,
        )
        assert int(rerun.get("updated") or 0) == 0
    finally:
        incident_store.close()


def test_incident_store_list_incidents_applies_sla(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    sql_store = SQLiteStore(db_path)
    try:
        alert_id = sql_store.insert_alert(
            {
                "timestamp": "2026-03-07T12:00:00+00:00",
                "sensor_id": "sensor-auto-sla",
                "dataset_source": "pcap:auto-sla.pcap",
                "src_ip": "10.3.0.1",
                "dst_ip": "1.1.1.1",
                "src_port": 51003,
                "dst_port": 80,
                "proto": "TCP",
                "severity": "medium",
                "engine": "signature",
                "rule_name": "Auto SLA",
                "summary": "auto sla",
                "is_labeled": 0,
            }
        )
    finally:
        sql_store.close()

    incident_store = IncidentStore(db_path)
    try:
        incident = incident_store.ensure_incident_for_alert(alert_id, emit_action=False)
        assert incident is not None
        incident_id = int(incident.get("incident_id") or 0)
        assert incident_id > 0

        now_dt = datetime.now(timezone.utc)
        created_at = (now_dt - timedelta(hours=3)).isoformat(timespec="seconds")
        due_at = (now_dt - timedelta(hours=1, minutes=10)).isoformat(timespec="seconds")

        incident_store.conn.execute(
            """
            UPDATE incidents
            SET created_at = ?,
                timestamp = ?,
                status = 'open',
                owner = NULL,
                priority = 'medium',
                due_at = ?,
                metadata = '{}'
            WHERE id = ?
            """,
            (created_at, created_at, due_at, incident_id),
        )
        incident_store.conn.commit()

        rows = incident_store.list_incidents(limit=20)
        selected = None
        for row in rows:
            if int(row.get("incident_id") or 0) == incident_id:
                selected = row
                break

        assert selected is not None
        assert str(selected.get("status") or "") in {"triage", "investigating"}
        assert str(selected.get("priority") or "") in {"high", "critical"}
        assert int(selected.get("sla_response_breached") or 0) == 1
        assert int(selected.get("sla_resolution_breached") or 0) == 1
    finally:
        incident_store.close()

