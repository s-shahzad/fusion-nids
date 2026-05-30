from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.reporting import generate_sla_weekly_summary
from src.NIDS.storage.incident_store import IncidentStore
from src.NIDS.storage.sqlite_store import SQLiteStore


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _seed_sla_db(db_path: Path) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)

    sql_store = SQLiteStore(db_path)
    try:
        alert_a = sql_store.insert_alert(
            {
                "timestamp": _iso(now - timedelta(days=1, hours=3)),
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:sla-a.pcap",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "src_port": 50100,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "high",
                "engine": "signature",
                "rule_name": "SLA A",
                "summary": "incident a",
                "is_labeled": 0,
            }
        )
        alert_b = sql_store.insert_alert(
            {
                "timestamp": _iso(now - timedelta(days=2, hours=1)),
                "sensor_id": "sensor-b",
                "dataset_source": "pcap:sla-b.pcap",
                "src_ip": "10.0.0.2",
                "dst_ip": "1.1.1.1",
                "src_port": 50101,
                "dst_port": 80,
                "proto": "TCP",
                "severity": "medium",
                "engine": "anomaly",
                "rule_name": "SLA B",
                "summary": "incident b",
                "is_labeled": 0,
            }
        )
    finally:
        sql_store.close()

    incident_store = IncidentStore(db_path)
    try:
        incident_a = incident_store.ensure_incident_for_alert(alert_a, emit_action=False)
        incident_b = incident_store.ensure_incident_for_alert(alert_b, emit_action=False)
        assert incident_a is not None
        assert incident_b is not None

        incident_a_id = int(incident_a.get("incident_id") or 0)
        incident_b_id = int(incident_b.get("incident_id") or 0)

        created_a = now - timedelta(days=1, hours=2)
        response_a = created_a + timedelta(minutes=30)
        due_a = created_a + timedelta(hours=1)
        resolved_a = created_a + timedelta(hours=2)

        created_b = now - timedelta(days=2)
        response_b = created_b + timedelta(minutes=10)
        due_b = now + timedelta(days=1)

        incident_store.conn.execute(
            """
            UPDATE incidents
            SET created_at = ?,
                timestamp = ?,
                updated_at = ?,
                status = 'resolved',
                owner = 'analyst-a',
                priority = 'high',
                due_at = ?,
                resolved_at = ?,
                metadata = ?
            WHERE id = ?
            """,
            (
                _iso(created_a),
                _iso(created_a),
                _iso(resolved_a),
                _iso(due_a),
                _iso(resolved_a),
                json.dumps({"sla_response_breached": True, "sla_overdue_stage": 1}, ensure_ascii=True),
                incident_a_id,
            ),
        )
        incident_store.conn.execute(
            """
            UPDATE incidents
            SET created_at = ?,
                timestamp = ?,
                updated_at = ?,
                status = 'triage',
                owner = 'analyst-b',
                priority = 'medium',
                due_at = ?,
                resolved_at = NULL,
                metadata = '{}'
            WHERE id = ?
            """,
            (
                _iso(created_b),
                _iso(created_b),
                _iso(response_b),
                _iso(due_b),
                incident_b_id,
            ),
        )

        incident_store.conn.execute(
            """
            INSERT INTO incident_actions(timestamp, alert_id, action, actor, actor_role, reason, ttl_minutes, metadata)
            VALUES (?, ?, ?, 'analyst-a', 'analyst', 'response started', NULL, '{}')
            """,
            (_iso(response_a), int(alert_a), "incident_assign"),
        )
        incident_store.conn.execute(
            """
            INSERT INTO incident_actions(timestamp, alert_id, action, actor, actor_role, reason, ttl_minutes, metadata)
            VALUES (?, ?, ?, 'analyst-b', 'analyst', 'triage started', NULL, '{}')
            """,
            (_iso(response_b), int(alert_b), "incident_status_triage"),
        )
        incident_store.conn.commit()
    finally:
        incident_store.close()


def test_generate_sla_weekly_summary_handles_missing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.db"
    json_path = tmp_path / "reports" / "sla.json"
    md_path = tmp_path / "reports" / "sla.md"

    out_json, out_md = generate_sla_weekly_summary(
        from_db=db_path,
        out_json=json_path,
        out_md=md_path,
        lookback_days=7,
    )

    assert out_json == json_path
    assert out_md == md_path

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "database_not_found" in str(payload.get("error") or "")

    markdown = md_path.read_text(encoding="utf-8")
    assert "NIDS SLA Weekly Summary" in markdown
    assert "Database not found" in markdown


def test_generate_sla_weekly_summary_computes_kpis_and_breakdowns(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_sla_db(db_path)

    json_path = tmp_path / "reports" / "weekly_sla_summary.json"
    md_path = tmp_path / "reports" / "weekly_sla_summary.md"

    generate_sla_weekly_summary(
        from_db=db_path,
        out_json=json_path,
        out_md=md_path,
        lookback_days=7,
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))

    totals = payload.get("totals", {})
    assert int(totals.get("incidents") or 0) == 2
    assert int(totals.get("open") or 0) == 1
    assert int(totals.get("resolved") or 0) == 1
    assert int(totals.get("response_breaches") or 0) == 1
    assert int(totals.get("resolution_breaches") or 0) == 1

    rates = payload.get("rates", {})
    assert float(rates.get("response_breach_rate") or 0.0) == 0.5
    assert float(rates.get("resolution_breach_rate") or 0.0) == 0.5

    kpis = payload.get("kpis", {})
    assert float(kpis.get("mean_response_minutes") or 0.0) == 20.0
    assert float(kpis.get("mean_resolution_minutes") or 0.0) == 120.0

    status_breakdown = payload.get("status_breakdown", {})
    assert int(status_breakdown.get("resolved") or 0) == 1
    assert int(status_breakdown.get("triage") or 0) == 1

    priority_breakdown = payload.get("priority_breakdown", {})
    assert int(priority_breakdown.get("high") or 0) == 1
    assert int(priority_breakdown.get("medium") or 0) == 1

    trend = payload.get("overdue_trend", [])
    assert len(trend) == 7
    assert any(int(row.get("count") or 0) >= 1 for row in trend)

    markdown = md_path.read_text(encoding="utf-8")
    assert "NIDS SLA Weekly Summary" in markdown
    assert "Incidents: 2" in markdown
    assert "Response breach rate: 50.00%" in markdown
