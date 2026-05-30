from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


INCIDENT_COLUMNS: dict[str, str] = {
    "alert_id": "INTEGER",
    "timestamp": "TEXT",
    "created_at": "TEXT",
    "updated_at": "TEXT",
    "status": "TEXT",
    "owner": "TEXT",
    "priority": "TEXT",
    "due_at": "TEXT",
    "resolved_at": "TEXT",
    "assigned_by": "TEXT",
    "notes": "TEXT",
    "sensor_id": "TEXT",
    "alert_severity": "TEXT",
    "alert_engine": "TEXT",
    "rule_name": "TEXT",
    "summary": "TEXT",
    "metadata": "TEXT",
}

VALID_STATUS = {"open", "triage", "investigating", "contained", "resolved"}
VALID_PRIORITY = {"low", "medium", "high", "critical"}

DEFAULT_RESPONSE_SLA_MINUTES = 30
DEFAULT_OVERDUE_ESCALATION_MINUTES = 60
DEFAULT_MAX_OVERDUE_STAGE = 3


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    token = str(value).strip()
    if token == "":
        return None
    try:
        parsed = datetime.fromisoformat(token.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _normalize_status(value: str | None) -> str:
    token = str(value or "").strip().lower()
    if token not in VALID_STATUS:
        return "open"
    return token


def _priority_from_severity(severity: str | None) -> str:
    token = str(severity or "").strip().lower()
    if token in {"critical"}:
        return "critical"
    if token in {"high", "alert"}:
        return "high"
    if token in {"medium", "warning", "monitor"}:
        return "medium"
    return "low"


def _normalize_priority(value: str | None, severity: str | None = None) -> str:
    token = str(value or "").strip().lower()
    if token in VALID_PRIORITY:
        return token
    return _priority_from_severity(severity)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _priority_rank(priority: str) -> int:
    order = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }
    return int(order.get(str(priority or "low").strip().lower(), 0))


def _default_due_at(priority: str, now: datetime | None = None) -> str:
    base = now or datetime.now(timezone.utc)
    windows = {
        "critical": timedelta(hours=1),
        "high": timedelta(hours=4),
        "medium": timedelta(hours=12),
        "low": timedelta(hours=24),
    }
    delta = windows.get(priority, timedelta(hours=24))
    return (base + delta).isoformat(timespec="seconds")


def _is_overdue(status: str | None, due_at: str | None, now: datetime | None = None) -> bool:
    if str(status or "").strip().lower() == "resolved":
        return False
    due = _parse_iso(due_at)
    if due is None:
        return False
    return due < (now or datetime.now(timezone.utc))


class IncidentStore:
    """Lifecycle store for incidents linked to alert rows."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def __enter__(self) -> "IncidentStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def _table_columns(self, table_name: str) -> set[str]:
        rows = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row[1]) for row in rows}

    def _table_exists(self, table_name: str) -> bool:
        return len(self._table_columns(table_name)) > 0

    def _ensure_columns(self, table_name: str, columns: dict[str, str]) -> None:
        existing = self._table_columns(table_name)
        for column_name, column_type in columns.items():
            if column_name not in existing:
                self.conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    def _ensure_incident_actions_table(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_actions(
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                alert_id INTEGER,
                action TEXT,
                actor TEXT,
                actor_role TEXT,
                reason TEXT,
                ttl_minutes INTEGER,
                metadata TEXT
            )
            """
        )

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents(
                id INTEGER PRIMARY KEY,
                alert_id INTEGER UNIQUE,
                timestamp TEXT,
                created_at TEXT,
                updated_at TEXT,
                status TEXT,
                owner TEXT,
                priority TEXT,
                due_at TEXT,
                resolved_at TEXT,
                assigned_by TEXT,
                notes TEXT,
                sensor_id TEXT,
                alert_severity TEXT,
                alert_engine TEXT,
                rule_name TEXT,
                summary TEXT,
                metadata TEXT
            )
            """
        )
        self._ensure_columns("incidents", INCIDENT_COLUMNS)
        self._ensure_incident_actions_table()

        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_alert ON incidents(alert_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_owner ON incidents(owner)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_due ON incidents(due_at)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_actions_time ON incident_actions(timestamp)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_actions_alert ON incident_actions(alert_id)")
        self.conn.commit()

    def _insert_incident_action(
        self,
        *,
        timestamp: str,
        alert_id: int,
        action: str,
        actor: str,
        actor_role: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO incident_actions(
                timestamp, alert_id, action, actor, actor_role, reason, ttl_minutes, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                timestamp,
                int(alert_id),
                str(action),
                str(actor),
                str(actor_role),
                str(reason or ""),
                json.dumps(metadata or {}, ensure_ascii=True),
            ),
        )
        return int(cursor.lastrowid)

    def _row_to_incident(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        metadata_raw = item.get("metadata")
        try:
            item["metadata"] = json.loads(metadata_raw or "{}")
        except Exception:
            item["metadata"] = {}

        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        status_token = str(item.get("status") or "open").strip().lower() or "open"
        owner_token = str(item.get("owner") or "").strip()
        created_at = _parse_iso(str(item.get("created_at") or "").strip())
        if created_at is None:
            created_at = _parse_iso(str(item.get("timestamp") or "").strip())

        response_window = max(1, _safe_int(metadata.get("sla_response_window_minutes"), DEFAULT_RESPONSE_SLA_MINUTES))
        response_due_at: datetime | None = None
        if created_at is not None:
            response_due_at = created_at + timedelta(minutes=response_window)

        response_due_token = str(metadata.get("sla_response_due_at") or "").strip()
        if response_due_at is not None:
            response_due_token = response_due_at.isoformat(timespec="seconds")

        now_dt = datetime.now(timezone.utc)
        response_breached = bool(metadata.get("sla_response_breached"))
        if not response_breached and response_due_at is not None:
            if owner_token == "" and status_token in {"open", "triage"} and response_due_at < now_dt:
                response_breached = True

        due_token = str(item.get("due_at") or "").strip()
        is_overdue = _is_overdue(status_token, due_token, now=now_dt)

        item["incident_id"] = int(item.get("id") or 0)
        item["is_overdue"] = 1 if is_overdue else 0
        item["sla_response_due_at"] = response_due_token
        item["sla_response_breached"] = 1 if response_breached else 0
        item["sla_resolution_due_at"] = due_token
        item["sla_resolution_breached"] = 1 if is_overdue else 0
        item["sla_overdue_stage"] = max(0, _safe_int(metadata.get("sla_overdue_stage"), 0))
        return item

    def _fetch_alert_min(self, alert_id: int) -> sqlite3.Row | None:
        if not self._table_exists("alerts"):
            return None
        return self.conn.execute(
            """
            SELECT id, timestamp, sensor_id, severity, engine, rule_name, summary
            FROM alerts
            WHERE id = ?
            """,
            (int(alert_id),),
        ).fetchone()

    def fetch_incident(self, incident_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM incidents WHERE id = ?", (int(incident_id),)).fetchone()
        if row is None:
            return None
        return self._row_to_incident(row)

    def fetch_incident_by_alert(self, alert_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM incidents WHERE alert_id = ?", (int(alert_id),)).fetchone()
        if row is None:
            return None
        return self._row_to_incident(row)

    def fetch_incidents_by_alert_ids(self, alert_ids: list[int]) -> dict[int, dict[str, Any]]:
        tokens = [int(x) for x in alert_ids if int(x) > 0]
        if not tokens:
            return {}
        placeholders = ",".join(["?"] * len(tokens))
        rows = self.conn.execute(
            f"SELECT * FROM incidents WHERE alert_id IN ({placeholders})",
            tuple(tokens),
        ).fetchall()
        payload: dict[int, dict[str, Any]] = {}
        for row in rows:
            incident = self._row_to_incident(row)
            payload[int(incident.get("alert_id") or 0)] = incident
        return payload

    def _insert_incident_for_alert(
        self,
        *,
        alert_row: sqlite3.Row,
        actor: str,
        actor_role: str,
        reason: str | None,
        emit_action: bool,
        status: str,
        owner: str | None,
        priority: str | None,
        due_at: str | None,
        metadata: dict[str, Any] | None,
    ) -> int:
        stamp = _now_iso()
        alert_id = int(alert_row["id"])
        severity = str(alert_row["severity"] or "")
        incident_status = _normalize_status(status)
        incident_priority = _normalize_priority(priority, severity=severity)

        due_token = due_at
        parsed_due = _parse_iso(due_token)
        if parsed_due is not None:
            due_token = parsed_due.isoformat(timespec="seconds")
        else:
            due_token = _default_due_at(incident_priority)

        owner_token = str(owner or "").strip() or None
        notes = str(reason or "").strip()

        cursor = self.conn.execute(
            """
            INSERT INTO incidents(
                alert_id, timestamp, created_at, updated_at,
                status, owner, priority, due_at,
                resolved_at, assigned_by, notes,
                sensor_id, alert_severity, alert_engine,
                rule_name, summary, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                str(alert_row["timestamp"] or stamp),
                stamp,
                stamp,
                incident_status,
                owner_token,
                incident_priority,
                due_token,
                str(actor or "system"),
                notes,
                str(alert_row["sensor_id"] or ""),
                severity,
                str(alert_row["engine"] or ""),
                str(alert_row["rule_name"] or ""),
                str(alert_row["summary"] or ""),
                json.dumps(metadata or {}, ensure_ascii=True),
            ),
        )
        incident_id = int(cursor.lastrowid)

        if emit_action:
            self._insert_incident_action(
                timestamp=stamp,
                alert_id=alert_id,
                action="incident_open",
                actor=str(actor or "system"),
                actor_role=str(actor_role or "system"),
                reason=reason or "incident opened",
                metadata={"incident_id": incident_id, **(metadata or {})},
            )

        return incident_id

    def ensure_incident_for_alert(
        self,
        alert_id: int,
        *,
        actor: str = "system",
        actor_role: str = "system",
        reason: str | None = None,
        emit_action: bool = True,
        status: str = "open",
        owner: str | None = None,
        priority: str | None = None,
        due_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        existing = self.fetch_incident_by_alert(int(alert_id))
        if existing is not None:
            return existing

        alert_row = self._fetch_alert_min(int(alert_id))
        if alert_row is None:
            return None

        incident_id = self._insert_incident_for_alert(
            alert_row=alert_row,
            actor=actor,
            actor_role=actor_role,
            reason=reason,
            emit_action=emit_action,
            status=status,
            owner=owner,
            priority=priority,
            due_at=due_at,
            metadata=metadata,
        )
        self.conn.commit()
        return self.fetch_incident(incident_id)

    def ensure_recent_incidents(self, limit: int = 2000) -> int:
        if not self._table_exists("alerts"):
            return 0

        safe_limit = max(1, min(20000, int(limit)))
        rows = self.conn.execute(
            """
            SELECT a.id, a.timestamp, a.sensor_id, a.severity, a.engine, a.rule_name, a.summary
            FROM alerts a
            LEFT JOIN incidents i ON i.alert_id = a.id
            WHERE i.id IS NULL
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

        created = 0
        for row in reversed(rows):
            self._insert_incident_for_alert(
                alert_row=row,
                actor="system",
                actor_role="system",
                reason="incident sync",
                emit_action=False,
                status="open",
                owner=None,
                priority=None,
                due_at=None,
                metadata={"source": "incident_sync"},
            )
            created += 1

        if created > 0:
            self.conn.commit()
        return created

    def apply_sla_policies(
        self,
        *,
        actor: str = "sla-bot",
        actor_role: str = "system",
        now: datetime | None = None,
        response_sla_minutes: int = DEFAULT_RESPONSE_SLA_MINUTES,
        overdue_escalation_minutes: int = DEFAULT_OVERDUE_ESCALATION_MINUTES,
        max_overdue_stage: int = DEFAULT_MAX_OVERDUE_STAGE,
    ) -> dict[str, int]:
        self.ensure_recent_incidents(limit=5000)

        now_dt = now or datetime.now(timezone.utc)
        now_iso = now_dt.isoformat(timespec="seconds")

        response_window = max(1, int(response_sla_minutes))
        overdue_step = max(5, int(overdue_escalation_minutes))
        max_stage = max(1, int(max_overdue_stage))

        rows = self.conn.execute(
            """
            SELECT id, alert_id, created_at, timestamp, status, owner, priority, due_at, metadata
            FROM incidents
            WHERE LOWER(COALESCE(status, 'open')) != 'resolved'
            ORDER BY id ASC
            """
        ).fetchall()

        stats = {
            "processed": 0,
            "updated": 0,
            "response_breaches": 0,
            "overdue_escalations": 0,
            "due_backfilled": 0,
        }

        for row in rows:
            stats["processed"] += 1

            incident_id = int(row["id"])
            alert_id = int(row["alert_id"] or 0)

            raw_metadata = row["metadata"]
            try:
                metadata = json.loads(raw_metadata or "{}")
            except Exception:
                metadata = {}
            if not isinstance(metadata, dict):
                metadata = {}

            status_token = _normalize_status(str(row["status"] or "open"))
            owner_token = str(row["owner"] or "").strip()
            priority_token = _normalize_priority(str(row["priority"] or ""), None)

            created_dt = _parse_iso(str(row["created_at"] or "").strip())
            if created_dt is None:
                created_dt = _parse_iso(str(row["timestamp"] or "").strip())

            due_token = str(row["due_at"] or "").strip()
            due_dt = _parse_iso(due_token)

            changed = False
            action_events: list[tuple[str, str, dict[str, Any]]] = []

            if due_dt is None:
                due_token = _default_due_at(priority_token, now=created_dt or now_dt)
                due_dt = _parse_iso(due_token)
                if due_dt is not None:
                    changed = True
                    stats["due_backfilled"] += 1
                    action_events.append(
                        (
                            "incident_sla_due_backfill",
                            "resolution due_at backfilled by SLA policy",
                            {"due_at": due_token},
                        )
                    )

            if created_dt is not None and owner_token == "" and status_token in {"open", "triage"}:
                response_due_dt = created_dt + timedelta(minutes=response_window)
                response_due_iso = response_due_dt.isoformat(timespec="seconds")
                if response_due_dt < now_dt and not bool(metadata.get("sla_response_breached")):
                    metadata["sla_response_breached"] = True
                    metadata["sla_response_breached_at"] = now_iso
                    metadata["sla_response_window_minutes"] = response_window
                    metadata["sla_response_due_at"] = response_due_iso

                    if _priority_rank(priority_token) < _priority_rank("high"):
                        priority_token = "high"
                    if status_token == "open":
                        status_token = "triage"

                    changed = True
                    stats["response_breaches"] += 1
                    action_events.append(
                        (
                            "incident_sla_response_breach",
                            f"response SLA breached after {response_window} minutes",
                            {"response_due_at": response_due_iso},
                        )
                    )

            if due_dt is not None and due_dt < now_dt:
                overdue_minutes = max(1, int((now_dt - due_dt).total_seconds() // 60))
                target_stage = min(max_stage, max(1, 1 + overdue_minutes // overdue_step))
                current_stage = max(0, _safe_int(metadata.get("sla_overdue_stage"), 0))

                if target_stage > current_stage:
                    metadata["sla_overdue_stage"] = target_stage
                    metadata.setdefault("sla_overdue_breached_at", now_iso)
                    metadata["sla_overdue_last_escalated_at"] = now_iso
                    metadata["sla_overdue_step_minutes"] = overdue_step

                    if target_stage >= 2:
                        priority_token = "critical"
                    elif _priority_rank(priority_token) < _priority_rank("high"):
                        priority_token = "high"

                    if status_token in {"open", "triage"}:
                        status_token = "investigating"

                    changed = True
                    stats["overdue_escalations"] += 1
                    action_events.append(
                        (
                            f"incident_sla_overdue_stage_{target_stage}",
                            f"resolution SLA overdue escalation stage {target_stage}",
                            {"overdue_minutes": overdue_minutes, "stage": target_stage},
                        )
                    )

            if not changed:
                continue

            self.conn.execute(
                """
                UPDATE incidents
                SET updated_at = ?,
                    status = ?,
                    priority = ?,
                    due_at = ?,
                    metadata = ?,
                    assigned_by = ?
                WHERE id = ?
                """,
                (
                    now_iso,
                    status_token,
                    priority_token,
                    due_token,
                    json.dumps(metadata, ensure_ascii=True),
                    str(actor),
                    incident_id,
                ),
            )

            for action, reason, extra_metadata in action_events:
                action_meta = {"incident_id": incident_id, "source": "sla_policy"}
                action_meta.update(extra_metadata)
                self._insert_incident_action(
                    timestamp=now_iso,
                    alert_id=alert_id,
                    action=action,
                    actor=str(actor),
                    actor_role=str(actor_role),
                    reason=reason,
                    metadata=action_meta,
                )

            stats["updated"] += 1

        if stats["updated"] > 0:
            self.conn.commit()
        return stats

    def _build_filter_sql(
        self,
        *,
        queue: str | None,
        status: str | None,
        owner: str | None,
        priority: str | None,
        sensor_id: str | None,
        severity: str | None,
        engine: str | None,
    ) -> tuple[str, list[Any]]:
        where_parts: list[str] = []
        params: list[Any] = []

        if status and str(status).strip().lower() != "all":
            where_parts.append("LOWER(status) = LOWER(?)")
            params.append(str(status).strip())

        if owner and str(owner).strip().lower() != "all":
            where_parts.append("LOWER(COALESCE(owner, '')) = LOWER(?)")
            params.append(str(owner).strip())

        if priority and str(priority).strip().lower() != "all":
            where_parts.append("LOWER(priority) = LOWER(?)")
            params.append(str(priority).strip())

        if sensor_id and str(sensor_id).strip().lower() != "all":
            where_parts.append("LOWER(COALESCE(sensor_id, '')) = LOWER(?)")
            params.append(str(sensor_id).strip())

        if severity and str(severity).strip().lower() != "all":
            where_parts.append("LOWER(COALESCE(alert_severity, '')) = LOWER(?)")
            params.append(str(severity).strip())

        if engine and str(engine).strip().lower() != "all":
            where_parts.append("LOWER(COALESCE(alert_engine, '')) = LOWER(?)")
            params.append(str(engine).strip())

        queue_token = str(queue or "all").strip().lower()
        now_iso = _now_iso()
        if queue_token == "unassigned":
            where_parts.append("(owner IS NULL OR TRIM(owner) = '')")
            where_parts.append("LOWER(COALESCE(status, 'open')) != 'resolved'")
        elif queue_token == "overdue":
            where_parts.append("LOWER(COALESCE(status, 'open')) != 'resolved'")
            where_parts.append("due_at IS NOT NULL AND TRIM(due_at) != ''")
            where_parts.append("julianday(REPLACE(due_at, 'Z', '+00:00')) < julianday(?)")
            params.append(now_iso)
        elif queue_token == "high":
            where_parts.append("LOWER(COALESCE(status, 'open')) != 'resolved'")
            where_parts.append("LOWER(COALESCE(priority, 'low')) IN ('high', 'critical')")
        elif queue_token == "open":
            where_parts.append("LOWER(COALESCE(status, 'open')) != 'resolved'")

        if not where_parts:
            return "", params
        return "WHERE " + " AND ".join(where_parts), params

    def list_incidents(
        self,
        *,
        limit: int = 50,
        queue: str | None = "all",
        status: str | None = None,
        owner: str | None = None,
        priority: str | None = None,
        sensor_id: str | None = None,
        severity: str | None = None,
        engine: str | None = None,
    ) -> list[dict[str, Any]]:
        self.ensure_recent_incidents(limit=max(500, int(limit) * 10))
        self.apply_sla_policies()
        safe_limit = max(1, min(1000, int(limit)))

        where_sql, params = self._build_filter_sql(
            queue=queue,
            status=status,
            owner=owner,
            priority=priority,
            sensor_id=sensor_id,
            severity=severity,
            engine=engine,
        )

        rows = self.conn.execute(
            f"""
            SELECT *
            FROM incidents
            {where_sql}
            ORDER BY
              CASE LOWER(COALESCE(status, 'open')) WHEN 'resolved' THEN 1 ELSE 0 END ASC,
              CASE LOWER(COALESCE(priority, 'low'))
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
              END ASC,
              CASE WHEN due_at IS NULL OR TRIM(due_at) = '' THEN 1 ELSE 0 END ASC,
              julianday(REPLACE(COALESCE(due_at, '9999-12-31T00:00:00+00:00'), 'Z', '+00:00')) ASC,
              id DESC
            LIMIT ?
            """,
            (*params, safe_limit),
        ).fetchall()
        return [self._row_to_incident(row) for row in rows]

    def incident_summary(
        self,
        *,
        status: str | None = None,
        owner: str | None = None,
        priority: str | None = None,
        sensor_id: str | None = None,
        severity: str | None = None,
        engine: str | None = None,
    ) -> dict[str, int]:
        self.ensure_recent_incidents(limit=5000)
        self.apply_sla_policies()
        where_sql, params = self._build_filter_sql(
            queue="all",
            status=status,
            owner=owner,
            priority=priority,
            sensor_id=sensor_id,
            severity=severity,
            engine=engine,
        )
        rows = self.conn.execute(
            f"""
            SELECT status, owner, priority, due_at
            FROM incidents
            {where_sql}
            """,
            tuple(params),
        ).fetchall()

        summary = {
            "total": 0,
            "open": 0,
            "resolved": 0,
            "unassigned": 0,
            "overdue": 0,
            "high_priority": 0,
        }

        for row in rows:
            state = str(row["status"] or "open").strip().lower() or "open"
            owner_token = str(row["owner"] or "").strip()
            priority_token = str(row["priority"] or "low").strip().lower()
            due_token = str(row["due_at"] or "")

            summary["total"] += 1
            if state == "resolved":
                summary["resolved"] += 1
            else:
                summary["open"] += 1

            if owner_token == "" and state != "resolved":
                summary["unassigned"] += 1

            if priority_token in {"high", "critical"} and state != "resolved":
                summary["high_priority"] += 1

            if _is_overdue(state, due_token):
                summary["overdue"] += 1

        return summary

    def update_incident(
        self,
        incident_id: int,
        *,
        actor: str,
        actor_role: str,
        status: str | None = None,
        owner: str | None = None,
        priority: str | None = None,
        due_at: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        current = self.fetch_incident(int(incident_id))
        if current is None:
            return None

        stamp = _now_iso()

        next_status = _normalize_status(status) if status is not None else str(current.get("status") or "open")
        next_owner = str(owner).strip() if owner is not None else str(current.get("owner") or "").strip()
        next_owner = next_owner or None
        next_priority = (
            _normalize_priority(priority, str(current.get("alert_severity") or ""))
            if priority is not None
            else _normalize_priority(str(current.get("priority") or ""), str(current.get("alert_severity") or ""))
        )

        if due_at is not None:
            parsed_due = _parse_iso(due_at)
            next_due = parsed_due.isoformat(timespec="seconds") if parsed_due is not None else None
        else:
            next_due = str(current.get("due_at") or "").strip() or None

        if next_due is None:
            next_due = _default_due_at(next_priority)

        resolved_at: str | None
        if next_status == "resolved":
            resolved_at = stamp
        elif str(current.get("status") or "").strip().lower() == "resolved":
            resolved_at = None
        else:
            resolved_at = str(current.get("resolved_at") or "").strip() or None

        note_tokens = str(current.get("notes") or "").strip()
        if reason:
            note_tokens = reason if note_tokens == "" else f"{note_tokens} | {reason}"

        self.conn.execute(
            """
            UPDATE incidents
            SET updated_at = ?,
                status = ?,
                owner = ?,
                priority = ?,
                due_at = ?,
                resolved_at = ?,
                assigned_by = ?,
                notes = ?,
                metadata = ?
            WHERE id = ?
            """,
            (
                stamp,
                next_status,
                next_owner,
                next_priority,
                next_due,
                resolved_at,
                str(actor),
                note_tokens,
                json.dumps(metadata or current.get("metadata") or {}, ensure_ascii=True),
                int(incident_id),
            ),
        )

        action = "incident_update"
        if status is not None and str(current.get("status") or "").strip().lower() != next_status:
            action = f"incident_status_{next_status}"
        elif owner is not None and str(current.get("owner") or "").strip() != (next_owner or ""):
            action = "incident_assign"

        self._insert_incident_action(
            timestamp=stamp,
            alert_id=int(current.get("alert_id") or 0),
            action=action,
            actor=str(actor),
            actor_role=str(actor_role),
            reason=reason or "incident updated",
            metadata={"incident_id": int(incident_id), **(metadata or {})},
        )

        self.conn.commit()
        return self.fetch_incident(int(incident_id))

    def assign_incident(
        self,
        incident_id: int,
        *,
        actor: str,
        actor_role: str,
        owner: str,
        priority: str | None = None,
        due_at: str | None = None,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        return self.update_incident(
            int(incident_id),
            actor=actor,
            actor_role=actor_role,
            owner=owner,
            priority=priority,
            due_at=due_at,
            reason=reason,
            metadata=metadata,
        )

    def set_incident_status(
        self,
        incident_id: int,
        *,
        actor: str,
        actor_role: str,
        status: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        return self.update_incident(
            int(incident_id),
            actor=actor,
            actor_role=actor_role,
            status=status,
            reason=reason,
            metadata=metadata,
        )

    def set_incident_status_for_alert(
        self,
        alert_id: int,
        *,
        actor: str,
        actor_role: str,
        status: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        incident = self.ensure_incident_for_alert(
            int(alert_id),
            actor=actor,
            actor_role=actor_role,
            reason="incident ensured",
            emit_action=False,
        )
        if incident is None:
            return None
        return self.set_incident_status(
            int(incident.get("incident_id") or incident.get("id") or 0),
            actor=actor,
            actor_role=actor_role,
            status=status,
            reason=reason,
            metadata=metadata,
        )
