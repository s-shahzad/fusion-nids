from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ALERT_COLUMNS: dict[str, str] = {
    "timestamp": "TEXT",
    "sensor_id": "TEXT",
    "dataset_source": "TEXT",
    "src_ip": "TEXT",
    "dst_ip": "TEXT",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "proto": "TEXT",
    "severity": "TEXT",
    "engine": "TEXT",
    "rule_name": "TEXT",
    "summary": "TEXT",
    "anomaly_score": "REAL",
    "predicted_label": "TEXT",
    "predicted_attack_type": "TEXT",
    "prediction_score": "REAL",
    "supervised_score": "REAL",
    "unsupervised_score": "REAL",
    "unsupervised_isolation_score": "REAL",
    "unsupervised_autoencoder_score": "REAL",
    "fusion_score": "REAL",
    "fusion_label": "TEXT",
    "fusion_agreement_count": "INTEGER",
    "label": "TEXT",
    "attack_type": "TEXT",
    "is_labeled": "INTEGER",
    "ack_status": "TEXT",
    "acknowledged_by": "TEXT",
    "acknowledged_at": "TEXT",
    "is_suppressed": "INTEGER",
    "suppressed_until": "TEXT",
    "suppressed_by": "TEXT",
    "suppressed_reason": "TEXT",
    "suppressed_ttl_minutes": "INTEGER",
    "extra": "TEXT",
}

FLOW_COLUMNS: dict[str, str] = {
    "timestamp": "TEXT",
    "sensor_id": "TEXT",
    "dataset_source": "TEXT",
    "src_ip": "TEXT",
    "dst_ip": "TEXT",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "proto": "TEXT",
    "packet_len": "INTEGER",
    "tcp_flags": "TEXT",
    "packet_count": "INTEGER",
    "packet_rate_dst": "REAL",
    "unique_dst_ports_src_window": "REAL",
    "unique_dst_hosts_src_window": "REAL",
    "label": "TEXT",
    "attack_type": "TEXT",
    "is_labeled": "INTEGER",
    "anomaly_score": "REAL",
    "predicted_label": "TEXT",
    "predicted_attack_type": "TEXT",
    "prediction_score": "REAL",
    "supervised_label": "TEXT",
    "supervised_score": "REAL",
    "unsupervised_label": "TEXT",
    "unsupervised_score": "REAL",
    "unsupervised_isolation_score": "REAL",
    "unsupervised_autoencoder_score": "REAL",
    "fusion_label": "TEXT",
    "fusion_score": "REAL",
    "fusion_agreement_count": "INTEGER",
    "payload_preview": "TEXT",
}

METRIC_COLUMNS: dict[str, str] = {
    "timestamp": "TEXT",
    "sensor_id": "TEXT",
    "metric_name": "TEXT",
    "metric_value": "REAL",
}

INCIDENT_ACTION_COLUMNS: dict[str, str] = {
    "timestamp": "TEXT",
    "alert_id": "INTEGER",
    "action": "TEXT",
    "actor": "TEXT",
    "actor_role": "TEXT",
    "reason": "TEXT",
    "ttl_minutes": "INTEGER",
    "metadata": "TEXT",
}

SUPPRESSION_RULE_COLUMNS: dict[str, str] = {
    "created_at": "TEXT",
    "updated_at": "TEXT",
    "source_alert_id": "INTEGER",
    "created_by": "TEXT",
    "created_role": "TEXT",
    "reason": "TEXT",
    "ttl_minutes": "INTEGER",
    "suppressed_until": "TEXT",
    "is_active": "INTEGER",
    "revoked_at": "TEXT",
    "revoked_by": "TEXT",
    "revoked_reason": "TEXT",
    "sensor_id": "TEXT",
    "engine": "TEXT",
    "rule_name": "TEXT",
    "src_ip": "TEXT",
    "dst_ip": "TEXT",
    "dst_port": "INTEGER",
    "proto": "TEXT",
    "metadata": "TEXT",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    token = str(value).strip()
    if token == "":
        return None
    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00"))
    except Exception:
        return None


class SQLiteStore:
    """SQLite store for alerts, flows, runtime metrics, incident actions, and suppression rules."""

    def __init__(self, db_path: str | Path, commit_batch_size: int = 1) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.commit_batch_size = max(1, int(commit_batch_size))
        self._pending_writes = 0
        self._init_schema()

    def _table_columns(self, table_name: str) -> set[str]:
        rows = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row[1]) for row in rows}

    def _ensure_columns(self, table_name: str, columns: dict[str, str]) -> None:
        existing = self._table_columns(table_name)
        for col, col_type in columns.items():
            if col not in existing:
                self.conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col} {col_type}")

    def _insert_payload(self, table_name: str, columns: dict[str, str], payload: dict[str, Any]) -> int:
        ordered_columns = list(columns.keys())
        column_sql = ", ".join(ordered_columns)
        placeholders = ", ".join("?" for _ in ordered_columns)
        values = tuple(payload.get(column) for column in ordered_columns)
        cursor = self.conn.execute(f"INSERT INTO {table_name}({column_sql}) VALUES ({placeholders})", values)
        self._pending_writes += 1
        if self._pending_writes >= self.commit_batch_size:
            self.conn.commit()
            self._pending_writes = 0
        return int(cursor.lastrowid)

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                sensor_id TEXT,
                dataset_source TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                severity TEXT,
                engine TEXT,
                rule_name TEXT,
                summary TEXT,
                anomaly_score REAL,
                predicted_label TEXT,
                predicted_attack_type TEXT,
                prediction_score REAL,
                supervised_score REAL,
                unsupervised_score REAL,
                unsupervised_isolation_score REAL,
                unsupervised_autoencoder_score REAL,
                fusion_score REAL,
                fusion_label TEXT,
                fusion_agreement_count INTEGER,
                label TEXT,
                attack_type TEXT,
                is_labeled INTEGER,
                ack_status TEXT,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                is_suppressed INTEGER,
                suppressed_until TEXT,
                suppressed_by TEXT,
                suppressed_reason TEXT,
                suppressed_ttl_minutes INTEGER,
                extra TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS flows(
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                sensor_id TEXT,
                dataset_source TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                packet_len INTEGER,
                tcp_flags TEXT,
                packet_count INTEGER,
                packet_rate_dst REAL,
                unique_dst_ports_src_window REAL,
                unique_dst_hosts_src_window REAL,
                label TEXT,
                attack_type TEXT,
                is_labeled INTEGER,
                anomaly_score REAL,
                predicted_label TEXT,
                predicted_attack_type TEXT,
                prediction_score REAL,
                supervised_label TEXT,
                supervised_score REAL,
                unsupervised_label TEXT,
                unsupervised_score REAL,
                unsupervised_isolation_score REAL,
                unsupervised_autoencoder_score REAL,
                fusion_label TEXT,
                fusion_score REAL,
                fusion_agreement_count INTEGER,
                payload_preview TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics(
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                sensor_id TEXT,
                metric_name TEXT,
                metric_value REAL
            )
            """
        )
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
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS suppression_rules(
                id INTEGER PRIMARY KEY,
                created_at TEXT,
                updated_at TEXT,
                source_alert_id INTEGER,
                created_by TEXT,
                created_role TEXT,
                reason TEXT,
                ttl_minutes INTEGER,
                suppressed_until TEXT,
                is_active INTEGER,
                revoked_at TEXT,
                revoked_by TEXT,
                revoked_reason TEXT,
                sensor_id TEXT,
                engine TEXT,
                rule_name TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                proto TEXT,
                metadata TEXT
            )
            """
        )

        self._ensure_columns("alerts", ALERT_COLUMNS)
        self._ensure_columns("flows", FLOW_COLUMNS)
        self._ensure_columns("metrics", METRIC_COLUMNS)
        self._ensure_columns("incident_actions", INCIDENT_ACTION_COLUMNS)
        self._ensure_columns("suppression_rules", SUPPRESSION_RULE_COLUMNS)

        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sensor ON alerts(sensor_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_engine ON alerts(engine)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(ack_status)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_supp ON alerts(is_suppressed)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(timestamp)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_sensor ON flows(sensor_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_label ON flows(label)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_actions_time ON incident_actions(timestamp)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_actions_alert ON incident_actions(alert_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suppression_rules_active ON suppression_rules(is_active, suppressed_until)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suppression_rules_match ON suppression_rules(engine, rule_name, src_ip, dst_ip, dst_port, proto)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_suppression_rules_source ON suppression_rules(source_alert_id)")
        self.conn.commit()

    def insert_alert(self, alert: dict[str, Any]) -> int:
        payload = dict(alert)
        extra = payload.get("extra")
        if isinstance(extra, (dict, list)):
            payload["extra"] = json.dumps(extra, ensure_ascii=True)
        elif extra is None:
            payload["extra"] = ""
        payload["is_labeled"] = int(payload.get("is_labeled") or 0)
        payload["ack_status"] = payload.get("ack_status") or "new"
        payload["is_suppressed"] = int(payload.get("is_suppressed") or 0)
        return self._insert_payload("alerts", ALERT_COLUMNS, payload)

    def insert_flow(self, flow: dict[str, Any]) -> int:
        payload = dict(flow)
        payload["packet_count"] = int(payload.get("packet_count") or 1)
        payload["is_labeled"] = int(payload.get("is_labeled") or 0)
        return self._insert_payload("flows", FLOW_COLUMNS, payload)

    def insert_metric(self, timestamp: str, sensor_id: str, name: str, value: float) -> int:
        cursor = self.conn.execute(
            "INSERT INTO metrics(timestamp, sensor_id, metric_name, metric_value) VALUES (?, ?, ?, ?)",
            (timestamp, sensor_id, name, float(value)),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def _insert_incident_action(
        self,
        *,
        timestamp: str,
        alert_id: int,
        action: str,
        actor: str,
        actor_role: str,
        reason: str | None,
        ttl_minutes: int | None,
        metadata: dict[str, Any] | None,
    ) -> int:
        metadata_payload = json.dumps(metadata or {}, ensure_ascii=True)
        cursor = self.conn.execute(
            """
            INSERT INTO incident_actions(
                timestamp, alert_id, action, actor, actor_role, reason, ttl_minutes, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                int(alert_id),
                str(action),
                str(actor),
                str(actor_role),
                reason or "",
                int(ttl_minutes) if ttl_minutes is not None else None,
                metadata_payload,
            ),
        )
        return int(cursor.lastrowid)

    def _insert_suppression_rule(
        self,
        *,
        created_at: str,
        updated_at: str,
        source_alert_id: int,
        created_by: str,
        created_role: str,
        reason: str | None,
        ttl_minutes: int,
        suppressed_until: str,
        sensor_id: str | None,
        engine: str | None,
        rule_name: str | None,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int | None,
        proto: str | None,
        metadata: dict[str, Any] | None,
    ) -> int:
        metadata_payload = json.dumps(metadata or {}, ensure_ascii=True)
        cursor = self.conn.execute(
            """
            INSERT INTO suppression_rules(
                created_at, updated_at, source_alert_id,
                created_by, created_role, reason,
                ttl_minutes, suppressed_until, is_active,
                revoked_at, revoked_by, revoked_reason,
                sensor_id, engine, rule_name,
                src_ip, dst_ip, dst_port, proto,
                metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                updated_at,
                int(source_alert_id),
                str(created_by),
                str(created_role),
                reason or "",
                int(ttl_minutes),
                suppressed_until,
                sensor_id,
                engine,
                rule_name,
                src_ip,
                dst_ip,
                int(dst_port) if dst_port is not None else None,
                proto,
                metadata_payload,
            ),
        )
        return int(cursor.lastrowid)

    def _row_to_suppression_rule(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        metadata_raw = item.get("metadata")
        try:
            item["metadata"] = json.loads(metadata_raw or "{}")
        except Exception:
            item["metadata"] = {}
        return item

    def fetch_alert(self, alert_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
        if row is None:
            return None
        return dict(row)

    def fetch_incident_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(500, int(limit)))
        rows = self.conn.execute(
            """
            SELECT id, timestamp, alert_id, action, actor, actor_role, reason, ttl_minutes, metadata
            FROM incident_actions
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
        payload: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            metadata_raw = item.get("metadata")
            try:
                item["metadata"] = json.loads(metadata_raw or "{}")
            except Exception:
                item["metadata"] = {}
            payload.append(item)
        return payload

    def fetch_suppression_rule(self, rule_id: int) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM suppression_rules WHERE id = ?", (int(rule_id),)).fetchone()
        if row is None:
            return None
        return self._row_to_suppression_rule(row)

    def fetch_suppression_rules(self, *, active_only: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(1000, int(limit)))
        if active_only:
            now_iso = _now_iso()
            rows = self.conn.execute(
                """
                SELECT *
                FROM suppression_rules
                WHERE is_active = 1
                  AND (
                    suppressed_until IS NULL
                    OR TRIM(suppressed_until) = ''
                    OR julianday(REPLACE(suppressed_until, 'Z', '+00:00')) >= julianday(?)
                  )
                ORDER BY id DESC
                LIMIT ?
                """,
                (now_iso, safe_limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT *
                FROM suppression_rules
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()

        return [self._row_to_suppression_rule(row) for row in rows]

    def _rule_is_active(self, rule: dict[str, Any]) -> bool:
        if int(rule.get("is_active") or 0) != 1:
            return False

        expires_at = _parse_iso(str(rule.get("suppressed_until") or ""))
        if expires_at is None:
            return True

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at >= datetime.now(timezone.utc)

    def _rule_matches_alert(self, rule: dict[str, Any], alert: dict[str, Any]) -> bool:
        if not self._rule_is_active(rule):
            return False

        text_keys = ("sensor_id", "engine", "rule_name", "src_ip", "dst_ip", "proto")
        for key in text_keys:
            expected = str(rule.get(key) or "").strip()
            if expected == "":
                continue

            actual = str(alert.get(key) or "").strip()
            if actual == "":
                return False
            if actual.lower() != expected.lower():
                return False

        expected_port = rule.get("dst_port")
        if expected_port not in (None, ""):
            try:
                expected_port_int = int(expected_port)
                actual_port_int = int(alert.get("dst_port") or -1)
            except Exception:
                return False
            if actual_port_int != expected_port_int:
                return False

        return True

    def match_active_suppression(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        active_rules = self.fetch_suppression_rules(active_only=True, limit=500)
        for rule in active_rules:
            if self._rule_matches_alert(rule, alert):
                return rule
        return None

    def acknowledge_alert(
        self,
        alert_id: int,
        *,
        actor: str,
        actor_role: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        stamp = _now_iso()
        cursor = self.conn.execute(
            """
            UPDATE alerts
            SET ack_status = 'acknowledged',
                acknowledged_by = ?,
                acknowledged_at = ?
            WHERE id = ?
            """,
            (str(actor), stamp, int(alert_id)),
        )
        changed = int(cursor.rowcount or 0) > 0
        if changed:
            self._insert_incident_action(
                timestamp=stamp,
                alert_id=int(alert_id),
                action="ack",
                actor=str(actor),
                actor_role=str(actor_role),
                reason=reason,
                ttl_minutes=None,
                metadata=metadata,
            )
            self.conn.commit()
        else:
            self.conn.rollback()
        return changed

    def create_suppression_rule_from_alert(
        self,
        alert_id: int,
        *,
        actor: str,
        actor_role: str,
        ttl_minutes: int = 60,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        alert = self.fetch_alert(alert_id)
        if alert is None:
            return None

        safe_ttl = max(1, min(24 * 60, int(ttl_minutes)))
        stamp = _now_iso()
        suppress_until = (datetime.now(timezone.utc) + timedelta(minutes=safe_ttl)).isoformat(timespec="seconds")

        source_metadata = dict(metadata or {})
        source_metadata.setdefault("source", "manual")
        source_metadata.setdefault("source_alert_id", int(alert_id))

        try:
            rule_id = self._insert_suppression_rule(
                created_at=stamp,
                updated_at=stamp,
                source_alert_id=int(alert_id),
                created_by=str(actor),
                created_role=str(actor_role),
                reason=reason,
                ttl_minutes=safe_ttl,
                suppressed_until=suppress_until,
                sensor_id=str(alert.get("sensor_id") or "") or None,
                engine=str(alert.get("engine") or "") or None,
                rule_name=str(alert.get("rule_name") or "") or None,
                src_ip=str(alert.get("src_ip") or "") or None,
                dst_ip=str(alert.get("dst_ip") or "") or None,
                dst_port=(int(alert.get("dst_port")) if alert.get("dst_port") not in (None, "") else None),
                proto=str(alert.get("proto") or "") or None,
                metadata=source_metadata,
            )

            self.conn.execute(
                """
                UPDATE alerts
                SET is_suppressed = 1,
                    suppressed_until = ?,
                    suppressed_by = ?,
                    suppressed_reason = ?,
                    suppressed_ttl_minutes = ?
                WHERE id = ?
                """,
                (suppress_until, str(actor), reason or "", safe_ttl, int(alert_id)),
            )

            self._insert_incident_action(
                timestamp=stamp,
                alert_id=int(alert_id),
                action="suppress",
                actor=str(actor),
                actor_role=str(actor_role),
                reason=reason,
                ttl_minutes=safe_ttl,
                metadata={
                    "suppression_rule_id": rule_id,
                    "suppressed_until": suppress_until,
                    **(metadata or {}),
                },
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        return self.fetch_suppression_rule(rule_id)

    def suppress_alert(
        self,
        alert_id: int,
        *,
        actor: str,
        actor_role: str,
        ttl_minutes: int = 60,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        rule = self.create_suppression_rule_from_alert(
            int(alert_id),
            actor=actor,
            actor_role=actor_role,
            ttl_minutes=ttl_minutes,
            reason=reason,
            metadata=metadata,
        )
        return rule is not None

    def revoke_suppression_rule(
        self,
        rule_id: int,
        *,
        actor: str,
        actor_role: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        rule = self.fetch_suppression_rule(rule_id)
        if rule is None:
            return False
        if not self._rule_is_active(rule):
            return False

        stamp = _now_iso()
        cursor = self.conn.execute(
            """
            UPDATE suppression_rules
            SET is_active = 0,
                updated_at = ?,
                revoked_at = ?,
                revoked_by = ?,
                revoked_reason = ?
            WHERE id = ?
            """,
            (stamp, stamp, str(actor), reason or "", int(rule_id)),
        )
        changed = int(cursor.rowcount or 0) > 0

        if changed:
            source_alert_id = int(rule.get("source_alert_id") or 0)
            self._insert_incident_action(
                timestamp=stamp,
                alert_id=source_alert_id,
                action="revoke_suppress",
                actor=str(actor),
                actor_role=str(actor_role),
                reason=reason,
                ttl_minutes=None,
                metadata={
                    "suppression_rule_id": int(rule_id),
                    **(metadata or {}),
                },
            )

            if source_alert_id > 0:
                self.conn.execute(
                    """
                    UPDATE alerts
                    SET is_suppressed = 0,
                        suppressed_until = NULL
                    WHERE id = ?
                    """,
                    (source_alert_id,),
                )

            self.conn.commit()
        else:
            self.conn.rollback()

        return changed

    def fetch_labeled_flows(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT *
            FROM flows
            WHERE label IS NOT NULL AND TRIM(label) != ''
            ORDER BY timestamp ASC
            """
        ).fetchall()

    def health_snapshot(self) -> dict[str, Any]:
        tables = ("alerts", "flows", "metrics", "artifacts", "incident_actions", "suppression_rules")
        payload: dict[str, Any] = {
            "ok": True,
            "db_path": str(self.db_path),
            "tables": {},
            "row_counts": {},
        }
        try:
            self.conn.execute("SELECT 1")
        except Exception:
            payload["ok"] = False
            return payload

        for table in tables:
            exists = bool(self._table_columns(table))
            payload["tables"][table] = exists
            if exists:
                row = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                payload["row_counts"][table] = int(row[0] if row else 0)
            else:
                payload["row_counts"][table] = 0
        return payload

    def prune_old_rows(self, retention_days: int, include_artifacts: bool = True) -> dict[str, Any]:
        safe_days = int(retention_days)
        if safe_days <= 0:
            raise ValueError("retention_days must be > 0")

        cutoff = datetime.now(timezone.utc) - timedelta(days=safe_days)
        cutoff_iso = cutoff.isoformat(timespec="seconds")

        tables = ["alerts", "flows", "metrics", "incident_actions"]
        if include_artifacts:
            tables.append("artifacts")

        deleted: dict[str, int] = {}
        for table in tables:
            if not self._table_columns(table):
                deleted[table] = 0
                continue

            cursor = self.conn.execute(
                f"""
                DELETE FROM {table}
                WHERE timestamp IS NOT NULL
                  AND TRIM(timestamp) != ''
                  AND julianday(REPLACE(timestamp, 'Z', '+00:00')) < julianday(?)
                """,
                (cutoff_iso,),
            )
            deleted[table] = int(cursor.rowcount or 0)

        self.conn.commit()
        return {
            "retention_days": safe_days,
            "cutoff": cutoff_iso,
            "deleted": deleted,
            "deleted_total": int(sum(deleted.values())),
        }

    def vacuum(self) -> None:
        self.conn.execute("VACUUM")
        self.conn.commit()

    def close(self) -> None:
        if getattr(self, "_pending_writes", 0):
            self.conn.commit()
            self._pending_writes = 0
        self.conn.close()


