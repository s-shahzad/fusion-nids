from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .analyzer import record_to_json

REQUIRED_COLUMNS: dict[str, str] = {
    "timestamp": "TEXT",
    "source_path": "TEXT",
    "stored_path": "TEXT",
    "filename": "TEXT",
    "extension": "TEXT",
    "mime_type": "TEXT",
    "size_bytes": "INTEGER",
    "sha256": "TEXT",
    "md5": "TEXT",
    "tags": "TEXT",
    "risk_level": "TEXT",
    "reasons": "TEXT",
    "extracted_text": "TEXT",
    "extracted_metadata": "TEXT",
}


class ArtifactStore:
    """Storage adapter for artifact analysis results (SQLite + JSONL)."""

    def __init__(self, db_path: Path, jsonl_path: Path) -> None:
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        self._ensure_schema()

    def _table_columns(self, table_name: str) -> set[str]:
        rows = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row[1]) for row in rows}

    def _ensure_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts(
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                source_path TEXT,
                stored_path TEXT,
                filename TEXT,
                extension TEXT,
                mime_type TEXT,
                size_bytes INTEGER,
                sha256 TEXT,
                md5 TEXT,
                tags TEXT,
                risk_level TEXT,
                reasons TEXT,
                extracted_text TEXT,
                extracted_metadata TEXT
            )
            """
        )

        existing_columns = self._table_columns("artifacts")
        for column_name, column_type in REQUIRED_COLUMNS.items():
            if column_name not in existing_columns:
                self.conn.execute(
                    f"ALTER TABLE artifacts ADD COLUMN {column_name} {column_type}"
                )

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_risk_level ON artifacts(risk_level)"
        )
        self.conn.commit()

    def find_by_sha256(self, sha256: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM artifacts WHERE sha256 = ? ORDER BY id DESC LIMIT 1",
            (sha256,),
        ).fetchone()
        if row is None:
            return None

        payload = dict(row)
        for json_key in ("tags", "reasons", "extracted_metadata"):
            raw = payload.get(json_key)
            if raw:
                try:
                    payload[json_key] = json.loads(raw)
                except Exception:
                    payload[json_key] = raw
            else:
                payload[json_key] = [] if json_key != "extracted_metadata" else {}

        return payload

    def insert_artifact(self, record: dict[str, Any]) -> int:
        tags = json.dumps(record.get("tags", []), ensure_ascii=True)
        reasons = json.dumps(record.get("reasons", []), ensure_ascii=True)
        metadata = json.dumps(record.get("extracted_metadata", {}), ensure_ascii=True)

        cursor = self.conn.execute(
            """
            INSERT INTO artifacts(
                timestamp,
                source_path,
                stored_path,
                filename,
                extension,
                mime_type,
                size_bytes,
                sha256,
                md5,
                tags,
                risk_level,
                reasons,
                extracted_text,
                extracted_metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.get("timestamp"),
                record.get("source_path"),
                record.get("stored_path"),
                record.get("filename"),
                record.get("extension"),
                record.get("mime_type"),
                int(record.get("size_bytes") or 0),
                record.get("sha256"),
                record.get("md5"),
                tags,
                record.get("risk_level"),
                reasons,
                record.get("extracted_text", ""),
                metadata,
            ),
        )
        self.conn.commit()
        row_id = int(cursor.lastrowid)

        payload = dict(record)
        payload["id"] = row_id
        self.append_jsonl(payload)
        return row_id

    def append_jsonl(self, record: dict[str, Any]) -> None:
        line = record_to_json(record)
        with self.jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def close(self) -> None:
        self.conn.close()
