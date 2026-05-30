from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..reporting import generate_incident_report
from ..platform.settings import PlatformSettings


class ReportService:
    def __init__(self, settings: PlatformSettings) -> None:
        self.settings = settings

    def recent_alerts(
        self,
        *,
        limit: int = 50,
        severity: str | None = None,
        engine: str | None = None,
    ) -> list[dict[str, Any]]:
        conn = sqlite3.connect(str(self.settings.sqlite_path))
        conn.row_factory = sqlite3.Row
        try:
            query = "SELECT id, timestamp, severity, engine, rule_name, summary, src_ip, dst_ip, proto, fusion_score FROM alerts"
            clauses: list[str] = []
            params: list[Any] = []
            if severity:
                clauses.append("severity = ?")
                params.append(severity)
            if engine:
                clauses.append("engine = ?")
                params.append(engine)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(max(1, min(int(limit), 500)))
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def generate_incident_markdown(self, out_path: str | Path) -> Path:
        destination = Path(out_path).resolve()
        generate_incident_report(self.settings.sqlite_path, destination)
        return destination
