from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ..reporting import generate_incident_report
from ..platform.settings import PlatformSettings


def _repo_root() -> Path:
    # src/nids/services/report_service.py -> repository root
    return Path(__file__).resolve().parents[3]


def _reports_root() -> Path:
    return (_repo_root() / "reports").resolve()


def _confine_report_path(out_path: str | Path) -> Path:
    """Resolve out_path under the fixed reports/ root and reject traversal.

    Uses the same relative_to(root) containment check as the API layer so a
    caller cannot write incident reports to an arbitrary filesystem location.
    """
    reports_root = _reports_root()
    raw = Path(out_path).expanduser()
    resolved = (reports_root / raw).resolve() if not raw.is_absolute() else raw.resolve()
    try:
        resolved.relative_to(reports_root)
    except ValueError as exc:
        raise ValueError("out_path must stay within the reports/ directory.") from exc
    return resolved


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
        destination = _confine_report_path(out_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        generate_incident_report(self.settings.sqlite_path, destination)
        return destination
