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

    The caller is naming a file *inside* reports/, never a location on the
    filesystem, so anything that could denote somewhere else is refused up
    front rather than resolved and then caught by the containment check.

    Rejecting early rather than relying solely on ``relative_to`` matters for
    two reasons: it is far easier for a human or a scanner to verify, and it
    removes ``expanduser()`` from an untrusted path entirely. There is no
    legitimate reason for an API caller to reference the server's home
    directory, and expanding ``~`` for them only widened what had to be caught
    later.

    The containment check is kept as the backstop, because symlinks inside
    reports/ can still redirect a nominally-relative path outward and only a
    post-resolution comparison catches that.
    """
    reports_root = _reports_root()
    raw = Path(out_path)
    text = str(out_path)

    if raw.is_absolute() or raw.drive or raw.root:
        raise ValueError("out_path must be relative to the reports/ directory.")
    if text.startswith("~"):
        raise ValueError("out_path must not reference a home directory.")
    if any(part == ".." for part in raw.parts):
        raise ValueError("out_path must not contain parent-directory segments.")
    if "\x00" in text:
        raise ValueError("out_path must not contain null bytes.")

    resolved = (reports_root / raw).resolve()
    try:
        resolved.relative_to(reports_root)
    except ValueError as exc:
        # Reached when a symlink under reports/ points outside it.
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
