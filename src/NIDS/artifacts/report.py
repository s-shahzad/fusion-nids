from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _safe_json_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]

    text = str(raw).strip()
    if not text:
        return []

    try:
        payload = json.loads(text)
        if isinstance(payload, list):
            return [str(item) for item in payload]
    except Exception:
        pass

    return [text]


def generate_artifact_report(db_path: str | Path, out_path: str | Path) -> Path:
    """Generate markdown summary from artifact records in SQLite."""
    db_file = Path(db_path)
    output_file = Path(out_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not db_file.exists():
        output_file.write_text(
            "# Artifact Analysis Summary\n\n"
            f"Generated: {generated_at}\n\n"
            f"Database not found: `{db_file}`\n",
            encoding="utf-8",
        )
        return output_file

    with sqlite3.connect(str(db_file)) as conn:
        if not _table_exists(conn, "artifacts"):
            output_file.write_text(
                "# Artifact Analysis Summary\n\n"
                f"Generated: {generated_at}\n\n"
                "No `artifacts` table found in database.\n",
                encoding="utf-8",
            )
            return output_file

        by_type = conn.execute(
            """
            SELECT COALESCE(NULLIF(extension, ''), '[none]') AS extension, COUNT(*) AS count
            FROM artifacts
            GROUP BY extension
            ORDER BY count DESC, extension ASC
            """
        ).fetchall()

        by_risk = conn.execute(
            """
            SELECT COALESCE(NULLIF(risk_level, ''), 'unknown') AS risk_level, COUNT(*) AS count
            FROM artifacts
            GROUP BY risk_level
            ORDER BY count DESC, risk_level ASC
            """
        ).fetchall()

        reason_rows = conn.execute("SELECT reasons FROM artifacts").fetchall()
        reason_counter: Counter[str] = Counter()
        for row in reason_rows:
            for reason in _safe_json_list(row[0]):
                if reason:
                    reason_counter[reason] += 1

        quarantined = conn.execute(
            """
            SELECT filename, stored_path
            FROM artifacts
            WHERE LOWER(stored_path) LIKE '%quarantine%'
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()

        total = conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]

    lines: list[str] = []
    lines.append("# Artifact Analysis Summary")
    lines.append("")
    lines.append(f"Generated: {generated_at}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"- Total artifacts analyzed: {int(total)}")
    lines.append(f"- Quarantined artifacts: {len(quarantined)}")
    lines.append("")

    lines.append("## Counts by File Type")
    lines.append("")
    if by_type:
        lines.append("| Extension | Count |")
        lines.append("|---|---:|")
        for extension, count in by_type:
            lines.append(f"| `{extension}` | {int(count)} |")
    else:
        lines.append("No artifacts recorded.")
    lines.append("")

    lines.append("## Counts by Risk")
    lines.append("")
    if by_risk:
        lines.append("| Risk | Count |")
        lines.append("|---|---:|")
        for risk_level, count in by_risk:
            lines.append(f"| `{risk_level}` | {int(count)} |")
    else:
        lines.append("No risk data available.")
    lines.append("")

    lines.append("## Top Suspicious Reasons")
    lines.append("")
    if reason_counter:
        lines.append("| Reason | Count |")
        lines.append("|---|---:|")
        for reason, count in reason_counter.most_common(20):
            lines.append(f"| `{reason}` | {int(count)} |")
    else:
        lines.append("No reasons recorded.")
    lines.append("")

    lines.append("## Quarantined Files")
    lines.append("")
    if quarantined:
        for filename, _stored_path in quarantined:
            lines.append(f"- {filename}")
    else:
        lines.append("- None")
    lines.append("")

    output_file.write_text("\n".join(lines), encoding="utf-8")
    return output_file
