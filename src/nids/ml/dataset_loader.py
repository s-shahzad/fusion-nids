from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd


TRAINING_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "packet_len",
    "packet_rate_dst",
    "unique_dst_ports_src_window",
    "unique_dst_hosts_src_window",
    "tcp_flags",
    "anomaly_score",
    "label",
    "attack_type",
    "is_labeled",
]


def load_labeled_flows(db_path: str | Path) -> pd.DataFrame:
    """Load labeled flow records from SQLite for supervised ML."""
    db = Path(db_path)
    if not db.exists():
        return pd.DataFrame()

    with sqlite3.connect(str(db)) as conn:
        tables = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "flows" not in tables:
            return pd.DataFrame(columns=TRAINING_COLUMNS)

        available_columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(flows)").fetchall()
        }

        select_parts: list[str] = []
        for column in TRAINING_COLUMNS:
            if column in available_columns:
                select_parts.append(column)
            else:
                select_parts.append(f"NULL AS {column}")

        query = f"""
            SELECT
                {", ".join(select_parts)}
            FROM flows
            WHERE label IS NOT NULL AND TRIM(label) != ''
        """
        return pd.read_sql_query(query, conn)
