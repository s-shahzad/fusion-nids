#!/usr/bin/env python
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.NIDS.storage.sqlite_store import SQLiteStore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _seed_dashboard_db(db_path: Path, sensor_id: str) -> None:
    store = SQLiteStore(db_path)
    try:
        timestamp = _now_iso()

        metrics = [
            ("runtime_heartbeat", 1.0),
            ("events_per_sec", 18.5),
            ("alerts_per_min", 2.0),
            ("queue_size", 3.0),
            ("ingest_lag_sec", 0.20),
            ("total_alerts", 2.0),
            ("suppressed_alerts", 0.0),
        ]

        for metric_name, metric_value in metrics:
            store.insert_metric(timestamp, sensor_id, metric_name, metric_value)

        alerts = [
            {
                "timestamp": timestamp,
                "sensor_id": sensor_id,
                "dataset_source": "ci-fixture",
                "src_ip": "10.10.10.5",
                "dst_ip": "192.168.10.20",
                "src_port": 51515,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "high",
                "engine": "signature",
                "rule_name": "Suspicious TLS Handshake",
                "summary": "Fixture alert 1",
                "is_labeled": 0,
            },
            {
                "timestamp": timestamp,
                "sensor_id": sensor_id,
                "dataset_source": "ci-fixture",
                "src_ip": "10.10.10.9",
                "dst_ip": "192.168.10.21",
                "src_port": 52525,
                "dst_port": 53,
                "proto": "UDP",
                "severity": "medium",
                "engine": "anomaly",
                "rule_name": "DNS Burst Spike",
                "summary": "Fixture alert 2",
                "is_labeled": 0,
            },
        ]

        for alert in alerts:
            store.insert_alert(alert)
    finally:
        store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a minimal dashboard SQLite fixture for CI smoke checks."
    )
    parser.add_argument(
        "--out",
        default="output/ci_dashboard_fixture.db",
        help="Output SQLite path.",
    )
    parser.add_argument(
        "--sensor-id",
        default="ci-sensor",
        help="Sensor identifier stored in seeded rows.",
    )
    args = parser.parse_args(argv)

    db_path = Path(args.out).expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _seed_dashboard_db(db_path, str(args.sensor_id))

    print(f"fixture_db_created={db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
