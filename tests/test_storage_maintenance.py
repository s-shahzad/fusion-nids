from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.storage.sqlite_store import SQLiteStore


def _iso(days_offset: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days_offset)).isoformat(timespec="seconds")


def test_health_snapshot_and_prune_old_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    store = SQLiteStore(db_path)
    try:
        old_ts = _iso(-45)
        new_ts = _iso(-1)

        for ts in (old_ts, new_ts):
            store.insert_alert(
                {
                    "timestamp": ts,
                    "sensor_id": "sensor-a",
                    "dataset_source": "pcap:test",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "8.8.8.8",
                    "src_port": 50000,
                    "dst_port": 443,
                    "proto": "TCP",
                    "severity": "low",
                    "engine": "signature",
                    "rule_name": "rule",
                    "summary": "alert",
                    "is_labeled": 0,
                }
            )
            store.insert_flow(
                {
                    "timestamp": ts,
                    "sensor_id": "sensor-a",
                    "dataset_source": "pcap:test",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "8.8.8.8",
                    "src_port": 50000,
                    "dst_port": 443,
                    "proto": "TCP",
                    "packet_len": 100,
                    "packet_count": 1,
                }
            )
            store.insert_metric(ts, "sensor-a", "events_per_sec", 10.0)

        before = store.health_snapshot()
        assert before["ok"] is True
        assert before["tables"]["alerts"] is True
        assert before["tables"]["flows"] is True
        assert before["tables"]["metrics"] is True

        result = store.prune_old_rows(retention_days=30, include_artifacts=True)
        assert result["deleted"]["alerts"] == 1
        assert result["deleted"]["flows"] == 1
        assert result["deleted"]["metrics"] == 1

        after = store.health_snapshot()
        assert after["row_counts"]["alerts"] == 1
        assert after["row_counts"]["flows"] == 1
        assert after["row_counts"]["metrics"] == 1
    finally:
        store.close()
