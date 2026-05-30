from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.storage.sqlite_store import SQLiteStore
from src.NIDS.visuals.queries import build_analytics


def _iso(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat(timespec="seconds")


def _seed(db_path: Path) -> None:
    store = SQLiteStore(db_path)
    try:
        store.insert_flow(
            {
                "timestamp": _iso(-2),
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:a",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "src_port": 50001,
                "dst_port": 443,
                "proto": "TCP",
                "packet_len": 120,
                "packet_count": 1,
            }
        )
        store.insert_flow(
            {
                "timestamp": _iso(-120),
                "sensor_id": "sensor-b",
                "dataset_source": "pcap:b",
                "src_ip": "10.0.0.2",
                "dst_ip": "1.1.1.1",
                "src_port": 50002,
                "dst_port": 53,
                "proto": "UDP",
                "packet_len": 130,
                "packet_count": 1,
            }
        )

        store.insert_alert(
            {
                "timestamp": _iso(-2),
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:a",
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "src_port": 50001,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "high",
                "engine": "signature",
                "rule_name": "A",
                "summary": "a",
                "is_labeled": 0,
            }
        )
        store.insert_alert(
            {
                "timestamp": _iso(-120),
                "sensor_id": "sensor-b",
                "dataset_source": "pcap:b",
                "src_ip": "10.0.0.2",
                "dst_ip": "1.1.1.1",
                "src_port": 50002,
                "dst_port": 53,
                "proto": "UDP",
                "severity": "low",
                "engine": "anomaly",
                "rule_name": "B",
                "summary": "b",
                "is_labeled": 0,
            }
        )
    finally:
        store.close()


def test_build_analytics_applies_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed(db_path)

    data = build_analytics(
        db_path,
        lookback_minutes=15,
        sensor_id="sensor-a",
        severity="high",
        engine="signature",
    )

    assert not data.alerts.empty
    assert set(data.alerts["sensor_id"].str.lower()) == {"sensor-a"}
    assert set(data.alerts["severity"].str.lower()) == {"high"}
    assert set(data.alerts["engine"].str.lower()) == {"signature"}

    assert not data.flows.empty
    assert set(data.flows["sensor_id"].str.lower()) == {"sensor-a"}

    assert not data.top_sources.empty
    assert data.top_sources.iloc[0]["src_ip"] == "10.0.0.1"
