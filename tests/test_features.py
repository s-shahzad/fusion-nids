from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.NIDS.detect.anomaly import AnomalyEngine
from src.NIDS.pipeline.features import FeatureExtractor


def _ts(offset_sec: float) -> str:
    base = datetime(2026, 3, 6, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_sec)).isoformat()


def test_feature_extractor_counts_only_initiator_tcp_syn_for_scan_windows() -> None:
    extractor = FeatureExtractor(scan_window_sec=12)

    syn_features = extractor.extract(
        {
            "timestamp": _ts(0),
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 22,
            "proto": "TCP",
            "tcp_flags": "S",
            "payload": b"",
        }
    )
    assert syn_features["unique_dst_ports_src_window"] == 1
    assert syn_features["unique_dst_hosts_src_window"] == 1

    response_features = extractor.extract(
        {
            "timestamp": _ts(0.1),
            "src_ip": "10.77.0.30",
            "dst_ip": "10.77.0.20",
            "dst_port": 45000,
            "proto": "TCP",
            "tcp_flags": "RA",
            "payload": b"",
        }
    )
    assert response_features["unique_dst_ports_src_window"] == 0
    assert response_features["unique_dst_hosts_src_window"] == 0


def test_anomaly_scan_threshold_ignores_reverse_tcp_response_fanout() -> None:
    extractor = FeatureExtractor(scan_window_sec=12)
    engine = AnomalyEngine(
        {
            "dos_packets_per_sec_threshold": 999,
            "scan_ports_threshold": 2,
            "scan_window_sec": 12,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "dns_unique_threshold": 999,
        }
    )

    alerts_seen: list[dict[str, object]] = []
    for idx, port in enumerate((22, 23), start=1):
        syn_event = {
            "timestamp": _ts(idx),
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "src_port": 45000 + idx,
            "dst_port": port,
            "proto": "TCP",
            "tcp_flags": "S",
            "payload": b"",
        }
        alerts, _ = engine.detect(syn_event, extractor.extract(syn_event))
        alerts_seen.extend(alerts)

        response_event = {
            "timestamp": _ts(idx + 0.01),
            "src_ip": "10.77.0.30",
            "dst_ip": "10.77.0.20",
            "src_port": port,
            "dst_port": 45000 + idx,
            "proto": "TCP",
            "tcp_flags": "RA",
            "payload": b"",
        }
        alerts, _ = engine.detect(response_event, extractor.extract(response_event))
        alerts_seen.extend(alerts)

    scan_alerts = [alert for alert in alerts_seen if alert["rule_name"] == "Port Scan Threshold"]
    assert len(scan_alerts) == 1
    assert "10.77.0.20" in str(scan_alerts[0]["summary"])
    assert "10.77.0.30" not in str(scan_alerts[0]["summary"])
