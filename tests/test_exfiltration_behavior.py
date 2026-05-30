from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.NIDS.detect.exfiltration_behavior import ExfiltrationBehaviorDetector


def _ts(offset_sec: int) -> str:
    base = datetime(2026, 3, 14, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_sec)).isoformat()


def _flow(
    offset_sec: int,
    *,
    src_ip: str = "10.10.10.10",
    dst_ip: str = "203.0.113.10",
    dst_port: int = 53,
    proto: str = "UDP",
    packet_len: int = 96,
) -> dict[str, object]:
    return {
        "timestamp": _ts(offset_sec),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "packet_len": packet_len,
    }


def test_exfiltration_behavior_detects_high_entropy_dns_query() -> None:
    detector = ExfiltrationBehaviorDetector(
        {
            "enabled": True,
            "dns_entropy_threshold": 3.2,
            "dns_min_label_length": 12,
            "long_subdomain_threshold": 999,
            "timing_min_events": 99,
            "outbound_min_events": 999,
        }
    )

    flow = _flow(0)
    event = {**flow, "dns_qname": "a9f3k1m8x2q7z4p6.example.test"}
    alerts = detector.detect(flow, event)

    assert any(alert["rule_name"] == "High Entropy DNS Query" for alert in alerts)


def test_exfiltration_behavior_detects_unusual_subdomain_length() -> None:
    detector = ExfiltrationBehaviorDetector(
        {
            "enabled": True,
            "dns_entropy_threshold": 9.9,
            "dns_min_label_length": 12,
            "long_subdomain_threshold": 30,
            "timing_min_events": 99,
            "outbound_min_events": 999,
        }
    )

    flow = _flow(0)
    event = {
        **flow,
        "dns_qname": "segment-one.segment-two.segment-three.segment-four.example.test",
    }
    alerts = detector.detect(flow, event)

    assert any(alert["rule_name"] == "Unusual DNS Subdomain Length" for alert in alerts)


def test_exfiltration_behavior_detects_timing_channel_pattern() -> None:
    detector = ExfiltrationBehaviorDetector(
        {
            "enabled": True,
            "dns_entropy_threshold": 9.9,
            "long_subdomain_threshold": 999,
            "timing_min_events": 5,
            "timing_window_sec": 60,
            "timing_min_interval_sec": 1.0,
            "timing_max_cv": 0.02,
            "timing_small_payload_max_bytes": 120,
            "outbound_min_events": 999,
        }
    )

    alerts: list[dict[str, object]] = []
    for index, offset_sec in enumerate((0, 2, 4, 6, 8)):
        flow = _flow(offset_sec, proto="TCP", dst_port=443, packet_len=96)
        alerts = detector.detect(flow, dict(flow))

    assert any(alert["rule_name"] == "Timing Channel Pattern" for alert in alerts)


def test_exfiltration_behavior_detects_abnormal_outbound_distribution() -> None:
    detector = ExfiltrationBehaviorDetector(
        {
            "enabled": True,
            "dns_entropy_threshold": 9.9,
            "long_subdomain_threshold": 999,
            "timing_min_events": 99,
            "outbound_window_sec": 60,
            "outbound_min_events": 7,
            "outbound_min_distinct_destinations": 3,
            "outbound_dominant_ratio": 0.7,
            "outbound_max_avg_payload": 180,
        }
    )

    destinations = [
        "198.51.100.10",
        "198.51.100.10",
        "198.51.100.10",
        "198.51.100.10",
        "198.51.100.10",
        "198.51.100.20",
        "198.51.100.30",
    ]
    alerts: list[dict[str, object]] = []
    for index, dst_ip in enumerate(destinations):
        flow = _flow(index, src_ip="10.20.30.40", dst_ip=dst_ip, dst_port=443, proto="TCP", packet_len=120)
        alerts = detector.detect(flow, dict(flow))

    assert any(alert["rule_name"] == "Abnormal Outbound Flow Distribution" for alert in alerts)
