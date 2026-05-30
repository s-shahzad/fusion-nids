from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.NIDS.detect.campaign_behavior import CampaignBehaviorDetector


def _ts(offset_sec: int) -> str:
    base = datetime(2026, 3, 14, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_sec)).isoformat()


def _flow(
    offset_sec: int,
    *,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str = "TCP",
    tcp_flags: str = "S",
) -> dict[str, object]:
    return {
        "timestamp": _ts(offset_sec),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "tcp_flags": tcp_flags,
    }


def test_campaign_behavior_detects_distributed_port_scan() -> None:
    detector = CampaignBehaviorDetector(
        {
            "enabled": True,
            "window_sec": 90,
            "alert_cooldown_sec": 300,
            "distributed_scan_min_sources": 3,
            "distributed_scan_min_ports": 6,
            "coordinated_probe_min_sources": 99,
            "coordinated_probe_min_targets": 99,
        }
    )

    alerts: list[dict[str, object]] = []
    probes = [
        ("10.0.0.10", 21),
        ("10.0.0.11", 22),
        ("10.0.0.12", 23),
        ("10.0.0.10", 80),
        ("10.0.0.11", 443),
        ("10.0.0.12", 3389),
    ]
    for index, (src_ip, dst_port) in enumerate(probes):
        flow = _flow(index, src_ip=src_ip, dst_ip="192.0.2.10", dst_port=dst_port)
        alerts = detector.detect(flow, flow)

    assert any(alert["rule_name"] == "Distributed Port Scan Campaign" for alert in alerts)


def test_campaign_behavior_detects_coordinated_service_probe() -> None:
    detector = CampaignBehaviorDetector(
        {
            "enabled": True,
            "window_sec": 90,
            "alert_cooldown_sec": 300,
            "distributed_scan_min_sources": 99,
            "distributed_scan_min_ports": 99,
            "coordinated_probe_min_sources": 3,
            "coordinated_probe_min_targets": 4,
        }
    )

    alerts: list[dict[str, object]] = []
    probes = [
        ("10.0.1.10", "192.0.2.20"),
        ("10.0.1.11", "192.0.2.21"),
        ("10.0.1.12", "192.0.2.22"),
        ("10.0.1.10", "192.0.2.23"),
    ]
    for index, (src_ip, dst_ip) in enumerate(probes):
        flow = _flow(index, src_ip=src_ip, dst_ip=dst_ip, dst_port=3389)
        alerts = detector.detect(flow, flow)

    assert any(alert["rule_name"] == "Coordinated Probing Campaign" for alert in alerts)
