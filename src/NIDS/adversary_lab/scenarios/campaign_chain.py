from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import (
    build_beacon_http_gets,
    build_dns_queries,
    build_http_login_attempts,
    build_http_posts,
    build_tcp_scan,
)


def build_campaign_chain_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 13, 0, tzinfo=timezone.utc).timestamp()
    target_ip = "10.77.0.30"
    scan_packets = []
    scan_packets.extend(
        build_tcp_scan(
            src_ip="10.77.0.20",
            dst_ip=target_ip,
            base_epoch=base_epoch,
            start_port=20,
            port_count=6,
            extra_ports=(3389, 8080),
            interval_ms=80,
            start_time_sec=0.0,
        )
    )
    scan_packets.extend(
        build_tcp_scan(
            src_ip="10.77.0.21",
            dst_ip=target_ip,
            base_epoch=base_epoch,
            start_port=26,
            port_count=6,
            extra_ports=(22,),
            interval_ms=80,
            start_time_sec=0.3,
        )
    )
    scan_packets.extend(
        build_tcp_scan(
            src_ip="10.77.0.22",
            dst_ip=target_ip,
            base_epoch=base_epoch,
            start_port=32,
            port_count=6,
            extra_ports=(23,),
            interval_ms=80,
            start_time_sec=0.6,
        )
    )
    brute_packets = build_http_login_attempts(
        src_ip="10.77.0.21",
        dst_ip=target_ip,
        base_epoch=base_epoch,
        count=8,
        interval_sec=0.9,
        dst_port=8080,
        host="auth.internal.lab",
        start_time_sec=3.0,
    )
    beacon_packets = build_beacon_http_gets(
        src_ip="10.77.0.22",
        dst_ip="198.51.100.120",
        base_epoch=base_epoch,
        count=6,
        interval_sec=10.0,
        dst_port=443,
        host="collector.campaign.lab",
        uri="/cb/status",
        start_time_sec=12.0,
    )
    exfil_dns = build_dns_queries(
        src_ip="10.77.0.22",
        dst_ip="10.77.0.53",
        base_epoch=base_epoch,
        qnames=[
            "m1x2n3b4v5c6x7z8.example.test",
            "p9o8i7u6y5t4r3e2.example.test",
            "h1j2k3l4q5w6e7r8.example.test",
        ],
        interval_sec=0.5,
        start_time_sec=24.0,
    )
    exfil_http = build_http_posts(
        src_ip="10.77.0.22",
        dst_ip="198.51.100.121",
        base_epoch=base_epoch,
        count=2,
        interval_sec=1.5,
        dst_port=8080,
        uri="/upload/archive-exfil",
        host="collector.campaign.lab",
        body_template="chunk={index}&filename=staged_loot.tar.gz&content-disposition=attachment&x-exfil-intent=staged-archive",
        headers={
            "Content-Disposition": "attachment; filename=staged_loot.tar.gz",
            "X-Exfil-Intent": "staged-archive",
        },
        start_time_sec=26.0,
    )
    packets = scan_packets + brute_packets + beacon_packets + exfil_dns + exfil_http
    target_ips = (
        "10.77.0.20",
        "10.77.0.21",
        "10.77.0.22",
        target_ip,
        "10.77.0.53",
        "198.51.100.120",
        "198.51.100.121",
    )
    return ScenarioMaterial(
        scenario_id="ADVLAB-007",
        name="Campaign-Style Chained Simulation",
        description="Recon, mock auth abuse, beaconing, and dummy exfiltration-like flows chained into one offline lab scenario.",
        attack_type="lab_generated:campaign_chain_pattern",
        packets=packets,
        target_ips=target_ips,
        tags=("campaign", "recon", "auth_abuse", "beaconing", "exfiltration", "offline_bundle"),
        notes=(
            "All behavior is synthetic and lab-generated.",
            "No exploit, shell, persistence, or unauthorized access logic is included.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:campaign_chain_pattern")],
        metadata={"expected_detectors": ["campaign_behavior", "exfiltration_behavior", "signature", "anomaly"]},
    )
