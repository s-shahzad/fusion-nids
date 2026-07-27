from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import build_dns_queries, build_http_posts


def build_exfiltration_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 12, 20, tzinfo=timezone.utc).timestamp()
    src_ip = "10.77.0.26"
    dns_dst = "10.77.0.53"
    http_dst = "198.51.100.90"
    dns_packets = build_dns_queries(
        src_ip=src_ip,
        dst_ip=dns_dst,
        base_epoch=base_epoch,
        qnames=[
            "a9f3k1m8x2q7z4p6.example.test",
            "f1n2g3e4r5p6r7i8.example.test",
            "q7w8e9r0t1y2u3i4.example.test",
            "z2x3c4v5b6n7m8k9.example.test",
        ],
        interval_sec=0.4,
    )
    http_packets = build_http_posts(
        src_ip=src_ip,
        dst_ip=http_dst,
        base_epoch=base_epoch,
        count=3,
        interval_sec=1.2,
        dst_port=8080,
        uri="/upload/archive-exfil",
        host="collector.exfil.local",
        body_template="chunk={index}&filename=staged_loot.tar.gz&content-disposition=attachment&x-exfil-intent=staged-archive&dummy=true",
        headers={
            "Content-Disposition": "attachment; filename=staged_loot.tar.gz",
            "X-Exfil-Intent": "staged-archive",
        },
        start_time_sec=4.0,
    )
    packets = dns_packets + http_packets
    return ScenarioMaterial(
        scenario_id="ADVLAB-004",
        name="Exfiltration-Like Transfer Simulation",
        description="Dummy DNS and HTTP transfer patterns that resemble covert data egress without using real data.",
        attack_type="lab_generated:exfiltration_pattern",
        packets=packets,
        target_ips=(src_ip, dns_dst, http_dst),
        tags=("exfiltration", "dns", "http", "offline_bundle"),
        notes=(
            "Only dummy strings are transmitted.",
            "No files, secrets, or live external targets are involved.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:exfiltration_pattern")],
        metadata={"expected_detectors": ["signature", "exfiltration_behavior"]},
    )
