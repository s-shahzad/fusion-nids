from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import build_tcp_scan


def build_port_scan_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 12, 0, tzinfo=timezone.utc).timestamp()
    src_ip = "10.77.0.20"
    dst_ip = "10.77.0.30"
    packets = build_tcp_scan(
        src_ip=src_ip,
        dst_ip=dst_ip,
        base_epoch=base_epoch,
        start_port=1,
        port_count=27,
        extra_ports=(3389,),
        interval_ms=30,
    )
    return ScenarioMaterial(
        scenario_id="ADVLAB-001",
        name="Port Scan Pattern Simulation",
        description="Low-noise TCP SYN sweep against a mock internal target for scan-threshold validation.",
        attack_type="lab_generated:port_scan_pattern",
        packets=packets,
        target_ips=(src_ip, dst_ip),
        tags=("recon", "scan", "offline_bundle"),
        notes=(
            "Dummy offline replay only.",
            "Designed to exercise existing port-scan signature and anomaly paths.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:port_scan_pattern")],
        metadata={"expected_detectors": ["signature", "anomaly"]},
    )
