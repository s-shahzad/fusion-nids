from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import build_beacon_http_gets


def build_beaconing_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 12, 10, tzinfo=timezone.utc).timestamp()
    src_ip = "10.77.0.25"
    dst_ip = "198.51.100.80"
    packets = build_beacon_http_gets(
        src_ip=src_ip,
        dst_ip=dst_ip,
        base_epoch=base_epoch,
        count=8,
        interval_sec=12.0,
        dst_port=443,
        host="collector.lab.example",
        uri="/beacon/health",
    )
    return ScenarioMaterial(
        scenario_id="ADVLAB-003",
        name="Beaconing Pattern Simulation",
        description="Regular periodic callback traffic to a documentation-only collector address.",
        attack_type="lab_generated:beaconing_pattern",
        packets=packets,
        target_ips=(src_ip, dst_ip),
        tags=("beaconing", "timing", "offline_bundle"),
        notes=(
            "Uses documentation-only destination IP space.",
            "Intended to validate timing-aware behavioral detectors.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:beaconing_pattern")],
        metadata={"expected_detectors": ["exfiltration_behavior"]},
    )
