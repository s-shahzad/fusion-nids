from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import build_lateral_probe_sequence


def build_lateral_sequence_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 12, 30, tzinfo=timezone.utc).timestamp()
    src_ip = "10.77.0.27"
    targets = ["10.77.0.40", "10.77.0.41", "10.77.0.42"]
    packets = build_lateral_probe_sequence(
        src_ip=src_ip,
        target_ips=targets,
        base_epoch=base_epoch,
        ports=(445, 3389, 5985, 22),
        interval_ms=120,
    )
    return ScenarioMaterial(
        scenario_id="ADVLAB-005",
        name="Lateral-Movement-Like Sequencing Simulation",
        description="Mock internal service probing across multiple hosts without any real access attempt or session establishment.",
        attack_type="lab_generated:lateral_sequence_pattern",
        packets=packets,
        target_ips=tuple([src_ip] + targets),
        tags=("lateral_sequence", "internal_probe", "offline_bundle"),
        notes=(
            "Only SYN-style service probes are generated.",
            "No shell, credential, or persistence behavior is included.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:lateral_sequence_pattern")],
        metadata={"expected_detectors": ["campaign_behavior", "anomaly"]},
    )
