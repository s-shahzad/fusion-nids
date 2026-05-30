from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import build_protocol_anomaly_packets


def build_protocol_anomaly_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 12, 40, tzinfo=timezone.utc).timestamp()
    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"
    packets = build_protocol_anomaly_packets(
        src_ip=src_ip,
        dst_ip=dst_ip,
        base_epoch=base_epoch,
    )
    return ScenarioMaterial(
        scenario_id="ADVLAB-006",
        name="Protocol Anomaly Simulation",
        description="Offline malformed-input pattern generation for parser and anomaly validation.",
        attack_type="lab_generated:protocol_anomaly_pattern",
        packets=packets,
        target_ips=(src_ip, dst_ip),
        tags=("protocol_anomaly", "localhost_only", "offline_bundle"),
        notes=(
            "Malformed traffic is generated only as offline replay material.",
            "No live network delivery or exploit behavior is implemented.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:protocol_anomaly_pattern")],
        metadata={"expected_detectors": ["exfiltration_behavior", "anomaly"]},
    )
