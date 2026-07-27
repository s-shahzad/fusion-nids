from __future__ import annotations

from datetime import datetime, timezone

from ..models import LabelEntry, ScenarioMaterial
from ..traffic_generators import build_http_login_attempts


def build_bruteforce_login_scenario() -> ScenarioMaterial:
    base_epoch = datetime(2026, 3, 14, 12, 5, tzinfo=timezone.utc).timestamp()
    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"
    packets = build_http_login_attempts(
        src_ip=src_ip,
        dst_ip=dst_ip,
        base_epoch=base_epoch,
        count=10,
        interval_sec=0.7,
        dst_port=8080,
        host="localhost",
    )
    return ScenarioMaterial(
        scenario_id="ADVLAB-002",
        name="Brute-Force Login Pattern Simulation",
        description="Repeated failed HTTP login attempts against a mock localhost service.",
        attack_type="lab_generated:bruteforce_login_pattern",
        packets=packets,
        target_ips=(src_ip, dst_ip),
        tags=("auth_abuse", "localhost_only", "offline_bundle"),
        notes=(
            "No credential theft or service access is performed.",
            "The bundle only replays failed-login-shaped traffic against a mock endpoint.",
        ),
        label_entries=[LabelEntry(attack_type="lab_generated:bruteforce_login_pattern")],
        metadata={"expected_detectors": ["anomaly"]},
    )
