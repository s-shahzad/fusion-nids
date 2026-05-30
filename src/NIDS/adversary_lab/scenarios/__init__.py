from __future__ import annotations

from .beaconing import build_beaconing_scenario
from .bruteforce import build_bruteforce_login_scenario
from .campaign_chain import build_campaign_chain_scenario
from .exfiltration import build_exfiltration_scenario
from .lateral_sequence import build_lateral_sequence_scenario
from .port_scan import build_port_scan_scenario
from .protocol_anomaly import build_protocol_anomaly_scenario


SCENARIO_BUILDERS = {
    "port_scan_pattern": build_port_scan_scenario,
    "bruteforce_login_pattern": build_bruteforce_login_scenario,
    "beaconing_pattern": build_beaconing_scenario,
    "exfiltration_pattern": build_exfiltration_scenario,
    "lateral_sequence_pattern": build_lateral_sequence_scenario,
    "protocol_anomaly_pattern": build_protocol_anomaly_scenario,
    "campaign_chain_pattern": build_campaign_chain_scenario,
}


def available_scenarios() -> list[str]:
    return sorted(SCENARIO_BUILDERS)


def build_named_scenario(name: str):
    try:
        builder = SCENARIO_BUILDERS[str(name).strip().lower()]
    except KeyError as exc:
        raise KeyError(f"Unknown adversary-lab scenario: {name}") from exc
    return builder()
