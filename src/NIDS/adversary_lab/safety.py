from __future__ import annotations

import ipaddress
from typing import Iterable

from .models import SafetyPolicy, ScenarioMaterial


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


class SafetyPolicyError(ValueError):
    pass


def _ip_allowed(ip_token: str, policy: SafetyPolicy) -> bool:
    try:
        candidate = ipaddress.ip_address(ip_token)
    except ValueError as exc:
        raise SafetyPolicyError(f"Invalid IP address in adversary-lab material: {ip_token}") from exc

    if policy.allow_loopback and candidate.is_loopback:
        return True
    if policy.allow_private_ranges and candidate.is_private:
        return True
    if policy.allow_documentation_ranges and any(candidate in network for network in DOCUMENTATION_NETWORKS):
        return True

    for cidr in policy.allowed_cidrs:
        if candidate in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def validate_targets(target_ips: Iterable[str], policy: SafetyPolicy) -> None:
    rejected = sorted({token for token in target_ips if token and not _ip_allowed(token, policy)})
    if rejected:
        raise SafetyPolicyError(
            "Adversary-lab targets fall outside the permitted lab boundary: "
            + ", ".join(rejected)
        )


def validate_material(material: ScenarioMaterial, policy: SafetyPolicy) -> None:
    validate_targets(material.target_ips, policy)
    packet_count = len(material.packets)
    if packet_count > policy.max_packets:
        raise SafetyPolicyError(
            f"Scenario {material.scenario_id} exceeds max_packets={policy.max_packets}: {packet_count}"
        )
    total_bytes = sum(len(packet) for packet in material.packets)
    if total_bytes > policy.max_total_bytes:
        raise SafetyPolicyError(
            f"Scenario {material.scenario_id} exceeds max_total_bytes={policy.max_total_bytes}: {total_bytes}"
        )


def safety_summary(policy: SafetyPolicy) -> dict[str, object]:
    return {
        "name": policy.name,
        "offline_bundle_only": policy.offline_bundle_only,
        "allow_loopback": policy.allow_loopback,
        "allow_private_ranges": policy.allow_private_ranges,
        "allow_documentation_ranges": policy.allow_documentation_ranges,
        "allowed_cidrs": list(policy.allowed_cidrs),
        "max_packets": policy.max_packets,
        "max_total_bytes": policy.max_total_bytes,
        "banner": policy.banner,
    }
