from __future__ import annotations

from ..models import SafetyPolicy


def offline_replay_profile(*, allowed_cidrs: list[str] | tuple[str, ...] = ()) -> SafetyPolicy:
    return SafetyPolicy(
        name="offline-replay-only",
        offline_bundle_only=True,
        allow_loopback=True,
        allow_private_ranges=True,
        allow_documentation_ranges=True,
        allowed_cidrs=tuple(str(item) for item in allowed_cidrs),
    )


def localhost_only_profile() -> SafetyPolicy:
    return SafetyPolicy(
        name="localhost-only",
        offline_bundle_only=True,
        allow_loopback=True,
        allow_private_ranges=False,
        allow_documentation_ranges=False,
        allowed_cidrs=(),
        max_packets=2048,
        max_total_bytes=750000,
    )


def explicit_lab_cidrs_profile(*cidrs: str) -> SafetyPolicy:
    return SafetyPolicy(
        name="explicit-lab-cidrs",
        offline_bundle_only=True,
        allow_loopback=True,
        allow_private_ranges=False,
        allow_documentation_ranges=True,
        allowed_cidrs=tuple(str(item) for item in cidrs if str(item).strip()),
    )
