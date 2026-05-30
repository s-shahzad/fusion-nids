from __future__ import annotations

import pytest

from src.NIDS.adversary_lab import generate_bundle, localhost_only_profile
from src.NIDS.adversary_lab.profiles.defaults import explicit_lab_cidrs_profile
from src.NIDS.adversary_lab.safety import SafetyPolicyError, validate_targets


def test_adversary_lab_rejects_public_targets_outside_lab_boundary() -> None:
    with pytest.raises(SafetyPolicyError):
        validate_targets(["8.8.8.8"], explicit_lab_cidrs_profile("10.77.0.0/24"))


def test_adversary_lab_localhost_profile_blocks_non_localhost_scenario(tmp_path) -> None:
    with pytest.raises(SafetyPolicyError):
        generate_bundle(
            scenario_name="port_scan_pattern",
            output_root=tmp_path,
            policy=localhost_only_profile(),
            run_stamp="pytest",
        )


def test_adversary_lab_explicit_lab_cidrs_accept_private_lab_range(tmp_path) -> None:
    manifest = generate_bundle(
        scenario_name="lateral_sequence_pattern",
        output_root=tmp_path,
        policy=explicit_lab_cidrs_profile("10.77.0.0/24"),
        run_stamp="pytest",
    )

    assert manifest["lab_generated"] is True
    assert manifest["safety_policy"]["allowed_cidrs"] == ["10.77.0.0/24"]
