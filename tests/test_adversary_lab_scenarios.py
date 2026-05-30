from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from src.NIDS.adversary_lab import generate_bundle, list_scenarios, offline_replay_profile
from src.NIDS.adversary_lab.validators import validate_bundle


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_adversary_lab_lists_expected_scenarios() -> None:
    scenarios = list_scenarios()
    assert scenarios == [
        "beaconing_pattern",
        "bruteforce_login_pattern",
        "campaign_chain_pattern",
        "exfiltration_pattern",
        "lateral_sequence_pattern",
        "port_scan_pattern",
        "protocol_anomaly_pattern",
    ]


def test_adversary_lab_generates_bundle_with_labels_and_logs(tmp_path: Path) -> None:
    manifest = generate_bundle(
        scenario_name="campaign_chain_pattern",
        output_root=tmp_path,
        policy=offline_replay_profile(),
        run_stamp="pytest",
    )

    bundle_dir = Path(manifest["bundle_dir"])
    summary = validate_bundle(bundle_dir)

    assert summary["manifest_exists"] is True
    assert summary["labels_exists"] is True
    assert summary["normalized_exists"] is True
    assert summary["suricata_exists"] is True
    assert summary["zeek_exists"] is True
    assert summary["lab_generated"] is True
    assert summary["pcap_files"] == ["campaign-chain-pattern.pcap"]
    assert summary["attack_types"] == ["lab_generated:campaign_chain_pattern"]

    readme_text = (bundle_dir / "README.md").read_text(encoding="utf-8")
    assert "WARNING: This bundle is lab-generated replay material only." in readme_text
    assert "python -m nids run --pcap-dir" in readme_text

    normalized_lines = (bundle_dir / "normalized_events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    first_event = json.loads(normalized_lines[0])
    assert first_event["label"] == "lab_generated"
    assert first_event["attack_type"] == "lab_generated:campaign_chain_pattern"


def test_run_adversary_lab_script_exposes_help() -> None:
    script_path = REPO_ROOT / "scripts" / "run_adversary_lab.py"
    result = subprocess.run(
        [sys.executable, str(script_path), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "lab-generated" in result.stdout.lower()
    assert "usage:" in result.stdout.lower()
