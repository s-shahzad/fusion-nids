from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.lab
def test_nids_testlab_assets_and_summaries_are_present() -> None:
    lab_root = Path(__file__).resolve().parents[1] / "NIDS_TestLab"
    required_dirs = [
        "config",
        "logs",
        "output",
        "pcaps",
        "reports",
        "results",
        "templates",
        "vms",
    ]
    required_files = [
        "README.md",
        "LAB_ACCESS.md",
        "BUILD_REALISTIC_LAB.ps1",
        "RUN_OFFLINE_TEST.ps1",
        "RUN_ARTIFACT_STATIC_SCAN.ps1",
        "virtualbox_lab_summary.json",
        "realistic_lab_summary.json",
    ]

    assert lab_root.exists()
    for directory in required_dirs:
        assert (lab_root / directory).is_dir()
    for file_name in required_files:
        assert (lab_root / file_name).is_file()

    realistic_summary = json.loads((lab_root / "realistic_lab_summary.json").read_text(encoding="utf-8-sig"))
    virtualbox_summary = json.loads((lab_root / "virtualbox_lab_summary.json").read_text(encoding="utf-8-sig"))
    readme_text = (lab_root / "README.md").read_text(encoding="utf-8")

    assert "realistic_lab" in realistic_summary
    assert realistic_summary["realistic_lab"]["sensor"]["vm"] == "nids-ubuntu-sensor"
    assert virtualbox_summary["recommended_network_mode"].startswith("NAT")
    assert "three-VM VirtualBox lab" in readme_text
