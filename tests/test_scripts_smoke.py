from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_SCRIPTS = [
    "bootstrap_training_db.py",
    "create_dashboard_fixture_db.py",
    "cloud_validation_workflow.py",
    "dashboard_load_probe.py",
    "dashboard_security_smoke.py",
    "live_vm_attack_validation.py",
    "prepared_env_validation.py",
    "run_adversary_lab.py",
    "run_comparison_baseline.py",
    "run_lab_scenario.py",
    "summarize_lab_results.py",
    "tls_endpoint_audit.py",
    "ubuntu_os_defense_validation.py",
]


@pytest.mark.integration
@pytest.mark.parametrize("script_name", PYTHON_SCRIPTS)
def test_python_scripts_expose_help(script_name: str) -> None:
    script_path = REPO_ROOT / "scripts" / script_name
    result = subprocess.run(
        [sys.executable, str(script_path), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()


@pytest.mark.integration
def test_create_dashboard_fixture_db_generates_expected_rows(tmp_path: Path) -> None:
    out_path = tmp_path / "dashboard_fixture.db"
    script_path = REPO_ROOT / "scripts" / "create_dashboard_fixture_db.py"

    result = subprocess.run(
        [sys.executable, str(script_path), "--out", str(out_path), "--sensor-id", "pytest-sensor"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert out_path.exists()
    assert "fixture_db_created=" in result.stdout

    with sqlite3.connect(str(out_path)) as conn:
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        metric_count = conn.execute("SELECT COUNT(*) FROM metrics").fetchone()[0]

    assert alert_count == 2
    assert metric_count >= 1
