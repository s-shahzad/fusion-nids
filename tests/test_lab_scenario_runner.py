from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest
import yaml

# Scenario bundles live in the self-hosted lab workspace and are not part of
# the public repository; run these on the lab runner only.
pytestmark = pytest.mark.lab

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(module_name: str, script_name: str):
    script_path = REPO_ROOT / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.integration
def test_run_scenario_executes_small_offline_bundle(tmp_path: Path) -> None:
    module = _load_module("run_lab_scenario", "run_lab_scenario.py")
    scenario_path = tmp_path / "scenario.yml"
    scenario_path.write_text(
        yaml.safe_dump(
            {
                "scenario_id": "LAB-SCN-TST",
                "name": "Pytest Scan Replay",
                "slug": "pytest-scan",
                "objective": "Exercise the offline scenario runner with a minimal scan replay.",
                "runtime": {
                    "config": str(REPO_ROOT / "NIDS_TestLab" / "config" / "offline_replay_profile.yml"),
                    "rules": str(REPO_ROOT / "rules" / "rules.yml"),
                    "sensor_id": "pytest-sensor",
                    "use_model": False,
                    "enable_unsupervised": False,
                    "metrics_interval": 1,
                    "threshold_lookback_days": 3650,
                },
                "expected": {
                    "required_rules": ["Suspicious Port Scan", "Port Scan Threshold"],
                    "expected_engines": ["signature", "anomaly"],
                    "fusion_behavior": "Not required for this smoke scenario.",
                },
                "network": {
                    "components": [
                        {
                            "kind": "tcp_scan",
                            "src_ip": "10.77.0.20",
                            "dst_ip": "10.77.0.30",
                            "src_port_start": 41000,
                            "start_port": 1,
                            "count": 27,
                            "extra_ports": [3389],
                            "start_time_sec": 0.0,
                            "interval_ms": 20,
                        }
                    ]
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    definition = module.load_scenario_definition(scenario_path)
    manifest = module.run_scenario(
        definition,
        scenario_path=scenario_path,
        results_root=tmp_path / "results",
        python_path=Path(sys.executable),
        run_prefix="pytest",
        skip_visualize=True,
        dry_run=False,
    )

    result_dir = Path(manifest["evidence"]["result_dir"])
    assert manifest["status"] == "pass"
    assert (result_dir / "manifest.json").exists()
    assert (result_dir / "summary.md").exists()
    assert (result_dir / "nids.db").exists()
    assert manifest["database_summary"]["rule_counts"]["Suspicious Port Scan"] >= 1
    assert manifest["database_summary"]["rule_counts"]["Port Scan Threshold"] >= 1


def test_build_execution_index_summarizes_latest_runs(tmp_path: Path) -> None:
    module = _load_module("run_lab_scenario", "run_lab_scenario.py")
    first_run = tmp_path / "run-a"
    second_run = tmp_path / "run-b"
    first_run.mkdir()
    second_run.mkdir()

    (first_run / "manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T10:00:00+00:00",
                "scenario_id": "LAB-SCN-001",
                "run_name": "run-a",
                "status": "pass",
                "environment": {"primary_mode": "offline_replay"},
                "evidence": {"result_dir": str(first_run)},
            }
        ),
        encoding="utf-8",
    )
    (second_run / "manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T11:00:00+00:00",
                "scenario_id": "LAB-SCN-001",
                "run_name": "run-b",
                "status": "partial",
                "environment": {"primary_mode": "offline_replay"},
                "evidence": {"result_dir": str(second_run)},
            }
        ),
        encoding="utf-8",
    )

    index = module.build_execution_index(tmp_path)
    markdown = module.execution_index_markdown(index)

    assert index["total_runs"] == 2
    assert index["latest_by_scenario"]["LAB-SCN-001"]["run_name"] == "run-b"
    assert "run-b" in markdown


def test_resolve_scenarios_supports_generated_ai_scenarios() -> None:
    module = _load_module("run_lab_scenario_ai", "run_lab_scenario.py")

    scenarios = module.resolve_scenarios(REPO_ROOT / "NIDS_TestLab" / "scenarios", ["all-ai"])

    assert [definition["slug"] for _, definition in scenarios] == [
        "ai-alert-flood",
        "ai-burst-then-idle",
        "ai-mimic-normal",
        "ai-partial-signal",
        "ai-slow-scan",
    ]
    assert all(path is None for path, _ in scenarios)


def test_generated_ground_truth_and_robustness_summary_are_stable(tmp_path: Path) -> None:
    module = _load_module("run_lab_scenario_ai_helpers", "run_lab_scenario.py")
    scenario_path = None
    definition = module.resolve_scenarios(REPO_ROOT / "NIDS_TestLab" / "scenarios", ["partial_signal"])[0][1]

    ground_truth_path = module._write_ground_truth(tmp_path / "ground_truth.json", definition["expected"])
    assert ground_truth_path is not None

    payload = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": 1,
        "expected_detections": [
            {
                "label": "partial_signature",
                "count": 1,
                "match_any": ["HTTP Suspicious Keyword"],
            }
        ],
        "expected_misses": ["Hybrid Fusion Decision"],
    }

    db_summary = {
        "counts": {"alerts": 1},
        "detections": {
            "signature_triggered": True,
            "anomaly_triggered": False,
            "ml_triggered": False,
            "fusion_triggered": False,
        },
        "rule_counts": {"HTTP Suspicious Keyword": 1},
    }
    metrics_payload = {
        "totals": {"tp": 1, "fp": 0, "fn": 0},
        "metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0},
    }
    markdown = module._robustness_summary_markdown(
        definition=definition,
        db_summary=db_summary,
        metrics_payload=metrics_payload,
        result_dir=tmp_path,
    )

    assert "Weakness tested: Single-signal behavior designed to avoid multi-engine agreement." in markdown
    assert "- TP: `1`" in markdown
    assert "- `Hybrid Fusion Decision`" in markdown
    assert scenario_path is None


def test_write_robustness_matrix_for_manifests_skips_single_and_writes_multi(tmp_path: Path) -> None:
    module = _load_module("run_lab_scenario_matrix", "run_lab_scenario.py")
    reports_root = tmp_path / "reports"
    bundle_a = tmp_path / "bundle-a"
    bundle_b = tmp_path / "bundle-b"
    bundle_a.mkdir()
    bundle_b.mkdir()

    (bundle_a / "manifest.json").write_text(
        json.dumps(
            {
                "scenario_name": "partial_signal",
                "scenario_id": "LAB-AI-004",
                "run_name": "run-a",
                "status": "pass",
                "expected": {"weakness_tested": "single-signal"},
                "database_summary": {
                    "counts": {"alerts": 1},
                    "detections": {
                        "signature_triggered": True,
                        "anomaly_triggered": False,
                        "ml_triggered": False,
                        "fusion_triggered": False,
                    },
                },
                "evidence": {"result_dir": str(bundle_a)},
            }
        ),
        encoding="utf-8",
    )
    (bundle_a / "metrics.json").write_text(
        json.dumps({"totals": {"tp": 1, "fp": 0, "fn": 0}, "metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0}}),
        encoding="utf-8",
    )
    (bundle_b / "manifest.json").write_text(
        json.dumps(
            {
                "scenario_name": "mimic_normal",
                "scenario_id": "LAB-AI-003",
                "run_name": "run-b",
                "status": "pass",
                "expected": {
                    "weakness_tested": "benign shaping",
                    "ground_truth": {"expected_misses": ["Hybrid Fusion Decision"]},
                },
                "database_summary": {
                    "counts": {"alerts": 0},
                    "detections": {
                        "signature_triggered": False,
                        "anomaly_triggered": False,
                        "ml_triggered": False,
                        "fusion_triggered": False,
                    },
                },
                "evidence": {"result_dir": str(bundle_b)},
            }
        ),
        encoding="utf-8",
    )
    (bundle_b / "metrics.json").write_text(
        json.dumps({"totals": {"tp": 0, "fp": 0, "fn": 0}, "metrics": {"precision": 0.0, "recall": 0.0, "f1": 0.0}}),
        encoding="utf-8",
    )

    assert module._write_robustness_matrix_for_manifests(
        manifests=[{"evidence": {"result_dir": str(bundle_a)}}],
        reports_root=reports_root,
    ) is None

    paths = module._write_robustness_matrix_for_manifests(
        manifests=[
            {"evidence": {"result_dir": str(bundle_a)}},
            {"evidence": {"result_dir": str(bundle_b)}},
        ],
        reports_root=reports_root,
    )

    assert paths is not None
    assert paths[0].exists()
    assert paths[1].exists()
    assert "AI Robustness Matrix" in paths[1].read_text(encoding="utf-8")


@pytest.mark.integration
def test_run_scenario_keeps_artifact_outputs_inside_bundle(tmp_path: Path) -> None:
    module = _load_module("run_lab_scenario_artifacts", "run_lab_scenario.py")
    scenario_path = tmp_path / "artifact_scenario.yml"
    scenario_path.write_text(
        yaml.safe_dump(
            {
                "scenario_id": "LAB-SCN-ART",
                "name": "Pytest Artifact Replay",
                "slug": "pytest-artifact-replay",
                "objective": "Ensure artifact evidence stays inside the scenario result bundle.",
                "runtime": {
                    "config": str(REPO_ROOT / "NIDS_TestLab" / "config" / "offline_replay_profile.yml"),
                    "rules": str(REPO_ROOT / "rules" / "rules.yml"),
                    "sensor_id": "pytest-sensor",
                    "use_model": False,
                    "enable_unsupervised": False,
                    "metrics_interval": 1,
                    "threshold_lookback_days": 3650,
                },
                "expected": {
                    "required_rules": [],
                    "expected_engines": [],
                    "fusion_behavior": "Not required for artifact-only regression coverage.",
                    "artifacts": {
                        "min_quarantined": 1,
                        "min_high_risk": 1,
                    },
                },
                "artifacts": {
                    "fixtures": [
                        {
                            "kind": "powershell_loader",
                            "filename": "stage_loader.ps1",
                        },
                        {
                            "kind": "benign_csv",
                            "filename": "asset_inventory.csv",
                        },
                    ]
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    definition = module.load_scenario_definition(scenario_path)
    manifest = module.run_scenario(
        definition,
        scenario_path=scenario_path,
        results_root=tmp_path / "results",
        python_path=Path(sys.executable),
        run_prefix="pytest",
        skip_visualize=True,
        dry_run=False,
    )

    result_dir = Path(manifest["evidence"]["result_dir"])
    processed_dir = result_dir / "inputs" / "artifacts" / "processed"
    quarantine_dir = result_dir / "inputs" / "artifacts" / "quarantine"

    assert manifest["status"] == "pass"
    assert manifest["evidence"]["artifact_processed_dir"] == str(processed_dir.resolve())
    assert manifest["evidence"]["artifact_quarantine_dir"] == str(quarantine_dir.resolve())
    assert processed_dir.exists()
    assert quarantine_dir.exists()

    with sqlite3.connect(result_dir / "nids.db") as conn:
        stored_paths = [
            row[0]
            for row in conn.execute(
                "SELECT stored_path FROM artifacts ORDER BY id"
            ).fetchall()
        ]

    assert stored_paths
    assert all(path.startswith(str(result_dir.resolve())) for path in stored_paths)
    assert any("quarantine" in path.lower() for path in stored_paths)


@pytest.mark.integration
def test_run_scenario_executes_generated_ai_partial_signal_bundle(tmp_path: Path) -> None:
    module = _load_module("run_lab_scenario_ai_exec", "run_lab_scenario.py")
    _, definition = module.resolve_scenarios(REPO_ROOT / "NIDS_TestLab" / "scenarios", ["partial_signal"])[0]

    manifest = module.run_scenario(
        definition,
        scenario_path=None,
        results_root=tmp_path / "results",
        python_path=Path(sys.executable),
        run_prefix="pytest-ai",
        skip_visualize=True,
        dry_run=False,
    )

    result_dir = Path(manifest["evidence"]["result_dir"])
    assert manifest["status"] == "pass"
    assert (result_dir / "scenario.generated.yml").exists()
    assert (result_dir / "ground_truth.json").exists()
    assert (result_dir / "robustness_summary.md").exists()
    assert (result_dir / "taxonomy_map.json").exists()
    assert (result_dir / "taxonomy_summary.md").exists()
    assert (result_dir / "metrics.json").exists()
    assert (result_dir / "database_summary.json").exists()

    metrics_payload = json.loads((result_dir / "metrics.json").read_text(encoding="utf-8"))
    assert set(metrics_payload["totals"]) == {"expected", "observed", "tp", "fp", "fn"}
    assert manifest["evidence"]["ground_truth_path"].endswith("ground_truth.json")
    assert manifest["evidence"]["robustness_summary_path"].endswith("robustness_summary.md")
    assert manifest["evidence"]["taxonomy_map_path"].endswith("taxonomy_map.json")
    assert manifest["taxonomy"]["attack_family"] == "suspicious_command_activity"
