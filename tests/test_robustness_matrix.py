from __future__ import annotations

import json
from pathlib import Path

from src.NIDS.adversary.robustness_matrix import (
    build_robustness_matrix,
    robustness_matrix_markdown,
    summarize_bundle,
    write_robustness_matrix,
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _scenario_bundle(
    root: Path,
    *,
    name: str,
    status: str = "pass",
    weakness_tested: str = "test weakness",
    alerts: int = 0,
    tp: int = 0,
    fp: int = 0,
    fn: int = 0,
    precision: float = 0.0,
    recall: float = 0.0,
    f1: float = 0.0,
    detections: dict[str, bool] | None = None,
    expected_misses: list[str] | None = None,
    include_database_summary: bool = True,
    include_fusion_trace: bool = True,
) -> Path:
    bundle_dir = root / name
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "scenario_name": name,
        "scenario_id": name.upper(),
        "run_name": f"run-{name}",
        "status": status,
        "expected": {
            "weakness_tested": weakness_tested,
            "ground_truth": {
                "expected_misses": expected_misses or [],
            },
        },
        "database_summary": {
            "counts": {"alerts": alerts},
            "detections": detections
            or {
                "signature_triggered": False,
                "anomaly_triggered": False,
                "ml_triggered": False,
                "fusion_triggered": False,
            },
            "engine_counts": {"fusion": 0},
        },
        "evidence": {"result_dir": str(bundle_dir)},
        "taxonomy": {
            "taxonomy_key": name,
            "attack_family": "test_family",
            "behavior_category": "test_behavior",
            "primary_detection_path": "test_path",
            "severity": "medium",
            "notes": [],
        },
    }
    _write_json(bundle_dir / "manifest.json", manifest)
    _write_json(
        bundle_dir / "metrics.json",
        {
            "totals": {"expected": tp + fn, "observed": tp + fp, "tp": tp, "fp": fp, "fn": fn},
            "metrics": {"precision": precision, "recall": recall, "f1": f1},
        },
    )
    if include_database_summary:
        _write_json(
            bundle_dir / "database_summary.json",
            {
                "counts": {"alerts": alerts},
                "detections": manifest["database_summary"]["detections"],
                "engine_counts": {"fusion": 1 if manifest["database_summary"]["detections"].get("fusion_triggered") else 0},
            },
        )
    if include_fusion_trace:
        _write_json(
            bundle_dir / "fusion_trace.json",
            [
                {"escalated": True, "fusion_alert_persisted": True}
                if manifest["database_summary"]["detections"].get("fusion_triggered")
                else {"escalated": False, "fusion_alert_persisted": False}
            ],
        )
    return bundle_dir


def test_summarize_bundle_handles_missing_optional_artifacts(tmp_path: Path) -> None:
    bundle_dir = _scenario_bundle(
        tmp_path,
        name="mimic_normal",
        alerts=0,
        expected_misses=["Hybrid Fusion Decision"],
        include_database_summary=False,
        include_fusion_trace=False,
    )

    summary = summarize_bundle(bundle_dir)

    assert summary["scenario_name"] == "mimic_normal"
    assert summary["status"] == "pass"
    assert "missing_optional_artifact:database_summary.json" in summary["notes"]
    assert "missing_optional_artifact:fusion_trace.json" in summary["notes"]
    assert "missing_optional_artifact:taxonomy_map.json" in summary["notes"]


def test_build_robustness_matrix_aggregates_multi_scenario_results(tmp_path: Path) -> None:
    first = _scenario_bundle(
        tmp_path,
        name="partial_signal",
        status="pass",
        alerts=1,
        tp=1,
        fp=0,
        fn=0,
        precision=1.0,
        recall=1.0,
        f1=1.0,
        detections={
            "signature_triggered": True,
            "anomaly_triggered": False,
            "ml_triggered": False,
            "fusion_triggered": False,
        },
    )
    second = _scenario_bundle(
        tmp_path,
        name="alert_flood",
        status="partial",
        alerts=6,
        tp=3,
        fp=3,
        fn=0,
        precision=0.5,
        recall=1.0,
        f1=0.6667,
        detections={
            "signature_triggered": True,
            "anomaly_triggered": False,
            "ml_triggered": False,
            "fusion_triggered": False,
        },
    )
    third = _scenario_bundle(
        tmp_path,
        name="fusion_case",
        status="fail",
        alerts=2,
        tp=1,
        fp=0,
        fn=1,
        precision=1.0,
        recall=0.5,
        f1=0.6667,
        detections={
            "signature_triggered": True,
            "anomaly_triggered": True,
            "ml_triggered": True,
            "fusion_triggered": True,
        },
    )

    matrix = build_robustness_matrix([first, second, third])

    assert matrix["scenario_count"] == 3
    assert matrix["engine_trigger_summary"]["signature"] == 3
    assert matrix["engine_trigger_summary"]["fusion"] == 1
    assert matrix["highlights"]["highest_fp_scenario"] == "alert_flood"
    assert matrix["highlights"]["highest_fn_scenario"] == "fusion_case"
    assert matrix["highlights"]["strongest_scenario"] == "partial_signal"


def test_status_inference_is_conservative_without_manifest_status(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "no-status"
    bundle_dir.mkdir()
    _write_json(
        bundle_dir / "manifest.json",
        {
            "scenario_name": "no-status",
            "expected": {"ground_truth": {"expected_misses": []}},
            "database_summary": {
                "counts": {"alerts": 2},
                "detections": {
                    "signature_triggered": True,
                    "anomaly_triggered": False,
                    "ml_triggered": False,
                    "fusion_triggered": False,
                },
            },
            "evidence": {"result_dir": str(bundle_dir)},
        },
    )
    _write_json(
        bundle_dir / "metrics.json",
        {
            "totals": {"expected": 2, "observed": 2, "tp": 1, "fp": 0, "fn": 1},
            "metrics": {"precision": 1.0, "recall": 0.5, "f1": 0.6667},
        },
    )

    summary = summarize_bundle(bundle_dir)

    assert summary["status"] == "fail"
    assert summary["status_reason"] == "metrics_fn_present"


def test_write_robustness_matrix_is_deterministic_shape(tmp_path: Path) -> None:
    first = _scenario_bundle(tmp_path, name="a-first", status="pass", tp=1, precision=1.0, recall=1.0, f1=1.0)
    second = _scenario_bundle(tmp_path, name="b-second", status="partial", fp=1, precision=0.0, recall=0.0, f1=0.0)

    json_path, md_path = write_robustness_matrix(
        bundle_dirs=[second, first],
        out_json=tmp_path / "robustness_matrix.json",
        out_md=tmp_path / "robustness_matrix.md",
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = md_path.read_text(encoding="utf-8")

    assert [row["scenario_name"] for row in payload["scenarios"]] == ["a-first", "b-second"]
    assert "| Scenario | Family | Severity | Status | Alerts | TP | FP | FN | Precision | Recall | F1 | Engines | Fusion Alerts |" in markdown
    assert "Highest-FP scenario" in markdown
    assert robustness_matrix_markdown(payload) == markdown
