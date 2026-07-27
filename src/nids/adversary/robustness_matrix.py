from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any] | list[Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _normalize_status(status: str) -> str:
    token = str(status or "").strip().lower()
    return token if token in {"pass", "partial", "fail"} else ""


def _infer_status(*, manifest: dict[str, Any], metrics: dict[str, Any], expected_misses: list[str], total_alerts: int) -> tuple[str, str]:
    manifest_status = _normalize_status(str(manifest.get("status") or ""))
    if manifest_status:
        return manifest_status, "manifest_status"

    expected = _as_dict(manifest.get("expected"))
    if expected.get("max_alerts") is not None and total_alerts > _safe_int(expected.get("max_alerts")):
        return "partial", "expected_max_alerts_exceeded"

    totals = _as_dict(metrics.get("totals"))
    fn = _safe_int(totals.get("fn"))
    fp = _safe_int(totals.get("fp"))
    observed = _safe_int(totals.get("observed"), total_alerts)
    if fn > 0:
        return "fail", "metrics_fn_present"
    if fp > 0:
        return "partial", "metrics_fp_present"
    if observed == 0 and expected_misses:
        return "pass", "expected_misses_only"
    if metrics:
        return "pass", "metrics_clean"
    if expected_misses and total_alerts == 0:
        return "pass", "no_alerts_expected"
    return "partial", "best_effort_inference"


def _fusion_alert_count(bundle_dir: Path, database_summary: dict[str, Any]) -> int:
    trace_payload = _read_json(bundle_dir / "fusion_trace.json")
    trace_rows = _as_list(trace_payload)
    if trace_rows:
        return sum(
            1
            for row in trace_rows
            if _as_dict(row).get("fusion_alert_persisted") or _as_dict(row).get("escalated")
        )
    engine_counts = _as_dict(database_summary.get("engine_counts"))
    return _safe_int(engine_counts.get("fusion"))


def summarize_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    result_dir = Path(bundle_dir).resolve()
    manifest = _as_dict(_read_json(result_dir / "manifest.json"))
    metrics = _as_dict(_read_json(result_dir / "metrics.json"))
    database_summary = _as_dict(_read_json(result_dir / "database_summary.json"))
    taxonomy = _as_dict(_read_json(result_dir / "taxonomy_map.json"))
    if not database_summary and "database_summary" in manifest:
        database_summary = _as_dict(manifest.get("database_summary"))
    if not taxonomy and "taxonomy" in manifest:
        taxonomy = _as_dict(manifest.get("taxonomy"))

    expected = _as_dict(manifest.get("expected"))
    ground_truth = _as_dict(expected.get("ground_truth"))
    expected_misses = [str(item) for item in _as_list(ground_truth.get("expected_misses")) if str(item).strip()]
    detections = _as_dict(database_summary.get("detections"))
    triggered_engines = [
        engine
        for engine in ("signature", "anomaly", "ml", "fusion")
        if bool(detections.get(f"{engine}_triggered"))
    ]
    total_alerts = _safe_int(_as_dict(database_summary.get("counts")).get("alerts"))
    totals = _as_dict(metrics.get("totals"))
    metric_values = _as_dict(metrics.get("metrics"))
    status, status_reason = _infer_status(
        manifest=manifest,
        metrics=metrics,
        expected_misses=expected_misses,
        total_alerts=total_alerts,
    )
    notes: list[str] = []
    for artifact_name in ("metrics.json", "database_summary.json", "fusion_trace.json", "taxonomy_map.json"):
        if not (result_dir / artifact_name).exists():
            notes.append(f"missing_optional_artifact:{artifact_name}")
    notes.extend(str(item) for item in _as_list(taxonomy.get("notes")) if str(item).strip())

    return {
        "scenario_name": str(
            manifest.get("scenario_name")
            or manifest.get("scenario_id")
            or result_dir.name
        ),
        "scenario_id": str(manifest.get("scenario_id") or ""),
        "run_name": str(manifest.get("run_name") or result_dir.name),
        "result_dir": str(result_dir),
        "weakness_tested": str(expected.get("weakness_tested") or "Not specified."),
        "total_alerts": total_alerts,
        "tp": _safe_int(totals.get("tp")),
        "fp": _safe_int(totals.get("fp")),
        "fn": _safe_int(totals.get("fn")),
        "precision": round(_safe_float(metric_values.get("precision")), 4),
        "recall": round(_safe_float(metric_values.get("recall")), 4),
        "f1": round(_safe_float(metric_values.get("f1")), 4),
        "triggered_engines": triggered_engines,
        "fusion_alert_count": _fusion_alert_count(result_dir, database_summary),
        "expected_misses": expected_misses,
        "attack_family": str(taxonomy.get("attack_family") or "unmapped"),
        "behavior_category": str(taxonomy.get("behavior_category") or "unmapped"),
        "primary_detection_path": str(taxonomy.get("primary_detection_path") or "unknown"),
        "severity": str(taxonomy.get("severity") or "unknown"),
        "taxonomy_key": str(taxonomy.get("taxonomy_key") or ""),
        "status": status,
        "status_reason": status_reason,
        "notes": notes,
    }


def build_robustness_matrix(bundle_dirs: list[str | Path]) -> dict[str, Any]:
    scenarios = [summarize_bundle(path) for path in bundle_dirs]
    scenarios.sort(key=lambda item: (item["scenario_name"], item["run_name"]))
    engine_summary = {
        engine: sum(1 for item in scenarios if engine in item["triggered_engines"])
        for engine in ("signature", "anomaly", "ml", "fusion")
    }

    def _pick_row(rows: list[dict[str, Any]], key: str, reverse: bool = False) -> dict[str, Any] | None:
        if not rows:
            return None
        return sorted(rows, key=lambda item: (item[key], item["scenario_name"]), reverse=reverse)[0]

    return {
        "generated_at": _utc_now_iso(),
        "scenario_count": len(scenarios),
        "assumptions": [
            "scenario status prefers manifest status when present because it already reflects scenario expectations",
            "when manifest status is unavailable, inference is conservative: false negatives fail, false positives are partial, clean metrics pass",
            "expected_misses with zero alerts are treated as pass in best-effort inference",
            "missing optional artifacts do not stop aggregation and are recorded in notes",
        ],
        "engine_trigger_summary": engine_summary,
        "scenarios": scenarios,
        "highlights": {
            "highest_fp_scenario": (_pick_row(scenarios, "fp", reverse=True) or {}).get("scenario_name", ""),
            "highest_fn_scenario": (_pick_row(scenarios, "fn", reverse=True) or {}).get("scenario_name", ""),
            "strongest_scenario": (_pick_row(scenarios, "f1", reverse=True) or {}).get("scenario_name", ""),
            "weakest_scenario": (_pick_row(scenarios, "f1", reverse=False) or {}).get("scenario_name", ""),
        },
    }


def robustness_matrix_markdown(matrix: dict[str, Any]) -> str:
    lines = [
        "# AI Robustness Matrix",
        "",
        f"Generated: {matrix.get('generated_at')}",
        f"Scenario count: {matrix.get('scenario_count')}",
        "",
        "## Scenario Comparison",
        "",
        "| Scenario | Family | Severity | Status | Alerts | TP | FP | FN | Precision | Recall | F1 | Engines | Fusion Alerts |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|",
    ]
    for row in _as_list(matrix.get("scenarios")):
        scenario = _as_dict(row)
        engines = ", ".join(str(item) for item in _as_list(scenario.get("triggered_engines"))) or "none"
        lines.append(
            f"| `{scenario.get('scenario_name', '')}` | `{scenario.get('attack_family', '')}` | "
            f"`{scenario.get('severity', '')}` | `{scenario.get('status', '')}` | "
            f"{_safe_int(scenario.get('total_alerts'))} | {_safe_int(scenario.get('tp'))} | "
            f"{_safe_int(scenario.get('fp'))} | {_safe_int(scenario.get('fn'))} | "
            f"{_safe_float(scenario.get('precision')):.4f} | {_safe_float(scenario.get('recall')):.4f} | "
            f"{_safe_float(scenario.get('f1')):.4f} | `{engines}` | {_safe_int(scenario.get('fusion_alert_count'))} |"
        )
    lines.extend(["", "## Per-Engine Trigger Summary", ""])
    for engine, count in _as_dict(matrix.get("engine_trigger_summary")).items():
        lines.append(f"- `{engine}` triggered in `{_safe_int(count)}` scenario(s)")
    highlights = _as_dict(matrix.get("highlights"))
    lines.extend(
        [
            "",
            "## Highlights",
            "",
            f"- Highest-FP scenario: `{highlights.get('highest_fp_scenario', '')}`",
            f"- Highest-FN scenario: `{highlights.get('highest_fn_scenario', '')}`",
            f"- Strongest scenario: `{highlights.get('strongest_scenario', '')}`",
            f"- Weakest scenario: `{highlights.get('weakest_scenario', '')}`",
            "",
            "## Notes",
            "",
        ]
    )
    for row in _as_list(matrix.get("scenarios")):
        scenario = _as_dict(row)
        if _as_list(scenario.get("notes")):
            lines.append(
                f"- `{scenario.get('scenario_name', '')}`: {', '.join(str(item) for item in _as_list(scenario.get('notes')))}"
            )
    if lines[-1] == "":
        lines.append("- none")
    elif lines[-1] == "## Notes":
        lines.append("")
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def write_robustness_matrix(
    *,
    bundle_dirs: list[str | Path],
    out_json: str | Path,
    out_md: str | Path,
) -> tuple[Path, Path]:
    matrix = build_robustness_matrix(bundle_dirs)
    json_path = Path(out_json)
    md_path = Path(out_md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(matrix, indent=2, ensure_ascii=True), encoding="utf-8")
    md_path.write_text(robustness_matrix_markdown(matrix), encoding="utf-8")
    return json_path, md_path
