from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _decision_reason(
    *,
    escalated_by_fusion: bool,
    fusion_score: float,
    agreement_count: int,
    min_agreement_count: int,
    high_threshold: float,
    active_components: list[str],
    ml_confirmation_contributed: bool,
) -> str:
    components = ", ".join(active_components) if active_components else "none"
    if escalated_by_fusion:
        return (
            "Escalated because the fusion decision emitted an alert with "
            f"agreement={agreement_count}/{min_agreement_count}, fusion_score={fusion_score:.2f}, "
            f"components={components}, ml_confirmation_contributed={str(ml_confirmation_contributed).lower()}."
        )
    return (
        "Not escalated because the evaluated fusion candidate stayed below the emit condition with "
        f"agreement={agreement_count}/{min_agreement_count} and fusion_score={fusion_score:.2f} "
        f"(high_threshold={high_threshold:.2f}); components={components}."
    )


def build_fusion_trace_entry(
    *,
    flow_id: int,
    flow_record: dict[str, Any],
    fusion_prediction: dict[str, Any],
    fusion_alerts: list[dict[str, Any]],
    persisted_fusion_alert_ids: list[int],
    config: dict[str, Any],
) -> dict[str, Any]:
    active_components = [str(item) for item in list(fusion_prediction.get("fusion_active_components") or []) if str(item)]
    supervised_score = _safe_float(fusion_prediction.get("supervised_score"))
    unsupervised_score = _safe_float(fusion_prediction.get("unsupervised_score"))
    statistical_score = _safe_float(fusion_prediction.get("statistical_score"))
    signature_score = _safe_float(fusion_prediction.get("signature_score"))
    min_component_score = _safe_float(config.get("min_component_score"), 0.55)
    ml_confirmation_contributed = (
        supervised_score >= min_component_score or unsupervised_score >= min_component_score
    )
    agreement_count = _safe_int(fusion_prediction.get("fusion_agreement_count"))
    min_agreement_count = _safe_int(config.get("min_agreement_count"), 2)
    fusion_score = _safe_float(fusion_prediction.get("fusion_score"))
    high_threshold = _safe_float(config.get("high_threshold"), 0.8)
    escalated_by_fusion = bool(fusion_alerts)
    alert_ref = persisted_fusion_alert_ids[0] if persisted_fusion_alert_ids else None

    return {
        "flow_id": int(flow_id),
        "timestamp": str(flow_record.get("timestamp") or ""),
        "sensor_id": str(flow_record.get("sensor_id") or ""),
        "src_ip": flow_record.get("src_ip"),
        "dst_ip": flow_record.get("dst_ip"),
        "proto": flow_record.get("proto"),
        "fusion_alert_id": alert_ref,
        "fusion_alert_ids": [int(item) for item in persisted_fusion_alert_ids],
        "fusion_label": str(fusion_prediction.get("fusion_label") or ""),
        "fusion_score": round(fusion_score, 4),
        "agreement_count": agreement_count,
        "agreement_threshold": min_agreement_count,
        "contributing_engines": active_components,
        "ml_confirmation_contributed": bool(ml_confirmation_contributed),
        "escalated_by_fusion": escalated_by_fusion,
        "persisted_fusion_alert": bool(persisted_fusion_alert_ids),
        "component_scores": {
            "signature": round(signature_score, 4),
            "statistical": round(statistical_score, 4),
            "supervised": round(supervised_score, 4),
            "unsupervised": round(unsupervised_score, 4),
        },
        "configured_thresholds": {
            "min_component_score": round(min_component_score, 4),
            "min_agreement_count": min_agreement_count,
            "alert_threshold": round(_safe_float(config.get("alert_threshold"), 0.65), 4),
            "high_threshold": round(high_threshold, 4),
            "critical_threshold": round(_safe_float(config.get("critical_threshold"), 0.92), 4),
        },
        "reason": _decision_reason(
            escalated_by_fusion=escalated_by_fusion,
            fusion_score=fusion_score,
            agreement_count=agreement_count,
            min_agreement_count=min_agreement_count,
            high_threshold=high_threshold,
            active_components=active_components,
            ml_confirmation_contributed=ml_confirmation_contributed,
        ),
    }


def write_fusion_trace_artifacts(
    *,
    records: list[dict[str, Any]],
    output_dir: str | Path,
    config: dict[str, Any],
) -> tuple[Path, Path]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "fusion_trace.json"
    md_path = out_dir / "fusion_summary.md"

    payload = {
        "generated_at": _utc_now_iso(),
        "trace_model": "stored_fusion_decision_trace_v1",
        "assumptions": [
            "trace reflects the existing fusion decision and does not re-score alerts",
            "contributing_engines come from fusion_active_components captured at decision time",
            "ml_confirmation_contributed is true when supervised or unsupervised score meets the configured min_component_score",
            "non-escalated entries describe why the evaluated fusion candidate did not emit a fusion alert",
        ],
        "configured_thresholds": {
            "min_component_score": round(_safe_float(config.get("min_component_score"), 0.55), 4),
            "min_agreement_count": _safe_int(config.get("min_agreement_count"), 2),
            "alert_threshold": round(_safe_float(config.get("alert_threshold"), 0.65), 4),
            "high_threshold": round(_safe_float(config.get("high_threshold"), 0.8), 4),
            "critical_threshold": round(_safe_float(config.get("critical_threshold"), 0.92), 4),
        },
        "totals": {
            "evaluated": len(records),
            "fusion_confirmed": sum(1 for item in records if bool(item.get("escalated_by_fusion"))),
            "not_escalated": sum(1 for item in records if not bool(item.get("escalated_by_fusion"))),
        },
        "records": records,
    }

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")

    lines = [
        "# Fusion Trace Summary",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "## Totals",
        "",
        f"- Evaluated fusion candidates: {payload['totals']['evaluated']}",
        f"- Fusion-confirmed alerts: {payload['totals']['fusion_confirmed']}",
        f"- Not escalated: {payload['totals']['not_escalated']}",
        "",
        "## Configured Thresholds",
        "",
    ]
    for key, value in payload["configured_thresholds"].items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Records", ""])
    if records:
        for item in records:
            lines.append(
                f"- flow_id={item['flow_id']} fusion_alert_id={item['fusion_alert_id']} "
                f"label={item['fusion_label']} agreement={item['agreement_count']}/{item['agreement_threshold']} "
                f"score={item['fusion_score']:.4f} engines={','.join(item['contributing_engines']) or 'none'} "
                f"escalated={str(bool(item['escalated_by_fusion'])).lower()}"
            )
            lines.append(f"  reason: {item['reason']}")
    else:
        lines.append("- none")
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
