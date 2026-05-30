from __future__ import annotations

import json

from src.NIDS.fusion_trace import build_fusion_trace_entry, write_fusion_trace_artifacts


def test_build_fusion_trace_entry_for_confirmed_case() -> None:
    entry = build_fusion_trace_entry(
        flow_id=7,
        flow_record={"timestamp": "2026-03-27T12:00:00Z", "sensor_id": "sensor-a", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "TCP"},
        fusion_prediction={
            "fusion_label": "attack",
            "fusion_score": 0.88,
            "fusion_agreement_count": 3,
            "signature_score": 0.9,
            "statistical_score": 0.9,
            "supervised_score": 0.91,
            "unsupervised_score": 0.72,
            "fusion_active_components": ["signature", "statistical", "supervised"],
        },
        fusion_alerts=[{"engine": "fusion"}],
        persisted_fusion_alert_ids=[11],
        config={"min_component_score": 0.55, "min_agreement_count": 3, "alert_threshold": 0.65, "high_threshold": 0.8, "critical_threshold": 0.92},
    )

    assert entry["fusion_alert_id"] == 11
    assert entry["agreement_count"] == 3
    assert entry["agreement_threshold"] == 3
    assert entry["ml_confirmation_contributed"] is True
    assert entry["escalated_by_fusion"] is True
    assert "Escalated because" in entry["reason"]


def test_build_fusion_trace_entry_for_insufficient_agreement() -> None:
    entry = build_fusion_trace_entry(
        flow_id=8,
        flow_record={"timestamp": "2026-03-27T12:00:01Z", "sensor_id": "sensor-a"},
        fusion_prediction={
            "fusion_label": "attack",
            "fusion_score": 0.66,
            "fusion_agreement_count": 1,
            "signature_score": 0.0,
            "statistical_score": 0.6,
            "supervised_score": 0.0,
            "unsupervised_score": 0.0,
            "fusion_active_components": ["statistical"],
        },
        fusion_alerts=[],
        persisted_fusion_alert_ids=[],
        config={"min_component_score": 0.55, "min_agreement_count": 3, "alert_threshold": 0.65, "high_threshold": 0.8, "critical_threshold": 0.92},
    )

    assert entry["fusion_alert_id"] is None
    assert entry["escalated_by_fusion"] is False
    assert entry["agreement_count"] == 1
    assert "Not escalated because" in entry["reason"]


def test_write_fusion_trace_artifacts_is_deterministic_shape(tmp_path) -> None:
    records = [
        {
            "flow_id": 1,
            "timestamp": "2026-03-27T12:00:00Z",
            "sensor_id": "sensor-a",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "proto": "TCP",
            "fusion_alert_id": 2,
            "fusion_alert_ids": [2],
            "fusion_label": "attack",
            "fusion_score": 0.88,
            "agreement_count": 3,
            "agreement_threshold": 3,
            "contributing_engines": ["signature", "supervised", "unsupervised"],
            "ml_confirmation_contributed": True,
            "escalated_by_fusion": True,
            "persisted_fusion_alert": True,
            "component_scores": {"signature": 0.9, "statistical": 0.0, "supervised": 0.91, "unsupervised": 0.72},
            "configured_thresholds": {"min_component_score": 0.55, "min_agreement_count": 3, "alert_threshold": 0.65, "high_threshold": 0.8, "critical_threshold": 0.92},
            "reason": "Escalated because the fusion decision emitted an alert.",
        }
    ]

    json_path, md_path = write_fusion_trace_artifacts(
        records=records,
        output_dir=tmp_path,
        config={"min_component_score": 0.55, "min_agreement_count": 3, "alert_threshold": 0.65, "high_threshold": 0.8, "critical_threshold": 0.92},
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_path.exists()
    assert md_path.exists()
    assert payload["totals"] == {"evaluated": 1, "fusion_confirmed": 1, "not_escalated": 0}
    assert isinstance(payload["records"], list)
    assert set(payload["records"][0].keys()) == {
        "flow_id",
        "timestamp",
        "sensor_id",
        "src_ip",
        "dst_ip",
        "proto",
        "fusion_alert_id",
        "fusion_alert_ids",
        "fusion_label",
        "fusion_score",
        "agreement_count",
        "agreement_threshold",
        "contributing_engines",
        "ml_confirmation_contributed",
        "escalated_by_fusion",
        "persisted_fusion_alert",
        "component_scores",
        "configured_thresholds",
        "reason",
    }
