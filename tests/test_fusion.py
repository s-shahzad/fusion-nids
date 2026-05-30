from __future__ import annotations

from src.NIDS.detect.fusion import FusionEngine


def test_fusion_engine_emits_alert_when_multiple_detectors_agree() -> None:
    engine = FusionEngine()

    alerts, decision = engine.fuse(
        signature_alerts=[],
        anomaly_alerts=[{"severity": "high"}],
        ml_alerts=[{"engine": "ml", "severity": "high"}],
        ml_prediction={
            "predicted_attack_type": "dos",
            "supervised_label": "dos",
            "supervised_score": 0.91,
            "unsupervised_label": "attack",
            "unsupervised_score": 0.72,
            "supervised_algorithms": ["random_forest", "xgboost"],
        },
        anomaly_score=0.82,
    )

    assert decision["fusion_label"] == "attack"
    assert decision["fusion_agreement_count"] == 3
    assert decision["fusion_components"]["statistical"] == 0.9
    assert set(decision["fusion_active_components"]) == {"statistical", "supervised", "unsupervised"}

    assert len(alerts) == 1
    assert alerts[0]["engine"] == "fusion"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["extra"]["fusion_components"]["supervised"] == 0.91
    assert alerts[0]["extra"]["recommended_attack_type"] == "dos"


def test_fusion_engine_does_not_duplicate_signature_only_alerts() -> None:
    engine = FusionEngine()

    alerts, decision = engine.fuse(
        signature_alerts=[{"severity": "high"}],
        anomaly_alerts=[],
        ml_alerts=[],
        ml_prediction={},
        anomaly_score=None,
    )

    assert alerts == []
    assert decision["fusion_label"] == "benign"
    assert decision["fusion_components"]["signature"] == 0.9
    assert decision["fusion_active_components"] == ["signature"]
