from __future__ import annotations

from src.nids.detect.fusion import FusionEngine


def test_fusion_engine_agreement_alone_no_longer_bypasses_score_threshold() -> None:
    # NOTE: this test previously asserted "attack"/"critical" purely because
    # 3 components agreed (agreement_count >= min_agreement_count), even
    # though the weighted fusion_score (0.525 here) is below alert_threshold
    # (0.65). That agreement-count fast-path bypassed the configured score
    # thresholds entirely -- see fusion.py -- and has been fixed so agreement
    # can no longer promote a fusion_score that hasn't cleared alert_threshold.
    # Updated to assert the corrected, threshold-respecting behavior.
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

    assert decision["fusion_agreement_count"] == 3
    assert decision["fusion_components"]["statistical"] == 0.9
    assert set(decision["fusion_active_components"]) == {"statistical", "supervised", "unsupervised"}
    assert decision["fusion_score"] == 0.525

    # fusion_score (0.525) is still below alert_threshold (0.65), so despite
    # 3 agreeing components this is no longer treated as an attack.
    assert decision["fusion_label"] == "benign"
    assert alerts == []


def test_fusion_engine_emits_alert_when_score_and_agreement_both_clear_threshold() -> None:
    # Same 3-component agreement as above, but with a signature hit added so
    # the weighted fusion_score itself clears alert_threshold -- this is the
    # path that should still produce a critical "attack" alert.
    engine = FusionEngine()

    alerts, decision = engine.fuse(
        signature_alerts=[{"severity": "critical"}],
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
    assert decision["fusion_agreement_count"] == 4
    assert decision["fusion_components"]["statistical"] == 0.9

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
