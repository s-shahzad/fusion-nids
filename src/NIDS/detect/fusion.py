from __future__ import annotations

from typing import Any


def _severity_score(severity: str) -> float:
    token = str(severity or "").lower()
    if token == "critical":
        return 1.0
    if token in {"high", "alert"}:
        return 0.9
    if token in {"medium", "warning", "monitor"}:
        return 0.65
    if token in {"low", "info"}:
        return 0.4
    return 0.0


def _is_benign(label: Any) -> bool:
    token = str(label or "").strip().lower()
    return token in {"", "none", "null", "benign", "normal", "0"}


class FusionEngine:
    """Fuse signature, statistical anomaly, and ML signals into one risk decision."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = dict(config or {})
        self.enabled = bool(cfg.get("enabled", True))
        self.emit_alerts = bool(cfg.get("emit_alerts", True))
        self.emit_on_signature_only = bool(cfg.get("emit_on_signature_only", False))
        self.min_component_score = float(cfg.get("min_component_score", 0.55))
        self.min_agreement_count = int(cfg.get("min_agreement_count", 2))
        self.alert_threshold = float(cfg.get("alert_threshold", 0.65))
        self.high_threshold = float(cfg.get("high_threshold", 0.8))
        self.critical_threshold = float(cfg.get("critical_threshold", 0.92))
        self.signature_weight = float(cfg.get("signature_weight", 0.4))
        self.statistical_weight = float(cfg.get("statistical_weight", 0.2))
        self.supervised_weight = float(cfg.get("supervised_weight", 0.3))
        self.unsupervised_weight = float(cfg.get("unsupervised_weight", 0.1))

    def fuse(
        self,
        *,
        signature_alerts: list[dict[str, Any]],
        anomaly_alerts: list[dict[str, Any]],
        ml_alerts: list[dict[str, Any]],
        ml_prediction: dict[str, Any],
        anomaly_score: float | None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if not self.enabled:
            return [], {
                "fusion_score": 0.0,
                "fusion_label": "benign",
                "fusion_agreement_count": 0,
                "signature_score": 0.0,
                "statistical_score": 0.0,
                "supervised_score": float(ml_prediction.get("supervised_score") or 0.0),
                "unsupervised_score": float(ml_prediction.get("unsupervised_score") or 0.0),
                "fusion_components": {},
                "fusion_active_components": [],
            }

        signature_score = max((_severity_score(item.get("severity")) for item in signature_alerts), default=0.0)
        anomaly_alert_score = max((_severity_score(item.get("severity")) for item in anomaly_alerts), default=0.0)
        statistical_score = max(float(anomaly_score or 0.0), anomaly_alert_score)

        supervised_score = float(ml_prediction.get("supervised_score") or 0.0)
        if _is_benign(ml_prediction.get("supervised_label")):
            supervised_score = 0.0

        unsupervised_score = float(ml_prediction.get("unsupervised_score") or 0.0)
        if _is_benign(ml_prediction.get("unsupervised_label")):
            unsupervised_score = 0.0

        component_scores = {
            "signature": signature_score,
            "statistical": statistical_score,
            "supervised": supervised_score,
            "unsupervised": unsupervised_score,
        }

        fusion_score = (
            self.signature_weight * signature_score
            + self.statistical_weight * statistical_score
            + self.supervised_weight * supervised_score
            + self.unsupervised_weight * unsupervised_score
        )

        active_components = [
            name
            for name, score in component_scores.items()
            if score >= self.min_component_score or (name == "signature" and score > 0.0)
        ]
        agreement_count = len(active_components)

        attack_signal = (
            fusion_score >= self.alert_threshold
            or agreement_count >= self.min_agreement_count
            or signature_score >= self.critical_threshold
        )
        fusion_label = "attack" if attack_signal else "benign"

        recommended_attack_type = ml_prediction.get("predicted_attack_type")
        if not recommended_attack_type and signature_score > 0:
            recommended_attack_type = "signature_match"
        if not recommended_attack_type and (statistical_score > 0 or unsupervised_score > 0):
            recommended_attack_type = "anomaly"

        emit_alert = self.emit_alerts and fusion_label == "attack"
        if emit_alert and not self.emit_on_signature_only:
            non_signature_signals = [
                score
                for key, score in component_scores.items()
                if key != "signature" and score >= self.min_component_score
            ]
            if signature_score > 0 and not non_signature_signals:
                emit_alert = False

        if emit_alert and agreement_count < self.min_agreement_count and fusion_score < self.high_threshold:
            emit_alert = False

        severity = "medium"
        if fusion_score >= self.critical_threshold or agreement_count >= 3:
            severity = "critical"
        elif fusion_score >= self.high_threshold or agreement_count >= 2:
            severity = "high"

        summary = (
            f"Hybrid fusion score={fusion_score:.2f} agreement={agreement_count} "
            f"components={', '.join(active_components) if active_components else 'none'}"
        )

        extra = {
            "fusion_components": component_scores,
            "active_components": active_components,
            "recommended_attack_type": recommended_attack_type,
            "supervised_label": ml_prediction.get("supervised_label"),
            "unsupervised_label": ml_prediction.get("unsupervised_label"),
            "ml_alert_count": len(ml_alerts),
            "signature_alert_count": len(signature_alerts),
            "anomaly_alert_count": len(anomaly_alerts),
            "supervised_algorithms": list(ml_prediction.get("supervised_algorithms") or []),
            "unsupervised_algorithms": list(ml_prediction.get("unsupervised_algorithms") or []),
            "unsupervised_active_components": list(ml_prediction.get("unsupervised_active_components") or []),
        }

        alerts: list[dict[str, Any]] = []
        if emit_alert:
            alerts.append(
                {
                    "engine": "fusion",
                    "severity": severity,
                    "rule_name": "Hybrid Fusion Decision",
                    "summary": summary,
                    "extra": extra,
                }
            )

        decision = {
            "fusion_score": float(fusion_score),
            "fusion_label": fusion_label,
            "fusion_agreement_count": int(agreement_count),
            "signature_score": float(signature_score),
            "statistical_score": float(statistical_score),
            "supervised_score": float(supervised_score),
            "unsupervised_score": float(unsupervised_score),
            "fusion_components": component_scores,
            "fusion_active_components": active_components,
        }
        return alerts, decision
