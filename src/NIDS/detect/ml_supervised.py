from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from ..ml.featureset import build_feature_vector
from ..ml.supervised_ensemble import payload_algorithm_names, payload_model_count, predict_from_payload


def _force_single_worker_inference(payload: Any) -> None:
    """Pin n_jobs=1 on loaded models so runtime inference never spawns workers."""

    def _apply(model: Any) -> None:
        if model is None or not hasattr(model, "set_params"):
            return
        try:
            params = model.get_params(deep=False) if hasattr(model, "get_params") else {}
        except Exception:
            return
        if "n_jobs" in params:
            try:
                model.set_params(n_jobs=1)
            except Exception:
                pass

    if isinstance(payload, dict):
        for entry in payload.get("models") or []:
            if isinstance(entry, dict):
                _apply(entry.get("model"))
        _apply(payload.get("model"))
    else:
        _apply(payload)


class SupervisedMLEngine:
    """Runtime supervised inference engine using saved sklearn model payload."""

    def __init__(self, model_path: str | Path, score_threshold: float = 0.6) -> None:
        self.model_path = Path(model_path)
        self.score_threshold = float(score_threshold)
        self.available = False
        self.payload: Any = None
        self.feature_columns: list[str] | None = None
        self.algorithm_names: list[str] = []
        self.model_count = 0

        if self.model_path.exists():
            try:
                payload = joblib.load(self.model_path)
                _force_single_worker_inference(payload)
                self.payload = payload
                if isinstance(payload, dict):
                    cols = payload.get("feature_columns")
                    self.feature_columns = list(cols) if isinstance(cols, list) else None
                self.algorithm_names = payload_algorithm_names(payload)
                self.model_count = payload_model_count(payload)
                self.available = self.payload is not None
            except Exception:
                self.available = False

    def detect(self, event: dict[str, Any], features: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if not self.available:
            return [], {}

        vector = build_feature_vector(event, features, self.feature_columns)
        matrix: Any
        if self.feature_columns:
            matrix = pd.DataFrame([vector], columns=self.feature_columns, dtype=float)
        else:
            matrix = np.array([vector], dtype=float)

        try:
            predictions, scores, _ = predict_from_payload(self.payload, matrix)
            label = str(predictions[0])
        except Exception:
            return [], {}

        score = float(scores[0]) if len(scores) else 0.0
        predicted_attack_type = None if label.lower() in {"benign", "normal", "0"} else label

        prediction: dict[str, Any] = {
            "predicted_label": label,
            "predicted_attack_type": predicted_attack_type,
            "prediction_score": score,
            "supervised_label": label,
            "supervised_attack_type": predicted_attack_type,
            "supervised_score": score,
            "supervised_algorithms": list(self.algorithm_names),
            "supervised_model_count": int(self.model_count),
        }

        alerts: list[dict[str, Any]] = []
        if label.lower() not in {"benign", "normal", "0"} and score >= self.score_threshold:
            severity = "high" if score >= 0.9 else "medium"
            alerts.append(
                {
                    "engine": "ml",
                    "severity": severity,
                    "rule_name": "Supervised Ensemble Detection",
                    "summary": f"Supervised ensemble predicted {label} (score={score:.2f})",
                    "extra": {
                        "algorithms": list(self.algorithm_names),
                        "model_count": int(self.model_count),
                    },
                }
            )

        return alerts, prediction
