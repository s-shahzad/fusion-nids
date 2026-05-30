from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ..ml.featureset import FEATURE_COLUMNS, build_feature_vector

SNAPSHOT_VERSION = 1


def _clip01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _calibrate_bounds(values: np.ndarray) -> tuple[float, float]:
    if values.size == 0:
        return 0.0, 1.0
    center = float(np.percentile(values, 50))
    upper = float(np.percentile(values, 95))
    if upper <= center:
        upper = center + 1e-6
    return center, upper


def _normalize_score(value: float, center: float, upper: float) -> float:
    if upper <= center:
        return 1.0 if value > upper else 0.0
    return _clip01((float(value) - center) / (upper - center))


class UnsupervisedMLEngine:
    """Hybrid unsupervised scorer using IsolationForest and a shallow autoencoder."""

    def __init__(
        self,
        warmup_samples: int = 200,
        contamination: float = 0.03,
        alert_threshold: float = 0.65,
        component_threshold: float | None = None,
        autoencoder_enabled: bool = True,
        autoencoder_hidden_size: int = 8,
        autoencoder_max_iter: int = 400,
        snapshot_path: str | Path | None = None,
        random_state: int = 42,
    ) -> None:
        self.warmup_samples = max(20, int(warmup_samples))
        self.alert_threshold = float(alert_threshold)
        self.component_threshold = (
            float(component_threshold)
            if component_threshold is not None
            else max(0.5, float(alert_threshold) - 0.1)
        )
        self.buffer: list[list[float]] = []
        self.random_state = int(random_state)
        self.contamination = float(contamination)
        self.autoencoder_enabled = bool(autoencoder_enabled)
        self.autoencoder_hidden_size = max(4, int(autoencoder_hidden_size))
        self.autoencoder_max_iter = max(100, int(autoencoder_max_iter))
        self.snapshot_path = Path(snapshot_path).resolve() if snapshot_path else None
        self._dirty = False

        self.isolation_model: IsolationForest | None = None
        self.isolation_center = 0.0
        self.isolation_upper = 1.0

        self.autoencoder_scaler: StandardScaler | None = None
        self.autoencoder_model: MLPRegressor | None = None
        self.autoencoder_center = 0.0
        self.autoencoder_upper = 1.0

        self._load_snapshot()

    def _algorithm_names(self) -> list[str]:
        names = ["isolation_forest"]
        if self.autoencoder_enabled:
            names.append("autoencoder")
        return names

    def _training_signature(self) -> dict[str, Any]:
        return {
            "feature_columns": list(FEATURE_COLUMNS),
            "contamination": float(self.contamination),
            "autoencoder_enabled": bool(self.autoencoder_enabled),
            "autoencoder_hidden_size": int(self.autoencoder_hidden_size),
            "autoencoder_max_iter": int(self.autoencoder_max_iter),
        }

    def _snapshot_payload(self) -> dict[str, Any]:
        return {
            "snapshot_version": SNAPSHOT_VERSION,
            "training_signature": self._training_signature(),
            "warmup_samples": int(self.warmup_samples),
            "buffer": list(self.buffer),
            "isolation_model": self.isolation_model,
            "isolation_center": float(self.isolation_center),
            "isolation_upper": float(self.isolation_upper),
            "autoencoder_scaler": self.autoencoder_scaler,
            "autoencoder_model": self.autoencoder_model,
            "autoencoder_center": float(self.autoencoder_center),
            "autoencoder_upper": float(self.autoencoder_upper),
        }

    def _load_snapshot(self) -> None:
        if self.snapshot_path is None or not self.snapshot_path.exists():
            return

        try:
            payload = joblib.load(self.snapshot_path)
        except Exception:
            return

        if not isinstance(payload, dict):
            return
        if int(payload.get("snapshot_version") or 0) != SNAPSHOT_VERSION:
            return
        if payload.get("training_signature") != self._training_signature():
            return

        self.buffer = [
            [float(value) for value in row]
            for row in list(payload.get("buffer") or [])
            if isinstance(row, (list, tuple))
        ]
        self.isolation_model = payload.get("isolation_model")
        self.isolation_center = float(payload.get("isolation_center") or 0.0)
        self.isolation_upper = float(payload.get("isolation_upper") or 1.0)
        self.autoencoder_scaler = payload.get("autoencoder_scaler")
        self.autoencoder_model = payload.get("autoencoder_model")
        self.autoencoder_center = float(payload.get("autoencoder_center") or 0.0)
        self.autoencoder_upper = float(payload.get("autoencoder_upper") or 1.0)

        if self.isolation_model is None and len(self.buffer) >= self.warmup_samples:
            self._fit_models()
        self._dirty = False

    def _fit_models(self) -> None:
        frame = np.array(self.buffer, dtype=float)
        if len(frame) == 0:
            return

        self.isolation_model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=200,
        )
        self.isolation_model.fit(frame)
        isolation_train_scores = -self.isolation_model.decision_function(frame)
        self.isolation_center, self.isolation_upper = _calibrate_bounds(isolation_train_scores)

        self.autoencoder_scaler = None
        self.autoencoder_model = None
        self.autoencoder_center = 0.0
        self.autoencoder_upper = 1.0

        if self.autoencoder_enabled:
            feature_count = int(frame.shape[1])
            hidden = min(self.autoencoder_hidden_size, max(4, feature_count - 1))
            hidden_layers = (max(hidden * 2, hidden + 2), hidden)

            self.autoencoder_scaler = StandardScaler()
            scaled = self.autoencoder_scaler.fit_transform(frame)
            self.autoencoder_model = MLPRegressor(
                hidden_layer_sizes=hidden_layers,
                activation="relu",
                solver="adam",
                learning_rate_init=0.001,
                max_iter=self.autoencoder_max_iter,
                random_state=self.random_state,
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=ConvergenceWarning)
                self.autoencoder_model.fit(scaled, scaled)

            reconstructed = self.autoencoder_model.predict(scaled)
            reconstruction_error = np.mean(np.square(scaled - reconstructed), axis=1)
            self.autoencoder_center, self.autoencoder_upper = _calibrate_bounds(reconstruction_error)

        self._dirty = True

    def save_snapshot(self) -> Path | None:
        if self.snapshot_path is None or not self._dirty:
            return None

        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._snapshot_payload(), self.snapshot_path)
        self._dirty = False
        return self.snapshot_path

    def detect(self, event: dict[str, Any], features: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        vector = build_feature_vector(event, features)

        if self.isolation_model is None:
            self.buffer.append(vector)
            self._dirty = True
            if len(self.buffer) >= self.warmup_samples:
                self._fit_models()
            return [], {
                "unsupervised_score": None,
                "unsupervised_label": None,
                "unsupervised_attack_type": None,
                "unsupervised_isolation_score": None,
                "unsupervised_autoencoder_score": None,
                "unsupervised_components": {},
                "unsupervised_active_components": [],
                "unsupervised_algorithms": self._algorithm_names(),
                "unsupervised_model_count": len(self._algorithm_names()),
            }

        arr = np.array([vector], dtype=float)
        component_scores: dict[str, float] = {}

        raw_isolation = float(-self.isolation_model.decision_function(arr)[0])
        component_scores["isolation_forest"] = _normalize_score(
            raw_isolation,
            self.isolation_center,
            self.isolation_upper,
        )

        if self.autoencoder_model is not None and self.autoencoder_scaler is not None:
            scaled = self.autoencoder_scaler.transform(arr)
            reconstructed = self.autoencoder_model.predict(scaled)
            reconstruction_error = float(np.mean(np.square(scaled - reconstructed), axis=1)[0])
            component_scores["autoencoder"] = _normalize_score(
                reconstruction_error,
                self.autoencoder_center,
                self.autoencoder_upper,
            )

        anomaly_score = max(component_scores.values(), default=0.0)
        active_components = [
            name for name, score in component_scores.items() if float(score) >= self.component_threshold
        ]
        predicted_label = "attack" if anomaly_score >= self.alert_threshold or len(active_components) >= 2 else "benign"

        alerts: list[dict[str, Any]] = []
        if predicted_label == "attack":
            severity = "high" if anomaly_score >= 0.85 or len(active_components) >= 2 else "medium"
            components_text = ", ".join(
                f"{name}={component_scores[name]:.2f}" for name in sorted(component_scores)
            )
            alerts.append(
                {
                    "engine": "ml",
                    "severity": severity,
                    "rule_name": "Hybrid Unsupervised Anomaly Score",
                    "summary": f"Hybrid unsupervised anomaly score={anomaly_score:.2f} ({components_text})",
                    "extra": {
                        "unsupervised_components": component_scores,
                        "unsupervised_active_components": active_components,
                        "unsupervised_algorithms": self._algorithm_names(),
                        "baseline_snapshot_path": str(self.snapshot_path) if self.snapshot_path else None,
                    },
                }
            )

        prediction = {
            "unsupervised_score": anomaly_score,
            "unsupervised_label": predicted_label,
            "unsupervised_attack_type": "anomaly" if predicted_label == "attack" else None,
            "unsupervised_isolation_score": component_scores.get("isolation_forest"),
            "unsupervised_autoencoder_score": component_scores.get("autoencoder"),
            "unsupervised_components": component_scores,
            "unsupervised_active_components": active_components,
            "unsupervised_algorithms": self._algorithm_names(),
            "unsupervised_model_count": len(component_scores),
            "unsupervised_baseline_path": str(self.snapshot_path) if self.snapshot_path else None,
        }
        return alerts, prediction
