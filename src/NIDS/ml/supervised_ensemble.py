from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - optional dependency
    XGBClassifier = None


@dataclass
class CandidateSpec:
    name: str
    estimator: Any
    use_sample_weight: bool = False


class LabelEncodedClassifier:
    """Wrap classifiers that require numeric labels while exposing string classes."""

    def __init__(self, estimator: Any) -> None:
        self.estimator = estimator
        self.encoder = LabelEncoder()
        self.classes_: np.ndarray = np.array([], dtype=object)

    def fit(self, X: Any, y: Any, sample_weight: Any = None) -> "LabelEncodedClassifier":
        encoded = self.encoder.fit_transform(np.asarray(y))
        fit_kwargs: dict[str, Any] = {}
        if sample_weight is not None:
            fit_kwargs["sample_weight"] = sample_weight
        self.estimator.fit(X, encoded, **fit_kwargs)
        self.classes_ = np.array(self.encoder.classes_, dtype=object)
        return self

    def predict(self, X: Any) -> np.ndarray:
        encoded = self.estimator.predict(X)
        return self.encoder.inverse_transform(np.asarray(encoded, dtype=int))

    def predict_proba(self, X: Any) -> np.ndarray:
        return np.asarray(self.estimator.predict_proba(X), dtype=float)


def build_candidate_specs(label_count: int, random_state: int = 42) -> list[CandidateSpec]:
    specs: list[CandidateSpec] = [
        CandidateSpec(
            name="random_forest",
            estimator=RandomForestClassifier(
                n_estimators=250,
                random_state=random_state,
                class_weight="balanced",
                n_jobs=-1,
            ),
            use_sample_weight=False,
        ),
        CandidateSpec(
            name="extra_trees",
            estimator=ExtraTreesClassifier(
                n_estimators=320,
                random_state=random_state,
                class_weight="balanced",
                n_jobs=-1,
            ),
            use_sample_weight=False,
        ),
        CandidateSpec(
            name="hist_gradient_boosting",
            estimator=HistGradientBoostingClassifier(
                learning_rate=0.08,
                max_depth=8,
                max_iter=220,
                random_state=random_state,
            ),
            use_sample_weight=True,
        ),
    ]

    if XGBClassifier is not None:
        objective = "binary:logistic" if int(label_count) <= 2 else "multi:softprob"
        specs.append(
            CandidateSpec(
                name="xgboost",
                estimator=LabelEncodedClassifier(
                    XGBClassifier(
                        objective=objective,
                        eval_metric="logloss" if int(label_count) <= 2 else "mlogloss",
                        n_estimators=220,
                        max_depth=6,
                        learning_rate=0.08,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        reg_lambda=1.0,
                        random_state=random_state,
                        n_jobs=4,
                    )
                ),
                use_sample_weight=True,
            )
        )

    return specs


def _ensure_label_classes(label_classes: list[str] | None, fallback: Any) -> list[str]:
    if label_classes:
        return [str(item) for item in label_classes]
    if fallback is None:
        return []
    return [str(item) for item in np.asarray(fallback, dtype=object).tolist()]


def align_probability_matrix(
    probabilities: np.ndarray,
    model_classes: list[str] | np.ndarray,
    label_classes: list[str],
) -> np.ndarray:
    aligned = np.zeros((probabilities.shape[0], len(label_classes)), dtype=float)
    class_index = {str(label): idx for idx, label in enumerate(label_classes)}

    for position, model_class in enumerate(np.asarray(model_classes, dtype=object).tolist()):
        index = class_index.get(str(model_class))
        if index is not None:
            aligned[:, index] = probabilities[:, position]
    return aligned


def predict_with_model(
    model: Any,
    X: Any,
    label_classes: list[str],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    classes = _ensure_label_classes(label_classes, getattr(model, "classes_", None))
    predictions = np.asarray(model.predict(X), dtype=object)

    if hasattr(model, "predict_proba"):
        raw_probabilities = np.asarray(model.predict_proba(X), dtype=float)
        model_classes = _ensure_label_classes(None, getattr(model, "classes_", classes))
        probabilities = align_probability_matrix(raw_probabilities, model_classes, classes)
    else:
        probabilities = np.zeros((len(predictions), len(classes)), dtype=float)
        class_index = {str(label): idx for idx, label in enumerate(classes)}
        for row_index, prediction in enumerate(predictions.tolist()):
            probabilities[row_index, class_index[str(prediction)]] = 1.0

    scores = probabilities.max(axis=1) if probabilities.size else np.zeros(len(predictions), dtype=float)
    return predictions, scores, probabilities


def payload_model_count(payload: Any) -> int:
    if isinstance(payload, dict) and payload.get("model_type") == "supervised_ensemble":
        return len(payload.get("models") or [])
    return 1 if payload is not None else 0


def payload_algorithm_names(payload: Any) -> list[str]:
    if isinstance(payload, dict) and payload.get("model_type") == "supervised_ensemble":
        names = [str(item.get("name") or "model") for item in (payload.get("models") or [])]
        return names

    model = payload.get("model") if isinstance(payload, dict) else payload
    if model is None:
        return []
    return [model.__class__.__name__]


def predict_from_payload(payload: Any, X: Any) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if isinstance(payload, dict) and payload.get("model_type") == "supervised_ensemble":
        label_classes = [str(item) for item in (payload.get("label_classes") or [])]
        entries = list(payload.get("models") or [])
        if not label_classes or not entries:
            return np.array([], dtype=object), np.array([], dtype=float), np.zeros((0, 0), dtype=float)

        combined = np.zeros((len(X), len(label_classes)), dtype=float)
        total_weight = 0.0
        for entry in entries:
            model = entry.get("model")
            if model is None:
                continue

            weight = max(0.001, float(entry.get("weight") or 0.0))
            _, _, probabilities = predict_with_model(model, X, label_classes)
            combined += weight * probabilities
            total_weight += weight

        if total_weight <= 0:
            return np.array([], dtype=object), np.array([], dtype=float), np.zeros((0, len(label_classes)), dtype=float)

        combined /= total_weight
        labels = np.asarray(label_classes, dtype=object)[np.argmax(combined, axis=1)]
        scores = combined.max(axis=1)
        return labels, scores, combined

    model = payload.get("model") if isinstance(payload, dict) else payload
    label_classes = _ensure_label_classes(
        payload.get("label_classes") if isinstance(payload, dict) else None,
        getattr(model, "classes_", None) if model is not None else None,
    )
    if model is None:
        return np.array([], dtype=object), np.array([], dtype=float), np.zeros((0, len(label_classes)), dtype=float)
    return predict_with_model(model, X, label_classes)


def _summary_metrics(y_true: Any, y_pred: np.ndarray) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }


def build_ensemble_payload(
    X_train: Any,
    y_train: Any,
    X_test: Any,
    y_test: Any,
    feature_columns: list[str],
    random_state: int = 42,
) -> tuple[dict[str, Any], dict[str, Any]]:
    label_classes = sorted(np.asarray(y_train, dtype=object).tolist() + np.asarray(y_test, dtype=object).tolist())
    label_classes = sorted({str(item) for item in label_classes})

    sample_weight = compute_sample_weight(class_weight="balanced", y=np.asarray(y_train, dtype=object))
    candidate_specs = build_candidate_specs(label_count=len(label_classes), random_state=random_state)

    trained_entries: list[dict[str, Any]] = []
    candidate_metrics: dict[str, Any] = {}

    for spec in candidate_specs:
        fit_kwargs: dict[str, Any] = {}
        if spec.use_sample_weight:
            fit_kwargs["sample_weight"] = sample_weight

        model = spec.estimator
        model.fit(X_train, y_train, **fit_kwargs)

        predictions, scores, _ = predict_with_model(model, X_test, label_classes)
        metrics = _summary_metrics(y_test, predictions)
        metrics["avg_prediction_score"] = float(np.mean(scores)) if len(scores) else 0.0
        candidate_metrics[spec.name] = metrics

        trained_entries.append(
            {
                "name": spec.name,
                "model": model,
                "weight": max(0.05, float(metrics["f1_weighted"])),
            }
        )

    weight_total = float(sum(float(entry["weight"]) for entry in trained_entries))
    if weight_total <= 0:
        raise ValueError("No supervised ensemble members were trained.")

    for entry in trained_entries:
        entry["weight"] = float(entry["weight"]) / weight_total

    payload: dict[str, Any] = {
        "model_type": "supervised_ensemble",
        "ensemble_method": "weighted_probability",
        "feature_columns": list(feature_columns),
        "label_classes": label_classes,
        "models": trained_entries,
    }

    ensemble_pred, ensemble_scores, _ = predict_from_payload(payload, X_test)
    ensemble_metrics = _summary_metrics(y_test, ensemble_pred)
    ensemble_metrics["avg_prediction_score"] = float(np.mean(ensemble_scores)) if len(ensemble_scores) else 0.0

    summary = {
        "algorithms": [str(entry["name"]) for entry in trained_entries],
        "weights": {str(entry["name"]): float(entry["weight"]) for entry in trained_entries},
        "candidate_metrics": candidate_metrics,
        "ensemble_metrics": ensemble_metrics,
    }
    return payload, summary
