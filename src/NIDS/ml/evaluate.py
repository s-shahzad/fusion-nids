from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

from .dataset_loader import load_labeled_flows
from .feature_builder import build_training_frame
from .supervised_ensemble import payload_algorithm_names, predict_from_payload


def evaluate_model(
    db_path: str | Path,
    model_path: str | Path,
    output_json: str | Path = "reports/ml_evaluation.json",
) -> dict[str, Any]:
    """Evaluate an existing supervised model against labeled flow rows."""
    payload = joblib.load(model_path)
    feature_columns = payload.get("feature_columns") if isinstance(payload, dict) else None

    frame = load_labeled_flows(db_path)
    if frame.empty:
        raise ValueError("No labeled flows available for evaluation.")

    X, y, default_columns = build_training_frame(frame)
    selected_columns = feature_columns or default_columns
    X = X[selected_columns]

    y_pred, scores, _ = predict_from_payload(payload, X)
    labels = sorted(list(set(y) | set(y_pred)))
    conf = confusion_matrix(y, y_pred, labels=labels)

    metrics: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "samples": int(len(X)),
        "labels": labels,
        "algorithms": payload_algorithm_names(payload),
        "accuracy": float(accuracy_score(y, y_pred)),
        "precision_weighted": float(precision_score(y, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y, y_pred, average="weighted", zero_division=0)),
        "avg_prediction_score": float(scores.mean()) if len(scores) else 0.0,
        "classification_report": classification_report(y, y_pred, output_dict=True, zero_division=0),
        "confusion_matrix": conf.astype(int).tolist(),
    }

    out = Path(output_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics
