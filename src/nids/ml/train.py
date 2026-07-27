from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from .dataset_loader import load_labeled_flows
from .feature_builder import build_training_frame
from .supervised_ensemble import build_ensemble_payload, payload_algorithm_names, predict_from_payload


def _write_metrics_md(metrics: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    ensemble = metrics.get("ensemble", {}) or {}
    weights = ensemble.get("weights", {}) or {}
    candidate_metrics = ensemble.get("candidate_metrics", {}) or {}

    lines: list[str] = []
    lines.append("# ML Training Metrics")
    lines.append("")
    lines.append(f"Generated: {metrics.get('generated_at', '')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- accuracy: {metrics.get('accuracy', 0):.4f}")
    lines.append(f"- precision_weighted: {metrics.get('precision_weighted', 0):.4f}")
    lines.append(f"- recall_weighted: {metrics.get('recall_weighted', 0):.4f}")
    lines.append(f"- f1_weighted: {metrics.get('f1_weighted', 0):.4f}")
    lines.append(f"- avg_prediction_score: {metrics.get('avg_prediction_score', 0):.4f}")
    lines.append("")

    lines.append("## Ensemble Algorithms")
    lines.append("")
    for algorithm in metrics.get("algorithms", []):
        weight = float(weights.get(algorithm, 0.0))
        member_metrics = candidate_metrics.get(algorithm, {}) or {}
        lines.append(
            "- "
            + f"{algorithm}: weight={weight:.4f}, "
            + f"accuracy={float(member_metrics.get('accuracy', 0.0)):.4f}, "
            + f"f1_weighted={float(member_metrics.get('f1_weighted', 0.0)):.4f}"
        )
    lines.append("")

    lines.append("## Labels")
    lines.append("")
    for label in metrics.get("labels", []):
        lines.append(f"- {label}")
    lines.append("")

    lines.append("## Confusion Matrix")
    lines.append("")
    matrix = metrics.get("confusion_matrix", [])
    for row in matrix:
        lines.append("- " + ", ".join(str(item) for item in row))
    lines.append("")

    output.write_text("\n".join(lines), encoding="utf-8")


def train_from_db(
    db_path: str | Path,
    out_model: str | Path,
    metrics_json: str | Path = "reports/ml_metrics.json",
    metrics_md: str | Path = "reports/ml_metrics.md",
    test_size: float = 0.25,
    random_state: int = 42,
) -> dict[str, Any]:
    """Train a supervised ensemble classifier from labeled flows in SQLite."""
    rows = load_labeled_flows(db_path)
    if rows.empty:
        raise ValueError("No labeled flows available in database.")

    X, y, feature_columns = build_training_frame(rows)
    if X.empty or len(y) < 10:
        raise ValueError("Not enough labeled samples to train model (need at least 10).")

    label_counts = y.value_counts()
    stratify = y if len(label_counts) > 1 and int(label_counts.min()) >= 2 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    model_payload, ensemble_summary = build_ensemble_payload(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        feature_columns=feature_columns,
        random_state=random_state,
    )
    y_pred, scores, _ = predict_from_payload(model_payload, X_test)

    labels = sorted(y.astype(str).unique().tolist())
    conf = confusion_matrix(y_test, y_pred, labels=labels)

    metrics: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "samples_total": int(len(X)),
        "samples_train": int(len(X_train)),
        "samples_test": int(len(X_test)),
        "labels": labels,
        "algorithms": payload_algorithm_names(model_payload),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_weighted": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "avg_prediction_score": float(np.mean(scores)) if len(scores) else 0.0,
        "classification_report": classification_report(y_test, y_pred, output_dict=True, zero_division=0),
        "confusion_matrix": conf.astype(int).tolist(),
        "feature_columns": feature_columns,
        "ensemble": ensemble_summary,
    }

    model_payload["created_at"] = metrics["generated_at"]

    model_path = Path(out_model)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_payload, model_path)

    metrics_json_path = Path(metrics_json)
    metrics_json_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_json_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    _write_metrics_md(metrics, Path(metrics_md))
    return metrics
