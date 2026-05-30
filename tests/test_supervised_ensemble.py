from __future__ import annotations

import warnings

import joblib
import pandas as pd
from sklearn.datasets import make_classification

from src.NIDS.detect.ml_supervised import SupervisedMLEngine
from src.NIDS.ml.supervised_ensemble import (
    build_ensemble_payload,
    payload_algorithm_names,
    payload_model_count,
    predict_from_payload,
)


def test_build_ensemble_payload_trains_multiple_supervised_models() -> None:
    X, y = make_classification(
        n_samples=72,
        n_features=6,
        n_informative=5,
        n_redundant=0,
        n_classes=3,
        n_clusters_per_class=1,
        class_sep=1.4,
        random_state=42,
    )
    feature_columns = [f"f{i}" for i in range(X.shape[1])]
    frame = pd.DataFrame(X, columns=feature_columns)
    labels = pd.Series([f"class_{value}" for value in y])

    X_train = frame.iloc[:54]
    X_test = frame.iloc[54:]
    y_train = labels.iloc[:54]
    y_test = labels.iloc[54:]

    payload, summary = build_ensemble_payload(
        X_train=X_train,
        y_train=y_train,
        X_test=X_test,
        y_test=y_test,
        feature_columns=feature_columns,
        random_state=42,
    )

    assert payload["model_type"] == "supervised_ensemble"
    assert payload_model_count(payload) >= 3

    algorithm_names = payload_algorithm_names(payload)
    assert "random_forest" in algorithm_names
    assert "extra_trees" in algorithm_names
    assert "hist_gradient_boosting" in algorithm_names

    predictions, scores, probabilities = predict_from_payload(payload, X_test)
    assert len(predictions) == len(X_test)
    assert len(scores) == len(X_test)
    assert probabilities.shape == (len(X_test), len(payload["label_classes"]))
    assert abs(sum(summary["weights"].values()) - 1.0) < 1e-9
    assert 0.0 <= summary["ensemble_metrics"]["accuracy"] <= 1.0


def test_supervised_runtime_uses_feature_names_without_sklearn_warnings(tmp_path) -> None:
    X, y = make_classification(
        n_samples=96,
        n_features=6,
        n_informative=5,
        n_redundant=0,
        n_classes=3,
        n_clusters_per_class=1,
        class_sep=1.35,
        random_state=7,
    )
    feature_columns = [f"f{i}" for i in range(X.shape[1])]
    frame = pd.DataFrame(X, columns=feature_columns)
    labels = pd.Series([f"class_{value}" for value in y])

    payload, _ = build_ensemble_payload(
        X_train=frame.iloc[:72],
        y_train=labels.iloc[:72],
        X_test=frame.iloc[72:],
        y_test=labels.iloc[72:],
        feature_columns=feature_columns,
        random_state=7,
    )

    model_path = tmp_path / "ensemble.pkl"
    joblib.dump(payload, model_path)
    engine = SupervisedMLEngine(model_path=model_path)

    event = {name: float(frame.iloc[0][name]) for name in feature_columns}
    event.update({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "TCP"})

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        alerts, prediction = engine.detect(event=event, features={})

    feature_name_warnings = [
        str(item.message)
        for item in caught
        if "feature names" in str(item.message).lower()
    ]

    assert feature_name_warnings == []
    assert isinstance(alerts, list)
    assert prediction["supervised_label"]
    assert prediction["supervised_score"] >= 0.0
