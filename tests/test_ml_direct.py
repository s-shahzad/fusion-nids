from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from src.NIDS.ml import evaluate as evaluate_module
from src.NIDS.ml import train as train_module
from src.NIDS.ml.dataset_loader import TRAINING_COLUMNS, load_labeled_flows
from src.NIDS.ml.feature_builder import build_training_frame
from src.NIDS.ml.featureset import FEATURE_COLUMNS, build_feature_vector
from src.NIDS.storage.sqlite_store import SQLiteStore


def _iso(offset_minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat(timespec="seconds")


def _seed_labeled_flows(db_path: Path, sample_count: int = 12) -> None:
    store = SQLiteStore(db_path)
    try:
        for index in range(sample_count):
            is_attack = index % 2 == 0
            store.insert_flow(
                {
                    "timestamp": _iso(-index),
                    "sensor_id": "sensor-ml",
                    "dataset_source": "pcap:ml-test",
                    "src_ip": f"10.0.0.{index + 1}",
                    "dst_ip": "8.8.8.8",
                    "src_port": 40000 + index,
                    "dst_port": 80 if is_attack else 443,
                    "proto": "TCP" if index % 3 else "UDP",
                    "packet_len": 100 + index,
                    "packet_rate_dst": 5 + index,
                    "unique_dst_ports_src_window": 2 + (index % 4),
                    "unique_dst_hosts_src_window": 1 + (index % 3),
                    "tcp_flags": "SA" if is_attack else "A",
                    "anomaly_score": 0.85 if is_attack else 0.12,
                    "label": "attack" if is_attack else "normal",
                    "attack_type": "scan" if is_attack else None,
                    "is_labeled": 1,
                }
            )
    finally:
        store.close()


def test_load_labeled_flows_returns_empty_for_missing_db(tmp_path: Path) -> None:
    frame = load_labeled_flows(tmp_path / "missing.db")
    assert frame.empty


def test_load_labeled_flows_returns_training_columns_when_flows_table_missing(tmp_path: Path) -> None:
    db_path = tmp_path / "empty.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE alerts(id INTEGER PRIMARY KEY)")
        conn.commit()

    frame = load_labeled_flows(db_path)
    assert frame.empty
    assert list(frame.columns) == TRAINING_COLUMNS


def test_load_labeled_flows_handles_schema_drift_and_filters_unlabeled_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "drift.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE flows(timestamp TEXT, src_ip TEXT, label TEXT)")
        conn.executemany(
            "INSERT INTO flows(timestamp, src_ip, label) VALUES (?, ?, ?)",
            [
                (_iso(-2), "10.0.0.1", "attack"),
                (_iso(-1), "10.0.0.2", ""),
            ],
        )
        conn.commit()

    frame = load_labeled_flows(db_path)

    assert list(frame.columns) == TRAINING_COLUMNS
    assert len(frame) == 1
    assert frame.iloc[0]["src_ip"] == "10.0.0.1"
    assert pd.isna(frame.iloc[0]["dst_port"])
    assert pd.isna(frame.iloc[0]["is_labeled"])


def test_build_training_frame_handles_empty_input() -> None:
    X, y, columns = build_training_frame(pd.DataFrame())

    assert X.empty
    assert y.empty
    assert columns == FEATURE_COLUMNS


def test_build_training_frame_coerces_malformed_values_and_missing_columns() -> None:
    frame = pd.DataFrame(
        [
            {
                "packet_len": "bad",
                "src_port": "12345",
                "dst_port": None,
                "proto": "udp",
                "tcp_flags": "SA",
                "packet_rate_dst": "4.5",
                "unique_dst_ports_src_window": "7",
                "label": "attack",
            }
        ]
    )

    X, y, columns = build_training_frame(frame)

    assert columns == FEATURE_COLUMNS
    assert float(X.iloc[0]["packet_len"]) == 0.0
    assert float(X.iloc[0]["payload_len"]) == 0.0
    assert float(X.iloc[0]["src_port"]) == 12345.0
    assert float(X.iloc[0]["dst_port"]) == 0.0
    assert float(X.iloc[0]["is_udp"]) == 1.0
    assert float(X.iloc[0]["tcp_syn"]) == 1.0
    assert float(X.iloc[0]["tcp_ack"]) == 1.0
    assert float(X.iloc[0]["unique_dst_hosts_src_window"]) == 0.0
    assert float(X.iloc[0]["has_dns_qname"]) == 0.0
    assert y.iloc[0] == "attack"


def test_build_feature_vector_uses_selected_columns_and_coerces_values() -> None:
    event = {"packet_len": "128", "src_port": "5000", "noise": "ignored"}
    features = {"packet_rate_dst": "7.5", "broken": object()}

    vector = build_feature_vector(
        event,
        features,
        columns=["packet_len", "packet_rate_dst", "broken", "missing"],
    )

    assert vector == [128.0, 7.5, 0.0, 0.0]


def test_train_from_db_writes_model_and_metrics(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_labeled_flows(db_path)

    out_model = tmp_path / "models" / "model.pkl"
    metrics_json = tmp_path / "reports" / "ml_metrics.json"
    metrics_md = tmp_path / "reports" / "ml_metrics.md"

    def fake_build_ensemble_payload(*, X_train, y_train, X_test, y_test, feature_columns, random_state):
        assert not X_train.empty
        assert len(y_train) > 0
        return (
            {
                "model_type": "supervised_ensemble",
                "feature_columns": list(feature_columns),
                "label_classes": ["attack", "normal"],
                "models": [{"name": "dummy_model", "weight": 1.0}],
            },
            {
                "weights": {"dummy_model": 1.0},
                "candidate_metrics": {"dummy_model": {"accuracy": 0.9, "f1_weighted": 0.88}},
            },
        )

    def fake_predict_from_payload(payload, X):
        labels = np.array(["attack" if idx % 2 == 0 else "normal" for idx in range(len(X))], dtype=object)
        scores = np.full(len(X), 0.82, dtype=float)
        probabilities = np.column_stack([scores, 1.0 - scores])
        return labels, scores, probabilities

    monkeypatch.setattr(train_module, "build_ensemble_payload", fake_build_ensemble_payload)
    monkeypatch.setattr(train_module, "predict_from_payload", fake_predict_from_payload)

    metrics = train_module.train_from_db(
        db_path=db_path,
        out_model=out_model,
        metrics_json=metrics_json,
        metrics_md=metrics_md,
        random_state=7,
    )

    assert out_model.exists()
    assert metrics_json.exists()
    assert metrics_md.exists()
    assert metrics["samples_total"] == 12
    assert metrics["algorithms"] == ["dummy_model"]
    assert metrics["feature_columns"] == FEATURE_COLUMNS

    saved_payload = joblib.load(out_model)
    assert saved_payload["model_type"] == "supervised_ensemble"
    assert saved_payload["created_at"] == metrics["generated_at"]

    saved_metrics = json.loads(metrics_json.read_text(encoding="utf-8"))
    assert saved_metrics["samples_total"] == 12
    assert "dummy_model" in metrics_md.read_text(encoding="utf-8")


def test_train_from_db_rejects_empty_dataset(tmp_path: Path) -> None:
    db_path = tmp_path / "empty.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE flows(timestamp TEXT, label TEXT)")
        conn.commit()

    with pytest.raises(ValueError, match="No labeled flows available"):
        train_module.train_from_db(db_path=db_path, out_model=tmp_path / "model.pkl")


def test_evaluate_model_writes_metrics(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_labeled_flows(db_path, sample_count=10)

    payload = {
        "model_type": "supervised_ensemble",
        "feature_columns": FEATURE_COLUMNS[:6],
        "label_classes": ["attack", "normal"],
        "models": [{"name": "dummy_model", "weight": 1.0}],
    }
    model_path = tmp_path / "models" / "model.pkl"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, model_path)

    def fake_predict_from_payload(saved_payload, X):
        assert list(X.columns) == FEATURE_COLUMNS[:6]
        labels = np.array(["attack" if idx % 2 == 0 else "normal" for idx in range(len(X))], dtype=object)
        scores = np.full(len(X), 0.76, dtype=float)
        probabilities = np.column_stack([scores, 1.0 - scores])
        return labels, scores, probabilities

    monkeypatch.setattr(evaluate_module, "predict_from_payload", fake_predict_from_payload)

    out_json = tmp_path / "reports" / "evaluation.json"
    metrics = evaluate_module.evaluate_model(db_path=db_path, model_path=model_path, output_json=out_json)

    assert out_json.exists()
    assert metrics["samples"] == 10
    assert metrics["algorithms"] == ["dummy_model"]
    assert json.loads(out_json.read_text(encoding="utf-8"))["samples"] == 10


def test_evaluate_model_rejects_empty_dataset(tmp_path: Path) -> None:
    db_path = tmp_path / "empty.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE flows(timestamp TEXT, label TEXT)")
        conn.commit()

    model_path = tmp_path / "models" / "model.pkl"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model_type": "supervised_ensemble", "models": []}, model_path)

    with pytest.raises(ValueError, match="No labeled flows available for evaluation"):
        evaluate_module.evaluate_model(db_path=db_path, model_path=model_path)
