from __future__ import annotations

import joblib

from src.NIDS.detect.ml_supervised import SupervisedMLEngine


class _PermissionSensitiveModel:
    classes_ = ["attack", "normal"]

    def __init__(self) -> None:
        self.n_jobs = -1

    def get_params(self, deep: bool = False):  # noqa: ARG002
        return {"n_jobs": self.n_jobs}

    def set_params(self, **params):
        if "n_jobs" in params:
            self.n_jobs = int(params["n_jobs"])
        return self

    def predict(self, X):  # noqa: ANN001
        if self.n_jobs != 1:
            raise PermissionError("parallel inference is not allowed in this environment")
        return ["attack"] * len(X)

    def predict_proba(self, X):  # noqa: ANN001
        if self.n_jobs != 1:
            raise PermissionError("parallel inference is not allowed in this environment")
        return [[0.9, 0.1] for _ in range(len(X))]


def test_supervised_runtime_forces_single_worker_inference(tmp_path) -> None:
    model_path = tmp_path / "ensemble.pkl"
    payload = {
        "model_type": "supervised_ensemble",
        "feature_columns": ["packet_len"],
        "label_classes": ["attack", "normal"],
        "models": [{"name": "permission_sensitive", "weight": 1.0, "model": _PermissionSensitiveModel()}],
    }
    joblib.dump(payload, model_path)

    engine = SupervisedMLEngine(model_path=model_path, score_threshold=0.5)
    alerts, prediction = engine.detect(
        event={"packet_len": 128, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "TCP"},
        features={},
    )

    assert prediction["supervised_label"] == "attack"
    assert prediction["supervised_score"] == 0.9
    assert alerts[0]["engine"] == "ml"
