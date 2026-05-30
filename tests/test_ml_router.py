from __future__ import annotations

from pathlib import Path

from src.NIDS.detect import ml as ml_module


class _DummySupervisedEngine:
    def __init__(self, model_path: str | Path, score_threshold: float = 0.6) -> None:
        self.available = True
        self.calls: list[tuple[dict[str, object], dict[str, object]]] = []

    def detect(self, event: dict[str, object], features: dict[str, object]) -> tuple[list[dict[str, object]], dict[str, object]]:
        self.calls.append((dict(event), dict(features)))
        score = 0.91 + (len(self.calls) * 0.01)
        return [], {
            "predicted_label": "attack",
            "predicted_attack_type": "dummy_attack",
            "prediction_score": score,
            "supervised_label": "attack",
            "supervised_attack_type": "dummy_attack",
            "supervised_score": score,
            "supervised_algorithms": ["dummy_supervised"],
            "supervised_model_count": 1,
        }


class _DummyUnsupervisedEngine:
    def __init__(self, **_: object) -> None:
        self.calls: list[tuple[dict[str, object], dict[str, object]]] = []

    def detect(self, event: dict[str, object], features: dict[str, object]) -> tuple[list[dict[str, object]], dict[str, object]]:
        self.calls.append((dict(event), dict(features)))
        return [], {
            "unsupervised_label": "benign",
            "unsupervised_score": 0.0,
            "unsupervised_components": {},
            "unsupervised_active_components": [],
            "unsupervised_algorithms": ["dummy_unsupervised"],
            "unsupervised_model_count": 1,
            "unsupervised_baseline_path": None,
        }

    def save_snapshot(self) -> None:
        return None


def test_live_router_throttles_and_reuses_cached_prediction(monkeypatch, tmp_path: Path) -> None:
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"dummy")

    monkeypatch.setattr(ml_module, "SupervisedMLEngine", _DummySupervisedEngine)
    monkeypatch.setattr(ml_module, "UnsupervisedMLEngine", _DummyUnsupervisedEngine)

    router = ml_module.MLEngineRouter(
        {
            "model_path": str(model_path),
            "score_threshold": 0.5,
            "unsupervised": True,
            "live_throttle_enabled": True,
            "live_min_inference_interval_sec": 1.0,
        }
    )

    event = {
        "dataset_source": "live",
        "timestamp": "2026-03-10T20:00:00+00:00",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 50000,
        "dst_port": 80,
        "proto": "TCP",
    }
    features = {"packet_rate_dst": 1.0}

    alerts1, prediction1 = router.detect(event, features)
    assert alerts1 == []
    assert prediction1["supervised_score"] == 0.92
    assert isinstance(router.supervised, _DummySupervisedEngine)
    assert isinstance(router.unsupervised, _DummyUnsupervisedEngine)
    assert len(router.supervised.calls) == 1
    assert len(router.unsupervised.calls) == 1

    alerts2, prediction2 = router.detect(
        {**event, "timestamp": "2026-03-10T20:00:00.500000+00:00"},
        features,
    )
    assert alerts2 == []
    assert prediction2["supervised_score"] == prediction1["supervised_score"]
    assert len(router.supervised.calls) == 1
    assert len(router.unsupervised.calls) == 1

    alerts3, prediction3 = router.detect(
        {**event, "timestamp": "2026-03-10T20:00:00.700000+00:00"},
        features,
        force=True,
    )
    assert alerts3 == []
    assert prediction3["supervised_score"] == 0.93
    assert len(router.supervised.calls) == 2
    assert len(router.unsupervised.calls) == 2


def test_live_router_does_not_reuse_cached_prediction_across_ports(monkeypatch, tmp_path: Path) -> None:
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"dummy")

    monkeypatch.setattr(ml_module, "SupervisedMLEngine", _DummySupervisedEngine)
    monkeypatch.setattr(ml_module, "UnsupervisedMLEngine", _DummyUnsupervisedEngine)

    router = ml_module.MLEngineRouter(
        {
            "model_path": str(model_path),
            "score_threshold": 0.5,
            "unsupervised": True,
            "live_throttle_enabled": True,
            "live_min_inference_interval_sec": 1.0,
        }
    )

    base_event = {
        "dataset_source": "live",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 50000,
        "proto": "TCP",
    }

    router.detect({**base_event, "timestamp": "2026-03-10T20:00:00+00:00", "dst_port": 80}, {})
    alerts2, prediction2 = router.detect(
        {**base_event, "timestamp": "2026-03-10T20:00:00.500000+00:00", "dst_port": 22},
        {},
    )

    assert alerts2 == []
    assert prediction2["supervised_score"] == 0.93
    assert isinstance(router.supervised, _DummySupervisedEngine)
    assert isinstance(router.unsupervised, _DummyUnsupervisedEngine)
    assert len(router.supervised.calls) == 2
    assert len(router.unsupervised.calls) == 2


def test_offline_router_does_not_throttle(monkeypatch, tmp_path: Path) -> None:
    model_path = tmp_path / "model.pkl"
    model_path.write_bytes(b"dummy")

    monkeypatch.setattr(ml_module, "SupervisedMLEngine", _DummySupervisedEngine)
    monkeypatch.setattr(ml_module, "UnsupervisedMLEngine", _DummyUnsupervisedEngine)

    router = ml_module.MLEngineRouter(
        {
            "model_path": str(model_path),
            "score_threshold": 0.5,
            "unsupervised": True,
            "live_throttle_enabled": True,
            "live_min_inference_interval_sec": 10.0,
        }
    )

    base_event = {
        "dataset_source": "pcap:test.pcap",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 50000,
        "dst_port": 443,
        "proto": "TCP",
    }

    router.detect({**base_event, "timestamp": "2026-03-10T20:00:00+00:00"}, {})
    router.detect({**base_event, "timestamp": "2026-03-10T20:00:00.010000+00:00"}, {})

    assert isinstance(router.supervised, _DummySupervisedEngine)
    assert isinstance(router.unsupervised, _DummyUnsupervisedEngine)
    assert len(router.supervised.calls) == 2
    assert len(router.unsupervised.calls) == 2
