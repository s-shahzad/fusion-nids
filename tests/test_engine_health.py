"""Engine availability must be observable, not inferred from silence.

Issue #14: when a model fails to load or is refused by the integrity check, the
router silently falls back to no supervised engine. Zero supervised alerts then
looks identical to clean traffic. These tests pin the health surface that makes
the two distinguishable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import joblib

from src.NIDS.detect.ml import (
    SUPERVISED_LOAD_FAILED,
    SUPERVISED_MISSING,
    SUPERVISED_OK,
    MLEngineRouter,
    supervised_model_health,
)


def _good_model(tmp_path: Path) -> Path:
    """A payload the supervised engine will accept."""
    path = tmp_path / "model.pkl"
    joblib.dump({"feature_columns": ["a", "b"], "models": []}, path)
    return path


def _sidecar(path: Path, digest: str) -> None:
    path.with_name(path.name + ".sha256").write_text(digest, encoding="utf-8")


def _real_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# static health probe
# --------------------------------------------------------------------------


def test_missing_model_reports_missing(tmp_path):
    health = supervised_model_health(tmp_path / "nope.pkl")

    assert health["available"] is False
    assert health["reason"] == SUPERVISED_MISSING
    assert health["integrity_digest_configured"] is False


def test_integrity_refused_model_reports_load_failed(tmp_path, monkeypatch):
    """A refused model must surface as unavailable, not as a quiet absence."""
    monkeypatch.delenv("NIDS_SUPERVISED_MODEL_SHA256", raising=False)
    model = _good_model(tmp_path)
    _sidecar(model, "55" * 32)  # wrong on purpose

    health = supervised_model_health(model)

    assert health["available"] is False
    assert health["reason"] == SUPERVISED_LOAD_FAILED
    assert health["integrity_digest_configured"] is True


def test_valid_model_reports_ok(tmp_path, monkeypatch):
    monkeypatch.delenv("NIDS_SUPERVISED_MODEL_SHA256", raising=False)
    model = _good_model(tmp_path)
    _sidecar(model, _real_digest(model))

    health = supervised_model_health(model)

    assert health["available"] is True
    assert health["reason"] == SUPERVISED_OK


def test_health_probe_reports_digest_not_configured(tmp_path, monkeypatch):
    """Unverified loads are permitted but must be visible as unverified."""
    monkeypatch.delenv("NIDS_SUPERVISED_MODEL_SHA256", raising=False)
    model = _good_model(tmp_path)

    health = supervised_model_health(model)

    assert health["integrity_digest_configured"] is False


# --------------------------------------------------------------------------
# router health
# --------------------------------------------------------------------------


def test_router_health_distinguishes_missing_from_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("NIDS_SUPERVISED_MODEL_SHA256", raising=False)

    absent = MLEngineRouter({"model_path": str(tmp_path / "nope.pkl")})
    assert absent.health()["supervised"] == {
        "available": False,
        "reason": SUPERVISED_MISSING,
        "model_path": str(tmp_path / "nope.pkl"),
    }

    model = _good_model(tmp_path)
    _sidecar(model, "66" * 32)
    refused = MLEngineRouter({"model_path": str(model)})

    assert refused.supervised is None
    assert refused.health()["supervised"]["reason"] == SUPERVISED_LOAD_FAILED


def test_router_logs_error_when_configured_model_is_refused(tmp_path, monkeypatch, caplog):
    """Refusal must reach the log, not only the health dict."""
    monkeypatch.delenv("NIDS_SUPERVISED_MODEL_SHA256", raising=False)
    model = _good_model(tmp_path)
    _sidecar(model, "77" * 32)

    with caplog.at_level("ERROR"):
        MLEngineRouter({"model_path": str(model)})

    assert "supervised detection is DISABLED" in caplog.text


def test_router_health_reports_unsupervised_disabled_by_default(tmp_path):
    router = MLEngineRouter({"model_path": str(tmp_path / "nope.pkl")})

    assert router.health()["unsupervised"] == {"enabled": False, "available": False}
