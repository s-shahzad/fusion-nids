"""Integrity verification around every joblib.load site.

``joblib.load`` unpickles, and unpickling executes arbitrary code, so each load
site is a code-execution sink if an attacker can swap the artefact. These tests
pin the behaviour at all three: the supervised engine, the unsupervised snapshot
loader, and the offline evaluator. See issue #13.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import joblib
import pytest

from src.nids.detect.ml_unsupervised import UnsupervisedMLEngine
from src.nids.ml import evaluate as evaluate_module
from src.nids.ml.integrity import (
    SUPERVISED_MODEL_SHA256_ENV,
    UNSUPERVISED_SNAPSHOT_SHA256_ENV,
    expected_digest_for,
    verify_artifact_integrity,
)

ENV_VAR = "NIDS_TEST_ARTEFACT_SHA256"


def _artefact(tmp_path: Path, content: bytes = b"trusted-payload") -> Path:
    path = tmp_path / "model.joblib"
    path.write_bytes(content)
    return path


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify(path: Path) -> bool:
    return verify_artifact_integrity(path, env_var=ENV_VAR, label="test artefact")


# --------------------------------------------------------------------------
# Core policy
# --------------------------------------------------------------------------


def test_allows_load_when_no_digest_configured(tmp_path, monkeypatch, caplog):
    """No configured digest still loads, but must say so rather than stay quiet."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    path = _artefact(tmp_path)

    with caplog.at_level("WARNING"):
        assert _verify(path) is True

    assert "WITHOUT integrity verification" in caplog.text


def test_matching_sidecar_digest_allows_load(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    path = _artefact(tmp_path)
    path.with_name(path.name + ".sha256").write_text(_digest(path), encoding="utf-8")

    assert _verify(path) is True


def test_mismatched_sidecar_digest_refuses_load(tmp_path, monkeypatch):
    """The whole point: a swapped artefact must be refused."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    path = _artefact(tmp_path)
    path.with_name(path.name + ".sha256").write_text("00" * 32, encoding="utf-8")

    assert _verify(path) is False


def test_sidecar_accepts_sha256sum_output_format(tmp_path, monkeypatch):
    """`sha256sum file > file.sha256` writes '<hex>  <name>'; only the hex matters."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    path = _artefact(tmp_path)
    path.with_name(path.name + ".sha256").write_text(
        f"{_digest(path)}  {path.name}\n", encoding="utf-8"
    )

    assert _verify(path) is True


def test_env_var_wins_over_sidecar(tmp_path, monkeypatch):
    path = _artefact(tmp_path)
    path.with_name(path.name + ".sha256").write_text(_digest(path), encoding="utf-8")
    monkeypatch.setenv(ENV_VAR, "11" * 32)

    assert expected_digest_for(path, ENV_VAR) == "11" * 32
    assert _verify(path) is False


def test_digest_comparison_is_case_insensitive(tmp_path, monkeypatch):
    path = _artefact(tmp_path)
    monkeypatch.setenv(ENV_VAR, _digest(path).upper())

    assert _verify(path) is True


def test_unreadable_artefact_refuses_when_digest_configured(tmp_path, monkeypatch):
    """Verification was requested and cannot be performed: fail closed, not open."""
    missing = tmp_path / "absent.joblib"
    monkeypatch.setenv(ENV_VAR, "22" * 32)

    assert verify_artifact_integrity(missing, env_var=ENV_VAR, label="test artefact") is False


# --------------------------------------------------------------------------
# Call site: unsupervised snapshot loader
# --------------------------------------------------------------------------


def _write_snapshot(path: Path) -> None:
    joblib.dump({"snapshot_version": 1, "buffer": [[1.0, 2.0]]}, path)


def test_unsupervised_snapshot_rejected_on_digest_mismatch(tmp_path, monkeypatch):
    snapshot = tmp_path / "unsup.joblib"
    _write_snapshot(snapshot)
    snapshot.with_name(snapshot.name + ".sha256").write_text("33" * 32, encoding="utf-8")
    monkeypatch.delenv(UNSUPERVISED_SNAPSHOT_SHA256_ENV, raising=False)

    engine = UnsupervisedMLEngine(snapshot_path=snapshot)

    # Refused before unpickling, so nothing from the snapshot is adopted.
    assert engine.buffer == []
    assert engine.isolation_model is None


def test_unsupervised_snapshot_load_is_attempted_when_digest_matches(tmp_path, monkeypatch):
    snapshot = tmp_path / "unsup.joblib"
    _write_snapshot(snapshot)
    snapshot.with_name(snapshot.name + ".sha256").write_text(
        _digest(snapshot), encoding="utf-8"
    )
    monkeypatch.delenv(UNSUPERVISED_SNAPSHOT_SHA256_ENV, raising=False)

    seen: list[Path] = []
    real_load = joblib.load

    def _spy(path, *args, **kwargs):
        seen.append(Path(path))
        return real_load(path, *args, **kwargs)

    monkeypatch.setattr("src.nids.detect.ml_unsupervised.joblib.load", _spy)
    UnsupervisedMLEngine(snapshot_path=snapshot)

    assert seen == [snapshot]


def test_corrupt_snapshot_is_logged_not_swallowed(tmp_path, monkeypatch, caplog):
    """A tampered snapshot must not be indistinguishable from a cold start (#14)."""
    snapshot = tmp_path / "unsup.joblib"
    snapshot.write_bytes(b"not a joblib payload at all")
    snapshot.with_name(snapshot.name + ".sha256").write_text(
        _digest(snapshot), encoding="utf-8"
    )
    monkeypatch.delenv(UNSUPERVISED_SNAPSHOT_SHA256_ENV, raising=False)

    with caplog.at_level("WARNING"):
        engine = UnsupervisedMLEngine(snapshot_path=snapshot)

    assert engine.buffer == []
    assert "Could not load unsupervised snapshot" in caplog.text


# --------------------------------------------------------------------------
# Call site: offline evaluator
# --------------------------------------------------------------------------


def test_evaluate_model_raises_on_digest_mismatch(tmp_path, monkeypatch):
    """Evaluation must refuse loudly: silent skip would report metrics for the wrong model."""
    model = tmp_path / "model.joblib"
    joblib.dump({"feature_columns": ["a"]}, model)
    model.with_name(model.name + ".sha256").write_text("44" * 32, encoding="utf-8")
    monkeypatch.delenv(SUPERVISED_MODEL_SHA256_ENV, raising=False)

    with pytest.raises(ValueError, match="integrity"):
        evaluate_module.evaluate_model(
            db_path=tmp_path / "nids.db",
            model_path=model,
            output_json=tmp_path / "eval.json",
        )


# --------------------------------------------------------------------------
# SSH host-key policy
# --------------------------------------------------------------------------


def _load_validation_module():
    """Load scripts/live_vm_attack_validation.py by path.

    `scripts/` is not a package, so it cannot be imported by dotted name.
    paramiko is declared in requirements.txt but may be absent in a slim local
    environment, so skip rather than fail when it is missing.
    """
    pytest.importorskip("paramiko")
    import importlib.util

    script = Path(__file__).resolve().parents[1] / "scripts" / "live_vm_attack_validation.py"
    spec = importlib.util.spec_from_file_location("live_vm_attack_validation", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ssh_client_rejects_unknown_hosts(tmp_path, monkeypatch):
    """AutoAddPolicy trusts any key on first contact; validation runs cannot."""
    paramiko = pytest.importorskip("paramiko")
    module = _load_validation_module()

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")
    monkeypatch.setenv(module.LAB_KNOWN_HOSTS_ENV, str(known_hosts))

    client = paramiko.SSHClient()
    module._load_known_hosts(client)

    policy = client._policy
    assert isinstance(policy, paramiko.RejectPolicy)
    assert not isinstance(policy, paramiko.AutoAddPolicy)


def test_missing_known_hosts_override_fails_loudly(tmp_path, monkeypatch):
    paramiko = pytest.importorskip("paramiko")
    module = _load_validation_module()
    monkeypatch.setenv(module.LAB_KNOWN_HOSTS_ENV, str(tmp_path / "nope"))

    with pytest.raises(FileNotFoundError, match="does not exist"):
        module._load_known_hosts(paramiko.SSHClient())
