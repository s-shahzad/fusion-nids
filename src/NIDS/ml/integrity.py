"""Integrity verification for on-disk model artefacts.

``joblib.load`` unpickles, and unpickling executes arbitrary code. Every place
that loads a model or snapshot from disk is therefore a code-execution sink if
an attacker can swap the file. This module holds the one implementation those
call sites share, so the guarantee cannot drift between them again.

Policy, deliberately chosen:

* An expected SHA-256 may come from an environment variable or from a sibling
  ``<artefact>.sha256`` file. The environment variable wins when both exist.
* A mismatch refuses the load. There is no override.
* No configured digest logs a warning and allows the load. That keeps existing
  deployments working, and an unverified load is at least visible in the log
  rather than silently trusted.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path

__all__ = [
    "verify_artifact_integrity",
    "expected_digest_for",
    "SUPERVISED_MODEL_SHA256_ENV",
    "UNSUPERVISED_SNAPSHOT_SHA256_ENV",
]

# Env-var names live here rather than at the call sites so the trainer, the
# runtime engines, and the offline evaluator cannot disagree about them.
SUPERVISED_MODEL_SHA256_ENV = "NIDS_SUPERVISED_MODEL_SHA256"
UNSUPERVISED_SNAPSHOT_SHA256_ENV = "NIDS_UNSUPERVISED_SNAPSHOT_SHA256"


def expected_digest_for(path: Path, env_var: str) -> str:
    """Return the configured SHA-256 for ``path``, or an empty string.

    Precedence is environment variable first, then a ``<name>.sha256`` sidecar.
    The sidecar may be bare hex or ``sha256sum`` output, so only the first
    whitespace-delimited field is read.
    """
    expected = (os.getenv(env_var) or "").strip().lower()
    if expected:
        return expected

    sidecar = path.with_name(path.name + ".sha256")
    if sidecar.exists():
        try:
            parts = sidecar.read_text(encoding="utf-8").strip().split()
        except OSError:
            return ""
        if parts:
            return parts[0].lower()
    return ""


def verify_artifact_integrity(
    path: Path,
    *,
    env_var: str,
    label: str,
    logger: logging.Logger | None = None,
) -> bool:
    """Check ``path`` against its configured SHA-256 before it is unpickled.

    Returns ``True`` when the artefact may be loaded: either the digest matched,
    or no digest was configured. Returns ``False`` only on an actual mismatch,
    or when the file cannot be read to hash it.

    ``label`` names the artefact kind in log messages, and ``env_var`` is the
    environment variable holding the expected digest, so callers stay
    distinguishable in the log.
    """
    log = logger or logging.getLogger(__name__)

    expected = expected_digest_for(path, env_var)
    if not expected:
        log.warning(
            "Loading %s %s WITHOUT integrity verification (set %s or add a <file>.sha256 sidecar).",
            label,
            path,
            env_var,
        )
        return True

    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        # Unreadable when a digest is configured is a failure, not a pass: the
        # caller asked for verification and we cannot provide it.
        log.error("Could not read %s %s to verify its SHA-256; refusing to load.", label, path)
        return False

    if not hmac.compare_digest(actual, expected):
        log.error("%s %s failed SHA-256 integrity check; refusing to load.", label.capitalize(), path)
        return False
    return True
