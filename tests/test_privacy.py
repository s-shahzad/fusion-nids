from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.fernet import Fernet

from src.NIDS.privacy import (
    apply_privacy_to_alert,
    privacy_config_from_mapping,
    write_encrypted_json,
)


def test_ip_masking_and_payload_redaction() -> None:
    config = privacy_config_from_mapping({"mode": "strict", "redact_ip_addresses": True, "redact_payloads": True})
    payload = {
        "src_ip": "10.1.2.3",
        "dst_ip": "192.168.1.44",
        "summary": "payload contains internal token and 10.0.0.1",
    }
    redacted = apply_privacy_to_alert(payload, config)
    assert redacted["src_ip"] == "10.1.2.x"
    assert redacted["dst_ip"] == "192.168.1.x"
    assert redacted["summary"] == "[redacted-payload]"


def test_privacy_mode_off_keeps_payload() -> None:
    config = privacy_config_from_mapping({"mode": "off"})
    payload = {"src_ip": "10.1.2.3", "summary": "keep me"}
    assert apply_privacy_to_alert(payload, config) == payload


def test_encrypted_artifact_write_and_read(tmp_path: Path, monkeypatch) -> None:
    raw_key = "unit-test-key"
    derived = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode("utf-8")).digest()).decode("utf-8")
    monkeypatch.setenv("NIDS_PRIVACY_KEY", raw_key)
    config = privacy_config_from_mapping({"mode": "review", "encrypt_exports": True})
    target = tmp_path / "bundle.json"
    target.write_text("{}", encoding="utf-8")
    encrypted_path = write_encrypted_json(target, {"status": "ok"}, config)
    assert encrypted_path is not None
    decrypted = Fernet(derived.encode("utf-8")).decrypt(encrypted_path.read_bytes())
    assert json.loads(decrypted.decode("utf-8"))["status"] == "ok"
