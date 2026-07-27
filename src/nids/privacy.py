from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet


IPV4_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s`]+")


@dataclass(frozen=True)
class PrivacyConfig:
    mode: str = "review"
    redact_ip_addresses: bool = False
    redact_payloads: bool = False
    redact_user_identifiers: bool = False
    redact_hostnames: bool = False
    redact_file_paths: bool = False
    encrypt_exports: bool = False
    encryption_key_env: str = "NIDS_PRIVACY_KEY"

    @property
    def enabled(self) -> bool:
        return self.mode.lower() != "off"


def privacy_config_from_mapping(payload: dict[str, Any] | None) -> PrivacyConfig:
    source = dict(payload or {})
    mode = str(source.get("mode") or "review").strip().lower()
    if mode not in {"off", "review", "strict"}:
        mode = "review"
    return PrivacyConfig(
        mode=mode,
        redact_ip_addresses=bool(source.get("redact_ip_addresses", mode in {"review", "strict"})),
        redact_payloads=bool(source.get("redact_payloads", mode == "strict")),
        redact_user_identifiers=bool(source.get("redact_user_identifiers", mode in {"review", "strict"})),
        redact_hostnames=bool(source.get("redact_hostnames", mode == "strict")),
        redact_file_paths=bool(source.get("redact_file_paths", mode in {"review", "strict"})),
        encrypt_exports=bool(source.get("encrypt_exports", False)),
        encryption_key_env=str(source.get("encryption_key_env") or "NIDS_PRIVACY_KEY"),
    )


def privacy_config_from_env() -> PrivacyConfig:
    payload: dict[str, Any] = {"mode": os.getenv("NIDS_PRIVACY_MODE", "review")}
    env_map = {
        "NIDS_REDACT_IP_ADDRESSES": "redact_ip_addresses",
        "NIDS_REDACT_PAYLOADS": "redact_payloads",
        "NIDS_REDACT_USER_IDENTIFIERS": "redact_user_identifiers",
        "NIDS_REDACT_HOSTNAMES": "redact_hostnames",
        "NIDS_REDACT_FILE_PATHS": "redact_file_paths",
        "NIDS_ENCRYPT_EXPORTS": "encrypt_exports",
    }
    for env_key, payload_key in env_map.items():
        raw = os.getenv(env_key)
        if raw is None or str(raw).strip() == "":
            continue
        payload[payload_key] = str(raw).lower() in {"1", "true", "yes"}
    payload["encryption_key_env"] = os.getenv("NIDS_PRIVACY_KEY_ENV", "NIDS_PRIVACY_KEY")
    return privacy_config_from_mapping(payload)


def mask_ip(value: str | None) -> str | None:
    token = str(value or "").strip()
    if not token:
        return value
    if ":" in token:
        pieces = token.split(":")
        if len(pieces) <= 2:
            return "xxxx::xxxx"
        return ":".join(pieces[:2] + ["xxxx"] + pieces[-1:])
    parts = token.split(".")
    if len(parts) != 4:
        return token
    return ".".join(parts[:3] + ["x"])


def hash_token(value: str | None) -> str | None:
    token = str(value or "").strip()
    if not token:
        return value
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


def truncate_text(value: str | None, length: int = 24) -> str | None:
    token = str(value or "")
    if not token:
        return value
    if len(token) <= length:
        return token
    return token[:length] + "..."


def redact_text(value: str | None, config: PrivacyConfig) -> str | None:
    token = str(value or "")
    if token == "":
        return value
    result = token
    if config.redact_ip_addresses:
        result = IPV4_RE.sub(lambda match: mask_ip(match.group(0)) or "", result)
    if config.redact_file_paths:
        result = PATH_RE.sub("[redacted-path]", result)
    if config.redact_payloads and len(result) > 32:
        result = "[redacted-payload]"
    return result


def apply_privacy_to_alert(payload: dict[str, Any], config: PrivacyConfig) -> dict[str, Any]:
    if not config.enabled:
        return dict(payload)

    redacted = dict(payload)
    rules_applied: list[str] = []
    if config.redact_ip_addresses:
        for key in ("src_ip", "dst_ip"):
            if key in redacted:
                redacted[key] = mask_ip(redacted.get(key))
        rules_applied.append("ip_masked")
    if config.redact_payloads:
        for key in ("summary", "payload_preview"):
            if key in redacted:
                redacted[key] = redact_text(redacted.get(key), config)
        rules_applied.append("payload_redacted")
    if config.redact_user_identifiers:
        for key in ("username", "user", "acknowledged_by", "suppressed_by"):
            if key in redacted and redacted.get(key):
                redacted[key] = hash_token(str(redacted.get(key)))
        rules_applied.append("user_hashed")
    if config.redact_hostnames:
        for key in ("hostname", "host", "sensor_id"):
            if key in redacted and redacted.get(key):
                redacted[key] = truncate_text(str(redacted.get(key)), 12)
        rules_applied.append("hostname_truncated")
    if config.redact_file_paths:
        for key in ("output_dir", "report_path", "visuals_path", "evidence_reference"):
            if key in redacted and redacted.get(key):
                redacted[key] = Path(str(redacted.get(key))).name
        rules_applied.append("path_sanitized")
    if rules_applied:
        redacted["privacy_metadata"] = {
            "privacy_mode": config.mode,
            "rules_applied": rules_applied,
        }
    return redacted


def apply_privacy_to_summary_text(text: str, config: PrivacyConfig) -> str:
    if not config.enabled:
        return text
    return redact_text(text, config) or ""


def write_encrypted_json(path: Path, payload: dict[str, Any], config: PrivacyConfig) -> Path | None:
    if not config.encrypt_exports:
        return None
    raw_key = os.getenv(config.encryption_key_env, "").strip()
    if not raw_key:
        return None
    key_bytes = raw_key.encode("utf-8")
    if len(raw_key) != 44:
        key_bytes = base64.urlsafe_b64encode(hashlib.sha256(key_bytes).digest())
    token = Fernet(key_bytes).encrypt(json.dumps(payload, indent=2, ensure_ascii=True).encode("utf-8"))
    encrypted_path = path.with_suffix(path.suffix + ".enc")
    encrypted_path.write_bytes(token)
    return encrypted_path
