from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "pipeline": {
        "queue_max_size": 20000,
        "metrics_interval_sec": 5,
        "replay_delay_ms": 0,
        "live_capture_backend": "auto",
        "live_capture_tcpdump_bin": "tcpdump",
        "live_capture_tcpdump_snaplen": 0,
        "live_capture_bpf_filter": "",
    },
    "detection": {
        "dos_packets_per_sec_threshold": 240,
        "scan_ports_threshold": 25,
        "scan_window_sec": 12,
        "ssh_bruteforce_threshold": 10,
        "ssh_bruteforce_window_sec": 12,
        "rdp_bruteforce_threshold": 10,
        "rdp_bruteforce_window_sec": 12,
        "http_login_threshold": 8,
        "http_login_window_sec": 20,
        "zscore_enabled": True,
        "zscore_threshold": 3.0,
        "anomaly_cooldown_sec": 8,
        "suppress_window_sec": 15,
    },
    "ml": {
        "model_path": "models/model.pkl",
        "score_threshold": 0.85,
        "live_throttle_enabled": True,
        "live_min_inference_interval_sec": 1.0,
        "unsupervised": False,
        "unsupervised_warmup_samples": 200,
        "unsupervised_contamination": 0.03,
        "unsupervised_alert_threshold": 0.65,
        "unsupervised_component_threshold": 0.55,
        "unsupervised_autoencoder": True,
        "unsupervised_autoencoder_hidden_size": 8,
        "unsupervised_autoencoder_max_iter": 400,
        "unsupervised_persist_baseline": True,
        "unsupervised_baseline_path": "",
    },
    "fusion": {
        "enabled": True,
        "emit_alerts": True,
        "emit_on_signature_only": False,
        "min_component_score": 0.55,
        "min_agreement_count": 2,
        "alert_threshold": 0.65,
        "high_threshold": 0.8,
        "critical_threshold": 0.92,
        "signature_weight": 0.4,
        "statistical_weight": 0.2,
        "supervised_weight": 0.3,
        "unsupervised_weight": 0.1,
    },
    "adapters": {
        "suricata": {"enabled": False, "path": "pcaps/suricata/eve.json"},
        "zeek": {"enabled": False, "path": "pcaps/zeek/conn.json"},
    },
    "maintenance": {
        "enabled": False,
        "retention_days": 30,
        "interval_hours": 24,
        "include_artifacts": False,
        "vacuum": False,
    },
    "notifications": {
        "enabled": False,
        "slack_webhook": "",
        "min_severity": "high",
        "timeout_sec": 3,
        "max_retries": 2,
        "backoff_sec": 0.5,
        "max_backoff_sec": 4.0,
        "min_interval_sec": 0.1,
        "dead_letter_path": "output/notification_failures.jsonl",
        "dead_letter_max_bytes": 10485760,
        "dead_letter_backup_count": 5,
    },
}


@dataclass
class RuntimeConfig:
    interface: str | None
    pcap_dir: Path | None
    rules_path: Path
    output_dir: Path
    pipeline: dict[str, Any]
    detection: dict[str, Any]
    ml: dict[str, Any]
    adapters: dict[str, Any]
    fusion: dict[str, Any] = field(default_factory=dict)
    maintenance: dict[str, Any] = field(default_factory=dict)
    notifications: dict[str, Any] = field(default_factory=dict)
    detectors: dict[str, Any] = field(default_factory=dict)
    threat_intel: dict[str, Any] = field(default_factory=dict)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_yaml(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Config file {path} must be a YAML mapping.")
    return payload


def build_runtime_config(args: Any) -> RuntimeConfig:
    config_path = Path(args.config).resolve() if getattr(args, "config", None) else None
    merged = _deep_merge(DEFAULT_CONFIG, _read_yaml(config_path))

    if getattr(args, "replay_delay_ms", None) is not None:
        merged["pipeline"]["replay_delay_ms"] = int(args.replay_delay_ms)
    if getattr(args, "metrics_interval", None) is not None:
        merged["pipeline"]["metrics_interval_sec"] = int(args.metrics_interval)

    if getattr(args, "model", None):
        merged["ml"]["model_path"] = str(args.model)
    if getattr(args, "model_path", None):
        merged["ml"]["model_path"] = str(args.model_path)

    if getattr(args, "unsupervised", False):
        merged["ml"]["unsupervised"] = True

    if getattr(args, "unsupervised_threshold", None) is not None:
        merged["ml"]["unsupervised_alert_threshold"] = float(args.unsupervised_threshold)

    if getattr(args, "suricata_log", None):
        merged["adapters"]["suricata"]["enabled"] = True
        merged["adapters"]["suricata"]["path"] = str(args.suricata_log)
    if getattr(args, "zeek_log", None):
        merged["adapters"]["zeek"]["enabled"] = True
        merged["adapters"]["zeek"]["path"] = str(args.zeek_log)

    if getattr(args, "enable_suricata", False):
        merged["adapters"]["suricata"]["enabled"] = True
    if getattr(args, "enable_zeek", False):
        merged["adapters"]["zeek"]["enabled"] = True

    if getattr(args, "maintenance_enabled", False):
        merged["maintenance"]["enabled"] = True
    if getattr(args, "maintenance_retention_days", None) is not None:
        merged["maintenance"]["retention_days"] = int(args.maintenance_retention_days)
    if getattr(args, "maintenance_interval_hours", None) is not None:
        merged["maintenance"]["interval_hours"] = float(args.maintenance_interval_hours)
    if getattr(args, "maintenance_include_artifacts", False):
        merged["maintenance"]["include_artifacts"] = True
    if getattr(args, "maintenance_vacuum", False):
        merged["maintenance"]["vacuum"] = True

    if getattr(args, "notify_webhook", None):
        merged["notifications"]["enabled"] = True
        merged["notifications"]["slack_webhook"] = str(args.notify_webhook)
    if getattr(args, "notify_min_severity", None):
        merged["notifications"]["min_severity"] = str(args.notify_min_severity)
    if getattr(args, "notify_timeout_sec", None) is not None:
        merged["notifications"]["timeout_sec"] = float(args.notify_timeout_sec)
    if getattr(args, "notify_max_retries", None) is not None:
        merged["notifications"]["max_retries"] = int(args.notify_max_retries)
    if getattr(args, "notify_backoff_sec", None) is not None:
        merged["notifications"]["backoff_sec"] = float(args.notify_backoff_sec)
    if getattr(args, "notify_max_backoff_sec", None) is not None:
        merged["notifications"]["max_backoff_sec"] = float(args.notify_max_backoff_sec)
    if getattr(args, "notify_min_interval_sec", None) is not None:
        merged["notifications"]["min_interval_sec"] = float(args.notify_min_interval_sec)
    if getattr(args, "notify_dead_letter", None):
        merged["notifications"]["dead_letter_path"] = str(args.notify_dead_letter)
    if getattr(args, "notify_dead_letter_max_bytes", None) is not None:
        merged["notifications"]["dead_letter_max_bytes"] = int(args.notify_dead_letter_max_bytes)
    if getattr(args, "notify_dead_letter_backup_count", None) is not None:
        merged["notifications"]["dead_letter_backup_count"] = int(args.notify_dead_letter_backup_count)

    interface = getattr(args, "interface", None)
    pcap_dir_raw = getattr(args, "pcap_dir", None)

    rules_path = Path(getattr(args, "rules", "rules/rules.yml")).resolve()
    output_dir = Path(getattr(args, "output_dir", "output")).resolve()

    pcap_dir: Path | None = None
    if pcap_dir_raw:
        pcap_dir = Path(pcap_dir_raw).resolve()

    adapters = merged.get("adapters", {})
    for key in ("suricata", "zeek"):
        adapter = adapters.get(key, {})
        if adapter.get("path"):
            adapter["path"] = str(Path(adapter["path"]).resolve())

    return RuntimeConfig(
        interface=interface,
        pcap_dir=pcap_dir,
        rules_path=rules_path,
        output_dir=output_dir,
        pipeline=merged.get("pipeline", {}),
        detection=merged.get("detection", {}),
        ml=merged.get("ml", {}),
        fusion=merged.get("fusion", {}),
        adapters=adapters,
        maintenance=merged.get("maintenance", {}),
        notifications=merged.get("notifications", {}),
        detectors=merged.get("detectors", {}),
        threat_intel=merged.get("threat_intel", {}),
    )
