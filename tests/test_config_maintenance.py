from __future__ import annotations

from argparse import Namespace

from src.NIDS.config import build_runtime_config


def _args(**overrides: object) -> Namespace:
    payload = {
        "config": "config/nids.yml",
        "interface": None,
        "pcap_dir": None,
        "rules": "rules/rules.yml",
        "output_dir": "output",
        "replay_delay_ms": None,
        "metrics_interval": None,
        "model": None,
        "model_path": None,
        "unsupervised": False,
        "unsupervised_threshold": None,
        "suricata_log": None,
        "zeek_log": None,
        "enable_suricata": False,
        "enable_zeek": False,
        "maintenance_enabled": False,
        "maintenance_retention_days": None,
        "maintenance_interval_hours": None,
        "maintenance_include_artifacts": False,
        "maintenance_vacuum": False,
        "notify_webhook": None,
        "notify_min_severity": None,
        "notify_timeout_sec": None,
        "notify_max_retries": None,
        "notify_backoff_sec": None,
        "notify_max_backoff_sec": None,
        "notify_min_interval_sec": None,
        "notify_dead_letter": None,
        "notify_dead_letter_max_bytes": None,
        "notify_dead_letter_backup_count": None,
    }
    payload.update(overrides)
    return Namespace(**payload)


def test_build_runtime_config_maintenance_overrides() -> None:
    cfg = build_runtime_config(
        _args(
            maintenance_enabled=True,
            maintenance_retention_days=14,
            maintenance_interval_hours=6,
            maintenance_include_artifacts=True,
            maintenance_vacuum=True,
        )
    )

    assert cfg.maintenance.get("enabled") is True
    assert int(cfg.maintenance.get("retention_days")) == 14
    assert float(cfg.maintenance.get("interval_hours")) == 6.0
    assert cfg.maintenance.get("include_artifacts") is True
    assert cfg.maintenance.get("vacuum") is True


def test_build_runtime_config_notification_overrides() -> None:
    cfg = build_runtime_config(
        _args(
            notify_webhook="https://example.test/hook",
            notify_min_severity="critical",
            notify_timeout_sec=7.5,
            notify_max_retries=4,
            notify_backoff_sec=1.25,
            notify_max_backoff_sec=8.0,
            notify_min_interval_sec=0.4,
            notify_dead_letter="output/custom_dead_letter.jsonl",
            notify_dead_letter_max_bytes=4096,
            notify_dead_letter_backup_count=2,
        )
    )

    notifications = cfg.notifications
    assert notifications.get("enabled") is True
    assert str(notifications.get("slack_webhook") or "") == "https://example.test/hook"
    assert str(notifications.get("min_severity") or "") == "critical"
    assert float(notifications.get("timeout_sec") or 0.0) == 7.5
    assert int(notifications.get("max_retries") or 0) == 4
    assert float(notifications.get("backoff_sec") or 0.0) == 1.25
    assert float(notifications.get("max_backoff_sec") or 0.0) == 8.0
    assert float(notifications.get("min_interval_sec") or 0.0) == 0.4
    assert str(notifications.get("dead_letter_path") or "") == "output/custom_dead_letter.jsonl"
    assert int(notifications.get("dead_letter_max_bytes") or 0) == 4096
    assert int(notifications.get("dead_letter_backup_count") or 0) == 2
