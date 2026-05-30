from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any

import src.NIDS.utils.notifications as notifications
from src.NIDS.utils.notifications import SlackWebhookNotifier


class _FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


def test_slack_notifier_retries_then_succeeds(monkeypatch: Any) -> None:
    call_count = {"value": 0}
    sleep_calls: list[float] = []

    def fake_urlopen(request: Any, timeout: float) -> _FakeResponse:
        del request, timeout
        call_count["value"] += 1
        if call_count["value"] == 1:
            raise urllib.error.URLError("transient")
        return _FakeResponse(status=200)

    monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(notifications.time, "sleep", lambda seconds: sleep_calls.append(float(seconds)))

    notifier = SlackWebhookNotifier(
        webhook_url="https://example.test/webhook",
        max_retries=1,
        backoff_sec=0.25,
        max_backoff_sec=1.0,
    )
    sent = notifier.notify_high_alert(
        {
            "severity": "high",
            "summary": "retry case",
            "engine": "signature",
            "rule_name": "Retry Rule",
            "src_ip": "10.0.0.1",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
        }
    )
    assert sent is True

    snapshot = notifier.health_snapshot()
    assert int(snapshot["stats"]["attempted"]) == 2
    assert int(snapshot["stats"]["sent"]) == 1
    assert int(snapshot["stats"]["failed"]) == 0
    assert sleep_calls == [0.25]


def test_slack_notifier_rate_limit_records_dead_letter(monkeypatch: Any, tmp_path: Path) -> None:
    dead_letter = tmp_path / "notification_failures.jsonl"
    call_count = {"value": 0}
    monotonic_values = iter([100.0, 101.0])

    def fake_monotonic() -> float:
        return float(next(monotonic_values))

    def fake_urlopen(request: Any, timeout: float) -> _FakeResponse:
        del request, timeout
        call_count["value"] += 1
        return _FakeResponse(status=200)

    monkeypatch.setattr(notifications.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)

    notifier = SlackWebhookNotifier(
        webhook_url="https://example.test/webhook",
        min_interval_sec=5.0,
        dead_letter_path=dead_letter,
        max_retries=0,
    )
    first = notifier.notify_incident_update(
        {"incident_id": 1, "status": "open", "owner": "", "priority": "low"},
        action="assign",
        actor="analyst-1",
    )
    second = notifier.notify_incident_update(
        {"incident_id": 1, "status": "triage", "owner": "analyst-1", "priority": "medium"},
        action="status:triage",
        actor="analyst-1",
    )

    assert first is True
    assert second is False
    assert call_count["value"] == 1

    snapshot = notifier.health_snapshot()
    assert int(snapshot["stats"]["attempted"]) == 1
    assert int(snapshot["stats"]["sent"]) == 1
    assert int(snapshot["stats"]["failed"]) == 0
    assert int(snapshot["stats"]["rate_limited"]) == 1
    assert int(snapshot["recent_failures"]) == 1

    lines = [line for line in dead_letter.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert str(event.get("reason")) == "rate_limited"
    assert int(event.get("attempts", -1)) == 0


def test_slack_notifier_delivery_failure_tracks_dead_letter(monkeypatch: Any, tmp_path: Path) -> None:
    dead_letter = tmp_path / "delivery_failures.jsonl"
    sleep_calls: list[float] = []
    call_count = {"value": 0}

    def fake_urlopen(request: Any, timeout: float) -> _FakeResponse:
        del request, timeout
        call_count["value"] += 1
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(notifications.time, "sleep", lambda seconds: sleep_calls.append(float(seconds)))

    notifier = SlackWebhookNotifier(
        webhook_url="https://example.test/webhook",
        max_retries=2,
        backoff_sec=0.2,
        max_backoff_sec=0.3,
        dead_letter_path=dead_letter,
    )
    sent = notifier.notify_incident_update(
        {"incident_id": 42, "status": "open", "owner": "", "priority": "high"},
        action="bulk_update",
        actor="analyst-2",
    )

    assert sent is False
    assert call_count["value"] == 3
    assert sleep_calls == [0.2, 0.3]

    snapshot = notifier.health_snapshot()
    assert int(snapshot["stats"]["attempted"]) == 3
    assert int(snapshot["stats"]["sent"]) == 0
    assert int(snapshot["stats"]["failed"]) == 1
    assert int(snapshot["recent_failures"]) == 1

    lines = [line for line in dead_letter.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert str(event.get("reason")) == "delivery_failed"
    assert int(event.get("attempts") or 0) == 3
    assert "offline" in str(event.get("error") or "")


def test_slack_notifier_dead_letter_rotation(monkeypatch: Any, tmp_path: Path) -> None:
    dead_letter = tmp_path / "rotation_failures.jsonl"
    first_backup = Path(f"{dead_letter}.1")

    dead_letter.write_text("old-current\n", encoding="utf-8")
    first_backup.write_text("old-backup\n", encoding="utf-8")

    def fake_urlopen(request: Any, timeout: float) -> _FakeResponse:
        del request, timeout
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(notifications.time, "sleep", lambda seconds: None)

    notifier = SlackWebhookNotifier(
        webhook_url="https://example.test/webhook",
        max_retries=0,
        dead_letter_path=dead_letter,
        dead_letter_max_bytes=10,
        dead_letter_backup_count=2,
    )

    sent = notifier.notify_incident_update(
        {"incident_id": 55, "status": "open", "owner": "", "priority": "medium"},
        action="bulk_update",
        actor="analyst-3",
    )
    assert sent is False

    second_backup = Path(f"{dead_letter}.2")
    assert first_backup.exists()
    assert second_backup.exists()
    assert first_backup.read_text(encoding="utf-8") == "old-current\n"
    assert second_backup.read_text(encoding="utf-8") == "old-backup\n"

    lines = [line for line in dead_letter.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert str(event.get("reason") or "") == "delivery_failed"

    snapshot = notifier.health_snapshot()
    assert int(snapshot["stats"].get("dead_letter_rotated") or 0) >= 1
