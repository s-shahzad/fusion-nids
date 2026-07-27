from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "warning": 1,
    "monitor": 1,
    "high": 2,
    "alert": 2,
    "critical": 3,
}


def _rank_severity(value: str | None) -> int:
    token = str(value or "").strip().lower()
    return int(SEVERITY_RANK.get(token, 0))


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_nonnegative_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(0, parsed)


class SlackWebhookNotifier:
    """Best-effort Slack webhook notifier with retry/backoff and dead-letter logging."""

    def __init__(
        self,
        webhook_url: str | None = None,
        *,
        min_severity: str = "high",
        timeout_sec: float = 3.0,
        max_retries: int = 2,
        backoff_sec: float = 0.5,
        max_backoff_sec: float = 4.0,
        min_interval_sec: float = 0.0,
        dead_letter_path: str | Path | None = None,
        dead_letter_max_bytes: int = 10 * 1024 * 1024,
        dead_letter_backup_count: int = 5,
        recent_failures_limit: int = 100,
    ) -> None:
        self.webhook_url = str(webhook_url or "").strip() or None
        self.min_severity = str(min_severity or "high").strip().lower() or "high"
        self.timeout_sec = max(1.0, float(timeout_sec or 3.0))
        self.max_retries = max(0, int(max_retries or 0))
        self.backoff_sec = max(0.0, float(backoff_sec or 0.0))
        self.max_backoff_sec = max(self.backoff_sec, float(max_backoff_sec or self.backoff_sec))
        self.min_interval_sec = max(0.0, float(min_interval_sec or 0.0))

        dead_letter_token = str(dead_letter_path or "").strip()
        self.dead_letter_path = Path(dead_letter_token) if dead_letter_token else None
        self.dead_letter_max_bytes = _safe_nonnegative_int(dead_letter_max_bytes, 10 * 1024 * 1024)
        self.dead_letter_backup_count = _safe_nonnegative_int(dead_letter_backup_count, 5)

        self._last_attempt_mono = 0.0
        self._recent_failures: deque[dict[str, Any]] = deque(maxlen=max(10, int(recent_failures_limit)))
        self._stats = {
            "attempted": 0,
            "sent": 0,
            "failed": 0,
            "rate_limited": 0,
            "dead_letter_rotated": 0,
        }

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    @property
    def recent_failures(self) -> list[dict[str, Any]]:
        return list(self._recent_failures)

    def health_snapshot(self) -> dict[str, Any]:
        payload = {
            "enabled": self.enabled,
            "min_severity": self.min_severity,
            "timeout_sec": self.timeout_sec,
            "max_retries": self.max_retries,
            "backoff_sec": self.backoff_sec,
            "max_backoff_sec": self.max_backoff_sec,
            "min_interval_sec": self.min_interval_sec,
            "dead_letter_enabled": self.dead_letter_path is not None,
            "dead_letter_path": str(self.dead_letter_path) if self.dead_letter_path is not None else "",
            "dead_letter_max_bytes": self.dead_letter_max_bytes,
            "dead_letter_backup_count": self.dead_letter_backup_count,
            "stats": dict(self._stats),
            "recent_failures": len(self._recent_failures),
        }
        if self._recent_failures:
            payload["last_failure"] = dict(self._recent_failures[-1])
        return payload

    def _rotate_dead_letter(self) -> None:
        if self.dead_letter_path is None:
            return
        if self.dead_letter_max_bytes <= 0:
            return
        if not self.dead_letter_path.exists():
            return

        if self.dead_letter_backup_count <= 0:
            try:
                self.dead_letter_path.unlink(missing_ok=True)
                self._stats["dead_letter_rotated"] += 1
            except Exception:
                return
            return

        try:
            for idx in range(self.dead_letter_backup_count, 0, -1):
                source = self.dead_letter_path if idx == 1 else Path(f"{self.dead_letter_path}.{idx - 1}")
                target = Path(f"{self.dead_letter_path}.{idx}")

                if not source.exists():
                    continue
                target.unlink(missing_ok=True)
                source.rename(target)
            self._stats["dead_letter_rotated"] += 1
        except Exception:
            return

    def _append_dead_letter(self, event: dict[str, Any]) -> None:
        if self.dead_letter_path is None:
            return
        try:
            self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event, ensure_ascii=True) + "\n"
            line_bytes = line.encode("utf-8")
            if self.dead_letter_max_bytes > 0 and self.dead_letter_path.exists():
                existing_size = int(self.dead_letter_path.stat().st_size)
                if existing_size + len(line_bytes) > self.dead_letter_max_bytes:
                    self._rotate_dead_letter()
            with self.dead_letter_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except Exception:
            return

    def _record_failure(
        self,
        *,
        reason: str,
        attempts: int,
        payload: dict[str, Any],
        error: str | None = None,
    ) -> None:
        event = {
            "timestamp": _utc_now_iso(),
            "reason": str(reason),
            "attempts": int(attempts),
            "error": str(error or ""),
            "payload": payload,
        }
        self._recent_failures.append(event)
        self._append_dead_letter(event)

    def _post(self, payload: dict[str, Any]) -> bool:
        if not self.enabled:
            return False

        now_mono = time.monotonic()
        if self.min_interval_sec > 0.0 and self._last_attempt_mono > 0.0:
            delta = now_mono - self._last_attempt_mono
            if delta < self.min_interval_sec:
                self._stats["rate_limited"] += 1
                self._record_failure(
                    reason="rate_limited",
                    attempts=0,
                    payload=payload,
                    error=f"delta={delta:.3f}s min_interval={self.min_interval_sec:.3f}s",
                )
                return False
        self._last_attempt_mono = now_mono

        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        request = urllib.request.Request(
            url=str(self.webhook_url),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        total_attempts = 1 + self.max_retries
        backoff = self.backoff_sec
        last_error = ""

        for attempt in range(1, total_attempts + 1):
            self._stats["attempted"] += 1
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_sec) as response:
                    status_code = int(getattr(response, "status", 0) or 0)
                    if 200 <= status_code < 300:
                        self._stats["sent"] += 1
                        return True
                    last_error = f"http_status={status_code}"
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                last_error = str(exc)

            if attempt < total_attempts and backoff > 0.0:
                time.sleep(min(backoff, self.max_backoff_sec))
                backoff = min(self.max_backoff_sec, backoff * 2.0 if backoff > 0 else self.max_backoff_sec)

        self._stats["failed"] += 1
        self._record_failure(
            reason="delivery_failed",
            attempts=total_attempts,
            payload=payload,
            error=last_error,
        )
        return False

    def notify_high_alert(self, alert: dict[str, Any]) -> bool:
        severity = str(alert.get("severity") or "").strip().lower()
        if _rank_severity(severity) < _rank_severity(self.min_severity):
            return False

        summary = str(alert.get("summary") or "alert")
        engine = str(alert.get("engine") or "unknown")
        rule_name = str(alert.get("rule_name") or "unknown_rule")
        src_ip = str(alert.get("src_ip") or "unknown")
        dst_ip = str(alert.get("dst_ip") or "unknown")
        dst_port = str(alert.get("dst_port") or "-")

        return self._post(
            {
                "text": f"[NIDS] High alert {severity.upper()} | {engine}:{rule_name} | {src_ip}->{dst_ip}:{dst_port} | {summary}",
            }
        )

    def notify_incident_update(self, incident: dict[str, Any], *, action: str, actor: str) -> bool:
        if not self.enabled:
            return False

        incident_id = int(incident.get("incident_id") or incident.get("id") or 0)
        status = str(incident.get("status") or "open")
        owner = str(incident.get("owner") or "unassigned")
        priority = str(incident.get("priority") or "low")
        due_at = str(incident.get("due_at") or "")
        rule_name = str(incident.get("rule_name") or "unknown_rule")

        due_token = due_at if due_at else "n/a"
        return self._post(
            {
                "text": f"[NIDS] Incident {incident_id} {action} by {actor} | status={status} owner={owner} priority={priority} due={due_token} rule={rule_name}",
            }
        )
