from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any


def _to_epoch(value: str) -> float:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


def _enabled(cfg: dict[str, Any] | bool | None) -> bool:
    if isinstance(cfg, bool):
        return cfg
    if isinstance(cfg, dict):
        return bool(cfg.get("enabled", False))
    return False


class CampaignBehaviorDetector:
    """Correlate distributed low-and-slow reconnaissance across multiple hosts."""

    def __init__(self, cfg: dict[str, Any] | bool | None = None) -> None:
        data = cfg if isinstance(cfg, dict) else {}
        self.enabled = _enabled(cfg)
        self.window_sec = max(10, int(data.get("window_sec", 180)))
        self.alert_cooldown_sec = max(1, int(data.get("alert_cooldown_sec", 120)))
        self.distributed_scan_min_sources = max(2, int(data.get("distributed_scan_min_sources", 3)))
        self.distributed_scan_min_ports = max(2, int(data.get("distributed_scan_min_ports", 12)))
        self.coordinated_probe_min_sources = max(2, int(data.get("coordinated_probe_min_sources", 3)))
        self.coordinated_probe_min_targets = max(2, int(data.get("coordinated_probe_min_targets", 4)))
        self._target_windows: dict[str, deque[tuple[float, str, int | None]]] = defaultdict(deque)
        self._service_windows: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self._last_alert_epoch: dict[str, float] = {}

    @staticmethod
    def _is_probe_candidate(flow_record: dict[str, Any], event: dict[str, Any]) -> bool:
        proto = str(flow_record.get("proto") or event.get("proto") or "").upper()
        tcp_flags = str(flow_record.get("tcp_flags") or event.get("tcp_flags") or "")
        if proto == "TCP":
            return "S" in tcp_flags and "A" not in tcp_flags
        return proto == "UDP"

    def _prune(self, window: deque[Any], now_epoch: float) -> None:
        while window and now_epoch - window[0][0] > self.window_sec:
            window.popleft()

    def _should_emit(self, key: str, now_epoch: float) -> bool:
        last = self._last_alert_epoch.get(key)
        if last is not None and now_epoch - last < self.alert_cooldown_sec:
            return False
        self._last_alert_epoch[key] = now_epoch
        return True

    def detect(self, flow_record: dict[str, Any], event: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.enabled or not self._is_probe_candidate(flow_record, event):
            return []

        timestamp = str(flow_record.get("timestamp") or event.get("timestamp") or "")
        now_epoch = _to_epoch(timestamp)
        src_ip = str(flow_record.get("src_ip") or event.get("src_ip") or "unknown")
        dst_ip = str(flow_record.get("dst_ip") or event.get("dst_ip") or "unknown")
        proto = str(flow_record.get("proto") or event.get("proto") or "").upper()
        dst_port = flow_record.get("dst_port", event.get("dst_port"))
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except Exception:
            dst_port = None

        alerts: list[dict[str, Any]] = []

        target_window = self._target_windows[dst_ip]
        target_window.append((now_epoch, src_ip, dst_port))
        self._prune(target_window, now_epoch)
        target_sources = {entry[1] for entry in target_window}
        target_ports = {entry[2] for entry in target_window if entry[2] is not None}

        if (
            len(target_sources) >= self.distributed_scan_min_sources
            and len(target_ports) >= self.distributed_scan_min_ports
            and self._should_emit(f"distributed:{dst_ip}", now_epoch)
        ):
            alerts.append(
                {
                    "engine": "campaign_behavior",
                    "severity": "high",
                    "rule_name": "Distributed Port Scan Campaign",
                    "summary": "Multiple sources coordinated low-and-slow probing across many ports on one target.",
                    "extra": {
                        "campaign_type": "distributed_port_scan",
                        "target_ip": dst_ip,
                        "window_sec": self.window_sec,
                        "source_count": len(target_sources),
                        "unique_port_count": len(target_ports),
                        "sources": sorted(target_sources),
                        "ports": sorted(target_ports),
                    },
                }
            )

        if dst_port is None:
            return alerts

        service_key = f"{proto}:{dst_port}"
        service_window = self._service_windows[service_key]
        service_window.append((now_epoch, src_ip, dst_ip))
        self._prune(service_window, now_epoch)
        service_sources = {entry[1] for entry in service_window}
        service_targets = {entry[2] for entry in service_window}
        if (
            len(service_sources) >= self.coordinated_probe_min_sources
            and len(service_targets) >= self.coordinated_probe_min_targets
            and self._should_emit(f"coordinated:{service_key}", now_epoch)
        ):
            alerts.append(
                {
                    "engine": "campaign_behavior",
                    "severity": "medium",
                    "rule_name": "Coordinated Probing Campaign",
                    "summary": "Multiple sources probed the same service across several targets within one campaign window.",
                    "extra": {
                        "campaign_type": "coordinated_service_probe",
                        "service_key": service_key,
                        "window_sec": self.window_sec,
                        "source_count": len(service_sources),
                        "target_count": len(service_targets),
                        "sources": sorted(service_sources),
                        "targets": sorted(service_targets),
                    },
                }
            )

        return alerts
