from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
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


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = float(len(value))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


class ExfiltrationBehaviorDetector:
    """Heuristics for DNS- and timing-oriented covert exfiltration behavior."""

    def __init__(self, cfg: dict[str, Any] | bool | None = None) -> None:
        data = cfg if isinstance(cfg, dict) else {}
        self.enabled = _enabled(cfg)
        self.alert_cooldown_sec = max(1, int(data.get("alert_cooldown_sec", 120)))
        self.dns_entropy_threshold = float(data.get("dns_entropy_threshold", 4.1))
        self.dns_min_label_length = max(6, int(data.get("dns_min_label_length", 18)))
        self.long_subdomain_threshold = max(12, int(data.get("long_subdomain_threshold", 45)))
        self.timing_window_sec = max(30, int(data.get("timing_window_sec", 240)))
        self.timing_min_events = max(3, int(data.get("timing_min_events", 6)))
        self.timing_min_interval_sec = float(data.get("timing_min_interval_sec", 0.5))
        self.timing_max_cv = float(data.get("timing_max_cv", 0.12))
        self.timing_small_payload_max_bytes = max(1, int(data.get("timing_small_payload_max_bytes", 220)))
        self.outbound_window_sec = max(30, int(data.get("outbound_window_sec", 180)))
        self.outbound_min_events = max(4, int(data.get("outbound_min_events", 12)))
        self.outbound_min_distinct_destinations = max(
            1, int(data.get("outbound_min_distinct_destinations", 3))
        )
        self.outbound_dominant_ratio = float(data.get("outbound_dominant_ratio", 0.8))
        self.outbound_max_avg_payload = max(1, int(data.get("outbound_max_avg_payload", 220)))
        self._last_alert_epoch: dict[str, float] = {}
        self._timing_windows: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._outbound_windows: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)

    def _should_emit(self, key: str, now_epoch: float) -> bool:
        last = self._last_alert_epoch.get(key)
        if last is not None and now_epoch - last < self.alert_cooldown_sec:
            return False
        self._last_alert_epoch[key] = now_epoch
        return True

    @staticmethod
    def _subdomain(qname: str) -> str:
        parts = [segment for segment in qname.split(".") if segment]
        if len(parts) <= 2:
            return parts[0] if parts else ""
        return ".".join(parts[:-2])

    def detect(self, flow_record: dict[str, Any], event: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.enabled:
            return []

        timestamp = str(flow_record.get("timestamp") or event.get("timestamp") or "")
        now_epoch = _to_epoch(timestamp)
        src_ip = str(flow_record.get("src_ip") or event.get("src_ip") or "unknown")
        dst_ip = str(flow_record.get("dst_ip") or event.get("dst_ip") or "unknown")
        proto = str(flow_record.get("proto") or event.get("proto") or "").upper()
        dst_port = flow_record.get("dst_port", event.get("dst_port"))
        try:
            dst_port = int(dst_port) if dst_port is not None else 0
        except Exception:
            dst_port = 0
        packet_len = int(flow_record.get("packet_len") or event.get("packet_len") or 0)

        alerts: list[dict[str, Any]] = []
        dns_qname = str(event.get("dns_qname") or "").strip().lower()

        if dns_qname:
            left_label = dns_qname.split(".", 1)[0]
            entropy = _shannon_entropy(left_label)
            if (
                len(left_label) >= self.dns_min_label_length
                and entropy >= self.dns_entropy_threshold
                and self._should_emit(f"dns_entropy:{src_ip}:{dst_ip}", now_epoch)
            ):
                alerts.append(
                    {
                        "engine": "exfiltration_behavior",
                        "severity": "medium",
                        "rule_name": "High Entropy DNS Query",
                        "summary": "Observed a DNS query with unusually high label entropy consistent with covert data exfiltration.",
                        "extra": {
                            "qname": dns_qname,
                            "label": left_label,
                            "label_length": len(left_label),
                            "entropy": round(entropy, 4),
                        },
                    }
                )

            subdomain = self._subdomain(dns_qname)
            if (
                len(subdomain) >= self.long_subdomain_threshold
                and self._should_emit(f"long_subdomain:{src_ip}:{dst_ip}", now_epoch)
            ):
                alerts.append(
                    {
                        "engine": "exfiltration_behavior",
                        "severity": "medium",
                        "rule_name": "Unusual DNS Subdomain Length",
                        "summary": "Observed a DNS query with an unusually long subdomain component.",
                        "extra": {
                            "qname": dns_qname,
                            "subdomain": subdomain,
                            "subdomain_length": len(subdomain),
                        },
                    }
                )

        timing_key = f"{src_ip}:{dst_ip}:{proto}:{dst_port}"
        timing_window = self._timing_windows[timing_key]
        timing_window.append((now_epoch, packet_len))
        while timing_window and now_epoch - timing_window[0][0] > self.timing_window_sec:
            timing_window.popleft()
        if len(timing_window) >= self.timing_min_events:
            intervals = [
                timing_window[index][0] - timing_window[index - 1][0]
                for index in range(1, len(timing_window))
            ]
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((value - mean_interval) ** 2 for value in intervals) / len(intervals)
                cv = (variance**0.5 / mean_interval) if mean_interval > 0 else 1.0
                if (
                    mean_interval >= self.timing_min_interval_sec
                    and cv <= self.timing_max_cv
                    and all(length <= self.timing_small_payload_max_bytes for _ts, length in timing_window)
                    and self._should_emit(f"timing:{timing_key}", now_epoch)
                ):
                    alerts.append(
                        {
                            "engine": "exfiltration_behavior",
                            "severity": "medium",
                            "rule_name": "Timing Channel Pattern",
                            "summary": "Observed low-variance inter-packet timing consistent with a covert timing channel.",
                            "extra": {
                                "channel": timing_key,
                                "sample_count": len(timing_window),
                                "mean_interval_sec": round(mean_interval, 4),
                                "coefficient_of_variation": round(cv, 4),
                            },
                        }
                    )

        outbound_window = self._outbound_windows[src_ip]
        outbound_window.append((now_epoch, dst_ip, packet_len))
        while outbound_window and now_epoch - outbound_window[0][0] > self.outbound_window_sec:
            outbound_window.popleft()
        if len(outbound_window) >= self.outbound_min_events:
            destination_counts = Counter(entry[1] for entry in outbound_window)
            dominant_dst, dominant_count = destination_counts.most_common(1)[0]
            dominant_share = dominant_count / len(outbound_window)
            dominant_lengths = [entry[2] for entry in outbound_window if entry[1] == dominant_dst]
            avg_payload = sum(dominant_lengths) / max(1, len(dominant_lengths))
            if (
                len(destination_counts) >= self.outbound_min_distinct_destinations
                and dominant_share >= self.outbound_dominant_ratio
                and avg_payload <= self.outbound_max_avg_payload
                and self._should_emit(f"outbound:{src_ip}:{dominant_dst}", now_epoch)
            ):
                alerts.append(
                    {
                        "engine": "exfiltration_behavior",
                        "severity": "medium",
                        "rule_name": "Abnormal Outbound Flow Distribution",
                        "summary": "Observed a sustained concentration of small outbound flows toward one destination.",
                        "extra": {
                            "source_ip": src_ip,
                            "dominant_destination": dominant_dst,
                            "window_sec": self.outbound_window_sec,
                            "event_count": len(outbound_window),
                            "distinct_destinations": len(destination_counts),
                            "dominant_share": round(dominant_share, 4),
                            "avg_dominant_packet_len": round(avg_payload, 2),
                        },
                    }
                )

        return alerts
