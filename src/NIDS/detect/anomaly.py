from __future__ import annotations

import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

HTTP_LOGIN_URI_PATTERNS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/session",
    "/wp-login",
    "/oauth/token",
)
HTTP_LOGIN_BODY_RE = re.compile(
    r"(password=|passwd=|pwd=|pass=|username=|user=|login=|grant_type=password)",
    re.IGNORECASE,
)


def _to_epoch(timestamp: str) -> float:
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


@dataclass
class EWMAStat:
    alpha: float = 0.15
    mean: float = 0.0
    variance: float = 1.0
    initialized: bool = False

    def update(self, value: float) -> None:
        if not self.initialized:
            self.mean = value
            self.variance = 1.0
            self.initialized = True
            return

        prev_mean = self.mean
        self.mean = self.alpha * value + (1.0 - self.alpha) * self.mean
        diff = value - prev_mean
        self.variance = self.alpha * (diff * diff) + (1.0 - self.alpha) * self.variance

    @property
    def std(self) -> float:
        return math.sqrt(max(self.variance, 1e-6))


class AnomalyEngine:
    """Threshold + EWMA-zscore detector for DoS, scans, and protocol bursts."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.dos_threshold = int(config.get("dos_packets_per_sec_threshold", 240))
        self.scan_ports_threshold = int(config.get("scan_ports_threshold", 25))
        self.scan_window_sec = int(config.get("scan_window_sec", 12))
        self.ssh_bruteforce_threshold = int(config.get("ssh_bruteforce_threshold", 10))
        self.ssh_bruteforce_window_sec = int(config.get("ssh_bruteforce_window_sec", self.scan_window_sec))
        self.rdp_bruteforce_threshold = int(config.get("rdp_bruteforce_threshold", 10))
        self.rdp_bruteforce_window_sec = int(config.get("rdp_bruteforce_window_sec", self.scan_window_sec))
        self.http_login_threshold = int(config.get("http_login_threshold", 8))
        self.http_login_window_sec = int(config.get("http_login_window_sec", 20))
        self.cooldown_sec = int(config.get("anomaly_cooldown_sec", 8))
        self.zscore_threshold = float(config.get("zscore_threshold", 3.0))
        self.zscore_enabled = bool(config.get("zscore_enabled", True))
        self.dns_unique_threshold = int(config.get("dns_unique_threshold", 30))

        self.rate_stats: dict[str, EWMAStat] = defaultdict(EWMAStat)
        self.scan_stats: dict[str, EWMAStat] = defaultdict(EWMAStat)
        self.dns_window: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.service_attempt_window: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self.last_alert_ts: dict[str, float] = defaultdict(float)

    def detect(self, event: dict[str, Any], features: dict[str, Any]) -> tuple[list[dict[str, Any]], float | None]:
        ts = _to_epoch(str(event.get("timestamp", "")))
        src_ip = str(event.get("src_ip") or "unknown")
        dst_ip = str(event.get("dst_ip") or "unknown")

        packet_rate = float(features.get("packet_rate_dst", 0.0))
        unique_ports = float(features.get("unique_dst_ports_src_window", 0.0))

        self.rate_stats[dst_ip].update(packet_rate)
        self.scan_stats[src_ip].update(unique_ports)

        alerts: list[dict[str, Any]] = []

        if packet_rate >= self.dos_threshold and self._allow(f"dos:{dst_ip}", ts):
            alerts.append(
                {
                    "engine": "anomaly",
                    "severity": "high",
                    "rule_name": "DoS Rate Threshold",
                    "summary": f"High packet rate to {dst_ip} ({int(packet_rate)} pkt/s)",
                }
            )

        if unique_ports >= self.scan_ports_threshold and self._allow(f"scan:{src_ip}", ts):
            alerts.append(
                {
                    "engine": "anomaly",
                    "severity": "medium",
                    "rule_name": "Port Scan Threshold",
                    "summary": f"Source {src_ip} touched {int(unique_ports)} ports in {self.scan_window_sec}s",
                }
            )

        dns_alert = self._detect_dns_burst(event, ts)
        if dns_alert and self._allow(f"dns:{src_ip}", ts):
            alerts.append(dns_alert)

        ssh_alert = self._detect_ssh_bruteforce(event, ts)
        if ssh_alert and self._allow(f"sshbf:{src_ip}:{dst_ip}", ts):
            alerts.append(ssh_alert)

        rdp_alert = self._detect_rdp_bruteforce(event, ts)
        if rdp_alert and self._allow(f"rdpbf:{src_ip}:{dst_ip}", ts):
            alerts.append(rdp_alert)

        http_login_alert = self._detect_http_login_bruteforce(event, ts)
        if http_login_alert and self._allow(f"httpbf:{src_ip}:{dst_ip}", ts):
            alerts.append(http_login_alert)

        anomaly_score = (
            self._zscore_score(src_ip=src_ip, dst_ip=dst_ip, packet_rate=packet_rate, unique_ports=unique_ports)
            if self.zscore_enabled
            else None
        )
        if self.zscore_enabled and anomaly_score is not None and anomaly_score >= 0.75 and self._allow(f"z:{src_ip}:{dst_ip}", ts):
            alerts.append(
                {
                    "engine": "anomaly",
                    "severity": "medium",
                    "rule_name": "EWMA Z-Score Spike",
                    "summary": f"Anomaly spike src={src_ip} dst={dst_ip} score={anomaly_score:.2f}",
                }
            )

        return alerts, anomaly_score

    def _allow(self, key: str, ts: float) -> bool:
        prev = self.last_alert_ts.get(key, 0.0)
        if ts - prev < self.cooldown_sec:
            return False
        self.last_alert_ts[key] = ts
        return True

    def _detect_dns_burst(self, event: dict[str, Any], ts: float) -> dict[str, Any] | None:
        if str(event.get("proto", "")).upper() != "UDP":
            return None

        qname = str(event.get("dns_qname") or "").strip()
        if not qname:
            return None

        src_ip = str(event.get("src_ip") or "unknown")
        window = self.dns_window[src_ip]
        window.append((ts, qname.lower()))

        while window and ts - window[0][0] > self.scan_window_sec:
            window.popleft()

        unique_qnames = len({name for _, name in window})
        if unique_qnames >= self.dns_unique_threshold:
            return {
                "engine": "anomaly",
                "severity": "medium",
                "rule_name": "DNS Burst / DGA-like Activity",
                "summary": f"Source {src_ip} queried {unique_qnames} unique DNS names in {self.scan_window_sec}s",
            }
        return None

    def _detect_ssh_bruteforce(self, event: dict[str, Any], ts: float) -> dict[str, Any] | None:
        return self._detect_tcp_bruteforce(
            event,
            ts,
            dst_port=22,
            threshold=self.ssh_bruteforce_threshold,
            window_sec=self.ssh_bruteforce_window_sec,
            rule_name="SSH Brute Force Threshold",
            service_name="SSH",
        )

    def _detect_rdp_bruteforce(self, event: dict[str, Any], ts: float) -> dict[str, Any] | None:
        return self._detect_tcp_bruteforce(
            event,
            ts,
            dst_port=3389,
            threshold=self.rdp_bruteforce_threshold,
            window_sec=self.rdp_bruteforce_window_sec,
            rule_name="RDP Brute Force Threshold",
            service_name="RDP",
        )

    def _detect_tcp_bruteforce(
        self,
        event: dict[str, Any],
        ts: float,
        *,
        dst_port: int,
        threshold: int,
        window_sec: int,
        rule_name: str,
        service_name: str,
    ) -> dict[str, Any] | None:
        if str(event.get("proto", "")).upper() != "TCP":
            return None
        if int(event.get("dst_port") or -1) != dst_port:
            return None

        tcp_flags = str(event.get("tcp_flags") or "")
        if "S" not in tcp_flags or "A" in tcp_flags:
            return None

        src_ip = str(event.get("src_ip") or "unknown")
        dst_ip = str(event.get("dst_ip") or "unknown")
        key = (src_ip, dst_ip, dst_port)
        window = self.service_attempt_window[key]
        window.append(ts)

        while window and ts - window[0] > window_sec:
            window.popleft()

        attempts = len(window)
        if attempts >= threshold:
            return {
                "engine": "anomaly",
                "severity": "high",
                "rule_name": rule_name,
                "summary": (
                    f"Source {src_ip} attempted {service_name} {attempts} times against {dst_ip} "
                    f"in {window_sec}s"
                ),
            }
        return None

    def _detect_http_login_bruteforce(self, event: dict[str, Any], ts: float) -> dict[str, Any] | None:
        if str(event.get("proto", "")).upper() != "TCP":
            return None

        http_method = str(event.get("http_method") or "").upper()
        if http_method != "POST":
            return None

        http_uri = str(event.get("http_uri") or "").lower()
        if not http_uri or not any(token in http_uri for token in HTTP_LOGIN_URI_PATTERNS):
            return None

        payload_text = bytes(event.get("payload", b""))[:2048].decode("utf-8", errors="ignore")
        if not HTTP_LOGIN_BODY_RE.search(payload_text):
            return None

        src_ip = str(event.get("src_ip") or "unknown")
        dst_ip = str(event.get("dst_ip") or "unknown")
        key = (src_ip, dst_ip, int(event.get("dst_port") or 0))
        window = self.service_attempt_window[key]
        window.append(ts)

        while window and ts - window[0] > self.http_login_window_sec:
            window.popleft()

        attempts = len(window)
        if attempts >= self.http_login_threshold:
            return {
                "engine": "anomaly",
                "severity": "high",
                "rule_name": "HTTP Login Brute Force Threshold",
                "summary": (
                    f"Source {src_ip} posted to login endpoint {attempts} times against {dst_ip} "
                    f"in {self.http_login_window_sec}s"
                ),
            }
        return None

    def _zscore_score(self, src_ip: str, dst_ip: str, packet_rate: float, unique_ports: float) -> float | None:
        rate_stat = self.rate_stats[dst_ip]
        scan_stat = self.scan_stats[src_ip]

        if not rate_stat.initialized or not scan_stat.initialized:
            return None

        z_rate = (packet_rate - rate_stat.mean) / max(rate_stat.std, 1e-6)
        z_scan = (unique_ports - scan_stat.mean) / max(scan_stat.std, 1e-6)

        z_peak = max(z_rate, z_scan)
        if z_peak <= 0:
            return 0.0

        normalized = max(0.0, min(1.0, z_peak / (self.zscore_threshold * 1.5)))
        return normalized
