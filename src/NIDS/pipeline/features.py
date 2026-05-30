from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any


def _to_epoch(timestamp: str) -> float:
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


class FeatureExtractor:
    """Flow-ish feature extraction shared across all ingest sources."""

    def __init__(self, scan_window_sec: int = 12) -> None:
        self.scan_window_sec = max(1, int(scan_window_sec))
        self.dst_rate_window: dict[str, deque[float]] = defaultdict(deque)
        self.src_port_window: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.src_dst_window: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

    @staticmethod
    def _is_scan_candidate(proto: str, tcp_flags: str) -> bool:
        if proto == "TCP":
            return "S" in tcp_flags and "A" not in tcp_flags
        if proto == "UDP":
            return True
        return False

    def extract(self, event: dict[str, Any]) -> dict[str, Any]:
        ts = _to_epoch(str(event.get("timestamp", "")))
        src_ip = str(event.get("src_ip", "unknown"))
        dst_ip = str(event.get("dst_ip", "unknown"))
        dst_port_raw = event.get("dst_port")
        proto = str(event.get("proto", "")).upper()
        tcp_flags = str(event.get("tcp_flags", ""))
        payload = bytes(event.get("payload", b""))

        dst_queue = self.dst_rate_window[dst_ip]
        dst_queue.append(ts)
        while dst_queue and ts - dst_queue[0] > 1.0:
            dst_queue.popleft()
        packet_rate_dst = len(dst_queue)

        src_ports = self.src_port_window[src_ip]
        if self._is_scan_candidate(proto, tcp_flags) and dst_port_raw is not None:
            try:
                src_ports.append((ts, int(dst_port_raw)))
            except Exception:
                pass

        while src_ports and ts - src_ports[0][0] > self.scan_window_sec:
            src_ports.popleft()

        unique_dst_ports_src_window = len({entry[1] for entry in src_ports})

        src_targets = self.src_dst_window[src_ip]
        if self._is_scan_candidate(proto, tcp_flags):
            src_targets.append((ts, dst_ip))
        while src_targets and ts - src_targets[0][0] > self.scan_window_sec:
            src_targets.popleft()
        unique_dst_hosts_src_window = len({entry[1] for entry in src_targets})

        features: dict[str, Any] = {
            "packet_rate_dst": packet_rate_dst,
            "unique_dst_ports_src_window": unique_dst_ports_src_window,
            "unique_dst_hosts_src_window": unique_dst_hosts_src_window,
            "packet_len": int(event.get("packet_len", 0) or 0),
            "payload_len": len(payload),
            "src_port": event.get("src_port"),
            "dst_port": event.get("dst_port"),
            "is_tcp": 1 if proto == "TCP" else 0,
            "is_udp": 1 if proto == "UDP" else 0,
            "is_icmp": 1 if proto == "ICMP" else 0,
            "tcp_syn": 1 if "S" in tcp_flags else 0,
            "tcp_ack": 1 if "A" in tcp_flags else 0,
            "has_dns_qname": 1 if event.get("dns_qname") else 0,
            "has_http_host": 1 if event.get("http_host") else 0,
            "has_tls_sni": 1 if event.get("tls_sni") else 0,
        }
        return features
