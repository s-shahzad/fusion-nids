from __future__ import annotations

from typing import Any

FEATURE_COLUMNS = [
    "packet_len",
    "payload_len",
    "src_port",
    "dst_port",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "tcp_syn",
    "tcp_ack",
    "packet_rate_dst",
    "unique_dst_ports_src_window",
    "unique_dst_hosts_src_window",
    "has_dns_qname",
    "has_http_host",
    "has_tls_sni",
]


def _as_float(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def build_feature_vector(event: dict[str, Any], features: dict[str, Any], columns: list[str] | None = None) -> list[float]:
    selected = columns or FEATURE_COLUMNS
    merged = dict(event)
    merged.update(features)

    vector: list[float] = []
    for col in selected:
        vector.append(_as_float(merged.get(col)))
    return vector
