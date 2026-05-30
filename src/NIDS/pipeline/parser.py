from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.packet import Packet, Raw

    SCAPY_AVAILABLE = True
except Exception:
    DNS = DNSQR = ICMP = IP = TCP = UDP = Raw = None  # type: ignore[assignment]
    Packet = Any  # type: ignore[misc,assignment]
    SCAPY_AVAILABLE = False

PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

HTTP_HOST_RE = re.compile(r"^host:\s*(.+)$", re.IGNORECASE)
HTTP_REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)", re.IGNORECASE)
TLS_SNI_TOKEN_RE = re.compile(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _decode_payload(payload: bytes) -> str:
    return payload[:4096].decode("utf-8", errors="ignore")


def _extract_http_fields(payload: bytes) -> tuple[str | None, str | None, str | None]:
    text = _decode_payload(payload)
    if not text:
        return None, None, None

    method: str | None = None
    host: str | None = None
    uri: str | None = None

    lines = text.splitlines()[:40]
    for index, line in enumerate(lines):
        line = line.strip()
        if index == 0:
            request_match = HTTP_REQUEST_LINE_RE.match(line)
            if request_match:
                method = request_match.group(1).upper()
                uri = request_match.group(2)
        host_match = HTTP_HOST_RE.match(line)
        if host_match:
            host = host_match.group(1).strip()

    return method, host, uri


def _extract_tls_sni(payload: bytes) -> str | None:
    text = _decode_payload(payload)
    if not text:
        return None

    if "server_name" in text.lower():
        match = TLS_SNI_TOKEN_RE.search(text)
        if match:
            return match.group(1).lower()

    return None


def _extract_dns_qname(packet: Packet) -> str | None:
    if DNS not in packet:  # type: ignore[operator]
        return None

    qd = packet[DNS].qd  # type: ignore[index]
    if qd is None:
        return None

    raw_qname = getattr(qd, "qname", b"")
    if not raw_qname and isinstance(qd, (list, tuple)) and qd:
        raw_qname = getattr(qd[0], "qname", b"")

    if isinstance(raw_qname, bytes):
        return raw_qname.decode("utf-8", errors="ignore").rstrip(".")
    if raw_qname:
        return str(raw_qname).rstrip(".")
    return None


def parse_packet(packet: Packet, dataset_source: str = "live") -> dict[str, Any] | None:
    """Parse a raw Scapy packet into a normalized event dict for the pipeline."""
    if not SCAPY_AVAILABLE:
        return None

    if IP not in packet:  # type: ignore[operator]
        return None

    ip_layer = packet[IP]  # type: ignore[index]
    timestamp_raw = getattr(packet, "time", None)
    try:
        timestamp = datetime.fromtimestamp(float(timestamp_raw), tz=timezone.utc).isoformat()
    except Exception:
        timestamp = datetime.now(timezone.utc).isoformat()

    proto_name = PROTO_MAP.get(int(ip_layer.proto), str(ip_layer.proto))

    src_port = None
    dst_port = None
    tcp_flags = ""

    if TCP in packet:  # type: ignore[operator]
        src_port = _safe_int(packet[TCP].sport)  # type: ignore[index]
        dst_port = _safe_int(packet[TCP].dport)  # type: ignore[index]
        tcp_flags = str(packet[TCP].flags)  # type: ignore[index]
    elif UDP in packet:  # type: ignore[operator]
        src_port = _safe_int(packet[UDP].sport)  # type: ignore[index]
        dst_port = _safe_int(packet[UDP].dport)  # type: ignore[index]
    elif ICMP in packet:  # type: ignore[operator]
        src_port = None
        dst_port = None

    payload_bytes = b""
    if Raw in packet:  # type: ignore[operator]
        payload_bytes = bytes(packet[Raw].load)  # type: ignore[index]

    dns_qname = _extract_dns_qname(packet)

    http_method, http_host, http_uri = _extract_http_fields(payload_bytes)
    tls_sni = _extract_tls_sni(payload_bytes)

    event: dict[str, Any] = {
        "timestamp": timestamp,
        "src_ip": str(ip_layer.src),
        "dst_ip": str(ip_layer.dst),
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto_name,
        "packet_len": int(len(packet)),
        "tcp_flags": tcp_flags,
        "payload": payload_bytes,
        "dns_qname": dns_qname,
        "http_method": http_method,
        "http_host": http_host,
        "http_uri": http_uri,
        "tls_sni": tls_sni,
        "dataset_source": dataset_source,
        "label": None,
        "attack_type": None,
        "is_labeled": 0,
    }
    return event
