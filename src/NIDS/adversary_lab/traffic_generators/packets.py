from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


def _set_packet_time(packet: Any, epoch: float) -> Any:
    packet.time = float(epoch)
    return packet


def _http_request_payload(
    *,
    method: str,
    uri: str,
    host: str,
    body: str = "",
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    lines = [f"{method.upper()} {uri} HTTP/1.1", f"Host: {host}", "User-Agent: universal-nids-lab"]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    body_bytes = body.encode("utf-8")
    if body_bytes:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body_bytes)}")
    return "\r\n".join(lines).encode("utf-8") + b"\r\n\r\n" + body_bytes


def build_tcp_scan(
    *,
    src_ip: str,
    dst_ip: str,
    base_epoch: float,
    start_port: int = 1,
    port_count: int = 27,
    extra_ports: tuple[int, ...] = (),
    interval_ms: int = 30,
    start_sport: int = 40000,
    start_time_sec: float = 0.0,
) -> list[Any]:
    ports = list(range(start_port, start_port + port_count)) + [int(item) for item in extra_ports]
    packets: list[Any] = []
    for index, dst_port in enumerate(ports):
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=start_sport + index, dport=dst_port, flags="S")
        packets.append(_set_packet_time(packet, base_epoch + start_time_sec + ((index * interval_ms) / 1000.0)))
    return packets


def build_http_login_attempts(
    *,
    src_ip: str,
    dst_ip: str,
    base_epoch: float,
    count: int = 10,
    interval_sec: float = 0.8,
    dst_port: int = 8080,
    start_sport: int = 42000,
    uri: str = "/login",
    host: str = "mock-auth.local",
    username: str = "lab-user",
    password_prefix: str = "wrong",
    start_time_sec: float = 0.0,
) -> list[Any]:
    packets: list[Any] = []
    for index in range(count):
        body = f"username={username}&password={password_prefix}{index}"
        payload = _http_request_payload(method="POST", uri=uri, host=host, body=body)
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=start_sport + index, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
    return packets


def build_beacon_http_gets(
    *,
    src_ip: str,
    dst_ip: str,
    base_epoch: float,
    count: int = 8,
    interval_sec: float = 12.0,
    dst_port: int = 443,
    start_sport: int = 43000,
    uri: str = "/health",
    host: str = "collector.beacon.local",
    start_time_sec: float = 0.0,
) -> list[Any]:
    packets: list[Any] = []
    for index in range(count):
        payload = _http_request_payload(method="GET", uri=uri, host=host)
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=start_sport + index, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
    return packets


def build_http_posts(
    *,
    src_ip: str,
    dst_ip: str,
    base_epoch: float,
    count: int,
    interval_sec: float,
    dst_port: int,
    uri: str,
    host: str,
    body_template: str,
    headers: dict[str, str] | None = None,
    start_sport: int = 44000,
    start_time_sec: float = 0.0,
) -> list[Any]:
    packets: list[Any] = []
    for index in range(count):
        body = body_template.format(index=index)
        payload = _http_request_payload(method="POST", uri=uri, host=host, body=body, extra_headers=headers)
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=start_sport + index, dport=dst_port, flags="PA") / Raw(load=payload)
        packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
    return packets


def build_dns_queries(
    *,
    src_ip: str,
    dst_ip: str,
    base_epoch: float,
    qnames: list[str],
    interval_sec: float = 0.5,
    dst_port: int = 53,
    start_sport: int = 45000,
    start_time_sec: float = 0.0,
) -> list[Any]:
    packets: list[Any] = []
    for index, qname in enumerate(qnames):
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=start_sport + index, dport=dst_port) / DNS(rd=1, qd=DNSQR(qname=qname))
        packets.append(_set_packet_time(packet, base_epoch + start_time_sec + (index * interval_sec)))
    return packets


def build_lateral_probe_sequence(
    *,
    src_ip: str,
    target_ips: list[str],
    base_epoch: float,
    ports: tuple[int, ...] = (445, 3389, 5985, 22),
    interval_ms: int = 120,
    start_sport: int = 46000,
    start_time_sec: float = 0.0,
) -> list[Any]:
    packets: list[Any] = []
    index = 0
    for dst_ip in target_ips:
        for dst_port in ports:
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=start_sport + index, dport=int(dst_port), flags="S")
            packets.append(_set_packet_time(packet, base_epoch + start_time_sec + ((index * interval_ms) / 1000.0)))
            index += 1
    return packets


def build_protocol_anomaly_packets(
    *,
    src_ip: str,
    dst_ip: str,
    base_epoch: float,
    start_sport: int = 47000,
    start_time_sec: float = 0.0,
) -> list[Any]:
    long_label = "anomaly-" + ("x" * 55)
    long_qname = f"{long_label}.protocol.lab.test"
    malformed_http = (
        b"GET /api/%ZZ HTTP/1.1\r\n"
        b"Host: malformed.lab\r\n"
        b"X-Oversized: "
        + (b"A" * 240)
        + b"\r\n\r\n"
    )
    packets: list[Any] = [
        _set_packet_time(
            IP(src=src_ip, dst=dst_ip) / UDP(sport=start_sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=long_qname)),
            base_epoch + start_time_sec,
        ),
        _set_packet_time(
            IP(src=src_ip, dst=dst_ip) / TCP(sport=start_sport + 1, dport=8081, flags="SFPU") / Raw(load=malformed_http),
            base_epoch + start_time_sec + 0.4,
        ),
    ]
    return packets
