from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.NIDS.pipeline.parser import parse_packet


def test_parse_packet_extracts_dns_qname_from_dns_query() -> None:
    packet = IP(src="10.77.0.20", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(
        rd=1,
        qd=DNSQR(qname="alpha.dga-test.example"),
    )

    event = parse_packet(packet, dataset_source="pcap:test")

    assert event is not None
    assert event["proto"] == "UDP"
    assert event["dst_port"] == 53
    assert event["dns_qname"] == "alpha.dga-test.example"


def test_parse_packet_extracts_http_method_host_and_uri() -> None:
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: app.internal\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 27\r\n\r\n"
        b"username=alice&password=bad"
    )
    packet = IP(src="10.77.0.20", dst="10.77.0.30") / TCP(sport=50123, dport=8080, flags="PA") / Raw(load=payload)

    event = parse_packet(packet, dataset_source="pcap:test")

    assert event is not None
    assert event["proto"] == "TCP"
    assert event["http_method"] == "POST"
    assert event["http_host"] == "app.internal"
    assert event["http_uri"] == "/login"
