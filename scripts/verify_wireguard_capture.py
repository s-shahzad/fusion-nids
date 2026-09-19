"""Verify actual lab captures using Fusion's parser and signature detector."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.layers.inet import IP, UDP
from scapy.utils import PcapReader
from src.nids.pipeline.parser import parse_packet
from src.nids.detect.signature import SignatureEngine


def verify(directory: Path) -> dict:
    engine = SignatureEngine(ROOT / "demo/vpn/demo-rule.yml")
    inner_events, alerts, outer_packets = [], [], 0
    with PcapReader(str(directory / "inner.pcap")) as packets:
        for packet in packets:
            event = parse_packet(packet, dataset_source="vpn-demo")
            if event:
                inner_events.append(event)
                alerts.extend(engine.detect(event, {}))
    if not any(e.get("dst_port") == 3389 and e.get("src_ip") == "10.203.0.1"
               and e.get("dst_ip") == "10.203.0.2" for e in inner_events) or not alerts:
        raise RuntimeError("Expected inner tunnel event and signature alert missing")
    with PcapReader(str(directory / "outer.pcap")) as packets:
        for packet in packets:
            if IP not in packet or UDP not in packet:
                raise RuntimeError("Unexpected outer capture protocol")
            if {packet[IP].src, packet[IP].dst} != {"192.0.2.1", "192.0.2.2"}:
                raise RuntimeError("Unexpected outer endpoint")
            if 51820 not in (packet[UDP].sport, packet[UDP].dport):
                raise RuntimeError("Unexpected outer port")
            event = parse_packet(packet, dataset_source="vpn-demo")
            if event and engine.detect(event, {}):
                raise RuntimeError("Inner-only signature unexpectedly matched outer traffic")
            outer_packets += 1
    if not outer_packets:
        raise RuntimeError("No outer tunnel packets")
    report = {"mode": "actual-isolated-lab-capture", "pqc": False,
              "inner_events": len(inner_events), "signature_alerts": len(alerts),
              "outer_udp_packets": outer_packets, "outer_signature_alerts": 0,
              "scope": "Parser and dedicated demo signature only; no ML or performance claim"}
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--report", type=Path, help="Optional new report file in a user-writable directory")
    args = parser.parse_args()
    result = json.dumps(verify(args.directory), indent=2) + "\n"
    if args.report is not None:
        with args.report.open("x", encoding="utf-8") as handle:
            handle.write(result)
    print(result, end="")
