from __future__ import annotations

from typing import Any

from ...pipeline.parser import parse_packet


def _payload_preview(event: dict[str, Any]) -> str:
    return bytes(event.get("payload", b""))[:256].decode("utf-8", errors="ignore")


def build_normalized_events(
    packets: list[Any],
    *,
    dataset_source: str,
    label: str,
    attack_type: str,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for packet in packets:
        event = parse_packet(packet, dataset_source=dataset_source)
        if not event:
            continue
        event["label"] = label
        event["attack_type"] = attack_type
        event["is_labeled"] = 1
        events.append(event)
    return events


def build_suricata_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for event in events:
        payloads.append(
            {
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "src_port": event.get("src_port"),
                "dst_port": event.get("dst_port"),
                "proto": event.get("proto"),
                "bytes": event.get("packet_len"),
                "payload": _payload_preview(event),
                "label": event.get("label"),
                "attack_type": event.get("attack_type"),
            }
        )
    return payloads


def build_zeek_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for event in events:
        payloads.append(
            {
                "ts": event.get("timestamp"),
                "id.orig_h": event.get("src_ip"),
                "id.resp_h": event.get("dst_ip"),
                "id.orig_p": event.get("src_port"),
                "id.resp_p": event.get("dst_port"),
                "proto": str(event.get("proto") or "").lower(),
                "bytes": event.get("packet_len"),
                "payload": _payload_preview(event),
                "label": event.get("label"),
                "attack_type": event.get("attack_type"),
            }
        )
    return payloads
