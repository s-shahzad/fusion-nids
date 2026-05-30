from __future__ import annotations

import asyncio
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..pipeline.parser import parse_packet

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@dataclass
class LabelRule:
    pcap_file: str
    start_time: float | None
    end_time: float | None
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    proto: str | None
    label: str
    attack_type: str | None


def _to_epoch(value: str | None) -> float | None:
    if value is None:
        return None

    token = str(value).strip()
    if not token:
        return None

    try:
        return float(token)
    except Exception:
        pass

    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _safe_int(value: str | None) -> int | None:
    if value is None:
        return None
    token = str(value).strip()
    if not token:
        return None
    try:
        return int(token)
    except Exception:
        return None


def _parse_label_rules(labels_path: Path | None) -> list[LabelRule]:
    if labels_path is None or not labels_path.exists():
        return []

    rules: list[LabelRule] = []
    with labels_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label = str(row.get("label") or "").strip()
            if not label:
                continue

            rules.append(
                LabelRule(
                    pcap_file=str(row.get("pcap_file") or "").strip().lower(),
                    start_time=_to_epoch(row.get("start_time")),
                    end_time=_to_epoch(row.get("end_time")),
                    src_ip=(str(row.get("src_ip") or "").strip() or None),
                    dst_ip=(str(row.get("dst_ip") or "").strip() or None),
                    src_port=_safe_int(row.get("src_port")),
                    dst_port=_safe_int(row.get("dst_port")),
                    proto=(str(row.get("proto") or "").strip().upper() or None),
                    label=label,
                    attack_type=(str(row.get("attack_type") or "").strip() or None),
                )
            )

    return rules


def _event_epoch(event: dict[str, Any]) -> float | None:
    raw = str(event.get("timestamp") or "")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _match_rule(rule: LabelRule, event: dict[str, Any], pcap_name: str) -> bool:
    if rule.pcap_file and rule.pcap_file not in {pcap_name.lower(), f"pcap:{pcap_name.lower()}"}:
        return False

    ts = _event_epoch(event)
    if rule.start_time is not None and (ts is None or ts < rule.start_time):
        return False
    if rule.end_time is not None and (ts is None or ts > rule.end_time):
        return False

    if rule.src_ip and str(event.get("src_ip")) != rule.src_ip:
        return False
    if rule.dst_ip and str(event.get("dst_ip")) != rule.dst_ip:
        return False

    if rule.src_port is not None and int(event.get("src_port") or -1) != rule.src_port:
        return False
    if rule.dst_port is not None and int(event.get("dst_port") or -1) != rule.dst_port:
        return False

    if rule.proto and str(event.get("proto") or "").upper() != rule.proto:
        return False

    return True


def _apply_labels(rules: list[LabelRule], event: dict[str, Any], pcap_name: str) -> None:
    for rule in rules:
        if _match_rule(rule, event, pcap_name):
            event["label"] = rule.label
            event["attack_type"] = rule.attack_type
            event["is_labeled"] = 1
            return

    event["label"] = event.get("label") or None
    event["attack_type"] = event.get("attack_type") or None
    event["is_labeled"] = 1 if event.get("label") else 0


def _pcap_files(path: Path) -> list[Path]:
    if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS:
        return [path]

    if not path.exists():
        return []

    matches = [
        file_path
        for file_path in path.rglob("*")
        if file_path.is_file() and file_path.suffix.lower() in PCAP_EXTENSIONS
    ]
    return sorted(matches)


async def _enqueue(queue: asyncio.Queue[dict[str, Any] | None], event: dict[str, Any]) -> None:
    while True:
        try:
            queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            await asyncio.sleep(0.005)


async def run_offline_pcaps(
    pcap_dir: str | Path,
    queue: asyncio.Queue[dict[str, Any] | None],
    stop_event: asyncio.Event,
    replay_delay_ms: int = 0,
    labels_path: str | Path | None = None,
    sensor_id: str = "offline",
) -> None:
    """Stream packets from PCAP files into the unified queue."""
    try:
        from scapy.utils import PcapReader
    except Exception as exc:
        print(f"offline-pcap: scapy is not available ({exc})")
        return

    base = Path(pcap_dir).resolve()
    labels = _parse_label_rules(Path(labels_path).resolve() if labels_path else None)

    for pcap_file in _pcap_files(base):
        if stop_event.is_set():
            break

        dataset_source = f"pcap:{pcap_file.name}"
        try:
            with PcapReader(str(pcap_file)) as reader:
                for packet in reader:
                    if stop_event.is_set():
                        break

                    event = parse_packet(packet, dataset_source=dataset_source)
                    if not event:
                        continue

                    event["sensor_id"] = sensor_id
                    event["dataset_source"] = dataset_source
                    _apply_labels(labels, event, pcap_file.name)
                    await _enqueue(queue, event)

                    if replay_delay_ms > 0:
                        await asyncio.sleep(replay_delay_ms / 1000.0)
        except Exception as exc:
            print(f"offline-pcap: failed to read {pcap_file}: {exc}")


def _normalize_adapter_event(payload: dict[str, Any], dataset_source: str, sensor_id: str) -> dict[str, Any] | None:
    timestamp = payload.get("timestamp") or payload.get("ts") or payload.get("@timestamp")
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    src_ip = payload.get("src_ip") or payload.get("id.orig_h")
    dst_ip = payload.get("dst_ip") or payload.get("id.resp_h")

    if not src_ip or not dst_ip:
        return None

    event: dict[str, Any] = {
        "timestamp": str(timestamp),
        "sensor_id": sensor_id,
        "dataset_source": dataset_source,
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": _safe_int(str(payload.get("src_port") or payload.get("sport") or payload.get("id.orig_p") or "")),
        "dst_port": _safe_int(str(payload.get("dst_port") or payload.get("dport") or payload.get("id.resp_p") or "")),
        "proto": str(payload.get("proto") or payload.get("protocol") or "").upper() or "UNKNOWN",
        "packet_len": int(payload.get("packet_len") or payload.get("bytes") or 0),
        "tcp_flags": str(payload.get("tcp_flags") or ""),
        "payload": str(payload.get("payload") or payload.get("alert", {}).get("signature") or "").encode("utf-8", errors="ignore"),
        "label": payload.get("label"),
        "attack_type": payload.get("attack_type"),
        "is_labeled": 1 if payload.get("label") else 0,
    }
    return event


async def run_suricata_eve(
    eve_path: str | Path,
    queue: asyncio.Queue[dict[str, Any] | None],
    stop_event: asyncio.Event,
    sensor_id: str = "suricata",
) -> None:
    """Ingest Suricata eve.json lines into the unified queue."""
    source = Path(eve_path).resolve()
    if not source.exists():
        return

    with source.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if stop_event.is_set():
                break

            line = line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = _normalize_adapter_event(payload, dataset_source=f"suricata:{source.name}", sensor_id=sensor_id)
            if not event:
                continue

            await _enqueue(queue, event)


async def run_zeek_json(
    zeek_path: str | Path,
    queue: asyncio.Queue[dict[str, Any] | None],
    stop_event: asyncio.Event,
    sensor_id: str = "zeek",
) -> None:
    """Ingest Zeek JSON logs into the unified queue."""
    source = Path(zeek_path).resolve()
    if not source.exists():
        return

    with source.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if stop_event.is_set():
                break

            line = line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = _normalize_adapter_event(payload, dataset_source=f"zeek:{source.name}", sensor_id=sensor_id)
            if not event:
                continue

            await _enqueue(queue, event)
