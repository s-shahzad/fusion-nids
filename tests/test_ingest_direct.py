from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

import src.NIDS.ingest.live as live_module
from src.NIDS.ingest.live import _enqueue_event, _run_scapy_capture
from src.NIDS.ingest.offline import (
    _normalize_adapter_event,
    run_offline_pcaps,
    run_suricata_eve,
    run_zeek_json,
)


@pytest.mark.integration
def test_run_offline_pcaps_replays_pcap_and_applies_labels(tmp_path: Path) -> None:
    pcap_path = tmp_path / "fixture.pcap"
    label_path = tmp_path / "labels.csv"
    packet = IP(src="10.0.0.5", dst="192.0.2.25") / TCP(sport=51515, dport=443, flags="S")
    wrpcap(str(pcap_path), [packet])

    label_path.write_text(
        "pcap_file,start_time,end_time,src_ip,dst_ip,src_port,dst_port,proto,label,attack_type\n"
        "fixture.pcap,,,10.0.0.5,192.0.2.25,51515,443,TCP,attack,scan\n",
        encoding="utf-8",
    )

    async def exercise() -> dict[str, object]:
        queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()
        stop_event = asyncio.Event()
        await run_offline_pcaps(
            pcap_dir=pcap_path,
            queue=queue,
            stop_event=stop_event,
            labels_path=label_path,
            sensor_id="offline-sensor",
        )
        event = await queue.get()
        assert event is not None
        return event

    event = asyncio.run(exercise())
    assert event["sensor_id"] == "offline-sensor"
    assert event["dataset_source"] == "pcap:fixture.pcap"
    assert event["src_ip"] == "10.0.0.5"
    assert event["dst_ip"] == "192.0.2.25"
    assert event["label"] == "attack"
    assert event["attack_type"] == "scan"
    assert int(event["is_labeled"]) == 1


@pytest.mark.integration
def test_run_suricata_and_zeek_adapters_normalize_records(tmp_path: Path) -> None:
    suricata_path = tmp_path / "eve.json"
    zeek_path = tmp_path / "conn.log"

    suricata_path.write_text(
        "\n".join(
            [
                "",
                "{not-json}",
                json.dumps(
                    {
                        "timestamp": "2026-03-08T11:00:00Z",
                        "src_ip": "10.0.0.7",
                        "dst_ip": "192.0.2.53",
                        "src_port": 53000,
                        "dst_port": 53,
                        "proto": "udp",
                        "bytes": 128,
                        "alert": {"signature": "dns burst"},
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    zeek_path.write_text(
        "\n".join(
            [
                "",
                "not-json",
                json.dumps(
                    {
                        "ts": "2026-03-08T11:00:05Z",
                        "id.orig_h": "10.0.0.9",
                        "id.resp_h": "192.0.2.80",
                        "id.orig_p": 52525,
                        "id.resp_p": 80,
                        "proto": "tcp",
                        "bytes": 512,
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    async def exercise() -> list[dict[str, object]]:
        queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()
        stop_event = asyncio.Event()
        await run_suricata_eve(suricata_path, queue, stop_event, sensor_id="suricata-a")
        await run_zeek_json(zeek_path, queue, stop_event, sensor_id="zeek-a")
        return [await queue.get(), await queue.get()]  # type: ignore[misc]

    events = asyncio.run(exercise())
    suricata_event = next(item for item in events if item["sensor_id"] == "suricata-a")
    zeek_event = next(item for item in events if item["sensor_id"] == "zeek-a")

    assert suricata_event["dataset_source"] == "suricata:eve.json"
    assert suricata_event["dst_port"] == 53
    assert bytes(suricata_event["payload"]).startswith(b"dns burst")

    assert zeek_event["dataset_source"] == "zeek:conn.log"
    assert zeek_event["src_ip"] == "10.0.0.9"
    assert zeek_event["proto"] == "TCP"
    assert zeek_event["packet_len"] == 512


def test_normalize_adapter_event_handles_aliases_and_invalid_records() -> None:
    normalized = _normalize_adapter_event(
        {
            "@timestamp": "2026-03-08T12:00:00Z",
            "id.orig_h": "10.0.0.10",
            "id.resp_h": "203.0.113.8",
            "id.orig_p": "40222",
            "id.resp_p": "22",
            "protocol": "tcp",
            "bytes": 900,
            "label": "attack",
            "attack_type": "bruteforce",
        },
        dataset_source="zeek:auth.log",
        sensor_id="sensor-b",
    )

    assert normalized is not None
    assert normalized["timestamp"] == "2026-03-08T12:00:00Z"
    assert normalized["src_port"] == 40222
    assert normalized["dst_port"] == 22
    assert normalized["proto"] == "TCP"
    assert normalized["packet_len"] == 900
    assert int(normalized["is_labeled"]) == 1

    missing_ips = _normalize_adapter_event({}, dataset_source="suricata:eve.json", sensor_id="sensor-c")
    assert missing_ips is None


def test_enqueue_event_sets_runtime_defaults_and_counts_drops() -> None:
    queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue(maxsize=1)
    dropped = {"count": 0}

    _enqueue_event(queue, {"summary": "first"}, sensor_id="sensor-x", dropped_counter=dropped)
    _enqueue_event(queue, {"summary": "second"}, sensor_id="sensor-x", dropped_counter=dropped)

    event = queue.get_nowait()
    assert event is not None
    assert event["sensor_id"] == "sensor-x"
    assert event["dataset_source"] == "live"
    assert int(event["is_labeled"]) == 0
    assert dropped["count"] == 1


def test_run_scapy_capture_enqueues_packets_and_reports_drops(monkeypatch: pytest.MonkeyPatch) -> None:
    packet = IP(src="10.0.0.20", dst="192.0.2.50") / UDP(sport=60000, dport=53) / Raw(load=b"test")

    async def exercise() -> tuple[int, list[dict[str, object]]]:
        queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue(maxsize=1)
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()

        class FakeAsyncSniffer:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.prn = kwargs["prn"]
                self.running = False

            def start(self) -> None:
                self.running = True
                self.prn(packet)
                self.prn(packet)
                loop.call_soon(stop_event.set)

            def stop(self) -> None:
                self.running = False

        monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeAsyncSniffer)
        monkeypatch.setattr(
            live_module,
            "parse_packet",
            lambda *_args, **_kwargs: {
                "timestamp": "2026-03-08T12:05:00+00:00",
                "src_ip": "10.0.0.20",
                "dst_ip": "192.0.2.50",
                "src_port": 60000,
                "dst_port": 53,
                "proto": "UDP",
                "packet_len": 60,
                "tcp_flags": "",
            },
        )

        dropped = await _run_scapy_capture(
            interface="Ethernet",
            queue=queue,
            stop_event=stop_event,
            sensor_id="live-sensor",
        )
        events = [await queue.get()]
        return dropped, events

    dropped, events = asyncio.run(exercise())
    assert dropped == 1
    assert events[0]["sensor_id"] == "live-sensor"
    assert events[0]["dataset_source"] == "live"
