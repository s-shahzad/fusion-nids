from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from src.NIDS.ingest.live import LiveCaptureTelemetry, _run_scapy_capture, _run_tcpdump_capture


pytestmark = [pytest.mark.live, pytest.mark.environment, pytest.mark.integration]


class _FakeStreamReader:
    def __init__(self, lines: list[str]) -> None:
        self._lines = [line.encode("utf-8") + b"\n" for line in lines]

    async def readline(self) -> bytes:
        if self._lines:
            return self._lines.pop(0)
        return b""


class _FakeProcess:
    def __init__(self, *, returncode: int | None = None, stderr_lines: list[str] | None = None) -> None:
        self.returncode = returncode
        self.stderr = _FakeStreamReader(stderr_lines or [])
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        if self.returncode is None:
            self.returncode = 0
        return int(self.returncode)


def test_tcpdump_fifo_streaming_handles_packet_burst_and_drop_count(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> tuple[int, dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=1)
        stop_event = asyncio.Event()
        telemetry = LiveCaptureTelemetry()
        loop = asyncio.get_running_loop()

        class FakePcapReader:
            def __init__(self, _fifo_path: str) -> None:
                self._packets = [object(), object()]

            def __enter__(self) -> "FakePcapReader":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read_packet(self) -> object:
                if self._packets:
                    return self._packets.pop(0)
                raise EOFError

        async def fake_create_subprocess_exec(*_args: object, **_kwargs: object) -> _FakeProcess:
            loop.call_soon(stop_event.set)
            return _FakeProcess(stderr_lines=[])

        monkeypatch.setattr("scapy.utils.PcapReader", FakePcapReader)
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)
        monkeypatch.setattr("shutil.which", lambda _binary: "/usr/sbin/tcpdump")
        monkeypatch.setattr("os.mkfifo", lambda _path: None, raising=False)
        monkeypatch.setattr(
            "src.NIDS.ingest.live.parse_packet",
            lambda *_args, **_kwargs: {
                "timestamp": "2026-03-08T14:00:00+00:00",
                "src_ip": "10.0.0.50",
                "dst_ip": "192.0.2.50",
                "src_port": 53000,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 128,
                "tcp_flags": "PA",
            },
        )

        dropped = await _run_tcpdump_capture(
            interface="eth0",
            queue=queue,
            stop_event=stop_event,
            sensor_id="sensor-live",
            tcpdump_bin="tcpdump",
            snaplen=96,
            bpf_filter="tcp port 80",
            telemetry=telemetry,
        )
        event = await queue.get()
        assert event is not None
        return dropped, {"event": event, "telemetry": telemetry.snapshot(backend="tcpdump")}

    dropped, payload = asyncio.run(exercise())
    event = payload["event"]
    telemetry = payload["telemetry"]
    assert dropped == 1
    assert event["sensor_id"] == "sensor-live"
    assert event["dataset_source"] == "live"
    assert event["src_ip"] == "10.0.0.50"
    assert telemetry["packets_received"] == 2
    assert telemetry["packets_parsed"] == 2
    assert telemetry["packets_enqueued"] == 1
    assert telemetry["packets_dropped_queue"] == 1
    assert telemetry["queue_depth_peak"] == 1


def test_tcpdump_capture_reports_backend_failure_without_queue_data(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def exercise() -> int:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=4)
        stop_event = asyncio.Event()

        class FakePcapReader:
            def __init__(self, _fifo_path: str) -> None:
                return None

            def __enter__(self) -> "FakePcapReader":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read_packet(self) -> object:
                raise EOFError

        async def fake_create_subprocess_exec(*_args: object, **_kwargs: object) -> _FakeProcess:
            return _FakeProcess(returncode=1, stderr_lines=["broken pipe"])

        monkeypatch.setattr("scapy.utils.PcapReader", FakePcapReader)
        monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)
        monkeypatch.setattr("shutil.which", lambda _binary: "/usr/sbin/tcpdump")
        monkeypatch.setattr("os.mkfifo", lambda _path: None, raising=False)

        return await _run_tcpdump_capture(
            interface="eth0",
            queue=queue,
            stop_event=stop_event,
            sensor_id="sensor-live",
            tcpdump_bin="tcpdump",
            snaplen=0,
            bpf_filter="",
            telemetry=LiveCaptureTelemetry(),
        )

    dropped = asyncio.run(exercise())
    output = capsys.readouterr().out
    assert dropped == 0
    assert "tcpdump backend exited with status 1" in output
    assert "broken pipe" in output


def test_scapy_capture_ignores_malformed_packets_and_stops_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    async def exercise() -> tuple[int, list[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=4)
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()

        packets = [object(), object()]

        class FakeAsyncSniffer:
            def __init__(self, *args: object, **kwargs: object) -> None:
                del args
                self.prn = kwargs["prn"]
                self.running = False

            def start(self) -> None:
                self.running = True
                for packet in packets:
                    self.prn(packet)
                loop.call_soon(stop_event.set)

            def stop(self) -> None:
                self.running = False

        parse_results = [
            None,
            {
                "timestamp": "2026-03-08T14:05:00+00:00",
                "src_ip": "10.0.0.60",
                "dst_ip": "192.0.2.60",
                "src_port": 60001,
                "dst_port": 443,
                "proto": "TCP",
                "packet_len": 64,
                "tcp_flags": "S",
            },
        ]

        monkeypatch.setattr("scapy.sendrecv.AsyncSniffer", FakeAsyncSniffer)
        monkeypatch.setattr("src.NIDS.ingest.live.parse_packet", lambda *_args, **_kwargs: parse_results.pop(0))

        dropped = await _run_scapy_capture(
            interface="Ethernet",
            queue=queue,
            stop_event=stop_event,
            sensor_id="sensor-iface",
            telemetry=LiveCaptureTelemetry(),
        )

        items: list[dict[str, Any]] = []
        while not queue.empty():
            item = await queue.get()
            assert item is not None
            items.append(item)
        return dropped, items

    dropped, items = asyncio.run(exercise())
    assert dropped == 0
    assert len(items) == 1
    assert items[0]["sensor_id"] == "sensor-iface"
    assert items[0]["dst_port"] == 443
