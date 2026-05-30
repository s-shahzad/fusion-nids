import asyncio
import os

import src.NIDS.ingest.live as live_module
from src.NIDS.ingest.live import _resolve_live_capture_backend, run_live_capture


def test_resolve_live_capture_backend_defaults_to_scapy() -> None:
    assert _resolve_live_capture_backend("auto", "tcpdump") == "scapy"
    assert _resolve_live_capture_backend("unknown", "tcpdump") == "scapy"


def test_resolve_live_capture_backend_explicit_tcpdump() -> None:
    expected = "scapy" if os.name == "nt" else "tcpdump"
    assert _resolve_live_capture_backend("tcpdump", "tcpdump") == expected


def test_resolve_live_capture_backend_explicit_tcpdump_unsupported_platform(monkeypatch) -> None:
    monkeypatch.setattr(live_module, "_tcpdump_backend_supported", lambda: False)
    assert _resolve_live_capture_backend("tcpdump", "tcpdump") == "scapy"


def test_run_live_capture_dispatches_tcpdump(monkeypatch) -> None:
    called: list[str] = []

    async def fake_scapy_capture(*args, **kwargs) -> int:
        called.append("scapy")
        return 0

    async def fake_tcpdump_capture(*args, **kwargs) -> int:
        called.append("tcpdump")
        return 0

    monkeypatch.setattr(live_module, "_tcpdump_backend_supported", lambda: True)
    monkeypatch.setattr("src.NIDS.ingest.live._run_scapy_capture", fake_scapy_capture)
    monkeypatch.setattr("src.NIDS.ingest.live._run_tcpdump_capture", fake_tcpdump_capture)

    asyncio.run(
        run_live_capture(
            interface="eth0",
            queue=asyncio.Queue(),
            stop_event=asyncio.Event(),
            sensor_id="sensor-test",
            backend="tcpdump",
        )
    )

    assert called == ["tcpdump"]


def test_run_live_capture_dispatches_scapy(monkeypatch) -> None:
    called: list[str] = []

    async def fake_scapy_capture(*args, **kwargs) -> int:
        called.append("scapy")
        return 0

    async def fake_tcpdump_capture(*args, **kwargs) -> int:
        called.append("tcpdump")
        return 0

    monkeypatch.setattr("src.NIDS.ingest.live._run_scapy_capture", fake_scapy_capture)
    monkeypatch.setattr("src.NIDS.ingest.live._run_tcpdump_capture", fake_tcpdump_capture)

    asyncio.run(
        run_live_capture(
            interface="eth0",
            queue=asyncio.Queue(),
            stop_event=asyncio.Event(),
            sensor_id="sensor-test",
            backend="auto",
        )
    )

    assert called == ["scapy"]
