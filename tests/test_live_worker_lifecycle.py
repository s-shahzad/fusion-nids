"""Offline lifecycle checks: no interface or capture privileges required."""
import asyncio

import pytest
from scapy.sendrecv import AsyncSniffer

from src.nids.ingest.live import _run_scapy_capture


@pytest.mark.parametrize("failure", [None, PermissionError("denied"), OSError("missing interface")])
def test_capture_returns_when_worker_exits(monkeypatch, capsys, failure):
    def fake_run(self, **kwargs):
        if failure is not None:
            raise failure

    monkeypatch.setattr(AsyncSniffer, "_run", fake_run)

    async def exercise():
        return await asyncio.wait_for(
            _run_scapy_capture(
                "unused-test-interface", asyncio.Queue(), asyncio.Event(), sensor_id="test"
            ),
            timeout=2,
        )

    assert asyncio.run(exercise()) == 0
    output = capsys.readouterr().out
    if isinstance(failure, PermissionError):
        assert "permission denied" in output
    elif failure is not None:
        assert "missing interface" in output
