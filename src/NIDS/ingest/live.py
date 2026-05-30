from __future__ import annotations

import asyncio
import functools
import os
import shlex
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..pipeline.parser import parse_packet


def _tcpdump_backend_supported() -> bool:
    return os.name != "nt" and hasattr(os, "mkfifo")


def _resolve_live_capture_backend(requested: str, tcpdump_bin: str) -> str:
    token = str(requested or "auto").strip().lower()
    if token == "scapy":
        return token
    if token == "tcpdump":
        return "tcpdump" if _tcpdump_backend_supported() else "scapy"
    if token == "auto":
        return "scapy"
    if token == "tcpdump-if-available" and _tcpdump_backend_supported() and shutil.which(tcpdump_bin):
        return "tcpdump"
    return "scapy"


def _enqueue_event(
    queue: asyncio.Queue[dict[str, Any] | None],
    event: dict[str, Any],
    *,
    sensor_id: str,
    dropped_counter: dict[str, int],
) -> None:
    event["sensor_id"] = sensor_id
    event["dataset_source"] = "live"
    event["is_labeled"] = 0
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        dropped_counter["count"] += 1


async def _run_scapy_capture(
    interface: str,
    queue: asyncio.Queue[dict[str, Any] | None],
    stop_event: asyncio.Event,
    *,
    sensor_id: str,
) -> int:
    try:
        from scapy.sendrecv import AsyncSniffer
    except Exception as exc:
        print(f"live-capture: scapy is not available ({exc})")
        return 0

    loop = asyncio.get_running_loop()
    dropped_counter = {"count": 0}

    def on_packet(packet: Any) -> None:
        event = parse_packet(packet, dataset_source="live")
        if not event:
            return
        loop.call_soon_threadsafe(
            functools.partial(
                _enqueue_event,
                queue,
                event,
                sensor_id=sensor_id,
                dropped_counter=dropped_counter,
            )
        )

    sniffer = AsyncSniffer(iface=interface, prn=on_packet, store=False)

    try:
        sniffer.start()
        while not stop_event.is_set():
            await asyncio.sleep(0.4)
    except PermissionError:
        print("live-capture: permission denied. Run with admin/root privileges for interface sniffing.")
    except OSError as exc:
        print(f"live-capture: failed to start interface capture on {interface}: {exc}")
    except Exception as exc:
        print(f"live-capture: capture error on {interface}: {exc}")
    finally:
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception:
            pass

    return dropped_counter["count"]


async def _run_tcpdump_capture(
    interface: str,
    queue: asyncio.Queue[dict[str, Any] | None],
    stop_event: asyncio.Event,
    *,
    sensor_id: str,
    tcpdump_bin: str,
    snaplen: int,
    bpf_filter: str,
) -> int:
    try:
        from scapy.utils import PcapReader
    except Exception as exc:
        print(f"live-capture: scapy pcap reader is not available ({exc})")
        return 0

    tcpdump_path = shutil.which(tcpdump_bin)
    if not tcpdump_path:
        print(f"live-capture: tcpdump backend requested but binary was not found: {tcpdump_bin}")
        return 0

    loop = asyncio.get_running_loop()
    dropped_counter = {"count": 0}
    stderr_lines: list[str] = []

    def consume_fifo(fifo_path: str) -> None:
        with PcapReader(fifo_path) as reader:
            while True:
                try:
                    packet = reader.read_packet()
                except EOFError:
                    break

                event = parse_packet(packet, dataset_source="live")
                if not event:
                    continue

                loop.call_soon_threadsafe(
                    functools.partial(
                        _enqueue_event,
                        queue,
                        event,
                        sensor_id=sensor_id,
                        dropped_counter=dropped_counter,
                    )
                )

    async def drain_stderr(stream: asyncio.StreamReader | None) -> None:
        if stream is None:
            return
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="ignore").strip()
            if text:
                stderr_lines.append(text)
                del stderr_lines[:-10]

    with tempfile.TemporaryDirectory(prefix="nids_tcpdump_") as temp_dir:
        fifo_path = str(Path(temp_dir) / "capture.pcap")
        os.mkfifo(fifo_path)

        command = [
            tcpdump_path,
            "-U",
            "-n",
            "-s",
            str(max(0, int(snaplen))),
            "-i",
            interface,
            "-w",
            fifo_path,
        ]
        if str(bpf_filter or "").strip():
            command.extend(shlex.split(str(bpf_filter)))

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        reader_task = asyncio.create_task(asyncio.to_thread(consume_fifo, fifo_path))
        stderr_task = asyncio.create_task(drain_stderr(process.stderr))

        try:
            while not stop_event.is_set():
                if process.returncode is not None:
                    break
                await asyncio.sleep(0.4)
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            await stderr_task
            await reader_task

        if process.returncode not in {0, -15, 143}:
            detail = f" stderr={' | '.join(stderr_lines)}" if stderr_lines else ""
            print(f"live-capture: tcpdump backend exited with status {process.returncode}.{detail}")

    return dropped_counter["count"]


async def run_live_capture(
    interface: str,
    queue: asyncio.Queue[dict[str, Any] | None],
    stop_event: asyncio.Event,
    sensor_id: str = "local",
    *,
    backend: str = "auto",
    tcpdump_bin: str = "tcpdump",
    tcpdump_snaplen: int = 0,
    bpf_filter: str = "",
) -> None:
    """Capture live packets from interface and push normalized events to queue."""
    resolved_backend = _resolve_live_capture_backend(backend, tcpdump_bin)
    dropped = 0

    if resolved_backend == "tcpdump":
        dropped = await _run_tcpdump_capture(
            interface,
            queue,
            stop_event,
            sensor_id=sensor_id,
            tcpdump_bin=tcpdump_bin,
            snaplen=tcpdump_snaplen,
            bpf_filter=bpf_filter,
        )
    else:
        if str(backend or "").strip().lower() == "tcpdump" and not _tcpdump_backend_supported():
            print("live-capture: tcpdump backend is not supported on this platform; falling back to scapy.")
        dropped = await _run_scapy_capture(
            interface,
            queue,
            stop_event,
            sensor_id=sensor_id,
        )

    if dropped > 0:
        print(f"live-capture: dropped {dropped} packets due to full queue")
