from __future__ import annotations

import asyncio
import ctypes
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import RuntimeConfig
from .runtime import NIDSRuntime


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _to_epoch(value: Any) -> float | None:
    token = str(value or "").strip()
    if not token:
        return None
    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def list_available_interfaces() -> list[str]:
    try:
        from scapy.config import conf
    except Exception:
        return []

    names: list[str] = []
    try:
        loopback = str(getattr(conf, "loopback_name", "") or "")
        if loopback:
            names.append(loopback)
        for iface in conf.ifaces.values():
            name = str(getattr(iface, "name", "") or "")
            if name:
                names.append(name)
    except Exception:
        return []

    ordered: list[str] = []
    seen: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(name)
    return ordered


def validate_interface(selected: str | None) -> str:
    token = str(selected or "").strip()
    available = list_available_interfaces()
    if not token or token.lower() == "auto":
        return autodetect_interface(selected)
    if not available:
        return token
    if any(token.lower() == name.lower() for name in available):
        return next(name for name in available if token.lower() == name.lower())
    raise ValueError(f"invalid capture interface: {token}. available interfaces: {', '.join(available)}")


def autodetect_interface(preferred: str | None = None) -> str:
    token = str(preferred or "").strip()
    if token and token.lower() != "auto":
        return validate_interface(token)

    available = list_available_interfaces()
    for candidate in available:
        lowered = candidate.lower()
        if "loopback" in lowered or lowered in {"lo", "lo0", "npcap loopback adapter"}:
            return candidate
    return available[0] if available else "lo"


def detect_capture_privileges() -> tuple[bool, str]:
    try:
        if os.name == "nt":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            if is_admin:
                return True, ""
            return False, "live capture may require Administrator privileges on Windows"
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid) and int(geteuid()) != 0:
            return False, "live capture may require root privileges on this platform"
    except Exception:
        return False, "unable to verify live capture privileges; interface sniffing may need admin/root access"
    return True, ""


@dataclass
class LiveMetrics:
    total_packets: int = 0
    processed_packets: int = 0
    dropped_packets: int = 0
    alerts_generated: int = 0
    runtime_duration: float = 0.0
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    avg_batch_processing_time_ms: float = 0.0
    max_batch_processing_time_ms: float = 0.0
    queue_depth_peak: int = 0
    packets_captured: int = 0
    packets_processed_runtime: int = 0
    packets_dropped_detectable: int = 0
    privilege_ok: bool = True
    privilege_warning: str = ""
    interface: str = ""
    available_interfaces: list[str] = field(default_factory=list)
    alert_latency_samples: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class LiveCaptureController:
    runtime: NIDSRuntime
    thread: threading.Thread
    interface: str
    batch_size: int
    duration: float | None = None
    available_interfaces: list[str] = field(default_factory=list)
    privilege_ok: bool = True
    privilege_warning: str = ""
    started_at_monotonic: float = field(default_factory=time.monotonic)
    _finished: threading.Event = field(default_factory=threading.Event)
    _stop_lock: threading.Lock = field(default_factory=threading.Lock)
    _metrics_lock: threading.Lock = field(default_factory=threading.Lock)
    _error: BaseException | None = None
    _processing_times_ms: list[float] = field(default_factory=list)
    _latency_samples_ms: list[float] = field(default_factory=list)
    _alert_latency_samples: list[dict[str, Any]] = field(default_factory=list)
    _queue_depth_peak: int = 0

    @property
    def error(self) -> BaseException | None:
        return self._error

    @property
    def is_running(self) -> bool:
        return self.thread.is_alive() and not self.runtime.stop_event.is_set()

    def record_event_metrics(
        self,
        *,
        queue_depth: int,
        processing_time_ms: float,
        event_timestamp: Any,
        new_alerts: int,
    ) -> None:
        with self._metrics_lock:
            self._queue_depth_peak = max(self._queue_depth_peak, int(queue_depth))
            self._processing_times_ms.append(float(processing_time_ms))
            if new_alerts <= 0:
                return
            capture_epoch = _to_epoch(event_timestamp)
            generated_at = _utc_now_iso()
            generated_epoch = _to_epoch(generated_at) or time.time()
            latency_ms = 0.0
            if capture_epoch is not None:
                latency_ms = max(0.0, (generated_epoch - capture_epoch) * 1000.0)
            for _ in range(int(new_alerts)):
                self._latency_samples_ms.append(latency_ms)
                self._alert_latency_samples.append(
                    {
                        "capture_timestamp": str(event_timestamp or ""),
                        "alert_generated_timestamp": generated_at,
                        "detection_latency_ms": round(latency_ms, 3),
                    }
                )

    def stop(self, timeout: float = 15.0) -> None:
        with self._stop_lock:
            self.runtime.stop_event.set()
        self.thread.join(timeout=max(0.1, float(timeout)))
        self._finished.set()
        if self.thread.is_alive():
            raise TimeoutError("live runtime did not stop cleanly within timeout")
        if self._error is not None:
            raise RuntimeError(f"live runtime failed: {self._error}") from self._error

    def snapshot(self) -> dict[str, Any]:
        telemetry = {}
        if self.runtime.live_capture_telemetry is not None:
            telemetry = self.runtime.live_capture_telemetry.snapshot(
                backend=str(self.runtime.cfg.pipeline.get("live_capture_backend", "auto"))
            )
        with self._metrics_lock:
            processing_times = list(self._processing_times_ms)
            latencies = list(self._latency_samples_ms)
            alert_samples = list(self._alert_latency_samples)
            queue_depth_peak = int(self._queue_depth_peak)
        return {
            "interface": self.interface,
            "available_interfaces": list(self.available_interfaces),
            "privilege_ok": bool(self.privilege_ok),
            "privilege_warning": self.privilege_warning,
            "batch_size": int(self.batch_size),
            "duration_seconds": None if self.duration is None else float(self.duration),
            "running": self.is_running,
            "queue_depth": int(self.runtime.queue.qsize()),
            "queue_depth_peak": queue_depth_peak,
            "events_seen": int(self.runtime.stats.events_seen),
            "alerts_emitted": int(self.runtime.stats.alerts_emitted),
            "packets_captured": int(telemetry.get("packets_received", 0)),
            "packets_processed": int(telemetry.get("packets_processed", 0)),
            "packets_dropped": int(telemetry.get("total_dropped_packets", 0)),
            "avg_batch_processing_time_ms": round(sum(processing_times) / len(processing_times), 3) if processing_times else 0.0,
            "max_batch_processing_time_ms": round(max(processing_times), 3) if processing_times else 0.0,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "max_latency_ms": round(max(latencies), 3) if latencies else 0.0,
            "alert_latency_samples": alert_samples,
            "telemetry": telemetry,
        }

    def build_metrics(self) -> LiveMetrics:
        snapshot = self.snapshot()
        return LiveMetrics(
            total_packets=int(snapshot["packets_captured"]),
            processed_packets=int(snapshot["packets_processed"]),
            dropped_packets=int(snapshot["packets_dropped"]),
            alerts_generated=int(snapshot["alerts_emitted"]),
            runtime_duration=round(time.monotonic() - self.started_at_monotonic, 3),
            avg_latency_ms=float(snapshot["avg_latency_ms"]),
            max_latency_ms=float(snapshot["max_latency_ms"]),
            avg_batch_processing_time_ms=float(snapshot["avg_batch_processing_time_ms"]),
            max_batch_processing_time_ms=float(snapshot["max_batch_processing_time_ms"]),
            queue_depth_peak=int(snapshot["queue_depth_peak"]),
            packets_captured=int(snapshot["packets_captured"]),
            packets_processed_runtime=int(snapshot["packets_processed"]),
            packets_dropped_detectable=int(snapshot["packets_dropped"]),
            privilege_ok=bool(snapshot["privilege_ok"]),
            privilege_warning=str(snapshot["privilege_warning"]),
            interface=str(snapshot["interface"]),
            available_interfaces=list(snapshot["available_interfaces"]),
            alert_latency_samples=list(snapshot["alert_latency_samples"]),
        )


_active_controller: LiveCaptureController | None = None


def _instrument_runtime(controller: LiveCaptureController) -> None:
    original = getattr(controller.runtime, "_process_event", None)
    if not callable(original):
        return

    def instrumented(event: dict[str, Any]) -> None:
        queue_depth_before = int(controller.runtime.queue.qsize())
        alerts_before = int(controller.runtime.stats.alerts_emitted)
        started = time.perf_counter()
        original(event)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        alerts_after = int(controller.runtime.stats.alerts_emitted)
        controller.record_event_metrics(
            queue_depth=queue_depth_before,
            processing_time_ms=elapsed_ms,
            event_timestamp=event.get("timestamp"),
            new_alerts=max(0, alerts_after - alerts_before),
        )

    controller.runtime._process_event = instrumented  # type: ignore[method-assign]


def _runtime_thread_target(controller: LiveCaptureController) -> None:
    try:
        asyncio.run(controller.runtime.run())
    except BaseException as exc:  # pragma: no cover
        controller._error = exc
    finally:
        controller._finished.set()


def start_live_capture(
    interface: str,
    *,
    cfg: RuntimeConfig,
    sensor_id: str = "sensor-live",
    duration: float | None = None,
    batch_size: int = 50,
) -> LiveCaptureController:
    global _active_controller

    available = list_available_interfaces()
    privilege_ok, privilege_warning = detect_capture_privileges()
    resolved_interface = validate_interface(interface)
    cfg.interface = resolved_interface
    cfg.pcap_dir = None
    cfg.pipeline = dict(cfg.pipeline)
    cfg.pipeline["live_capture_backend"] = "scapy"
    cfg.pipeline["live_batch_size"] = int(max(1, int(batch_size)))

    runtime = NIDSRuntime(cfg=cfg, sensor_id=sensor_id)
    runtime._capture_fusion_trace = bool(cfg.pipeline.get("enable_fusion_trace", False))
    controller = LiveCaptureController(
        runtime=runtime,
        thread=threading.Thread(target=lambda: None),
        interface=resolved_interface,
        batch_size=int(max(1, int(batch_size))),
        duration=None if duration is None else float(duration),
        available_interfaces=available,
        privilege_ok=privilege_ok,
        privilege_warning=privilege_warning,
    )
    _instrument_runtime(controller)
    controller.thread = threading.Thread(
        target=_runtime_thread_target,
        args=(controller,),
        name="nids-live-runtime",
        daemon=True,
    )
    if not privilege_ok and privilege_warning:
        print(f"live-capture: warning: {privilege_warning}. Try running as Administrator/root.", flush=True)
    controller.thread.start()

    if duration is not None:
        timer = threading.Timer(float(duration), controller.runtime.stop_event.set)
        timer.daemon = True
        timer.start()

    _active_controller = controller
    return controller


def stop_live_capture(timeout: float = 15.0) -> None:
    global _active_controller
    controller = _active_controller
    if controller is None:
        return
    try:
        controller.stop(timeout=timeout)
    finally:
        _active_controller = None


def process_packet_batch(controller: LiveCaptureController | None = None) -> dict[str, Any]:
    active = controller or _active_controller
    if active is None:
        return {
            "running": False,
            "batch_size": 0,
            "queue_depth": 0,
            "queue_depth_peak": 0,
            "events_seen": 0,
            "alerts_emitted": 0,
            "packets_captured": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "avg_batch_processing_time_ms": 0.0,
            "max_batch_processing_time_ms": 0.0,
            "avg_latency_ms": 0.0,
            "max_latency_ms": 0.0,
            "telemetry": {},
        }
    return active.snapshot()
