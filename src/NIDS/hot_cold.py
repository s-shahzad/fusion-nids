from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable


ColdTask = tuple[str, Callable[..., Any], tuple[Any, ...], dict[str, Any], float]


@dataclass
class ColdPathStats:
    submitted: int = 0
    completed: int = 0
    failed: int = 0
    lag_samples_ms: list[float] = field(default_factory=list)
    queue_depth_peak: int = 0


class ColdPathWorker:
    def __init__(self, *, enabled: bool, queue_maxsize: int = 32) -> None:
        self.enabled = bool(enabled)
        self._queue: queue.Queue[ColdTask | None] = queue.Queue(maxsize=max(1, int(queue_maxsize)))
        self._stats = ColdPathStats()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="nids-cold-worker", daemon=True)
        if self.enabled:
            self._thread.start()

    def submit(self, name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> bool:
        if not self.enabled:
            return False
        enqueued_at = time.perf_counter()
        self._queue.put((name, fn, args, kwargs, enqueued_at))
        with self._lock:
            self._stats.submitted += 1
            self._stats.queue_depth_peak = max(self._stats.queue_depth_peak, int(self._queue.qsize()))
        return True

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                _name, fn, args, kwargs, enqueued_at = item
                lag_ms = max(0.0, (time.perf_counter() - enqueued_at) * 1000.0)
                try:
                    fn(*args, **kwargs)
                    with self._lock:
                        self._stats.completed += 1
                        self._stats.lag_samples_ms.append(lag_ms)
                except Exception:
                    with self._lock:
                        self._stats.failed += 1
                        self._stats.lag_samples_ms.append(lag_ms)
            finally:
                self._queue.task_done()

    def drain(self, timeout: float | None = None) -> None:
        if not self.enabled:
            return
        end = None if timeout is None else time.monotonic() + float(timeout)
        while self._queue.unfinished_tasks > 0:
            if end is not None and time.monotonic() >= end:
                break
            time.sleep(0.05)

    def stop(self, *, wait: bool = True, timeout: float = 5.0) -> None:
        if not self.enabled:
            return
        if wait:
            self.drain(timeout=timeout)
        self._queue.put(None)
        self._thread.join(timeout=max(0.1, float(timeout)))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            lags = list(self._stats.lag_samples_ms)
            return {
                "enabled": self.enabled,
                "submitted": self._stats.submitted,
                "completed": self._stats.completed,
                "failed": self._stats.failed,
                "queue_depth": int(self._queue.qsize()) if self.enabled else 0,
                "queue_depth_peak": self._stats.queue_depth_peak,
                "avg_lag_ms": round(sum(lags) / len(lags), 3) if lags else 0.0,
                "max_lag_ms": round(max(lags), 3) if lags else 0.0,
            }
