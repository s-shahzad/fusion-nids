from __future__ import annotations

import threading
import time

from src.NIDS.hot_cold import ColdPathWorker


def test_queue_handoff_and_completion() -> None:
    worker = ColdPathWorker(enabled=True, queue_maxsize=4)
    seen: list[str] = []
    worker.submit("task-a", lambda: seen.append("done"))
    worker.drain(timeout=2.0)
    snapshot = worker.snapshot()
    worker.stop(wait=False)
    assert seen == ["done"]
    assert snapshot["submitted"] == 1
    assert snapshot["completed"] == 1


def test_cold_task_failure_does_not_break_worker() -> None:
    worker = ColdPathWorker(enabled=True, queue_maxsize=4)
    marker = threading.Event()

    def _boom() -> None:
        raise RuntimeError("expected failure")

    worker.submit("bad", _boom)
    worker.submit("good", marker.set)
    worker.drain(timeout=2.0)
    snapshot = worker.snapshot()
    worker.stop(wait=False)
    assert marker.is_set() is True
    assert snapshot["failed"] == 1
    assert snapshot["completed"] == 1


def test_hot_artifact_can_exist_before_cold_drain(tmp_path) -> None:
    worker = ColdPathWorker(enabled=True, queue_maxsize=2)
    hot_path = tmp_path / "alerts.json"
    cold_path = tmp_path / "report.md"
    hot_path.write_text("[]", encoding="utf-8")

    def _slow_write() -> None:
        time.sleep(0.2)
        cold_path.write_text("# report\n", encoding="utf-8")

    worker.submit("slow-report", _slow_write)
    assert hot_path.exists()
    assert cold_path.exists() is False
    worker.drain(timeout=2.0)
    worker.stop(wait=False)
    assert cold_path.exists() is True
