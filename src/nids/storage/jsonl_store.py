from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JSONLStore:
    """Append-only JSONL outputs for alerts, flows, and metrics."""

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.alerts_path = self.output_dir / "alerts.jsonl"
        self.flows_path = self.output_dir / "flows.jsonl"
        self.metrics_path = self.output_dir / "metrics.jsonl"

    @staticmethod
    def _line(payload: dict[str, Any]) -> str:
        return json.dumps(payload, ensure_ascii=True)

    def append_alert(self, payload: dict[str, Any]) -> None:
        with self.alerts_path.open("a", encoding="utf-8") as handle:
            handle.write(self._line(payload) + "\n")

    def append_flow(self, payload: dict[str, Any]) -> None:
        with self.flows_path.open("a", encoding="utf-8") as handle:
            handle.write(self._line(payload) + "\n")

    def append_metric(self, payload: dict[str, Any]) -> None:
        with self.metrics_path.open("a", encoding="utf-8") as handle:
            handle.write(self._line(payload) + "\n")
