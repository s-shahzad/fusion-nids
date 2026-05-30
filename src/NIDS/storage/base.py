from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class AlertReader(Protocol):
    def recent_alerts(self, *, limit: int = 50, severity: str | None = None, engine: str | None = None) -> list[dict[str, Any]]:
        ...


class ReportWriter(Protocol):
    def generate_incident_markdown(self, out_path: str | Path) -> Path:
        ...
