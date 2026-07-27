from __future__ import annotations

from dataclasses import dataclass


@dataclass
class HealthStatus:
    name: str
    ok: bool
    detail: str
