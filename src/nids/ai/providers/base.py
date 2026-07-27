from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class AIResponse:
    provider: str
    model: str
    text: str


class ExplainProvider(Protocol):
    provider_name: str
    model_name: str

    def available(self) -> bool: ...

    def generate(self, *, prompt: str) -> AIResponse: ...
