from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .base import AIResponse


@dataclass(frozen=True)
class OllamaProvider:
    base_url: str
    model_name: str
    timeout_seconds: float = 8.0
    enabled: bool = True

    @classmethod
    def from_env(cls) -> "OllamaProvider":
        enabled = str(os.getenv("NIDS_OLLAMA_ENABLED", "false")).strip().lower() in {"1", "true", "yes", "on"}
        base_url = str(os.getenv("NIDS_OLLAMA_BASE_URL", "http://localhost:11434")).strip().rstrip("/")
        model_name = str(os.getenv("NIDS_OLLAMA_MODEL", "llama3.1:8b")).strip() or "llama3.1:8b"
        timeout_seconds = float(os.getenv("NIDS_OLLAMA_TIMEOUT_SECONDS", "8"))
        return cls(base_url=base_url, model_name=model_name, timeout_seconds=timeout_seconds, enabled=enabled)

    @property
    def provider_name(self) -> str:
        return "ollama"

    def available(self) -> bool:
        if not self.enabled:
            return False
        request = urllib.request.Request(
            f"{self.base_url}/api/tags",
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return int(getattr(response, "status", 0) or 0) == 200
        except Exception:
            return False

    def generate(self, *, prompt: str) -> AIResponse:
        payload = json.dumps(
            {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc
        data = json.loads(body or "{}")
        return AIResponse(provider=self.provider_name, model=self.model_name, text=str(data.get("response") or "").strip())
