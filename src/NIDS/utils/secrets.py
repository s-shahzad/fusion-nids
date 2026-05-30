from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable


_LOADED_DOTENV_PATHS: set[Path] = set()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _candidate_dotenv_paths() -> list[Path]:
    candidates = [Path.cwd() / ".env", _repo_root() / ".env"]
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def _strip_optional_quotes(value: str) -> str:
    token = value.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _load_dotenv(path: Path) -> None:
    resolved = path.resolve()
    if resolved in _LOADED_DOTENV_PATHS:
        return
    _LOADED_DOTENV_PATHS.add(resolved)
    if not resolved.exists():
        return

    for raw_line in resolved.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        env_name = key.strip()
        if not env_name:
            continue
        os.environ.setdefault(env_name, _strip_optional_quotes(raw_value))


def _load_known_dotenvs() -> None:
    for path in _candidate_dotenv_paths():
        _load_dotenv(path)


def get_secret(
    name: str,
    default: str | None = None,
    *,
    required: bool = False,
    aliases: Iterable[str] = (),
) -> str | None:
    _load_known_dotenvs()

    for env_name in (name, *aliases):
        value = os.getenv(env_name)
        if value is not None and str(value).strip() != "":
            return value

    if required:
        candidates = ", ".join([name, *aliases])
        raise ValueError(f"Missing required secret. Set one of: {candidates}")

    return default
