from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_list(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class PlatformSettings:
    env: str
    output_dir: Path
    sqlite_path: Path
    storage_backend: str
    postgres_dsn: str | None
    api_host: str
    api_port: int
    api_token: str | None
    action_token: str | None
    allow_remote_api: bool
    allow_mutating_routes: bool
    trusted_hosts: list[str]
    log_level: str

    @classmethod
    def from_env(cls) -> "PlatformSettings":
        output_dir = Path(os.getenv("NIDS_OUTPUT_DIR", "output")).resolve()
        sqlite_path = Path(os.getenv("NIDS_SQLITE_PATH", str(output_dir / "nids.db"))).resolve()
        return cls(
            env=os.getenv("NIDS_ENV", "local"),
            output_dir=output_dir,
            sqlite_path=sqlite_path,
            storage_backend=os.getenv("NIDS_STORAGE_BACKEND", "sqlite").strip().lower(),
            postgres_dsn=os.getenv("NIDS_POSTGRES_DSN") or None,
            api_host=os.getenv("NIDS_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("NIDS_API_PORT", "8080")),
            api_token=os.getenv("NIDS_API_TOKEN") or None,
            action_token=os.getenv("NIDS_ACTION_TOKEN") or None,
            allow_remote_api=_as_bool(os.getenv("NIDS_ALLOW_REMOTE_API"), False),
            allow_mutating_routes=_as_bool(os.getenv("NIDS_ALLOW_MUTATING_ROUTES"), False),
            trusted_hosts=_as_list(os.getenv("NIDS_TRUSTED_HOSTS"), ["127.0.0.1", "localhost"]),
            log_level=os.getenv("NIDS_LOG_LEVEL", "INFO").upper(),
        )
