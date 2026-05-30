from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> None:
    repo_root = _repo_root()
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from src.NIDS.api.app import app

    host = os.getenv("NIDS_API_HOST", "127.0.0.1")
    port = int(os.getenv("NIDS_API_PORT", "8010"))
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=os.getenv("NIDS_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
