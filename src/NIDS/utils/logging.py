from __future__ import annotations

import logging
from typing import Optional


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure root logging for the NIDS runtime."""
    normalized = (level or "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, normalized, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    return logging.getLogger("nids")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    if name:
        return logging.getLogger(f"nids.{name}")
    return logging.getLogger("nids")
