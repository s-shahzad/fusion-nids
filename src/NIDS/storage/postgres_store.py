from __future__ import annotations

from pathlib import Path


class PostgreSQLStore:
    """
    Migration-preparation stub.

    This class exists to define the future integration point for PostgreSQL
    without changing the validated SQLite-based runtime path today.
    """

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def healthcheck(self) -> bool:
        raise NotImplementedError("PostgreSQL support is scaffolded but not implemented yet.")

    def generate_incident_markdown(self, out_path: str | Path) -> Path:
        raise NotImplementedError("PostgreSQL-backed reporting is not implemented yet.")
