from __future__ import annotations

from ..platform.health import HealthStatus
from ..platform.settings import PlatformSettings


class HealthService:
    def __init__(self, settings: PlatformSettings) -> None:
        self.settings = settings

    def live(self) -> HealthStatus:
        return HealthStatus(name="api", ok=True, detail="process alive")

    def ready(self) -> list[HealthStatus]:
        checks = [
            HealthStatus(
                name="output_dir",
                ok=self.settings.output_dir.exists(),
                detail=str(self.settings.output_dir),
            ),
            HealthStatus(
                name="sqlite",
                ok=self.settings.storage_backend != "sqlite" or self.settings.sqlite_path.exists(),
                detail=str(self.settings.sqlite_path),
            ),
        ]
        return checks
