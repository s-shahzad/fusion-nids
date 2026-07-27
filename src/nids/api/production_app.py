from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from .router_v1 import router as v1_router
from ..platform.errors import register_exception_handlers
from ..platform.logging_config import configure_logging
from ..platform.settings import PlatformSettings
from ..services.health_service import HealthService


def create_app() -> FastAPI:
    settings = PlatformSettings.from_env()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Universal NIDS Production API",
        version="1.0.0-scaffold",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.settings = settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts or ["127.0.0.1", "localhost"])
    register_exception_handlers(app)
    app.include_router(v1_router)

    @app.get("/health/live", tags=["health"])
    def health_live() -> dict:
        status = HealthService(settings).live()
        return {"name": status.name, "ok": status.ok, "detail": status.detail}

    @app.get("/health/ready", tags=["health"])
    def health_ready() -> dict:
        checks = HealthService(settings).ready()
        return {
            "ok": all(item.ok for item in checks),
            "checks": [{"name": item.name, "ok": item.ok, "detail": item.detail} for item in checks],
        }

    return app
