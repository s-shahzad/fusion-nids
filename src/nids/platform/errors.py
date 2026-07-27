from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class PlatformError(Exception):
    status_code = 500
    error_code = "platform_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AccessDeniedError(PlatformError):
    status_code = 403
    error_code = "access_denied"


class RouteDisabledError(PlatformError):
    status_code = 403
    error_code = "route_disabled"


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(PlatformError)
    async def _handle_platform_error(_: Request, exc: PlatformError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.error_code, "message": exc.message},
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": str(exc)},
        )
