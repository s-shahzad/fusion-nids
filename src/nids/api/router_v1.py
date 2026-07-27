from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from .dependencies import require_read_access, require_write_access
from ..services.report_service import ReportService


router = APIRouter(prefix="/v1", tags=["production"])


class RecentAlertsResponse(BaseModel):
    count: int
    alerts: list[dict]


class GenerateIncidentReportRequest(BaseModel):
    out_path: str = Field(default="reports/summary.md", min_length=1, max_length=260)


class GenerateIncidentReportResponse(BaseModel):
    out_path: str


@router.get("/alerts/recent", response_model=RecentAlertsResponse, dependencies=[Depends(require_read_access)])
def get_recent_alerts(
    request: Request,
    limit: int = 50,
    severity: str | None = None,
    engine: str | None = None,
) -> RecentAlertsResponse:
    service = ReportService(request.app.state.settings)
    alerts = service.recent_alerts(limit=limit, severity=severity, engine=engine)
    return RecentAlertsResponse(count=len(alerts), alerts=alerts)


@router.post(
    "/reports/incident",
    response_model=GenerateIncidentReportResponse,
    dependencies=[Depends(require_write_access)],
)
def generate_incident_report_endpoint(
    request: Request,
    payload: GenerateIncidentReportRequest,
) -> GenerateIncidentReportResponse:
    service = ReportService(request.app.state.settings)
    out_path = service.generate_incident_markdown(Path(payload.out_path))
    return GenerateIncidentReportResponse(out_path=str(out_path))
