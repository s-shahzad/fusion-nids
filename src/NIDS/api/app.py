from __future__ import annotations

from argparse import Namespace
import logging
import platform
from pathlib import Path
import re
import time
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from .assist import AnalyzeAlertsRequest
from .assist import AnalyzeAlertsResponse
from .assist import AssistAlert
from .assist import AssistRunSummary
from .assist import ExplainAlertRequest
from .assist import ExplainAlertResponse
from .assist import SummarizeRunRequest
from .assist import SummarizeRunResponse
from .assist import get_assist_provider
from .dependencies import enforce_rate_limit
from .dependencies import get_universal_nids_api_key
from .dashboard_page import render_dashboard_html
from .ops import InMemoryRateLimiter
from .ops import error_payload
from .ops import log_api_event
from .ops import request_id
from .ops import request_id_from_headers
from .. import __version__
from ..ai.services.explainer_service import ExplainerService
from ..config import build_runtime_config
from ..config import _read_yaml
from ..pipeline.runtime import LocalPipelineResult, run_local_pipeline
from ..privacy import privacy_config_from_env
from ..services.export_service import ExportService
from ..services.run_inspection_service import RunInspectionService


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


class RunLocalRequest(BaseModel):
    pcap_path: str
    rules_path: str | None = None
    config_path: str | None = None
    output_dir: str
    sensor_id: str = "sensor-local"


class RunLocalResponse(BaseModel):
    status: str
    output_dir: str
    flows: int | None
    alerts: int | None
    report_path: str | None
    visuals_path: str | None
    error: str | None = None


class RunSummaryResponse(BaseModel):
    run_name: str
    output_dir: str
    flows: int
    alerts: int
    report_path: str | None
    visuals_path: str | None
    status: str


class AlertRecord(BaseModel):
    timestamp: str | None = None
    severity: str | None = None
    engine: str | None = None
    rule_name: str | None = None
    summary: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    proto: str | None = None
    privacy_metadata: dict[str, Any] | None = None


class RunAlertsResponse(BaseModel):
    run_name: str
    output_dir: str
    limit: int
    count: int
    alerts: list[AlertRecord]


class RouteInfo(BaseModel):
    path: str
    methods: list[str]


class RoutesResponse(BaseModel):
    routes: list[RouteInfo]


class SystemStatusResponse(BaseModel):
    api_health: str
    version: str
    privacy_mode: str
    hot_cold_enabled: bool
    cold_worker_enabled: bool
    latest_run: dict[str, Any] | None = None


class RunListItem(BaseModel):
    run_name: str
    output_dir: str
    status: str
    flows: int
    alerts: int
    modified_at: int
    engine_distribution: dict[str, int]
    severity_distribution: dict[str, int]


class RunsResponse(BaseModel):
    runs: list[RunListItem]


class RunMetricsResponse(BaseModel):
    run_name: str
    output_dir: str
    flows: int
    alerts: int
    report_path: str | None
    visuals_path: str | None
    status: str
    engine_distribution: dict[str, int]
    severity_distribution: dict[str, int]
    baseline_comparison: dict[str, Any]


class ExplainRunRequest(BaseModel):
    compare_run_name: str | None = None
    alert_limit: int = 10


class ExplainRunResponse(BaseModel):
    provider: str
    model: str
    fallback_used: bool
    summary: str
    error: str | None = None


class PortfolioBundleRequest(BaseModel):
    run_name: str
    bundle_name: str | None = None


class PortfolioBundleResponse(BaseModel):
    status: str
    run_name: str
    bundle_name: str
    output_dir: str
    files: list[str]


RATE_LIMITS: dict[tuple[str, str], tuple[int, int]] = {
    ("POST", "/llm/summarize-run"): (10, 60),
    ("POST", "/llm/explain-alert"): (12, 60),
    ("POST", "/llm/analyze-alerts"): (10, 60),
    ("POST", "/exports/portfolio-bundle"): (4, 60),
}


def _dashboard_html() -> str:
    return render_dashboard_html()


def _baseline_profile() -> dict[str, Any]:
    profile_path = _repo_root() / "NIDS_TestLab" / "config" / "offline_replay_profile.yml"
    payload = _read_yaml(profile_path)
    ml_cfg = dict(payload.get("ml") or {})
    fusion_cfg = dict(payload.get("fusion") or {})
    return {
        "ml": {
            "unsupervised_confirmation_hits": int(ml_cfg.get("unsupervised_confirmation_hits", 0)),
        },
        "fusion": {
            "min_agreement_count": int(fusion_cfg.get("min_agreement_count", 0)),
        },
        "validated_result": {
            "flows": 509,
            "alerts": 10,
            "alert_ratio": 0.0196,
            "status": "stable / validated",
        },
    }


def _as_assist_summary(summary: RunSummaryResponse) -> AssistRunSummary:
    return AssistRunSummary(**summary.model_dump())


def _as_assist_alerts(alerts: list[AlertRecord]) -> list[AssistAlert]:
    return [AssistAlert(**alert.model_dump()) for alert in alerts]


def _resolve_repo_path(path_str: str, *, label: str) -> Path:
    repo_root = _repo_root()
    raw = Path(path_str).expanduser()
    path = (repo_root / raw).resolve() if not raw.is_absolute() else raw.resolve()
    try:
        path.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"{label} must stay within the repository root.") from exc
    return path


def _output_root() -> Path:
    return (_repo_root() / "output").resolve()


def _resolve_run_dir(run_name: str) -> Path:
    token = str(run_name).strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", token):
        raise ValueError("run_name contains invalid characters.")
    run_dir = (_output_root() / token).resolve()
    try:
        run_dir.relative_to(_output_root())
    except ValueError as exc:
        raise ValueError("run_name must resolve under the repo output directory.") from exc
    if not run_dir.exists() or not run_dir.is_dir():
        raise FileNotFoundError(f"Run output directory not found: {token}")
    return run_dir


def _validate_output_dir(output_dir: Path) -> Path:
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ValueError("output_dir must be a directory path.")
        if any(output_dir.iterdir()):
            raise ValueError("output_dir must be fresh and empty.")
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _build_run_local_namespace(request: RunLocalRequest) -> Namespace:
    repo_root = _repo_root()
    pcap_path = _resolve_repo_path(request.pcap_path, label="pcap_path")
    rules_path = _resolve_repo_path(request.rules_path, label="rules_path") if request.rules_path else (
        repo_root / "rules" / "rules.yml"
    ).resolve()
    config_path = _resolve_repo_path(request.config_path, label="config_path") if request.config_path else (
        repo_root / "config" / "nids.yml"
    ).resolve()
    output_dir = _validate_output_dir(_resolve_repo_path(request.output_dir, label="output_dir"))
    return Namespace(
        config=str(config_path),
        enable_suricata=False,
        enable_zeek=False,
        interface=None,
        labels=None,
        maintenance_enabled=False,
        maintenance_include_artifacts=False,
        maintenance_interval_hours=None,
        maintenance_retention_days=None,
        maintenance_vacuum=False,
        metrics_interval=None,
        model=None,
        notify_backoff_sec=None,
        notify_dead_letter=None,
        notify_dead_letter_backup_count=None,
        notify_dead_letter_max_bytes=None,
        notify_max_backoff_sec=None,
        notify_max_retries=None,
        notify_min_interval_sec=None,
        notify_min_severity=None,
        notify_timeout_sec=None,
        notify_webhook=None,
        output_dir=str(output_dir),
        pcap_dir=str(pcap_path),
        replay_delay_ms=None,
        rules=str(rules_path),
        sensor_id=request.sensor_id,
        suricata_log=None,
        unsupervised=False,
        unsupervised_threshold=None,
        zeek_log=None,
    )


def _run_local_request(request: RunLocalRequest) -> LocalPipelineResult:
    args = _build_run_local_namespace(request)
    cfg = build_runtime_config(args)
    return run_local_pipeline(
        cfg=cfg,
        labels_path=None,
        sensor_id=str(request.sensor_id),
    )


def _success_response(result: LocalPipelineResult) -> RunLocalResponse:
    return RunLocalResponse(
        status="ok",
        output_dir=str(result.output_dir),
        flows=result.flow_count,
        alerts=result.alert_count,
        report_path=str(result.report_path),
        visuals_path=str(result.visual_index_path),
        error=None,
    )


def _read_summary(run_name: str) -> RunSummaryResponse:
    payload = RunInspectionService(_repo_root()).read_summary(run_name)
    return RunSummaryResponse(**payload)


def _route_listing(app: FastAPI) -> RoutesResponse:
    blocked = {'/docs', '/docs/oauth2-redirect', '/openapi.json', '/redoc'}
    routes: list[RouteInfo] = []
    for route in app.routes:
        path = getattr(route, 'path', '')
        methods = sorted(method for method in getattr(route, 'methods', set()) if method not in {'HEAD', 'OPTIONS'})
        if not path or path in blocked or not methods:
            continue
        routes.append(RouteInfo(path=path, methods=methods))
    routes.sort(key=lambda item: item.path)
    return RoutesResponse(routes=routes)


def _system_status_snapshot(run_service: RunInspectionService) -> SystemStatusResponse:
    config = _read_yaml(_repo_root() / "config" / "nids.yml")
    privacy = privacy_config_from_env()
    latest_run = None
    runs = run_service.list_runs(limit=1)
    if runs:
        latest_run = runs[0]
    pipeline_cfg = dict(config.get("pipeline") or {})
    return SystemStatusResponse(
        api_health="ok",
        version=__version__,
        privacy_mode=privacy.mode,
        hot_cold_enabled=bool(pipeline_cfg.get("enable_hot_cold_pipeline", False)),
        cold_worker_enabled=bool(pipeline_cfg.get("cold_worker_enabled", False)),
        latest_run=latest_run,
    )


def _read_alerts(run_name: str, limit: int) -> RunAlertsResponse:
    payload = RunInspectionService(_repo_root()).read_alerts(run_name, limit=limit)
    records = [
        AlertRecord(
            timestamp=item.get("timestamp"),
            severity=item.get("severity"),
            engine=item.get("engine"),
            rule_name=item.get("rule_name"),
            summary=item.get("summary"),
            src_ip=item.get("src_ip"),
            dst_ip=item.get("dst_ip"),
            proto=item.get("proto"),
            privacy_metadata=item.get("privacy_metadata"),
        )
        for item in payload["alerts"]
    ]
    return RunAlertsResponse(
        run_name=payload["run_name"],
        output_dir=payload["output_dir"],
        limit=payload["limit"],
        count=payload["count"],
        alerts=records,
    )


def _read_metrics(run_name: str) -> RunMetricsResponse:
    payload = RunInspectionService(_repo_root()).read_metrics(run_name)
    return RunMetricsResponse(**payload)


def _list_runs(limit: int) -> RunsResponse:
    runs = RunInspectionService(_repo_root()).list_runs(limit=limit)
    return RunsResponse(runs=[RunListItem(**item) for item in runs])


def _resolve_summary_request(request: SummarizeRunRequest) -> tuple[AssistRunSummary, list[AssistAlert]]:
    if request.run_name:
        summary = _as_assist_summary(_read_summary(request.run_name))
        alerts = _as_assist_alerts(_read_alerts(request.run_name, request.alert_limit).alerts)
        return summary, alerts
    if request.summary is not None:
        return request.summary, []
    raise ValueError("Provide either run_name or summary.")


def _resolve_explain_alert_request(request: ExplainAlertRequest) -> AssistAlert:
    if request.alert is not None:
        return request.alert
    if request.run_name is None:
        raise ValueError("Provide either alert or run_name plus alert_index.")
    if request.alert_index is None:
        raise ValueError("alert_index is required when using run_name.")
    alerts = _read_alerts(request.run_name, request.alert_index + 1).alerts
    if request.alert_index >= len(alerts):
        raise ValueError("alert_index is out of range for the bounded alert set.")
    return AssistAlert(**alerts[request.alert_index].model_dump())


def create_app() -> FastAPI:
    assist_provider = get_assist_provider()
    run_service = RunInspectionService(_repo_root())
    export_service = ExportService(_repo_root(), run_service)
    explainer_service = ExplainerService.from_env()
    limiter = InMemoryRateLimiter()
    app = FastAPI(
        title="Universal NIDS API",
        version=__version__,
        description="Minimal API wrapper for the validated Universal NIDS baseline.",
    )
    app.state.rate_limiter = limiter
    app.state.rate_limit_clock = time.monotonic

    @app.middleware("http")
    async def add_request_id_and_rate_limit(request: Request, call_next: Any) -> JSONResponse | HTMLResponse | Any:
        request.state.request_id = request_id_from_headers(request)
        request.state.started_at = time.time()
        key = RATE_LIMITS.get((request.method.upper(), request.url.path))
        if key is not None:
            limit, window_sec = key
            client_host = request.client.host if request.client and request.client.host else "local"
            bucket_key = f"{request.method.upper()}:{request.url.path}:{client_host}"
            allowed = limiter.allow(bucket_key, limit=limit, window_sec=window_sec, now=app.state.rate_limit_clock())
            if not allowed:
                log_api_event(
                    logging.WARNING,
                    "rate_limit",
                    request=request,
                    limit=limit,
                    window_sec=window_sec,
                )
                payload = error_payload(
                    request,
                    status_code=429,
                    error="rate_limit_exceeded",
                    detail="Too many requests for this route. Try again later.",
                )
                response = JSONResponse(status_code=429, content=payload.model_dump())
                response.headers["X-Request-ID"] = payload.request_id
                return response
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id(request)
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = str(exc.detail)
        if exc.status_code in {401, 503} and request.url.path == "/run-local":
            log_api_event(logging.WARNING, "auth_failure", request=request, detail=detail)
        if exc.status_code == 429:
            log_api_event(logging.WARNING, "rate_limit", request=request, detail=detail)
        payload = error_payload(
            request,
            status_code=int(exc.status_code),
            error="http_error",
            detail=detail,
        )
        response = JSONResponse(status_code=int(exc.status_code), content=payload.model_dump())
        response.headers["X-Request-ID"] = payload.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        payload = error_payload(
            request,
            status_code=422,
            error="validation_error",
            detail=str(exc),
        )
        response = JSONResponse(status_code=422, content=payload.model_dump())
        response.headers["X-Request-ID"] = payload.request_id
        return response

    @app.exception_handler(FileNotFoundError)
    async def file_not_found_handler(request: Request, exc: FileNotFoundError) -> JSONResponse:
        log_api_event(logging.INFO, "missing_run_access", request=request, detail=str(exc))
        payload = error_payload(
            request,
            status_code=404,
            error="not_found",
            detail=str(exc),
        )
        response = JSONResponse(status_code=404, content=payload.model_dump())
        response.headers["X-Request-ID"] = payload.request_id
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        log_api_event(logging.ERROR, "unhandled_error", request=request, detail=str(exc))
        payload = error_payload(
            request,
            status_code=500,
            error="internal_error",
            detail="Internal server error.",
        )
        response = JSONResponse(status_code=500, content=payload.model_dump())
        response.headers["X-Request-ID"] = payload.request_id
        return response

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/version")
    async def version() -> dict[str, str]:
        return {
            "app": "Universal NIDS API",
            "version": __version__,
            "python": platform.python_version(),
        }

    @app.get("/baseline")
    async def baseline() -> dict[str, Any]:
        return _baseline_profile()

    @app.get("/routes", response_model=RoutesResponse)
    async def routes() -> RoutesResponse:
        return _route_listing(app)

    @app.get("/status", response_model=SystemStatusResponse)
    async def status() -> SystemStatusResponse:
        return await run_in_threadpool(_system_status_snapshot, run_service)

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(_dashboard_html())

    @app.get("/runs", response_model=RunsResponse)
    async def runs(limit: int = 12) -> RunsResponse:
        items = await run_in_threadpool(run_service.list_runs, limit=max(1, min(int(limit), 50)))
        return RunsResponse(runs=[RunListItem(**item) for item in items])

    @app.post(
        "/run-local",
        response_model=RunLocalResponse,
        dependencies=[Depends(get_universal_nids_api_key), Depends(enforce_rate_limit(limit=2, window_sec=60))],
    )
    async def run_local(
        request: RunLocalRequest,
        http_request: Request,
    ) -> RunLocalResponse:
        log_api_event(logging.INFO, "run_local_attempt", request=http_request, output_dir=request.output_dir)
        result = await run_in_threadpool(_run_local_request, request)
        log_api_event(
            logging.INFO,
            "run_local_success",
            request=http_request,
            output_dir=str(result.output_dir),
            flows=result.flow_count,
            alerts=result.alert_count,
        )
        return _success_response(result)

    @app.get(
        "/runs/{run_name}/summary",
        response_model=RunSummaryResponse,
        dependencies=[Depends(enforce_rate_limit(limit=30, window_sec=60))],
    )
    async def run_summary(run_name: str, request: Request) -> RunSummaryResponse:
        try:
            return await run_in_threadpool(_read_summary, run_name)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=request, run_name=run_name)
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get(
        "/runs/{run_name}/alerts",
        response_model=RunAlertsResponse,
        dependencies=[Depends(enforce_rate_limit(limit=20, window_sec=60))],
    )
    async def run_alerts(run_name: str, request: Request, limit: int = 10) -> RunAlertsResponse:
        try:
            return await run_in_threadpool(_read_alerts, run_name, limit)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=request, run_name=run_name)
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/runs/{run_name}/metrics", response_model=RunMetricsResponse)
    async def run_metrics(run_name: str, request: Request) -> RunMetricsResponse:
        try:
            payload = await run_in_threadpool(run_service.read_metrics, run_name)
            return RunMetricsResponse(**payload)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=request, run_name=run_name)
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/runs/{run_name}/explain", response_model=ExplainRunResponse)
    async def run_explain(run_name: str, payload: ExplainRunRequest, request: Request) -> ExplainRunResponse:
        try:
            summary = await run_in_threadpool(run_service.read_summary, run_name)
            metrics = await run_in_threadpool(run_service.read_metrics, run_name)
            alerts_payload = await run_in_threadpool(run_service.read_alerts, run_name, payload.alert_limit)
            compare_summary = None
            if payload.compare_run_name:
                compare_summary = await run_in_threadpool(run_service.read_summary, payload.compare_run_name)
            log_api_event(logging.INFO, "run_explain", request=request, run_name=run_name)
            explanation = await run_in_threadpool(
                explainer_service.explain_run,
                summary=summary,
                metrics=metrics,
                alerts=alerts_payload["alerts"],
                compare_summary=compare_summary,
            )
            return ExplainRunResponse(**explanation)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=request, run_name=run_name)
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/exports/portfolio-bundle", response_model=PortfolioBundleResponse)
    async def export_portfolio_bundle(payload: PortfolioBundleRequest, request: Request) -> PortfolioBundleResponse:
        try:
            log_api_event(logging.INFO, "portfolio_bundle_export", request=request, run_name=payload.run_name)
            bundle = await run_in_threadpool(
                export_service.export_portfolio_bundle,
                run_name=payload.run_name,
                bundle_name=payload.bundle_name,
            )
            return PortfolioBundleResponse(**bundle)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=request, run_name=payload.run_name)
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/llm/summarize-run", response_model=SummarizeRunResponse)
    async def llm_summarize_run(request: SummarizeRunRequest, http_request: Request) -> SummarizeRunResponse:
        try:
            log_api_event(
                logging.INFO,
                "llm_summarize_run",
                request=http_request,
                run_name=request.run_name,
                alert_limit=request.alert_limit,
                provider=getattr(assist_provider, "provider_name", "unknown"),
            )
            summary, alerts = await run_in_threadpool(_resolve_summary_request, request)
            return await run_in_threadpool(assist_provider.summarize_run, summary=summary, alerts=alerts)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=http_request, run_name=request.run_name)
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/llm/explain-alert", response_model=ExplainAlertResponse)
    async def llm_explain_alert(request: ExplainAlertRequest, http_request: Request) -> ExplainAlertResponse:
        try:
            log_api_event(
                logging.INFO,
                "llm_explain_alert",
                request=http_request,
                run_name=request.run_name,
                alert_index=request.alert_index,
                provider=getattr(assist_provider, "provider_name", "unknown"),
            )
            alert = await run_in_threadpool(_resolve_explain_alert_request, request)
            return await run_in_threadpool(assist_provider.explain_alert, alert=alert)
        except FileNotFoundError:
            log_api_event(logging.INFO, "missing_run_access", request=http_request, run_name=request.run_name)
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/llm/analyze-alerts", response_model=AnalyzeAlertsResponse)
    async def llm_analyze_alerts(request: AnalyzeAlertsRequest, http_request: Request) -> AnalyzeAlertsResponse:
        try:
            log_api_event(
                logging.INFO,
                "llm_analyze_alerts",
                request=http_request,
                alert_count=len(request.alerts),
                provider=getattr(assist_provider, "provider_name", "unknown"),
            )
            return await run_in_threadpool(assist_provider.analyze_alerts, alerts=request.alerts)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


app = create_app()
