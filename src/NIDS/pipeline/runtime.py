from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import RuntimeConfig
from ..reporting import generate_incident_report
from ..runtime import run_runtime
from ..visuals.export import run_visual_export


@dataclass(frozen=True)
class LocalPipelineResult:
    output_dir: Path
    db_path: Path
    flows_jsonl_path: Path
    alerts_jsonl_path: Path
    metrics_jsonl_path: Path
    report_path: Path
    visual_dir: Path
    visual_index_path: Path
    chart_count: int
    flow_count: int
    alert_count: int
    metric_count: int


def _log_stage(stage: str, message: str) -> None:
    print(f"local-pipeline[{stage}]: {message}")


def _section_enabled(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("enabled", False))
    return bool(value)


def _enabled_adapters(cfg: RuntimeConfig) -> list[str]:
    adapters = dict(cfg.adapters or {})
    enabled: list[str] = []
    for name in ("suricata", "zeek"):
        if _section_enabled(adapters.get(name, {})):
            enabled.append(name)
    return enabled


def _resolve_report_path(output_dir: Path, report_out: str | Path | None) -> Path:
    if report_out is None:
        return (output_dir / "summary.md").resolve()
    return Path(report_out).resolve()


def _resolve_visual_dir(output_dir: Path, visual_out: str | Path | None) -> Path:
    if visual_out is None:
        return (output_dir / "graphs").resolve()
    return Path(visual_out).resolve()


def _count_rows(db_path: Path) -> dict[str, int]:
    counts = {"flows": 0, "alerts": 0, "metrics": 0}
    if not db_path.exists():
        return counts

    with sqlite3.connect(str(db_path)) as conn:
        for table_name in counts:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
            ).fetchone()
            if row is None:
                continue
            counts[table_name] = int(conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0])
    return counts


def _describe_detectors(cfg: RuntimeConfig) -> str:
    engines = ["signature", "anomaly", "ml", "fusion"]
    detector_cfg = dict(cfg.detectors or {})
    if _section_enabled(detector_cfg.get("campaign_behavior", {})):
        engines.append("campaign_behavior")
    if _section_enabled(detector_cfg.get("exfiltration_behavior", {})):
        engines.append("exfiltration_behavior")
    if _section_enabled(cfg.threat_intel):
        engines.append("threat_intel")
    return ", ".join(engines)


def _validate_local_inputs(cfg: RuntimeConfig, labels_path: Path | None) -> Path:
    if cfg.interface:
        raise ValueError("run-local accepts replay input only; live capture is not supported.")

    enabled_adapters = _enabled_adapters(cfg)
    if enabled_adapters:
        joined = ", ".join(enabled_adapters)
        raise ValueError(f"run-local accepts replay input only; adapter ingest is not supported ({joined}).")

    if cfg.pcap_dir is None:
        raise ValueError("run-local requires --pcap-dir for offline replay input.")

    pcap_path = cfg.pcap_dir.resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"Replay input not found: {pcap_path}")

    rules_path = cfg.rules_path.resolve()
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    if labels_path is not None:
        resolved_labels = labels_path.resolve()
        if not resolved_labels.exists():
            raise FileNotFoundError(f"Labels file not found: {resolved_labels}")

    return pcap_path


def run_local_pipeline(
    *,
    cfg: RuntimeConfig,
    labels_path: Path | None = None,
    sensor_id: str = "sensor-local",
    report_out: str | Path | None = None,
    visual_out: str | Path | None = None,
) -> LocalPipelineResult:
    replay_source = _validate_local_inputs(cfg, labels_path)
    output_dir = cfg.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    db_path = (output_dir / "nids.db").resolve()
    flows_jsonl_path = (output_dir / "flows.jsonl").resolve()
    alerts_jsonl_path = (output_dir / "alerts.jsonl").resolve()
    metrics_jsonl_path = (output_dir / "metrics.jsonl").resolve()
    report_path = _resolve_report_path(output_dir, report_out)
    visual_dir = _resolve_visual_dir(output_dir, visual_out)

    _log_stage("ingest", f"replay_source={replay_source}")
    if labels_path is not None:
        _log_stage("ingest", f"labels={labels_path.resolve()}")
    _log_stage(
        "preprocess",
        "normalization=src/NIDS/pipeline/parser.py features=src/NIDS/pipeline/features.py",
    )
    _log_stage("detect", f"engines={_describe_detectors(cfg)}")
    _log_stage("store", f"sqlite={db_path} jsonl_dir={output_dir}")

    try:
        run_runtime(cfg=cfg, labels_path=labels_path, sensor_id=sensor_id)
    except Exception as exc:
        raise RuntimeError(f"runtime stage failed: {exc}") from exc

    if not db_path.exists():
        raise RuntimeError(f"runtime stage completed without creating SQLite output: {db_path}")

    counts = _count_rows(db_path)
    _log_stage(
        "store",
        f"persisted flows={counts['flows']} alerts={counts['alerts']} metrics={counts['metrics']}",
    )

    try:
        report_path = generate_incident_report(from_db=db_path, out=report_path).resolve()
    except Exception as exc:
        raise RuntimeError(f"report stage failed: {exc}") from exc
    _log_stage("report", f"markdown={report_path}")

    try:
        visual_index_path, charts = run_visual_export(db_path=db_path, output_dir=visual_dir)
    except Exception as exc:
        raise RuntimeError(f"visualize stage failed: {exc}") from exc
    visual_index_path = visual_index_path.resolve()
    _log_stage("visualize", f"index={visual_index_path} charts={len(charts)}")
    _log_stage("done", f"db={db_path} report={report_path} visuals={visual_index_path}")

    return LocalPipelineResult(
        output_dir=output_dir,
        db_path=db_path,
        flows_jsonl_path=flows_jsonl_path,
        alerts_jsonl_path=alerts_jsonl_path,
        metrics_jsonl_path=metrics_jsonl_path,
        report_path=report_path,
        visual_dir=visual_dir,
        visual_index_path=visual_index_path,
        chart_count=len(charts),
        flow_count=counts["flows"],
        alert_count=counts["alerts"],
        metric_count=counts["metrics"],
    )
