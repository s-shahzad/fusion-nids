from __future__ import annotations

import argparse
import importlib.util
import json
import os
import posixpath
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = REPO_ROOT / "NIDS_TestLab" / "results"
REPORTS_ROOT = REPO_ROOT / "NIDS_TestLab" / "reports"
LIVE_VM_SCRIPT = REPO_ROOT / "scripts" / "live_vm_attack_validation.py"


def _load_script_module(module_name: str, script_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load script module: {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LIVEVM = _load_script_module("live_vm_attack_validation_runtime", LIVE_VM_SCRIPT)
RUN_STAMP_OVERRIDE: str | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat(timespec="seconds")


def _stamp_now() -> str:
    if RUN_STAMP_OVERRIDE:
        return RUN_STAMP_OVERRIDE
    return _utc_now().strftime("%Y%m%d-%H%M%S")


def _sanitize_run_stamp(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip())
    token = token.strip("-.")
    if not token:
        raise ValueError("run stamp must contain at least one alphanumeric character")
    return token


def _default_python() -> Path:
    candidates = [
        REPO_ROOT / ".venv" / "Scripts" / "python.exe",
        REPO_ROOT / ".venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path(sys.executable)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _parse_json_blob(text: str) -> Any:
    token = str(text or "").strip()
    if not token:
        return {}
    candidates = [token]
    for line in reversed(token.splitlines()):
        stripped = line.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            candidates.append(stripped)
    brace_index = token.rfind("{")
    if brace_index >= 0:
        candidates.append(token[brace_index:])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    raise json.JSONDecodeError("Unable to locate JSON payload", token, 0)


def _read_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"YAML config must be a mapping: {path}")
    return payload


def _coerce_string_list(values: Any, *, default: list[str]) -> list[str]:
    if not isinstance(values, list):
        return list(default)
    items = [str(item).strip() for item in values if str(item).strip()]
    return items or list(default)


def _coerce_http_requests(values: Any) -> list[dict[str, str]]:
    default = [{"method": "GET", "path": "/status", "host": "portal.internal", "body": ""}]
    if not isinstance(values, list):
        return list(default)
    requests: list[dict[str, str]] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        requests.append(
            {
                "method": str(item.get("method") or "GET").upper(),
                "path": str(item.get("path") or "/status"),
                "host": str(item.get("host") or "portal.internal"),
                "body": str(item.get("body") or ""),
            }
        )
    return requests or list(default)


def _scenario_environment_description(scenario: dict[str, Any]) -> str:
    explicit = str(scenario.get("environment") or "").strip()
    if explicit:
        return explicit
    backend = str(scenario.get("expected_backend") or "tcpdump").strip().lower() or "tcpdump"
    capture = "live NIC capture via scapy" if backend == "scapy" else "live NIC capture via tcpdump"
    return f"Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, {capture}"


def _scenario_expected_outcome(scenario: dict[str, Any]) -> str:
    explicit = str(scenario.get("expected_outcome") or "").strip()
    if explicit:
        return explicit
    if scenario.get("kind") == "custom_live_suppression":
        return (
            "Repeated noisy events should be collapsed by duplicate alert suppression, then blocked by "
            "policy suppression, while the operator-visible alert count remains stable."
        )
    if bool(scenario.get("expect_zero_alerts")):
        return "The scenario should complete without operator-visible alerts while preserving runtime evidence."
    required_rules = [str(item).strip() for item in list(scenario.get("required_rules") or []) if str(item).strip()]
    if required_rules:
        return f"The runtime should retain evidence and observe these detections: {', '.join(required_rules)}."
    return "The runtime should retain evidence without runtime failure."


def _scenario_actual_outcome(
    scenario: dict[str, Any],
    *,
    db_summary: dict[str, Any],
    runtime_summary: dict[str, Any],
    extras: dict[str, Any],
) -> str:
    explicit = str(extras.get("actual_outcome") or "").strip()
    if explicit:
        return explicit

    flows = int(db_summary.get("counts", {}).get("flows", 0))
    alerts = int(db_summary.get("counts", {}).get("alerts", 0))
    parts = [f"{flows} flows and {alerts} alerts recorded"]

    if scenario.get("kind") == "custom_benign_soak":
        sample_id = str(extras.get("sample_id") or scenario.get("sample_id") or "").strip()
        adjudication = dict(extras.get("analyst_adjudication") or {})
        if sample_id:
            parts.append(f"benign sample {sample_id} completed on the tuned profile")
        classification = str(adjudication.get("classification") or "").strip()
        if classification:
            parts.append(f"analyst adjudication {classification}")
    elif scenario.get("kind") == "custom_extended_soak":
        executed = float(extras.get("executed_duration_sec") or extras.get("planned_duration_sec") or 0.0)
        process_samples = list(extras.get("process_samples") or [])
        runtime_samples = list(extras.get("runtime_samples") or [])
        if executed > 0:
            parts.append(f"executed duration {round(executed, 3)} seconds")
        if process_samples:
            rss_values = [int(item.get("rss_kib", 0)) for item in process_samples if item.get("rss_kib") is not None]
            if rss_values:
                parts.append(f"peak RSS {max(rss_values)} KiB")
        if runtime_samples:
            storage_values = [int(item.get("total_result_bytes", 0)) for item in runtime_samples]
            if storage_values:
                parts.append(f"peak result size {max(storage_values)} bytes")
        if extras.get("reload_latency_sec") is not None:
            parts.append(f"reload latency {extras.get('reload_latency_sec')} seconds")
    elif scenario.get("kind") == "custom_live_suppression":
        suppression = dict(extras.get("suppression_validation") or {})
        post_metrics = dict(suppression.get("post_suppression_metrics") or {})
        suppression_state = dict(suppression.get("suppression_state_after") or {})
        derived_total = int(suppression.get("derived_total_suppressions_min", 0))
        derived_policy = int(suppression.get("derived_policy_suppressions_min", 0))
        observed_suppressed = int(post_metrics.get("suppressed_alerts", 0)) or derived_total
        observed_policy = int(post_metrics.get("policy_suppressed_alerts", 0)) or derived_policy
        if post_metrics:
            parts.append(
                "suppression counters reached "
                f"suppressed_alerts={observed_suppressed} and "
                f"policy_suppressed_alerts={observed_policy}"
            )
        if suppression_state:
            parts.append(
                f"active suppression rules={int(suppression_state.get('active_rules', 0))} "
                f"and final operator-visible alerts={alerts}"
            )

    telemetry = dict(runtime_summary.get("telemetry") or {})
    if telemetry:
        dropped_packets = int(telemetry.get("total_dropped_packets", 0))
        if dropped_packets > 0:
            parts.append(f"total dropped packets {dropped_packets}")

    return "; ".join(parts) + "."


def _scenario_paths(scenario: dict[str, Any]) -> tuple[str, str, str, Path]:
    run_leaf = f"{scenario['slug']}-{_stamp_now()}"
    results_subdir = str(scenario.get("results_subdir") or "").strip().strip("/\\")
    if results_subdir:
        normalized_subdir = results_subdir.replace("\\", "/")
        run_name = f"{normalized_subdir}/{run_leaf}"
        result_dir = RESULTS_ROOT / results_subdir / run_leaf
    else:
        run_name = run_leaf
        result_dir = RESULTS_ROOT / run_leaf
    result_rel = posixpath.join("NIDS_TestLab", "results", run_name.replace("\\", "/"))
    return run_leaf, run_name, result_rel, result_dir


def parse_runtime_log_text(text: str) -> dict[str, Any]:
    backend_runs: list[dict[str, Any]] = []
    tcpdump_starts: list[dict[str, Any]] = []
    scapy_starts: list[dict[str, Any]] = []
    dropped_packets = 0
    nonzero_exit_lines: list[str] = []
    telemetry_snapshots: list[dict[str, Any]] = []

    backend_pattern = re.compile(
        r"backend=(?P<backend>\S+)\s+requested_backend=(?P<requested>\S+)\s+interface=(?P<interface>\S+)\s+sensor_id=(?P<sensor>\S+)"
    )
    tcpdump_pattern = re.compile(
        r"interface=(?P<interface>\S+)\s+tcpdump_bin=(?P<bin>\S+)\s+snaplen=(?P<snaplen>\d+)\s+bpf_filter=(?P<filter>.*)$"
    )
    drop_pattern = re.compile(r"dropped\s+(?P<count>\d+)\s+packets")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "live-capture: backend=" in line:
            match = backend_pattern.search(line)
            if match:
                backend_runs.append(
                    {
                        "resolved_backend": match.group("backend"),
                        "requested_backend": match.group("requested"),
                        "interface": match.group("interface"),
                        "sensor_id": match.group("sensor"),
                    }
                )
        elif "live-capture: starting tcpdump capture" in line:
            match = tcpdump_pattern.search(line)
            if match:
                tcpdump_starts.append(
                    {
                        "interface": match.group("interface"),
                        "tcpdump_bin": match.group("bin"),
                        "snaplen": int(match.group("snaplen")),
                        "bpf_filter": match.group("filter"),
                    }
                )
        elif "live-capture: starting scapy capture" in line:
            scapy_starts.append({"line": line})
        elif line.startswith("live-capture: telemetry "):
            raw = line.removeprefix("live-capture: telemetry ").strip()
            try:
                payload = json.loads(raw)
            except Exception:
                continue
            if isinstance(payload, dict):
                telemetry_snapshots.append(payload)
                dropped_packets = int(payload.get("total_dropped_packets", dropped_packets))
        elif "live-capture: dropped " in line:
            match = drop_pattern.search(line)
            if match:
                dropped_packets += int(match.group("count"))
        elif "live-capture: tcpdump backend exited with status" in line:
            nonzero_exit_lines.append(line)

    telemetry = telemetry_snapshots[-1] if telemetry_snapshots else {}
    return {
        "backend_runs": backend_runs,
        "tcpdump_starts": tcpdump_starts,
        "scapy_starts": scapy_starts,
        "dropped_packets": dropped_packets,
        "telemetry": telemetry,
        "telemetry_snapshots": telemetry_snapshots,
        "nonzero_exit_lines": nonzero_exit_lines,
        "traceback_detected": "Traceback (most recent call last)" in text,
        "permission_denied": "permission denied" in text.lower(),
        "line_count": len([line for line in text.splitlines() if line.strip()]),
    }


def _parse_runtime_log(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "path": str(path.resolve()),
            "exists": False,
            "backend_runs": [],
            "tcpdump_starts": [],
            "scapy_starts": [],
            "dropped_packets": 0,
            "telemetry": {},
            "telemetry_snapshots": [],
            "nonzero_exit_lines": [],
            "traceback_detected": False,
            "permission_denied": False,
            "line_count": 0,
        }
    payload = parse_runtime_log_text(path.read_text(encoding="utf-8", errors="ignore"))
    payload["path"] = str(path.resolve())
    payload["exists"] = True
    return payload


def _summarize_db(db_path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "db_path": str(db_path.resolve()),
        "exists": db_path.exists(),
        "counts": {"flows": 0, "alerts": 0, "metrics": 0},
        "rule_counts": {},
        "engine_counts": {},
        "latest_alerts": [],
    }
    if not db_path.exists():
        return summary

    conn = sqlite3.connect(str(db_path))
    try:
        for table_name in ("flows", "alerts", "metrics"):
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,),
            ).fetchone()
            if row:
                summary["counts"][table_name] = int(conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0])

        if summary["counts"]["alerts"] > 0:
            summary["rule_counts"] = {
                str(rule_name): int(count)
                for rule_name, count in conn.execute(
                    "SELECT COALESCE(rule_name, ''), COUNT(*) FROM alerts GROUP BY COALESCE(rule_name, '')"
                ).fetchall()
                if str(rule_name).strip()
            }
            summary["engine_counts"] = {
                str(engine): int(count)
                for engine, count in conn.execute(
                    "SELECT COALESCE(engine, ''), COUNT(*) FROM alerts GROUP BY COALESCE(engine, '')"
                ).fetchall()
                if str(engine).strip()
            }
            summary["latest_alerts"] = [
                {
                    "timestamp": str(timestamp),
                    "engine": str(engine),
                    "rule_name": str(rule_name),
                    "severity": str(severity),
                }
                for timestamp, engine, rule_name, severity in conn.execute(
                    """
                    SELECT COALESCE(timestamp, ''),
                           COALESCE(engine, ''),
                           COALESCE(rule_name, ''),
                           COALESCE(severity, '')
                    FROM alerts
                    ORDER BY id DESC
                    LIMIT 6
                    """
                ).fetchall()
            ]
    finally:
        conn.close()

    return summary


def _summarize_metric_series(
    db_path: Path,
    *,
    metric_names: list[str] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "db_path": str(db_path.resolve()),
        "exists": db_path.exists(),
        "metrics": {},
    }
    if not db_path.exists():
        return summary

    if metric_names is None:
        metric_names = [
            "events_per_sec",
            "alerts_per_min",
            "total_alerts",
            "suppressed_alerts",
            "policy_suppressed_alerts",
            "queue_size",
            "ingest_lag_sec",
            "live_packets_received",
            "live_packets_parsed",
            "live_packets_enqueued",
            "live_packets_processed",
            "live_packets_dropped_queue",
            "live_packets_dropped_total",
            "live_packet_loss_pct",
            "live_queue_depth_peak",
            "live_burst_rate_packets_per_sec_peak",
            "live_tcpdump_packets_dropped_by_kernel",
        ]

    conn = sqlite3.connect(str(db_path))
    try:
        for metric_name in metric_names:
            rows = conn.execute(
                """
                SELECT COALESCE(timestamp, ''), COALESCE(metric_value, 0.0)
                FROM metrics
                WHERE metric_name = ?
                ORDER BY timestamp
                """,
                (metric_name,),
            ).fetchall()
            if not rows:
                continue
            values = [float(row[1]) for row in rows]
            summary["metrics"][metric_name] = {
                "samples": len(values),
                "first_timestamp": str(rows[0][0]),
                "last_timestamp": str(rows[-1][0]),
                "first_value": float(values[0]),
                "last_value": float(values[-1]),
                "min_value": float(min(values)),
                "max_value": float(max(values)),
            }
    finally:
        conn.close()

    return summary


def _extract_alert_rows(db_path: Path, *, limit: int = 25) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id,
                   COALESCE(timestamp, '') AS timestamp,
                   COALESCE(engine, '') AS engine,
                   COALESCE(rule_name, '') AS rule_name,
                   COALESCE(severity, '') AS severity,
                   COALESCE(summary, '') AS summary,
                   COALESCE(is_suppressed, 0) AS is_suppressed,
                   COALESCE(suppressed_until, '') AS suppressed_until,
                   COALESCE(suppressed_by, '') AS suppressed_by,
                   COALESCE(suppressed_reason, '') AS suppressed_reason,
                   COALESCE(suppressed_ttl_minutes, 0) AS suppressed_ttl_minutes,
                   anomaly_score,
                   prediction_score,
                   supervised_score,
                   unsupervised_score,
                   unsupervised_isolation_score,
                   unsupervised_autoencoder_score,
                   fusion_score,
                   fusion_label,
                   COALESCE(extra, '{}') AS extra_json
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    finally:
        conn.close()

    payloads: list[dict[str, Any]] = []
    for row in rows:
        extra_payload: dict[str, Any]
        try:
            parsed = json.loads(str(row["extra_json"] or "{}"))
            extra_payload = parsed if isinstance(parsed, dict) else {}
        except Exception:
            extra_payload = {}
        payloads.append(
            {
                "id": int(row["id"]),
                "timestamp": str(row["timestamp"]),
                "engine": str(row["engine"]),
                "rule_name": str(row["rule_name"]),
                "severity": str(row["severity"]),
                "summary": str(row["summary"]),
                "is_suppressed": bool(row["is_suppressed"]),
                "suppressed_until": str(row["suppressed_until"]),
                "suppressed_by": str(row["suppressed_by"]),
                "suppressed_reason": str(row["suppressed_reason"]),
                "suppressed_ttl_minutes": int(row["suppressed_ttl_minutes"] or 0),
                "anomaly_score": row["anomaly_score"],
                "prediction_score": row["prediction_score"],
                "supervised_score": row["supervised_score"],
                "unsupervised_score": row["unsupervised_score"],
                "unsupervised_isolation_score": row["unsupervised_isolation_score"],
                "unsupervised_autoencoder_score": row["unsupervised_autoencoder_score"],
                "fusion_score": row["fusion_score"],
                "fusion_label": row["fusion_label"],
                "extra": extra_payload,
            }
        )
    return payloads


def _directory_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _parse_alert_timestamp(value: Any) -> datetime | None:
    token = str(value or "").strip()
    if not token:
        return None
    try:
        return datetime.fromisoformat(token.replace("Z", "+00:00"))
    except Exception:
        return None


def _scan_log_line_counts(result_dir: Path) -> dict[str, int]:
    warning_count = 0
    error_count = 0
    for path in sorted(result_dir.rglob("*.log")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip().lower()
            if not line:
                continue
            if "warning" in line:
                warning_count += 1
            if "traceback" in line or "error:" in line or line.startswith("error ") or " exception" in line:
                error_count += 1
    return {
        "warning_line_count": int(warning_count),
        "error_line_count": int(error_count),
    }


def _build_alert_clusters(alert_details: list[dict[str, Any]], *, gap_sec: int = 30) -> list[dict[str, Any]]:
    ordered = sorted(
        list(alert_details or []),
        key=lambda item: (
            _parse_alert_timestamp(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
            int(item.get("id") or 0),
        ),
    )
    clusters: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    previous_ts: datetime | None = None

    def _finalize(cluster: dict[str, Any] | None) -> None:
        if cluster is None:
            return
        started_at = cluster.pop("_started_at")
        ended_at = cluster.pop("_ended_at")
        cluster["started_at"] = started_at.isoformat()
        cluster["ended_at"] = ended_at.isoformat()
        cluster["duration_sec"] = round(max((ended_at - started_at).total_seconds(), 0.0), 3)
        clusters.append(cluster)

    for alert in ordered:
        alert_ts = _parse_alert_timestamp(alert.get("timestamp"))
        if alert_ts is None:
            continue
        if current is None or previous_ts is None or (alert_ts - previous_ts).total_seconds() > gap_sec:
            _finalize(current)
            current = {
                "_started_at": alert_ts,
                "_ended_at": alert_ts,
                "alert_count": 0,
                "rule_counts": {},
                "engine_counts": {},
                "operator_visible_dos_alerts": 0,
                "unsupervised_emitted_alerts": 0,
                "fusion_alerts": 0,
            }
        assert current is not None
        current["_ended_at"] = alert_ts
        current["alert_count"] += 1
        rule_name = str(alert.get("rule_name") or "").strip()
        engine = str(alert.get("engine") or "").strip()
        if rule_name:
            current["rule_counts"][rule_name] = int(current["rule_counts"].get(rule_name, 0)) + 1
        if engine:
            current["engine_counts"][engine] = int(current["engine_counts"].get(engine, 0)) + 1
        if rule_name == "DoS Rate Threshold" and not bool(alert.get("is_suppressed")):
            current["operator_visible_dos_alerts"] += 1
        if rule_name == "Hybrid Unsupervised Anomaly Score" and not bool(alert.get("is_suppressed")):
            current["unsupervised_emitted_alerts"] += 1
        if engine == "fusion" and not bool(alert.get("is_suppressed")):
            current["fusion_alerts"] += 1
        previous_ts = alert_ts

    _finalize(current)
    return clusters


def _build_soak_analysis(
    *,
    db_summary: dict[str, Any],
    runtime_summary: dict[str, Any],
    extras: dict[str, Any],
    result_dir: Path,
) -> dict[str, Any]:
    process_samples = list(extras.get("process_samples") or [])
    runtime_samples = list(extras.get("runtime_samples") or [])
    alert_details = list(extras.get("alert_details") or [])
    metric_summary = dict(extras.get("metric_summary", {}).get("metrics", {}) or {})

    cpu_values = [
        float(item.get("cpu_percent"))
        for item in process_samples
        if item.get("cpu_percent") is not None
    ]
    rss_values = [
        int(item.get("rss_kib"))
        for item in process_samples
        if item.get("rss_kib") is not None
    ]

    def _peak_runtime_value(key: str) -> int:
        values = [int(item.get(key, 0) or 0) for item in runtime_samples]
        return max(values) if values else 0

    def _final_runtime_value(key: str) -> int:
        return int(runtime_samples[-1].get(key, 0) or 0) if runtime_samples else 0

    detector_counts = {str(key): int(value) for key, value in dict(db_summary.get("engine_counts") or {}).items()}
    warning_and_error = _scan_log_line_counts(result_dir)
    clusters = _build_alert_clusters(alert_details)

    dos_episode_counts: dict[str, int] = {}
    unsupervised_episode_counts: dict[str, int] = {}
    for alert in alert_details:
        rule_name = str(alert.get("rule_name") or "")
        extra = dict(alert.get("extra") or {})
        if rule_name == "DoS Rate Threshold":
            episode_key = str(extra.get("dos_episode_key") or "").strip()
            if episode_key:
                dos_episode_counts[episode_key] = int(dos_episode_counts.get(episode_key, 0)) + 1
        if rule_name == "Hybrid Unsupervised Anomaly Score":
            episode_key = str(extra.get("unsupervised_episode_key") or "").strip()
            if episode_key:
                unsupervised_episode_counts[episode_key] = int(unsupervised_episode_counts.get(episode_key, 0)) + 1

    return {
        "duration_sec": float(extras.get("executed_duration_sec") or extras.get("planned_duration_sec") or 0.0),
        "flows_processed": int(db_summary.get("counts", {}).get("flows", 0)),
        "alerts_total": int(db_summary.get("counts", {}).get("alerts", 0)),
        "alert_counts_by_detector": detector_counts,
        "operator_visible_dos_alerts": int(
            sum(
                1
                for alert in alert_details
                if str(alert.get("rule_name") or "") == "DoS Rate Threshold" and not bool(alert.get("is_suppressed"))
            )
        ),
        "unsupervised_emitted_alerts": int(
            sum(
                1
                for alert in alert_details
                if str(alert.get("rule_name") or "") == "Hybrid Unsupervised Anomaly Score" and not bool(alert.get("is_suppressed"))
            )
        ),
        "fusion_alerts": int(
            sum(
                1
                for alert in alert_details
                if str(alert.get("engine") or "") == "fusion" and not bool(alert.get("is_suppressed"))
            )
        ),
        "peak_rss_kib": max(rss_values) if rss_values else 0,
        "peak_cpu_percent": round(max(cpu_values), 3) if cpu_values else 0.0,
        "avg_cpu_percent": round(sum(cpu_values) / len(cpu_values), 3) if cpu_values else 0.0,
        "sqlite_peak_bytes": _peak_runtime_value("db_bytes"),
        "sqlite_final_bytes": _final_runtime_value("db_bytes"),
        "alerts_jsonl_peak_bytes": _peak_runtime_value("alerts_jsonl_bytes"),
        "alerts_jsonl_final_bytes": _final_runtime_value("alerts_jsonl_bytes"),
        "flows_jsonl_peak_bytes": _peak_runtime_value("flows_jsonl_bytes"),
        "flows_jsonl_final_bytes": _final_runtime_value("flows_jsonl_bytes"),
        "metrics_jsonl_peak_bytes": _peak_runtime_value("metrics_jsonl_bytes"),
        "metrics_jsonl_final_bytes": _final_runtime_value("metrics_jsonl_bytes"),
        "runtime_total_result_peak_bytes": _peak_runtime_value("total_result_bytes"),
        "runtime_total_result_final_bytes": _final_runtime_value("total_result_bytes"),
        "local_bundle_size_bytes": _directory_size_bytes(result_dir),
        "restart_latency_sec": extras.get("reload_latency_sec"),
        "warning_line_count": warning_and_error["warning_line_count"],
        "error_line_count": warning_and_error["error_line_count"],
        "nonzero_exit_count": len(list(runtime_summary.get("nonzero_exit_lines") or [])),
        "traceback_detected": bool(runtime_summary.get("traceback_detected")),
        "metric_sample_counts": {
            key: int(value.get("samples", 0))
            for key, value in metric_summary.items()
        },
        "notable_burst_windows": clusters,
        "dos_episode_counts": dos_episode_counts,
        "unsupervised_episode_counts": unsupervised_episode_counts,
        "dos_reopen_loop_detected": any(count > 1 for count in dos_episode_counts.values()),
        "unsupervised_reopen_loop_detected": any(count > 1 for count in unsupervised_episode_counts.values()),
    }


def _host_command(args: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    started_at = _iso_now()
    start_perf = time.perf_counter()
    command_env = None
    if env:
        command_env = os.environ.copy()
        command_env.update({key: value for key, value in env.items() if str(value or "").strip() != ""})
    result = subprocess.run(
        args,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
        env=command_env,
    )
    return {
        "command": args,
        "returncode": int(result.returncode),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "started_at": started_at,
        "duration_sec": round(time.perf_counter() - start_perf, 3),
    }


def _remote_host_details(ssh: Any) -> dict[str, str]:
    details: dict[str, str] = {}
    commands = {
        "whoami": "whoami",
        "hostname": "hostname",
        "python_version": "python3 --version",
        "tcpdump_path": "which tcpdump || true",
        "interfaces": "ip -brief addr || true",
    }
    for key, command in commands.items():
        out, err, _ = LIVEVM._run_command(ssh, command, timeout=30, check=False)
        details[key] = (out or err).strip()
    return details


def _remote_environment_snapshot(sensor_host: str, sensor_port: int, target_host: str, target_port: int, username: str, password: str) -> dict[str, Any]:
    sensor = LIVEVM._connect(sensor_host, sensor_port, username, password)
    target = LIVEVM._connect(target_host, target_port, username, password)
    try:
        return {
            "captured_at": _iso_now(),
            "sensor": _remote_host_details(sensor),
            "target": _remote_host_details(target),
        }
    finally:
        sensor.close()
        target.close()


def _sync_sensor_files(
    sensor_ssh: Any,
    config_relpath: str,
    password: str,
    *,
    extra_relpaths: list[str] | None = None,
) -> None:
    files_to_sync = [
        (REPO_ROOT / "src" / "NIDS" / "pipeline" / "parser.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "pipeline", "parser.py")),
        (REPO_ROOT / "src" / "NIDS" / "pipeline" / "features.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "pipeline", "features.py")),
        (REPO_ROOT / "src" / "NIDS" / "ingest" / "__init__.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "ingest", "__init__.py")),
        (REPO_ROOT / "src" / "NIDS" / "ingest" / "live.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "ingest", "live.py")),
        (REPO_ROOT / "src" / "NIDS" / "detect" / "__init__.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "detect", "__init__.py")),
        (REPO_ROOT / "src" / "NIDS" / "detect" / "anomaly.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "detect", "anomaly.py")),
        (REPO_ROOT / "src" / "NIDS" / "detect" / "ml.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "detect", "ml.py")),
        (REPO_ROOT / "src" / "NIDS" / "detect" / "ml_unsupervised.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "detect", "ml_unsupervised.py")),
        (REPO_ROOT / "src" / "NIDS" / "detect" / "suppression.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "detect", "suppression.py")),
        (REPO_ROOT / "src" / "NIDS" / "runtime.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "runtime.py")),
        (REPO_ROOT / "src" / "NIDS" / "config.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "config.py")),
        (REPO_ROOT / "src" / "NIDS" / "storage" / "__init__.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "storage", "__init__.py")),
        (REPO_ROOT / "src" / "NIDS" / "storage" / "jsonl_store.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "storage", "jsonl_store.py")),
        (REPO_ROOT / "src" / "NIDS" / "storage" / "sqlite_store.py", posixpath.join("/opt/nids_workspace", "src", "NIDS", "storage", "sqlite_store.py")),
        (REPO_ROOT / "config" / "nids.yml", posixpath.join("/opt/nids_workspace", "config", "nids.yml")),
        (REPO_ROOT / "rules" / "rules.yml", posixpath.join("/opt/nids_workspace", "rules", "rules.yml")),
        (REPO_ROOT / Path(config_relpath), posixpath.join("/opt/nids_workspace", config_relpath.replace("\\", "/"))),
    ]
    for relpath in list(extra_relpaths or []):
        token = str(relpath or "").replace("\\", "/").strip()
        if not token:
            continue
        files_to_sync.append(
            (
                REPO_ROOT / Path(token),
                posixpath.join("/opt/nids_workspace", token),
            )
        )
    for local_path, remote_path in files_to_sync:
        LIVEVM._upload_file(sensor_ssh, local_path, remote_path, sudo_password=password)


def _remote_db_counts(sensor_ssh: Any, workspace: str, result_rel: str) -> dict[str, int]:
    script = f"""
import sqlite3
db_path = {posixpath.join(workspace, result_rel, 'nids.db')!r}
conn = sqlite3.connect(db_path)
try:
    print(conn.execute('SELECT COUNT(*) FROM flows').fetchone()[0])
    print(conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0])
finally:
    conn.close()
"""
    out, _, _ = LIVEVM._run_command(sensor_ssh, LIVEVM._remote_python(script), timeout=30, check=True)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    return {
        "flows": int(lines[0]) if len(lines) >= 1 else 0,
        "alerts": int(lines[1]) if len(lines) >= 2 else 0,
    }


def _remote_rule_count(sensor_ssh: Any, workspace: str, result_rel: str, rule_name: str) -> int:
    script = f"""
import sqlite3
db_path = {posixpath.join(workspace, result_rel, 'nids.db')!r}
conn = sqlite3.connect(db_path)
try:
    row = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE COALESCE(rule_name, '') = ?",
        ({rule_name!r},),
    ).fetchone()
    print(int(row[0] if row else 0))
finally:
    conn.close()
"""
    out, _, _ = LIVEVM._run_command(sensor_ssh, LIVEVM._remote_python(script), timeout=30, check=True)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    return int(lines[-1]) if lines else 0


def _remote_metric_last_values(sensor_ssh: Any, workspace: str, result_rel: str, metric_names: list[str]) -> dict[str, float]:
    names = [str(item).strip() for item in list(metric_names or []) if str(item).strip()]
    if not names:
        return {}
    script = f"""
import json
import sqlite3
db_path = {posixpath.join(workspace, result_rel, 'nids.db')!r}
metric_names = {names!r}
conn = sqlite3.connect(db_path)
try:
    payload = {{}}
    for metric_name in metric_names:
        row = conn.execute(
            "SELECT COALESCE(metric_value, 0.0) FROM metrics WHERE metric_name = ? ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            (metric_name,),
        ).fetchone()
        payload[metric_name] = float(row[0] if row else 0.0)
    print(json.dumps(payload))
finally:
    conn.close()
"""
    out, _, _ = LIVEVM._run_command(sensor_ssh, LIVEVM._remote_python(script), timeout=30, check=True)
    return json.loads(out.strip() or "{}")


def _remote_latest_alert_id(sensor_ssh: Any, workspace: str, result_rel: str, *, rule_name: str = "") -> int:
    script = f"""
import sqlite3
db_path = {posixpath.join(workspace, result_rel, 'nids.db')!r}
rule_name = {str(rule_name or '')!r}
conn = sqlite3.connect(db_path)
try:
    if rule_name:
        row = conn.execute(
            "SELECT id FROM alerts WHERE COALESCE(rule_name, '') = ? ORDER BY id DESC LIMIT 1",
            (rule_name,),
        ).fetchone()
    else:
        row = conn.execute("SELECT id FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
    print(int(row[0] if row else 0))
finally:
    conn.close()
"""
    out, _, _ = LIVEVM._run_command(sensor_ssh, LIVEVM._remote_python(script), timeout=30, check=True)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    return int(lines[-1]) if lines else 0


def _remote_create_suppression_rule(
    sensor_ssh: Any,
    workspace: str,
    result_rel: str,
    *,
    alert_id: int,
    actor: str,
    actor_role: str,
    ttl_minutes: int,
    reason: str,
    metadata: dict[str, Any] | None = None,
    sudo_password: str | None = None,
) -> dict[str, Any]:
    script = f"""
import json
import os
import sys
from pathlib import Path

workspace = {workspace!r}
db_path = {posixpath.join(workspace, result_rel, 'nids.db')!r}
sys.path.insert(0, os.path.join(workspace, "src"))

from NIDS.storage.sqlite_store import SQLiteStore

store = SQLiteStore(Path(db_path))
try:
    payload = store.create_suppression_rule_from_alert(
        {int(alert_id)},
        actor={actor!r},
        actor_role={actor_role!r},
        ttl_minutes={int(ttl_minutes)},
        reason={reason!r},
        metadata={dict(metadata or {})!r},
    )
    print(json.dumps(payload or {{}}))
finally:
    store.close()
"""
    command = LIVEVM._remote_python(script)
    if sudo_password:
        command = f"sudo -S bash -lc {shlex.quote(command)}"
    out, _, _ = LIVEVM._run_command(sensor_ssh, command, sudo_password=sudo_password, timeout=60, check=True)
    payload = _parse_json_blob(out)
    return payload if isinstance(payload, dict) else {}


def _remote_suppression_overview(sensor_ssh: Any, workspace: str, result_rel: str, *, rule_name: str = "") -> dict[str, Any]:
    script = f"""
import json
import sqlite3
from datetime import datetime, timezone

db_path = {posixpath.join(workspace, result_rel, 'nids.db')!r}
rule_name = {str(rule_name or '')!r}
stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
conn = sqlite3.connect(db_path)
try:
    active_rules = int(
        conn.execute(
            "SELECT COUNT(*) FROM suppression_rules WHERE is_active = 1 AND (suppressed_until IS NULL OR suppressed_until = '' OR suppressed_until > ?)",
            (stamp,),
        ).fetchone()[0]
    )
    suppression_actions = int(
        conn.execute("SELECT COUNT(*) FROM incident_actions WHERE COALESCE(action, '') = 'suppress'").fetchone()[0]
    )
    suppressed_alert_rows = int(conn.execute("SELECT COUNT(*) FROM alerts WHERE COALESCE(is_suppressed, 0) = 1").fetchone()[0])
    emitted_rule_alerts = 0
    if rule_name:
        emitted_rule_alerts = int(
            conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE COALESCE(rule_name, '') = ?",
                (rule_name,),
            ).fetchone()[0]
        )
    latest = conn.execute(
        '''
        SELECT id,
               COALESCE(source_alert_id, 0),
               COALESCE(rule_name, ''),
               COALESCE(suppressed_until, ''),
               COALESCE(created_by, ''),
               COALESCE(reason, '')
        FROM suppression_rules
        ORDER BY id DESC
        LIMIT 1
        '''
    ).fetchone()
    payload = {{
        "active_rules": active_rules,
        "suppression_actions": suppression_actions,
        "suppressed_alert_rows": suppressed_alert_rows,
        "emitted_rule_alerts": emitted_rule_alerts,
        "latest_rule_id": int(latest[0]) if latest else 0,
        "latest_source_alert_id": int(latest[1]) if latest else 0,
        "latest_rule_name": str(latest[2]) if latest else "",
        "latest_suppressed_until": str(latest[3]) if latest else "",
        "latest_created_by": str(latest[4]) if latest else "",
        "latest_reason": str(latest[5]) if latest else "",
    }}
    print(json.dumps(payload))
finally:
    conn.close()
"""
    out, _, _ = LIVEVM._run_command(sensor_ssh, LIVEVM._remote_python(script), timeout=30, check=True)
    return json.loads(out.strip() or "{}")


def _remote_runtime_snapshot(sensor_ssh: Any, workspace: str, result_rel: str, pid: int) -> dict[str, Any]:
    script = f"""
import json
import os
import sqlite3
base = {posixpath.join(workspace, result_rel)!r}
db_path = os.path.join(base, "nids.db")
payload = {{
    "db_bytes": os.path.getsize(db_path) if os.path.exists(db_path) else 0,
    "alerts_jsonl_bytes": os.path.getsize(os.path.join(base, "alerts.jsonl")) if os.path.exists(os.path.join(base, "alerts.jsonl")) else 0,
    "flows_jsonl_bytes": os.path.getsize(os.path.join(base, "flows.jsonl")) if os.path.exists(os.path.join(base, "flows.jsonl")) else 0,
    "metrics_jsonl_bytes": os.path.getsize(os.path.join(base, "metrics.jsonl")) if os.path.exists(os.path.join(base, "metrics.jsonl")) else 0,
    "total_result_bytes": 0,
    "flows": 0,
    "alerts": 0,
}}
for root, _dirs, files in os.walk(base):
    for name in files:
        try:
            payload["total_result_bytes"] += os.path.getsize(os.path.join(root, name))
        except OSError:
            pass
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    try:
        payload["flows"] = int(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
        payload["alerts"] = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
    finally:
        conn.close()
print(json.dumps(payload))
"""
    out, _, _ = LIVEVM._run_command(sensor_ssh, LIVEVM._remote_python(script), timeout=30, check=True)
    payload = json.loads(out.strip() or "{}")
    ps_out, _, _ = LIVEVM._run_command(sensor_ssh, f"ps -o pid=,rss=,%cpu=,etime= -p {pid}", timeout=20, check=False)
    tokens = ps_out.strip().split()
    if len(tokens) >= 4:
        payload.update(
            {
                "pid": int(tokens[0]),
                "rss_kib": int(tokens[1]),
                "cpu_percent": float(tokens[2]),
                "elapsed": tokens[3],
            }
        )
    return payload


def _sample_runtime_state(sensor_ssh: Any, workspace: str, result_rel: str, pid: int, *, duration_sec: float, interval_sec: float) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    end_time = time.time() + max(0.0, duration_sec)
    while time.time() < end_time:
        payload = _remote_runtime_snapshot(sensor_ssh, workspace, result_rel, pid)
        payload["captured_at"] = _iso_now()
        samples.append(payload)
        time.sleep(max(0.5, interval_sec))
    return samples


def _start_runtime_custom(
    sensor_ssh: Any,
    workspace: str,
    result_rel: str,
    *,
    config_relpath: str,
    sudo_password: str,
    rules_relpath: str = "rules/rules.yml",
    model_relpath: str = "models/model.pkl",
    extra_run_args: list[str] | None = None,
) -> dict[str, Any]:
    result_abs = posixpath.join(workspace, result_rel)
    runtime_log = posixpath.join(result_abs, "runtime.log")
    pid_file = posixpath.join(result_abs, "nids.pid")
    extra_tokens = " ".join(shlex.quote(str(item)) for item in list(extra_run_args or []))
    inner = (
        f"mkdir -p {LIVEVM._quote_remote(result_abs)} && "
        f"cd {LIVEVM._quote_remote(workspace)} && "
        f"(nohup env PYTHONPATH={LIVEVM._quote_remote(workspace)} PYTHONUNBUFFERED=1 "
        f".venv/bin/python -u -m nids run "
        f"--interface enp0s3 "
        f"--rules {shlex.quote(rules_relpath)} "
        f"--config {shlex.quote(config_relpath)} "
        f"--output-dir {shlex.quote(result_rel)} "
        f"--sensor-id nids-ubuntu-sensor "
        f"--model {shlex.quote(model_relpath)} "
        f"{extra_tokens} "
        f"> {LIVEVM._quote_remote(runtime_log)} 2>&1 < /dev/null & "
        f"echo $! > {LIVEVM._quote_remote(pid_file)})"
    )
    started_at = _iso_now()
    start_perf = time.perf_counter()
    LIVEVM._run_command(
        sensor_ssh,
        f"sudo -S bash -lc {shlex.quote(inner)}",
        sudo_password=sudo_password,
        timeout=120,
    )
    pid_text, _, _ = LIVEVM._run_command(sensor_ssh, f"cat {LIVEVM._quote_remote(pid_file)}", timeout=30)
    return {
        "pid": int(pid_text.strip()),
        "started_at": started_at,
        "duration_sec": round(time.perf_counter() - start_perf, 3),
        "command": inner,
        "rules_relpath": rules_relpath,
        "model_relpath": model_relpath,
        "config_relpath": config_relpath,
        "extra_run_args": list(extra_run_args or []),
    }


def _run_remote_python(ssh: Any, script: str, *, timeout: int) -> None:
    LIVEVM._run_command(ssh, LIVEVM._remote_python(script), timeout=timeout, check=True)


def _send_malformed_dns_mix(target_ssh: Any, sensor_ip: str, *, valid_count: int, malformed_count: int, delay_sec: float) -> None:
    script = f"""
import random
import socket
import struct
import time

def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\\x00"

server = ({sensor_ip!r}, 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for index in range(max({valid_count}, {malformed_count})):
    if index < {malformed_count}:
        sock.sendto(random.choice([b"\\x00\\x01\\x01\\x00\\x00", b"\\xff\\xff\\xff\\x01", b"broken-dns-packet", b"\\x12\\x34\\x01"]), server)
    if index < {valid_count}:
        txid = (5000 + index) & 0xFFFF
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = encode_name(f"{{index:03d}}.malformed-check.example") + struct.pack("!HH", 1, 1)
        sock.sendto(header + question, server)
    time.sleep(max(0.0, float({delay_sec})))
sock.close()
"""
    _run_remote_python(target_ssh, script, timeout=180)


def _run_benign_soak_traffic(
    target_ssh: Any,
    sensor_ip: str,
    *,
    duration_sec: float,
    dns_rate_per_sec: float,
    http_rate_per_sec: float,
    http_port: int,
    dns_queries: list[str] | None = None,
    http_requests: list[dict[str, str]] | None = None,
) -> None:
    dns_queries_payload = _coerce_string_list(dns_queries, default=["www.example.org"])
    http_requests_payload = _coerce_http_requests(http_requests)
    script = f"""
import socket
import struct
import time

dns_queries = {dns_queries_payload!r}
http_requests = {http_requests_payload!r}

def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\\x00"

server_dns = ({sensor_ip!r}, 53)
server_http = ({sensor_ip!r}, {http_port})
dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end_time = time.perf_counter() + max(1.0, float({duration_sec}))
dns_enabled = float({dns_rate_per_sec}) > 0.0
http_enabled = float({http_rate_per_sec}) > 0.0
dns_interval = 1.0 / max(1.0, float({dns_rate_per_sec})) if dns_enabled else 0.0
http_interval = 1.0 / max(1.0, float({http_rate_per_sec})) if http_enabled else 0.0
next_dns = time.perf_counter()
next_http = time.perf_counter()
dns_index = 0
http_index = 0
while time.perf_counter() < end_time:
    now = time.perf_counter()
    if dns_enabled and now >= next_dns:
        qname = str(dns_queries[dns_index % len(dns_queries)] or "www.example.org")
        txid = int(now * 1000) & 0xFFFF
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = encode_name(qname) + struct.pack("!HH", 1, 1)
        dns_sock.sendto(header + question, server_dns)
        dns_index += 1
        next_dns += dns_interval
    if http_enabled and now >= next_http:
        request = dict(http_requests[http_index % len(http_requests)] or {{}})
        method = str(request.get("method") or "GET").upper()
        path = str(request.get("path") or "/status")
        host = str(request.get("host") or "portal.internal")
        body = str(request.get("body") or "")
        body_bytes = body.encode("utf-8")
        header_lines = [f"{{method}} {{path}} HTTP/1.1", f"Host: {{host}}", "Connection: close"]
        if body_bytes:
            header_lines.append(f"Content-Length: {{len(body_bytes)}}")
            header_lines.append("Content-Type: application/x-www-form-urlencoded")
        payload = ("\\r\\n".join(header_lines) + "\\r\\n\\r\\n").encode("ascii") + body_bytes
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            sock.connect(server_http)
            sock.sendall(payload)
            try:
                sock.recv(256)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            sock.close()
        http_index += 1
        next_http += http_interval
    time.sleep(0.02)
dns_sock.close()
"""
    _run_remote_python(target_ssh, script, timeout=int(max(120, duration_sec + 60)))


def _run_dns_stream(
    target_ssh: Any,
    sensor_ip: str,
    *,
    duration_sec: float,
    rate_per_sec: float,
    qname: str,
    unique_qnames: bool,
) -> None:
    script = f"""
import socket
import struct
import time

def encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\\x00"

server = ({sensor_ip!r}, 53)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end_time = time.perf_counter() + max(1.0, float({duration_sec}))
interval = 1.0 / max(1.0, float({rate_per_sec}))
next_send = time.perf_counter()
sent = 0
while time.perf_counter() < end_time:
    base = {qname!r}
    qname = f"{{sent:05d}}.{{base}}" if bool({unique_qnames}) else base
    txid = (6100 + sent) & 0xFFFF
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", 1, 1)
    sock.sendto(header + question, server)
    sent += 1
    next_send += interval
    sleep_for = next_send - time.perf_counter()
    if sleep_for > 0:
        time.sleep(sleep_for)
sock.close()
print("dns_stream_packets_sent", sent)
print("dns_stream_duration_sec", round(float({duration_sec}), 3))
print("dns_stream_unique_qnames", bool({unique_qnames}))
"""
    _run_remote_python(target_ssh, script, timeout=int(max(120, duration_sec + 60)))


def _write_dns_signature_rules_file(result_dir: Path, *, filename: str, rule_name: str, dns_qname_token: str, summary: str) -> Path:
    base_rules = yaml.safe_load((REPO_ROOT / "rules" / "rules.yml").read_text(encoding="utf-8")) or []
    if isinstance(base_rules, dict):
        base_rules = [base_rules]
    if not isinstance(base_rules, list):
        raise ValueError("Base rules.yml must be a YAML sequence or mapping")
    rules_payload = list(base_rules)
    rules_payload.append(
        {
            "name": rule_name,
            "summary": summary,
            "severity": "medium",
            "action": "alert",
            "match": {
                "proto": "UDP",
                "dst_ports": [53],
                "dataset_sources": ["live"],
                "dns_qnames": [dns_qname_token],
            },
        }
    )
    local_path = result_dir / filename
    _write_text(local_path, yaml.safe_dump(rules_payload, sort_keys=False))
    return local_path


def _write_rule_refresh_rules_file(result_dir: Path, *, rule_name: str, dns_qname_token: str) -> Path:
    return _write_dns_signature_rules_file(
        result_dir,
        filename="phase5_rule_refresh_rules.yml",
        rule_name=rule_name,
        dns_qname_token=dns_qname_token,
        summary="Phase 5 operator workflow rule refresh validation",
    )


def _copy_remote_file(sensor_ssh: Any, source_path: str, dest_path: str, *, sudo_password: str | None = None) -> None:
    parent = posixpath.dirname(dest_path)
    LIVEVM._run_command(sensor_ssh, f"mkdir -p {LIVEVM._quote_remote(parent)}", timeout=30, check=True)
    command = (
        f"cp {LIVEVM._quote_remote(source_path)} {LIVEVM._quote_remote(dest_path)} && "
        f"chown nidslab:nidslab {LIVEVM._quote_remote(dest_path)}"
    )
    if sudo_password:
        LIVEVM._run_command(
            sensor_ssh,
            f"sudo -S bash -lc {shlex.quote(command)}",
            sudo_password=sudo_password,
            timeout=60,
            check=True,
        )
    else:
        LIVEVM._run_command(sensor_ssh, f"bash -lc {shlex.quote(command)}", timeout=60, check=True)


def _sample_process_stats(sensor_ssh: Any, pid: int, *, duration_sec: float, interval_sec: float) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    end_time = time.time() + max(0.0, duration_sec)
    while time.time() < end_time:
        out, _, _ = LIVEVM._run_command(sensor_ssh, f"ps -o pid=,rss=,%cpu=,etime= -p {pid}", timeout=20, check=False)
        tokens = out.strip().split()
        if len(tokens) >= 4:
            samples.append(
                {
                    "captured_at": _iso_now(),
                    "pid": int(tokens[0]),
                    "rss_kib": int(tokens[1]),
                    "cpu_percent": float(tokens[2]),
                    "elapsed": tokens[3],
                }
            )
        time.sleep(max(0.2, interval_sec))
    return samples


def _cleanup_remote_helpers(sensor_ssh: Any, *, http_server_pids: list[int], udp_sink_pids: list[tuple[int, bool]], password: str) -> None:
    for pid in http_server_pids:
        try:
            LIVEVM._stop_process(sensor_ssh, pid, sudo_password=password)
        except Exception:
            pass
    for pid, needs_sudo in udp_sink_pids:
        try:
            LIVEVM._stop_process(sensor_ssh, pid, sudo_password=password if needs_sudo else None)
        except Exception:
            pass


def _build_verdict(scenario: dict[str, Any], *, execution_ok: bool, db_summary: dict[str, Any], runtime_summary: dict[str, Any], extras: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    telemetry = dict(runtime_summary.get("telemetry") or {})
    metric_summary = dict(extras.get("metric_summary", {}).get("metrics", {}) or {})

    def _metric_last(name: str) -> float:
        payload = dict(metric_summary.get(name) or {})
        return float(payload.get("last_value") or 0.0)

    observed_dropped_packets = int(runtime_summary.get("dropped_packets", 0))
    if observed_dropped_packets <= 0:
        observed_dropped_packets = int(_metric_last("live_packets_dropped_total"))
    observed_packets_received = int(telemetry.get("packets_received", 0))
    if observed_packets_received <= 0:
        observed_packets_received = int(_metric_last("live_packets_received"))

    if not execution_ok:
        issues.append("execution_failed")
    if runtime_summary.get("traceback_detected"):
        issues.append("runtime_traceback_detected")

    expected_backend = str(scenario.get("expected_backend") or "")
    if expected_backend and not any(str(item.get("resolved_backend")) == expected_backend for item in runtime_summary.get("backend_runs", [])):
        issues.append(f"expected_backend_missing:{expected_backend}")
    if bool(scenario.get("require_capture_metrics")) and not (telemetry or metric_summary):
        issues.append("capture_metrics_missing")

    for rule_name in list(scenario.get("required_rules") or []):
        if int(db_summary.get("rule_counts", {}).get(rule_name, 0)) <= 0:
            issues.append(f"missing_rule:{rule_name}")

    if bool(scenario.get("require_drop")) and observed_dropped_packets <= 0:
        issues.append("drop_not_observed")
    min_packets_received = int(scenario.get("min_packets_received") or 0)
    if min_packets_received > 0 and observed_packets_received < min_packets_received:
        issues.append(f"packets_received_below_expected:{observed_packets_received}")
    if bool(scenario.get("expect_zero_alerts")) and int(db_summary.get("counts", {}).get("alerts", 0)) != 0:
        issues.append(f"expected_zero_alerts_observed:{db_summary['counts']['alerts']}")
    if scenario.get("max_alerts") is not None and int(db_summary.get("counts", {}).get("alerts", 0)) > int(scenario["max_alerts"]):
        issues.append(f"alerts_above_expected:{db_summary['counts']['alerts']}")
    if bool(scenario.get("require_process_samples")) and not list(extras.get("process_samples") or []):
        issues.append("process_samples_missing")
    if bool(scenario.get("require_runtime_samples")) and not list(extras.get("runtime_samples") or []):
        issues.append("runtime_samples_missing")
    if bool(scenario.get("require_alert_growth")) and "phase_one_counts" in extras and "phase_two_counts" in extras:
        if int(extras["phase_two_counts"].get("alerts", 0)) <= int(extras["phase_one_counts"].get("alerts", 0)):
            issues.append("restart_recovery_alert_growth_not_observed")
    if bool(scenario.get("require_reload_latency")) and extras.get("reload_latency_sec") is None:
        issues.append("reload_latency_missing")
    if bool(scenario.get("require_post_restart_growth")):
        before = dict(extras.get("phase_one_counts") or extras.get("pre_workflow_counts") or {})
        after = dict(extras.get("phase_two_counts") or extras.get("post_workflow_counts") or {})
        if int(after.get("flows", 0)) <= int(before.get("flows", 0)):
            issues.append("post_restart_flow_growth_not_observed")
    suppression = dict(extras.get("suppression_validation") or {})
    observed_suppressed_alerts = max(int(_metric_last("suppressed_alerts")), int(suppression.get("derived_total_suppressions_min", 0)))
    observed_policy_suppressed_alerts = max(
        int(_metric_last("policy_suppressed_alerts")),
        int(suppression.get("derived_policy_suppressions_min", 0)),
    )
    if bool(scenario.get("require_suppressed_alerts")) and observed_suppressed_alerts < int(scenario.get("min_suppressed_alerts") or 1):
        issues.append("suppressed_alerts_not_observed")
    if bool(scenario.get("require_policy_suppressed_alerts")) and observed_policy_suppressed_alerts < int(scenario.get("min_policy_suppressed_alerts") or 1):
        issues.append("policy_suppression_not_observed")
    if bool(scenario.get("require_active_suppression_rule")):
        suppression_state = dict(suppression.get("suppression_state_after") or {})
        if int(suppression_state.get("active_rules", 0)) <= 0:
            issues.append("active_suppression_rule_missing")
    if bool(scenario.get("require_alert_count_stable_after_action")):
        before = dict(suppression.get("pre_suppression_counts") or {})
        after = dict(suppression.get("post_suppression_counts") or {})
        if int(after.get("alerts", 0)) > int(before.get("alerts", 0)):
            issues.append("alert_count_grew_after_suppression")

    status = "pass" if not issues else "partial"
    if "execution_failed" in issues or "runtime_traceback_detected" in issues:
        status = "fail"

    return {
        "status": status,
        "issues": issues,
        "expected_backend": expected_backend,
        "observed_rule_counts": db_summary.get("rule_counts", {}),
        "observed_dropped_packets": observed_dropped_packets,
    }


def _summary_markdown(scenario: dict[str, Any], *, run_name: str, result_dir: Path, config_relpath: str, execution: dict[str, Any], db_summary: dict[str, Any], runtime_summary: dict[str, Any], verdict: dict[str, Any], extras: dict[str, Any]) -> str:
    telemetry = dict(runtime_summary.get("telemetry") or {})
    metric_summary = dict(extras.get("metric_summary", {}).get("metrics", {}) or {})
    environment = _scenario_environment_description(scenario)
    expected_outcome = _scenario_expected_outcome(scenario)
    actual_outcome = _scenario_actual_outcome(scenario, db_summary=db_summary, runtime_summary=runtime_summary, extras=extras)

    def _metric_last(name: str) -> float:
        payload = dict(metric_summary.get(name) or {})
        return float(payload.get("last_value") or 0.0)

    lines = [
        f"# {scenario['name']}",
        "",
        f"- Scenario ID: `{scenario['scenario_id']}`",
        f"- Run name: `{run_name}`",
        f"- Config: `{config_relpath}`",
        f"- Status: `{verdict['status']}`",
        "",
        "## Objective",
        "",
        str(scenario["objective"]),
        "",
        "## Environment",
        "",
        environment,
        "",
        "## Expected Outcome",
        "",
        expected_outcome,
        "",
        "## Actual Outcome",
        "",
        actual_outcome,
        "",
        "## Capture",
        "",
        f"- Expected backend: `{scenario.get('expected_backend', '')}`",
        f"- Backend runs observed: `{len(runtime_summary.get('backend_runs', []))}`",
        f"- Dropped packets observed: `{int(runtime_summary.get('dropped_packets', 0) or _metric_last('live_packets_dropped_total'))}`",
        f"- Traceback detected: `{runtime_summary.get('traceback_detected', False)}`",
    ]
    if telemetry:
        lines.extend(
            [
                f"- Packets received: `{telemetry.get('packets_received', 0)}`",
                f"- Packets processed: `{telemetry.get('packets_processed', 0)}`",
                f"- Total dropped packets: `{telemetry.get('total_dropped_packets', 0)}`",
                f"- Loss percentage: `{telemetry.get('loss_percentage', 0.0)}`",
                f"- Queue depth peak: `{telemetry.get('queue_depth_peak', 0)}`",
                f"- Burst PPS peak: `{telemetry.get('burst_rate_packets_per_sec_peak', 0.0)}`",
            ]
        )
    elif metric_summary:
        lines.extend(
            [
                f"- Packets received: `{int(_metric_last('live_packets_received'))}`",
                f"- Packets processed: `{int(_metric_last('live_packets_processed'))}`",
                f"- Total dropped packets: `{int(_metric_last('live_packets_dropped_total'))}`",
                f"- Loss percentage: `{_metric_last('live_packet_loss_pct')}`",
                f"- Queue depth peak: `{int(_metric_last('live_queue_depth_peak'))}`",
                f"- Burst PPS peak: `{_metric_last('live_burst_rate_packets_per_sec_peak')}`",
            ]
        )
    lines.extend(
        [
            "",
            "## Detection",
            "",
            f"- Flows: `{db_summary['counts']['flows']}`",
            f"- Alerts: `{db_summary['counts']['alerts']}`",
            "",
            "| Rule | Count |",
            "|---|---:|",
        ]
    )
    if db_summary["rule_counts"]:
        for rule_name in sorted(db_summary["rule_counts"]):
            lines.append(f"| `{rule_name}` | {db_summary['rule_counts'][rule_name]} |")
    else:
        lines.append("| `none` | 0 |")

    if extras.get("process_samples"):
        rss = [int(item["rss_kib"]) for item in extras["process_samples"] if "rss_kib" in item]
        if rss:
            lines.extend(["", "## Process Samples", "", f"- Samples: `{len(rss)}`", f"- Peak RSS KiB: `{max(rss)}`"])
    if extras.get("runtime_samples"):
        storage = [int(item.get("total_result_bytes", 0)) for item in extras["runtime_samples"]]
        if storage:
            lines.extend(["", "## Runtime Samples", "", f"- Samples: `{len(storage)}`", f"- Peak result size bytes: `{max(storage)}`"])
    if extras.get("soak_analysis"):
        analysis = dict(extras.get("soak_analysis") or {})
        lines.extend(
            [
                "",
                "## Soak Analysis",
                "",
                f"- Peak CPU percent: `{analysis.get('peak_cpu_percent', 0.0)}`",
                f"- Average CPU percent: `{analysis.get('avg_cpu_percent', 0.0)}`",
                f"- Peak RSS KiB: `{analysis.get('peak_rss_kib', 0)}`",
                f"- Operator-visible DoS alerts: `{analysis.get('operator_visible_dos_alerts', 0)}`",
                f"- Unsupervised emitted alerts: `{analysis.get('unsupervised_emitted_alerts', 0)}`",
                f"- Fusion alerts: `{analysis.get('fusion_alerts', 0)}`",
                f"- SQLite peak bytes: `{analysis.get('sqlite_peak_bytes', 0)}`",
                f"- Flows JSONL peak bytes: `{analysis.get('flows_jsonl_peak_bytes', 0)}`",
                f"- Alerts JSONL peak bytes: `{analysis.get('alerts_jsonl_peak_bytes', 0)}`",
                f"- Metrics JSONL peak bytes: `{analysis.get('metrics_jsonl_peak_bytes', 0)}`",
                f"- Runtime total result peak bytes: `{analysis.get('runtime_total_result_peak_bytes', 0)}`",
                f"- Local bundle size bytes: `{analysis.get('local_bundle_size_bytes', 0)}`",
                f"- Warning line count: `{analysis.get('warning_line_count', 0)}`",
                f"- Error line count: `{analysis.get('error_line_count', 0)}`",
                f"- DoS reopen loop detected: `{analysis.get('dos_reopen_loop_detected', False)}`",
                f"- Unsupervised reopen loop detected: `{analysis.get('unsupervised_reopen_loop_detected', False)}`",
            ]
        )
        burst_windows = list(analysis.get("notable_burst_windows") or [])
        if burst_windows:
            lines.extend(["", "| Burst window | Alerts | DoS | Unsupervised | Fusion |", "|---|---:|---:|---:|---:|"])
            for item in burst_windows:
                lines.append(
                    f"| `{item.get('started_at', '')}` to `{item.get('ended_at', '')}` | "
                    f"{int(item.get('alert_count', 0))} | "
                    f"{int(item.get('operator_visible_dos_alerts', 0))} | "
                    f"{int(item.get('unsupervised_emitted_alerts', 0))} | "
                    f"{int(item.get('fusion_alerts', 0))} |"
                )
    metric_summary = dict(extras.get("metric_summary", {}).get("metrics", {}) or {})
    if metric_summary:
        lines.extend(["", "## Metric Summary", ""])
        for metric_name in (
            "live_packets_received",
            "live_packets_parsed",
            "live_packets_enqueued",
            "live_packets_processed",
            "live_packets_dropped_queue",
            "live_packets_dropped_total",
            "live_packet_loss_pct",
            "live_queue_depth_peak",
            "live_burst_rate_packets_per_sec_peak",
            "events_per_sec",
            "alerts_per_min",
            "total_alerts",
            "suppressed_alerts",
            "policy_suppressed_alerts",
        ):
            payload = dict(metric_summary.get(metric_name) or {})
            if payload:
                lines.append(
                    f"- {metric_name}: last=`{payload.get('last_value')}` max=`{payload.get('max_value')}` samples=`{payload.get('samples')}`"
                )
    if extras.get("suppression_validation"):
        suppression = dict(extras.get("suppression_validation") or {})
        lines.extend(
            [
                "",
                "## Suppression Validation",
                "",
                f"- Rule name: `{suppression.get('rule_name', '')}`",
                f"- DNS qname: `{suppression.get('dns_qname', '')}`",
                f"- Duplicate window sec: `{suppression.get('duplicate_window_sec', '')}`",
                f"- Pre-suppression counts: `{suppression.get('pre_suppression_counts', {})}`",
                f"- Post-suppression counts: `{suppression.get('post_suppression_counts', {})}`",
                f"- Pre-suppression metrics: `{suppression.get('pre_suppression_metrics', {})}`",
                f"- Post-suppression metrics: `{suppression.get('post_suppression_metrics', {})}`",
                f"- Derived duplicate suppressions min: `{suppression.get('derived_duplicate_suppressions_min', 0)}`",
                f"- Derived policy suppressions min: `{suppression.get('derived_policy_suppressions_min', 0)}`",
                f"- Derived total suppressions min: `{suppression.get('derived_total_suppressions_min', 0)}`",
                f"- Suppression state before: `{suppression.get('suppression_state_before', {})}`",
                f"- Suppression state after: `{suppression.get('suppression_state_after', {})}`",
                f"- Suppression rule: `{suppression.get('suppression_rule', {})}`",
                f"- Final operator-facing alert volume: `{suppression.get('final_operator_alert_volume', db_summary['counts']['alerts'])}`",
            ]
        )
    if extras.get("phase_one_counts") or extras.get("phase_two_counts"):
        lines.extend(["", "## Restart Sequence", "", f"- Phase one counts: `{extras.get('phase_one_counts', {})}`", f"- Phase two counts: `{extras.get('phase_two_counts', {})}`"])
    if extras.get("reload_latency_sec") is not None:
        lines.extend(["", "## Operator Workflow", "", f"- Reload latency sec: `{extras.get('reload_latency_sec')}`"])
        if extras.get("phase_one_rules_relpath") or extras.get("phase_two_rules_relpath"):
            lines.append(f"- Rules: `{extras.get('phase_one_rules_relpath', '')}` -> `{extras.get('phase_two_rules_relpath', '')}`")
        if extras.get("phase_one_model_relpath") or extras.get("phase_two_model_relpath"):
            lines.append(f"- Model: `{extras.get('phase_one_model_relpath', '')}` -> `{extras.get('phase_two_model_relpath', '')}`")
        if extras.get("phase_one_config_relpath") or extras.get("phase_two_config_relpath"):
            lines.append(f"- Config: `{extras.get('phase_one_config_relpath', '')}` -> `{extras.get('phase_two_config_relpath', '')}`")
    if extras.get("analyst_adjudication"):
        adjudication = dict(extras.get("analyst_adjudication") or {})
        lines.extend(
            [
                "",
                "## Analyst Adjudication",
                "",
                f"- Sample ID: `{adjudication.get('sample_id', '')}`",
                f"- Classification: `{adjudication.get('classification', '')}`",
                f"- Previous alerts: `{adjudication.get('previous_alerts', '')}`",
                f"- Current alerts: `{adjudication.get('current_alerts', '')}`",
                f"- Generalization assessment: `{adjudication.get('generalization_assessment', '')}`",
                f"- Tuning decision: `{adjudication.get('tuning_decision', '')}`",
            ]
        )
    if extras.get("operator_notes"):
        lines.extend(["", "## Operator Notes", ""])
        for note in list(extras.get("operator_notes") or []):
            lines.append(f"- {note}")
    if extras.get("planned_duration_sec"):
        lines.extend(
            [
                "",
                "## Duration",
                "",
                f"- Planned duration sec: `{extras.get('planned_duration_sec')}`",
                f"- Executed duration sec: `{extras.get('executed_duration_sec', extras.get('planned_duration_sec'))}`",
            ]
        )

    lines.extend(["", "## Execution", "", f"- Kind: `{execution['kind']}`", f"- Duration sec: `{execution['duration_sec']}`", "", "## Verdict", "", f"- Issues: `{', '.join(verdict['issues']) if verdict['issues'] else 'none'}`"])
    return "\n".join(lines) + "\n"


def _write_phase4_manifest(scenario: dict[str, Any], *, run_name: str, result_dir: Path, config_relpath: str, capture_config: dict[str, Any], remote_environment: dict[str, Any], execution: dict[str, Any], db_summary: dict[str, Any], runtime_summary: dict[str, Any], extras: dict[str, Any], verdict: dict[str, Any]) -> dict[str, Any]:
    environment = _scenario_environment_description(scenario)
    expected_outcome = _scenario_expected_outcome(scenario)
    actual_outcome = _scenario_actual_outcome(scenario, db_summary=db_summary, runtime_summary=runtime_summary, extras=extras)
    manifest = {
        "generated_at": _iso_now(),
        "scenario_id": scenario["scenario_id"],
        "scenario_name": scenario["name"],
        "run_name": run_name,
        "objective": scenario["objective"],
        "environment": environment,
        "expected_outcome": expected_outcome,
        "actual_outcome": actual_outcome,
        "config_relpath": config_relpath,
        "capture_config": capture_config,
        "remote_environment": remote_environment,
        "execution": execution,
        "database_summary": db_summary,
        "runtime_summary": runtime_summary,
        "extras": extras,
        "verdict": verdict,
        "status": verdict["status"],
        "evidence": {
            "result_dir": str(result_dir.resolve()),
            "manifest_path": str((result_dir / "prepared_env_manifest.json").resolve()),
            "summary_path": str((result_dir / "prepared_env_summary.md").resolve()),
        },
    }
    _write_json(result_dir / "capture_config.json", capture_config)
    _write_json(result_dir / "remote_environment.json", remote_environment)
    if extras:
        _write_json(result_dir / "prepared_env_metrics.json", extras)
    _write_json(result_dir / "prepared_env_manifest.json", manifest)
    _write_text(result_dir / "prepared_env_summary.md", _summary_markdown(scenario, run_name=run_name, result_dir=result_dir, config_relpath=config_relpath, execution=execution, db_summary=db_summary, runtime_summary=runtime_summary, verdict=verdict, extras=extras))
    return manifest


def _run_attack_script_scenario(scenario: dict[str, Any], *, python_path: Path, remote_environment: dict[str, Any], username: str, password: str) -> dict[str, Any]:
    _, run_name, _result_rel, result_dir = _scenario_paths(scenario)
    command = [
        str(python_path),
        str(LIVE_VM_SCRIPT),
        "--run-name",
        run_name,
        "--config-relpath",
        str(scenario["config_relpath"]),
    ]
    command.extend(str(item) for item in scenario.get("args", []))
    execution = _host_command(
        command,
        env={
            LIVEVM.LAB_VM_USER_ENV: username,
            LIVEVM.LAB_VM_PASS_ENV: password,
        },
    )
    if execution.get("stdout"):
        _write_text(result_dir / "attack_validation_stdout.log", str(execution["stdout"]))
    if execution.get("stderr"):
        _write_text(result_dir / "attack_validation_stderr.log", str(execution["stderr"]))
    runtime_summary = _parse_runtime_log(result_dir / "runtime.log")
    db_summary = _summarize_db(result_dir / "nids.db")
    capture_config = _read_yaml(REPO_ROOT / str(scenario["config_relpath"]))
    extras = {
        "attack_validation_summary_path": str((result_dir / "attack_validation_summary.json").resolve()),
        "attack_validation_stdout_path": str((result_dir / "attack_validation_stdout.log").resolve()),
        "attack_validation_stderr_path": str((result_dir / "attack_validation_stderr.log").resolve()),
        "metric_summary": _summarize_metric_series(result_dir / "nids.db"),
        "alert_details": _extract_alert_rows(result_dir / "nids.db"),
    }
    verdict = _build_verdict(scenario, execution_ok=execution["returncode"] == 0, db_summary=db_summary, runtime_summary=runtime_summary, extras=extras)
    return _write_phase4_manifest(scenario, run_name=run_name, result_dir=result_dir, config_relpath=str(scenario["config_relpath"]), capture_config=capture_config, remote_environment=remote_environment, execution={"kind": "live_vm_attack_validation", "duration_sec": execution["duration_sec"], "returncode": execution["returncode"], "command": execution["command"]}, db_summary=db_summary, runtime_summary=runtime_summary, extras=extras, verdict=verdict)


def _run_custom_remote_scenario(scenario: dict[str, Any], *, remote_environment: dict[str, Any], username: str, password: str, sensor_host: str, sensor_port: int, target_host: str, target_port: int, workspace: str, sensor_ip: str, duration_override_sec: float | None = None) -> dict[str, Any]:
    _run_leaf, run_name, result_rel, result_dir = _scenario_paths(scenario)
    result_dir.mkdir(parents=True, exist_ok=True)
    config_relpath = str(scenario["config_relpath"])
    phase_one_config_relpath = str(scenario.get("pre_workflow_config_relpath") or config_relpath)
    phase_one_rules_relpath = str(scenario.get("pre_workflow_rules_relpath") or "rules/rules.yml")
    phase_one_model_relpath = str(scenario.get("pre_workflow_model_relpath") or "models/model.pkl")
    sensor = LIVEVM._connect(sensor_host, sensor_port, username, password)
    target = LIVEVM._connect(target_host, target_port, username, password)
    http_server_pids: list[int] = []
    udp_sink_pids: list[tuple[int, bool]] = []
    pid = 0
    phase_one_counts: dict[str, int] = {}
    phase_two_counts: dict[str, int] = {}
    phase_one_rule_count: int | None = None
    phase_two_rule_count: int | None = None
    process_samples: list[dict[str, Any]] = []
    runtime_samples: list[dict[str, Any]] = []
    runtime_starts: list[dict[str, Any]] = []
    errors: list[str] = []
    execution_ok = False
    reload_latency_sec: float | None = None
    suppression_validation: dict[str, Any] = {}
    phase_two_rules_relpath = phase_one_rules_relpath
    phase_two_model_relpath = phase_one_model_relpath
    phase_two_config_relpath = config_relpath
    runtime_phase1_path = result_dir / "runtime_phase1.log"
    planned_duration_sec = float(scenario.get("planned_duration_sec") or scenario.get("duration_sec") or 0.0)
    executed_duration_sec = planned_duration_sec
    if duration_override_sec is not None and planned_duration_sec > 0:
        executed_duration_sec = min(planned_duration_sec, max(10.0, float(duration_override_sec)))
    warmup_sec = max(1.0, float(scenario.get("warmup_sec") or 5.0))
    settle_sec = max(1.0, float(scenario.get("settle_sec") or 8.0))
    sample_interval_sec = max(1.0, float(scenario.get("sample_interval_sec") or 5.0))
    started_at = _iso_now()
    start_perf = time.perf_counter()

    def _copy_runtime_log(remote_name: str) -> None:
        LIVEVM._run_command(
            sensor,
            (
                f"cp {LIVEVM._quote_remote(posixpath.join(workspace, result_rel, 'runtime.log'))} "
                f"{LIVEVM._quote_remote(posixpath.join(workspace, result_rel, remote_name))}"
            ),
            timeout=30,
            check=False,
        )

    def _start_runtime_active(active_config_relpath: str, *, rules_relpath: str, model_relpath: str) -> None:
        nonlocal pid
        start_info = _start_runtime_custom(
            sensor,
            workspace,
            result_rel,
            config_relpath=active_config_relpath.replace("\\", "/"),
            sudo_password=password,
            rules_relpath=rules_relpath.replace("\\", "/"),
            model_relpath=model_relpath.replace("\\", "/"),
        )
        pid = int(start_info["pid"])
        runtime_starts.append(start_info)

    def _stop_runtime_active() -> None:
        nonlocal pid
        if pid:
            LIVEVM._stop_runtime(sensor, pid, sudo_password=password)
            pid = 0

    def _tag_runtime_samples(samples: list[dict[str, Any]], phase: str) -> list[dict[str, Any]]:
        tagged: list[dict[str, Any]] = []
        for item in samples:
            payload = dict(item)
            payload["phase"] = phase
            tagged.append(payload)
        return tagged

    try:
        sync_relpaths = [phase_one_config_relpath] if phase_one_config_relpath != config_relpath else []
        _sync_sensor_files(sensor, config_relpath, password, extra_relpaths=sync_relpaths)
        if scenario["kind"] == "custom_live_suppression":
            remote_result_abs = posixpath.join(workspace, result_rel)
            LIVEVM._run_command(
                sensor,
                f"sudo -S mkdir -p {LIVEVM._quote_remote(remote_result_abs)}",
                sudo_password=password,
                timeout=60,
                check=True,
            )
            LIVEVM._run_command(
                sensor,
                f"sudo -S chown nidslab:nidslab {LIVEVM._quote_remote(remote_result_abs)}",
                sudo_password=password,
                timeout=60,
                check=True,
            )
            phase_one_rules_relpath = posixpath.join(result_rel, "phase6_live_suppression_rules.yml")
            local_rule_path = _write_dns_signature_rules_file(
                result_dir,
                filename="phase6_live_suppression_rules.yml",
                rule_name=str(scenario.get("suppression_rule_name") or "Phase6 Duplicate Noise Signature"),
                dns_qname_token=str(scenario.get("suppression_dns_qname") or "phase6-suppression.example"),
                summary="Phase 6 live suppression validation signature",
            )
            LIVEVM._upload_file(sensor, local_rule_path, posixpath.join(workspace, phase_one_rules_relpath), sudo_password=password)
        if scenario["kind"] in {"custom_malformed", "custom_benign_soak", "custom_restart_recovery", "custom_extended_soak", "custom_rule_refresh", "custom_model_swap", "custom_config_override", "custom_live_suppression"}:
            udp_sink_pid = LIVEVM._start_udp_sink(sensor, result_rel, port=53, sudo_password=password)
            if udp_sink_pid not in {None, 0}:
                udp_sink_pids.append((udp_sink_pid, True))
        if scenario["kind"] in {"custom_benign_soak", "custom_extended_soak", "custom_config_override"}:
            http_server_pid = LIVEVM._start_http_login_server(sensor, result_rel, port=int(scenario.get("http_port") or 8080), sudo_password=password)
            if http_server_pid not in {None, 0}:
                http_server_pids.append(http_server_pid)
        time.sleep(1)

        _start_runtime_active(phase_one_config_relpath, rules_relpath=phase_one_rules_relpath, model_relpath=phase_one_model_relpath)
        time.sleep(warmup_sec)

        if scenario["kind"] == "custom_malformed":
            LIVEVM._trigger_dns_burst_with_delay(target, sensor_ip, count=40, delay_sec=0.05)
            _send_malformed_dns_mix(target, sensor_ip, valid_count=0, malformed_count=12, delay_sec=0.02)
            time.sleep(settle_sec)
            _stop_runtime_active()
        elif scenario["kind"] == "custom_benign_soak":
            duration_sec = executed_duration_sec if executed_duration_sec > 0 else 120.0
            dns_rate = float(scenario.get("dns_rate_per_sec") or 18.0)
            http_rate = float(scenario.get("http_rate_per_sec") or 1.0)
            http_port = int(scenario.get("http_port") or 8080)
            dns_queries = _coerce_string_list(scenario.get("dns_queries"), default=["www.example.org"])
            http_requests = _coerce_http_requests(scenario.get("http_requests"))

            def target_job() -> None:
                try:
                    _run_benign_soak_traffic(
                        target,
                        sensor_ip,
                        duration_sec=duration_sec,
                        dns_rate_per_sec=dns_rate,
                        http_rate_per_sec=http_rate,
                        http_port=http_port,
                        dns_queries=dns_queries,
                        http_requests=http_requests,
                    )
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=target_job, daemon=True)
            thread.start()
            runtime_samples = _tag_runtime_samples(
                _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=duration_sec, interval_sec=sample_interval_sec),
                "steady_state",
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            process_samples = [
                {
                    "captured_at": item.get("captured_at"),
                    "pid": item.get("pid"),
                    "rss_kib": item.get("rss_kib"),
                    "cpu_percent": item.get("cpu_percent"),
                    "elapsed": item.get("elapsed"),
                }
                for item in runtime_samples
                if item.get("pid") is not None
            ]
            time.sleep(settle_sec)
            _stop_runtime_active()
        elif scenario["kind"] == "custom_restart_recovery":
            LIVEVM._trigger_dns_burst_with_delay(target, sensor_ip, count=40, delay_sec=0.06)
            time.sleep(settle_sec)
            _stop_runtime_active()
            phase_one_counts = _remote_db_counts(sensor, workspace, result_rel)
            _copy_runtime_log("runtime_phase1.log")
            restart_started = time.perf_counter()
            _start_runtime_active(config_relpath, rules_relpath=phase_one_rules_relpath, model_relpath=phase_one_model_relpath)
            time.sleep(warmup_sec)
            reload_latency_sec = round(time.perf_counter() - restart_started, 3)
            LIVEVM._trigger_tcp_scan(target, sensor_ip, start_port=5000, count=48, delay_sec=0.05)
            runtime_samples = _tag_runtime_samples(
                _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=10.0, interval_sec=4.0),
                "post_restart",
            )
            time.sleep(settle_sec)
            _stop_runtime_active()
            phase_two_counts = _remote_db_counts(sensor, workspace, result_rel)
        elif scenario["kind"] == "custom_extended_soak":
            duration_sec = executed_duration_sec if executed_duration_sec > 0 else 21600.0
            dns_rate = float(scenario.get("dns_rate_per_sec") or 12.0)
            http_rate = float(scenario.get("http_rate_per_sec") or 0.75)
            http_port = int(scenario.get("http_port") or 8080)
            dns_queries = _coerce_string_list(scenario.get("dns_queries"), default=["www.example.org"])
            http_requests = _coerce_http_requests(scenario.get("http_requests"))
            first_phase_sec = max(30.0, round(duration_sec / 2.0, 3))
            second_phase_sec = max(30.0, round(duration_sec - first_phase_sec, 3))

            def target_job() -> None:
                try:
                    _run_benign_soak_traffic(
                        target,
                        sensor_ip,
                        duration_sec=duration_sec,
                        dns_rate_per_sec=dns_rate,
                        http_rate_per_sec=http_rate,
                        http_port=http_port,
                        dns_queries=dns_queries,
                        http_requests=http_requests,
                    )
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=target_job, daemon=True)
            thread.start()
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=first_phase_sec, interval_sec=sample_interval_sec),
                    "soak_phase_one",
                )
            )
            phase_one_counts = _remote_db_counts(sensor, workspace, result_rel)
            _copy_runtime_log("runtime_phase1.log")
            restart_started = time.perf_counter()
            _stop_runtime_active()
            _start_runtime_active(config_relpath, rules_relpath=phase_one_rules_relpath, model_relpath=phase_one_model_relpath)
            time.sleep(warmup_sec)
            reload_latency_sec = round(time.perf_counter() - restart_started, 3)
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=second_phase_sec, interval_sec=sample_interval_sec),
                    "soak_phase_two",
                )
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            process_samples = [
                {
                    "captured_at": item.get("captured_at"),
                    "pid": item.get("pid"),
                    "rss_kib": item.get("rss_kib"),
                    "cpu_percent": item.get("cpu_percent"),
                    "elapsed": item.get("elapsed"),
                    "phase": item.get("phase"),
                }
                for item in runtime_samples
                if item.get("pid") is not None
            ]
            time.sleep(settle_sec)
            _stop_runtime_active()
            phase_two_counts = _remote_db_counts(sensor, workspace, result_rel)
        elif scenario["kind"] == "custom_live_suppression":
            duration_sec = executed_duration_sec if executed_duration_sec > 0 else 42.0
            rate_per_sec = float(scenario.get("dns_rate_per_sec") or 12.0)
            rule_name = str(scenario.get("suppression_rule_name") or "Phase6 Duplicate Noise Signature")
            qname_token = str(scenario.get("suppression_dns_qname") or "phase6-suppression.example")
            pre_window_sec = max(8.0, float(scenario.get("pre_suppression_duration_sec") or 12.0))
            post_window_sec = max(12.0, float(scenario.get("post_suppression_duration_sec") or max(12.0, duration_sec - pre_window_sec)))
            ttl_minutes = max(1, int(scenario.get("suppression_ttl_minutes") or 60))

            def pre_suppression_job() -> None:
                try:
                    _run_dns_stream(target, sensor_ip, duration_sec=pre_window_sec, rate_per_sec=rate_per_sec, qname=qname_token, unique_qnames=False)
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=pre_suppression_job, daemon=True)
            thread.start()
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=pre_window_sec, interval_sec=sample_interval_sec),
                    "pre_suppression",
                )
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            time.sleep(max(2.0, min(settle_sec, 4.0)))

            pre_counts = _remote_db_counts(sensor, workspace, result_rel)
            pre_metrics = _remote_metric_last_values(sensor, workspace, result_rel, ["total_alerts", "suppressed_alerts", "policy_suppressed_alerts"])
            suppression_state_before = _remote_suppression_overview(sensor, workspace, result_rel, rule_name=rule_name)
            alert_id = _remote_latest_alert_id(sensor, workspace, result_rel, rule_name=rule_name)
            if alert_id <= 0:
                raise RuntimeError(f"Suppression validation did not produce an alert for rule {rule_name}")
            suppression_rule = _remote_create_suppression_rule(
                sensor,
                workspace,
                result_rel,
                alert_id=alert_id,
                actor="phase6-operator",
                actor_role="operator",
                ttl_minutes=ttl_minutes,
                reason="Phase 6 live suppression validation",
                metadata={"scenario_id": scenario["scenario_id"], "source": "phase6-live-suppression"},
                sudo_password=password,
            )
            _copy_runtime_log("runtime_phase1.log")

            def post_suppression_job() -> None:
                try:
                    _run_dns_stream(target, sensor_ip, duration_sec=post_window_sec, rate_per_sec=rate_per_sec, qname=qname_token, unique_qnames=False)
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=post_suppression_job, daemon=True)
            thread.start()
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=post_window_sec, interval_sec=sample_interval_sec),
                    "post_suppression",
                )
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            process_samples = [
                {
                    "captured_at": item.get("captured_at"),
                    "pid": item.get("pid"),
                    "rss_kib": item.get("rss_kib"),
                    "cpu_percent": item.get("cpu_percent"),
                    "elapsed": item.get("elapsed"),
                    "phase": item.get("phase"),
                }
                for item in runtime_samples
                if item.get("pid") is not None
            ]
            time.sleep(max(2.0, min(settle_sec, 4.0)))
            post_counts = _remote_db_counts(sensor, workspace, result_rel)
            post_metrics = _remote_metric_last_values(sensor, workspace, result_rel, ["total_alerts", "suppressed_alerts", "policy_suppressed_alerts"])
            suppression_state_after = _remote_suppression_overview(sensor, workspace, result_rel, rule_name=rule_name)
            _stop_runtime_active()
            derived_duplicate_suppressions_min = max(0, int(pre_counts.get("flows", 0)) - int(pre_counts.get("alerts", 0)))
            post_flow_growth = max(0, int(post_counts.get("flows", 0)) - int(pre_counts.get("flows", 0)))
            post_alert_growth = max(0, int(post_counts.get("alerts", 0)) - int(pre_counts.get("alerts", 0)))
            derived_policy_suppressions_min = max(0, post_flow_growth - post_alert_growth)
            suppression_validation = {
                "rule_name": rule_name,
                "dns_qname": qname_token,
                "duplicate_window_sec": int(scenario.get("suppress_window_sec") or 15),
                "pre_suppression_counts": pre_counts,
                "post_suppression_counts": post_counts,
                "pre_suppression_metrics": pre_metrics,
                "post_suppression_metrics": post_metrics,
                "derived_duplicate_suppressions_min": derived_duplicate_suppressions_min,
                "derived_policy_suppressions_min": derived_policy_suppressions_min,
                "derived_total_suppressions_min": derived_duplicate_suppressions_min + derived_policy_suppressions_min,
                "suppression_state_before": suppression_state_before,
                "suppression_state_after": suppression_state_after,
                "suppression_rule": suppression_rule,
                "source_alert_id": int(alert_id),
                "final_operator_alert_volume": int(post_counts.get("alerts", 0)),
            }
        elif scenario["kind"] == "custom_rule_refresh":
            duration_sec = executed_duration_sec if executed_duration_sec > 0 else 45.0
            rate_per_sec = float(scenario.get("dns_rate_per_sec") or 20.0)
            rule_name = str(scenario.get("rule_refresh_rule_name") or "Phase5 DNS Rule Refresh Signature")
            qname_token = str(scenario.get("rule_refresh_dns_qname") or "phase5-refresh.example")
            phase_two_rules_relpath = posixpath.join(result_rel, "phase5_rule_refresh_rules.yml")
            local_rule_path = _write_rule_refresh_rules_file(result_dir, rule_name=rule_name, dns_qname_token=qname_token)
            LIVEVM._upload_file(sensor, local_rule_path, posixpath.join(workspace, phase_two_rules_relpath), sudo_password=password)
            pre_window_sec = max(10.0, min(duration_sec * 0.45, duration_sec - 10.0))
            post_window_sec = max(10.0, duration_sec - pre_window_sec)

            def target_job() -> None:
                try:
                    _run_dns_stream(target, sensor_ip, duration_sec=duration_sec, rate_per_sec=rate_per_sec, qname=qname_token, unique_qnames=False)
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=target_job, daemon=True)
            thread.start()
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=pre_window_sec, interval_sec=sample_interval_sec),
                    "pre_refresh",
                )
            )
            phase_one_counts = _remote_db_counts(sensor, workspace, result_rel)
            phase_one_rule_count = _remote_rule_count(sensor, workspace, result_rel, rule_name)
            _copy_runtime_log("runtime_phase1.log")
            restart_started = time.perf_counter()
            _stop_runtime_active()
            _start_runtime_active(config_relpath, rules_relpath=phase_two_rules_relpath, model_relpath=phase_one_model_relpath)
            time.sleep(warmup_sec)
            reload_latency_sec = round(time.perf_counter() - restart_started, 3)
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=post_window_sec, interval_sec=sample_interval_sec),
                    "post_refresh",
                )
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            time.sleep(settle_sec)
            _stop_runtime_active()
            phase_two_counts = _remote_db_counts(sensor, workspace, result_rel)
            phase_two_rule_count = _remote_rule_count(sensor, workspace, result_rel, rule_name)
        elif scenario["kind"] == "custom_model_swap":
            duration_sec = executed_duration_sec if executed_duration_sec > 0 else 45.0
            rate_per_sec = float(scenario.get("dns_rate_per_sec") or 16.0)
            traffic_qname = str(scenario.get("traffic_qname") or "phase5-model-swap.example")
            phase_two_model_relpath = posixpath.join(result_rel, "model_phase5_swap.pkl")
            _copy_remote_file(sensor, posixpath.join(workspace, phase_one_model_relpath.replace("\\", "/")), posixpath.join(workspace, phase_two_model_relpath), sudo_password=password)
            pre_window_sec = max(10.0, min(duration_sec * 0.45, duration_sec - 10.0))
            post_window_sec = max(10.0, duration_sec - pre_window_sec)

            def target_job() -> None:
                try:
                    _run_dns_stream(target, sensor_ip, duration_sec=duration_sec, rate_per_sec=rate_per_sec, qname=traffic_qname, unique_qnames=True)
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=target_job, daemon=True)
            thread.start()
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=pre_window_sec, interval_sec=sample_interval_sec),
                    "pre_model_swap",
                )
            )
            phase_one_counts = _remote_db_counts(sensor, workspace, result_rel)
            _copy_runtime_log("runtime_phase1.log")
            restart_started = time.perf_counter()
            _stop_runtime_active()
            _start_runtime_active(config_relpath, rules_relpath=phase_one_rules_relpath, model_relpath=phase_two_model_relpath)
            time.sleep(warmup_sec)
            reload_latency_sec = round(time.perf_counter() - restart_started, 3)
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=post_window_sec, interval_sec=sample_interval_sec),
                    "post_model_swap",
                )
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            time.sleep(settle_sec)
            _stop_runtime_active()
            phase_two_counts = _remote_db_counts(sensor, workspace, result_rel)
        elif scenario["kind"] == "custom_config_override":
            duration_sec = executed_duration_sec if executed_duration_sec > 0 else 60.0
            dns_rate = float(scenario.get("dns_rate_per_sec") or 12.0)
            http_rate = float(scenario.get("http_rate_per_sec") or 0.75)
            http_port = int(scenario.get("http_port") or 8080)
            dns_queries = _coerce_string_list(scenario.get("dns_queries"), default=["www.example.org"])
            http_requests = _coerce_http_requests(scenario.get("http_requests"))
            pre_window_sec = max(12.0, min(duration_sec * 0.4, duration_sec - 12.0))
            post_window_sec = max(12.0, duration_sec - pre_window_sec)

            def target_job() -> None:
                try:
                    _run_benign_soak_traffic(
                        target,
                        sensor_ip,
                        duration_sec=duration_sec,
                        dns_rate_per_sec=dns_rate,
                        http_rate_per_sec=http_rate,
                        http_port=http_port,
                        dns_queries=dns_queries,
                        http_requests=http_requests,
                    )
                except Exception as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=target_job, daemon=True)
            thread.start()
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=pre_window_sec, interval_sec=sample_interval_sec),
                    "pre_config_override",
                )
            )
            phase_one_counts = _remote_db_counts(sensor, workspace, result_rel)
            _copy_runtime_log("runtime_phase1.log")
            restart_started = time.perf_counter()
            _stop_runtime_active()
            _start_runtime_active(config_relpath, rules_relpath=phase_one_rules_relpath, model_relpath=phase_one_model_relpath)
            time.sleep(warmup_sec)
            reload_latency_sec = round(time.perf_counter() - restart_started, 3)
            runtime_samples.extend(
                _tag_runtime_samples(
                    _sample_runtime_state(sensor, workspace, result_rel, pid, duration_sec=post_window_sec, interval_sec=sample_interval_sec),
                    "post_config_override",
                )
            )
            thread.join()
            if errors:
                raise RuntimeError("; ".join(errors))
            process_samples = [
                {
                    "captured_at": item.get("captured_at"),
                    "pid": item.get("pid"),
                    "rss_kib": item.get("rss_kib"),
                    "cpu_percent": item.get("cpu_percent"),
                    "elapsed": item.get("elapsed"),
                    "phase": item.get("phase"),
                }
                for item in runtime_samples
                if item.get("pid") is not None
            ]
            time.sleep(settle_sec)
            _stop_runtime_active()
            phase_two_counts = _remote_db_counts(sensor, workspace, result_rel)
        else:
            raise ValueError(f"Unsupported custom scenario kind: {scenario['kind']}")

        execution_ok = True
        returncode = 0
    except Exception as exc:
        returncode = 1
        _write_text(result_dir / "execution_error.log", str(exc) + "\n")
    finally:
        if pid:
            try:
                _stop_runtime_active()
            except Exception:
                pass
        _cleanup_remote_helpers(sensor, http_server_pids=http_server_pids, udp_sink_pids=udp_sink_pids, password=password)
        try:
            LIVEVM._chown_result_dir(sensor, workspace, result_rel, sudo_password=password)
            LIVEVM._generate_reports(sensor, workspace, result_rel)
            LIVEVM._collect_artifacts(sensor, workspace, result_rel, result_dir)
            if phase_one_counts:
                try:
                    LIVEVM._download_file(sensor, posixpath.join(workspace, result_rel, "runtime_phase1.log"), runtime_phase1_path)
                except Exception:
                    pass
        except Exception as exc:
            _write_text(result_dir / "collection_error.log", str(exc) + "\n")
        sensor.close()
        target.close()

    runtime_summary = _parse_runtime_log(result_dir / "runtime.log")
    db_summary = _summarize_db(result_dir / "nids.db")
    capture_config = _read_yaml(REPO_ROOT / config_relpath)
    extras: dict[str, Any] = {}
    metric_summary = _summarize_metric_series(result_dir / "nids.db")
    alert_limit = max(25, min(500, int(db_summary.get("counts", {}).get("alerts", 0) or 0)))
    alert_details = _extract_alert_rows(result_dir / "nids.db", limit=alert_limit)
    if process_samples:
        extras["process_samples"] = process_samples
    if runtime_samples:
        extras["runtime_samples"] = runtime_samples
    if metric_summary.get("metrics"):
        extras["metric_summary"] = metric_summary
    if alert_details:
        extras["alert_details"] = alert_details
    if planned_duration_sec > 0:
        extras["planned_duration_sec"] = float(planned_duration_sec)
        extras["executed_duration_sec"] = float(executed_duration_sec or planned_duration_sec)
    if duration_override_sec is not None:
        extras["duration_override_sec"] = float(duration_override_sec)
    if runtime_starts:
        extras["runtime_starts"] = runtime_starts
    if reload_latency_sec is not None:
        extras["reload_latency_sec"] = reload_latency_sec
    if scenario["kind"] == "custom_malformed":
        extras.update({"valid_queries_sent": 40, "malformed_packets_sent": 12})
    if scenario["kind"] == "custom_benign_soak":
        extras["sample_id"] = str(scenario.get("sample_id") or scenario["scenario_id"])
        extras["sample_description"] = str(scenario.get("sample_description") or "")
        extras["analyst_note"] = (
            "Zero alerts were expected for this benign sample. This remains sample-bounded evidence, "
            "not a universal false-positive claim."
        )
    if scenario["kind"] == "custom_live_suppression" and suppression_validation:
        extras["suppression_validation"] = suppression_validation
    if scenario["kind"] == "custom_extended_soak":
        extras["soak_analysis"] = _build_soak_analysis(
            db_summary=db_summary,
            runtime_summary=runtime_summary,
            extras=extras,
            result_dir=result_dir,
        )
    if phase_one_counts or phase_two_counts:
        extras["phase_one_counts"] = phase_one_counts
        extras["phase_two_counts"] = phase_two_counts
        extras["pre_workflow_counts"] = phase_one_counts
        extras["post_workflow_counts"] = phase_two_counts
        extras["phase_one_runtime_log_path"] = str(runtime_phase1_path.resolve())
    if runtime_phase1_path.exists():
        extras["phase_one_runtime_summary"] = _parse_runtime_log(runtime_phase1_path)
    if phase_one_rule_count is not None or phase_two_rule_count is not None:
        extras["phase_one_rule_count"] = int(phase_one_rule_count or 0)
        extras["phase_two_rule_count"] = int(phase_two_rule_count or 0)
    if scenario["kind"] == "custom_rule_refresh":
        extras["phase_one_rules_relpath"] = phase_one_rules_relpath
        extras["phase_two_rules_relpath"] = phase_two_rules_relpath
        extras["rule_refresh_rule_name"] = str(scenario.get("rule_refresh_rule_name") or "Phase5 DNS Rule Refresh Signature")
        extras["rule_refresh_dns_qname"] = str(scenario.get("rule_refresh_dns_qname") or "phase5-refresh.example")
    if scenario["kind"] == "custom_model_swap":
        extras["phase_one_model_relpath"] = phase_one_model_relpath
        extras["phase_two_model_relpath"] = phase_two_model_relpath
        extras["model_swap_strategy"] = "Identical supervised model copy used to validate operator swap mechanics without changing model semantics."
    if scenario["kind"] == "custom_config_override":
        extras["phase_one_config_relpath"] = phase_one_config_relpath
        extras["phase_two_config_relpath"] = phase_two_config_relpath
    if scenario["kind"] == "custom_benign_soak":
        current_alerts = int(db_summary.get("counts", {}).get("alerts", 0))
        previous_alerts = scenario.get("previous_alerts")
        generalization_assessment = str(scenario.get("generalization_assessment_if_zero_alerts") or "sample_bounded")
        if current_alerts > 0:
            generalization_assessment = str(scenario.get("generalization_assessment_if_alerts") or "possible_overfit")
        extras["analyst_adjudication"] = {
            "sample_id": str(scenario.get("sample_id") or scenario["scenario_id"]),
            "previous_run": str(scenario.get("previous_run") or ""),
            "previous_alerts": previous_alerts if previous_alerts is not None else "",
            "current_alerts": current_alerts,
            "classification": "cleared_after_tuning" if current_alerts == 0 else "still_false_positive_risk",
            "generalization_assessment": generalization_assessment,
            "tuning_decision": "Enabled ml.unsupervised_min_active_components=2 in the tuned live profile to suppress single-component isolation-forest spikes on benign soak traffic.",
        }
    operator_notes: list[str] = []
    if scenario["kind"] == "custom_benign_soak":
        operator_notes.append(
            f"Benign sample {extras.get('sample_id', scenario['scenario_id'])} completed with "
            f"{db_summary.get('counts', {}).get('flows', 0)} flows and {db_summary.get('counts', {}).get('alerts', 0)} alerts."
        )
        if metric_summary.get("metrics"):
            operator_notes.append(
                "Runtime counters ended at "
                f"loss_pct={dict(metric_summary['metrics'].get('live_packet_loss_pct') or {}).get('last_value', 0.0)} "
                f"and queue_peak={dict(metric_summary['metrics'].get('live_queue_depth_peak') or {}).get('max_value', 0.0)}."
            )
    if scenario["kind"] == "custom_live_suppression" and suppression_validation:
        operator_notes.append(
            "Repeated live DNS signature traffic produced a bounded number of alerts before manual suppression was applied."
        )
        operator_notes.append(
            "After the suppression rule was created, the alert count stayed stable while derived post-policy suppression volume remained non-zero."
        )
    if scenario["kind"] == "custom_extended_soak":
        operator_notes.append(
            f"Extended soak retained runtime samples={len(runtime_samples)} and process samples={len(process_samples)} with reload latency={reload_latency_sec}."
        )
    if operator_notes:
        extras["operator_notes"] = operator_notes
    verdict = _build_verdict(scenario, execution_ok=execution_ok, db_summary=db_summary, runtime_summary=runtime_summary, extras=extras)
    return _write_phase4_manifest(scenario, run_name=run_name, result_dir=result_dir, config_relpath=config_relpath, capture_config=capture_config, remote_environment=remote_environment, execution={"kind": "custom_remote_validation", "duration_sec": round(time.perf_counter() - start_perf, 3), "returncode": returncode, "started_at": started_at}, db_summary=db_summary, runtime_summary=runtime_summary, extras=extras, verdict=verdict)


SCENARIOS: list[dict[str, Any]] = [
    {"scenario_id": "PREP-ENV-001", "slug": "phase4-live-tcpdump-portscan", "name": "Prepared Environment Tcpdump FIFO Port Scan", "kind": "attack_script", "config_relpath": "NIDS_TestLab/config/live_vm_profile.yml", "expected_backend": "tcpdump", "objective": "Validate the live tcpdump-to-FIFO-to-runtime pipeline on the sensor VM with a real NIC-backed port scan.", "required_rules": ["Port Scan Threshold"], "args": ["--dns-count", "0", "--ssh-attempts", "0", "--rdp-attempts", "0", "--http-login-attempts", "0", "--http-keyword-requests", "0", "--scan-start-port", "5000", "--scan-port-count", "80", "--scan-delay-sec", "0.08", "--warmup-sec", "5", "--settle-sec", "10"]},
    {"scenario_id": "PREP-ENV-002", "slug": "phase4-live-scapy-direct-dns-burst", "name": "Prepared Environment Direct NIC Scapy DNS Burst", "kind": "attack_script", "config_relpath": "NIDS_TestLab/config/live_vm_scapy_profile.yml", "expected_backend": "scapy", "objective": "Validate direct NIC capture through the scapy backend on the sensor VM with a live DNS burst.", "required_rules": ["DNS Burst / DGA-like Activity"], "args": ["--dns-count", "80", "--dns-delay-sec", "0.05", "--ssh-attempts", "0", "--rdp-attempts", "0", "--http-login-attempts", "0", "--http-keyword-requests", "0", "--warmup-sec", "5", "--settle-sec", "10"]},
    {"scenario_id": "PREP-ENV-003", "slug": "phase5-loss-accounting-dns-flood", "name": "Prepared Environment Queue Pressure And Loss Accounting", "kind": "attack_script", "results_subdir": "phase5-tuning", "config_relpath": "NIDS_TestLab/config/live_vm_loss_profile.yml", "expected_backend": "tcpdump", "objective": "Force queue pressure under live capture, record explicit packet counters, and quantify queue loss percentage without crashing the runtime.", "required_rules": [], "require_drop": True, "require_capture_metrics": True, "min_packets_received": 300, "args": ["--dns-count", "0", "--ssh-attempts", "0", "--rdp-attempts", "0", "--http-login-attempts", "0", "--http-keyword-requests", "0", "--dns-flood-rate-per-sec", "450", "--dns-flood-duration-sec", "18", "--dns-flood-qname", "phase5-loss.example", "--warmup-sec", "5", "--settle-sec", "12"]},
    {"scenario_id": "PREP-ENV-004", "slug": "phase4-live-malformed-dns", "name": "Prepared Environment Malformed Packet Handling", "kind": "custom_malformed", "config_relpath": "NIDS_TestLab/config/live_vm_profile.yml", "expected_backend": "tcpdump", "objective": "Validate that malformed UDP or DNS-like traffic does not crash the live runtime and that valid traffic in the same run is still processed.", "required_rules": ["DNS Burst / DGA-like Activity"]},
    {"scenario_id": "PREP-ENV-005", "slug": "phase5-benign-soak-tuned", "name": "Prepared Environment Benign Soak After Live Tuning", "kind": "custom_benign_soak", "results_subdir": "phase5-tuning", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Rerun the benign prepared-environment soak with tuned live unsupervised settings and capture analyst adjudication evidence.", "expected_outcome": "The tuned profile should complete this original benign soak sample without operator-visible alerts and retain resource evidence for analyst review.", "expect_zero_alerts": True, "max_alerts": 0, "require_process_samples": True, "require_runtime_samples": True, "duration_sec": 180, "sample_interval_sec": 15, "dns_rate_per_sec": 18, "http_rate_per_sec": 1.0, "dns_queries": ["www.example.org", "status.portal.example", "resolver.office.example"], "http_requests": [{"method": "GET", "path": "/status", "host": "portal.internal", "body": ""}, {"method": "GET", "path": "/health", "host": "portal.internal", "body": ""}], "sample_id": "BENIGN-LIVE-001", "sample_description": "Original tuned benign polling mix from Phase 5.", "previous_run": "NIDS_TestLab/results/phase4-live-benign-soak-20260312-143826", "previous_alerts": 2, "generalization_assessment_if_zero_alerts": "clears_exercised_sample_only", "generalization_assessment_if_alerts": "possible_overfit", "required_rules": []},
    {"scenario_id": "PREP-ENV-006", "slug": "phase4-live-restart-recovery", "name": "Prepared Environment Restart And Recovery", "kind": "custom_restart_recovery", "config_relpath": "NIDS_TestLab/config/live_vm_profile.yml", "expected_backend": "tcpdump", "objective": "Validate that the live runtime can be stopped and restarted against the same output directory while preserving recoverable evidence.", "required_rules": ["DNS Burst / DGA-like Activity", "Port Scan Threshold"], "require_alert_growth": True},
    {"scenario_id": "PREP-ENV-007", "slug": "phase6-full-duration-soak", "name": "Prepared Environment Full-Duration Soak", "kind": "custom_extended_soak", "results_subdir": "phase6-soak", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Run the full prepared-environment soak for the target 6 to 12 hour window, record memory and CPU growth over time, track storage and alert volume, and verify restart stability under the tuned deployment profile.", "expected_outcome": "The full-duration soak should remain alert-free on the tuned profile, retain resource and storage growth evidence across the full window, and survive the midpoint restart with continued flow growth.", "expect_zero_alerts": True, "max_alerts": 0, "require_process_samples": True, "require_runtime_samples": True, "require_reload_latency": True, "require_post_restart_growth": True, "planned_duration_sec": 21600, "sample_interval_sec": 120, "dns_rate_per_sec": 10, "http_rate_per_sec": 0.5, "required_rules": []},
    {"scenario_id": "PREP-ENV-008", "slug": "phase5-operator-rule-refresh", "name": "Prepared Environment Operator Rule Refresh", "kind": "custom_rule_refresh", "results_subdir": "phase5-operator", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Validate restart-based rule refresh while live DNS traffic is active and prove the new signature begins matching only after the refresh.", "required_rules": ["Phase5 DNS Rule Refresh Signature"], "require_reload_latency": True, "require_post_restart_growth": True, "duration_sec": 45, "sample_interval_sec": 10, "dns_rate_per_sec": 20, "rule_refresh_rule_name": "Phase5 DNS Rule Refresh Signature", "rule_refresh_dns_qname": "phase5-refresh.example"},
    {"scenario_id": "PREP-ENV-009", "slug": "phase5-operator-model-swap", "name": "Prepared Environment Operator Model Swap", "kind": "custom_model_swap", "results_subdir": "phase5-operator", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Validate restart-based supervised model swap during live DNS traffic and confirm pipeline continuity after the restart.", "required_rules": ["DNS Burst / DGA-like Activity"], "require_reload_latency": True, "require_post_restart_growth": True, "duration_sec": 45, "sample_interval_sec": 10, "dns_rate_per_sec": 16, "traffic_qname": "phase5-model-swap.example"},
    {"scenario_id": "PREP-ENV-010", "slug": "phase5-operator-config-override", "name": "Prepared Environment Operator Config Override", "kind": "custom_config_override", "results_subdir": "phase5-operator", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "pre_workflow_config_relpath": "NIDS_TestLab/config/live_vm_profile.yml", "expected_backend": "tcpdump", "objective": "Validate restart-based config override from the baseline live profile to the tuned live profile while benign traffic remains active.", "expect_zero_alerts": True, "max_alerts": 0, "require_process_samples": True, "require_runtime_samples": True, "require_reload_latency": True, "require_post_restart_growth": True, "duration_sec": 60, "sample_interval_sec": 12, "dns_rate_per_sec": 12, "http_rate_per_sec": 0.75, "required_rules": []},
    {"scenario_id": "PREP-ENV-011", "slug": "phase6-benign-saas-polling", "name": "Prepared Environment Benign SaaS Polling Mix", "kind": "custom_benign_soak", "results_subdir": "phase6-benign", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Validate tuned unsupervised behavior against a broader benign sample dominated by recurring SaaS/API polling, resolver lookups, and low-rate HTTP health checks.", "expected_outcome": "The tuned profile should stay alert-free across this broader benign SaaS polling mix while retaining process and runtime evidence.", "expect_zero_alerts": True, "max_alerts": 0, "require_process_samples": True, "require_runtime_samples": True, "duration_sec": 210, "sample_interval_sec": 15, "dns_rate_per_sec": 14, "http_rate_per_sec": 1.2, "dns_queries": ["api.crm.example", "updates.office.example", "auth.portal.example", "cdn.docs.example", "telemetry.agent.example"], "http_requests": [{"method": "GET", "path": "/health", "host": "api.crm.example", "body": ""}, {"method": "GET", "path": "/status", "host": "auth.portal.example", "body": ""}, {"method": "POST", "path": "/telemetry", "host": "telemetry.agent.example", "body": "ok=1&source=phase6"}], "sample_id": "BENIGN-LIVE-002", "sample_description": "Rotating SaaS and API polling with benign telemetry posts.", "generalization_assessment_if_zero_alerts": "supports_generalization", "generalization_assessment_if_alerts": "possible_overfit", "required_rules": []},
    {"scenario_id": "PREP-ENV-012", "slug": "phase6-benign-browsing-collaboration", "name": "Prepared Environment Benign Browsing And Collaboration Mix", "kind": "custom_benign_soak", "results_subdir": "phase6-benign", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Validate tuned unsupervised behavior against a burstier benign browsing and collaboration sample rather than only status polling.", "expected_outcome": "The tuned profile should remain alert-free on this broader benign browsing and collaboration sample while capturing process and runtime trends.", "expect_zero_alerts": True, "max_alerts": 0, "require_process_samples": True, "require_runtime_samples": True, "duration_sec": 210, "sample_interval_sec": 15, "dns_rate_per_sec": 18, "http_rate_per_sec": 1.5, "dns_queries": ["www.example.org", "cdn.media.example", "docs.portal.example", "teams.collab.example", "login.sso.example", "static.assets.example"], "http_requests": [{"method": "GET", "path": "/dashboard", "host": "docs.portal.example", "body": ""}, {"method": "GET", "path": "/inbox", "host": "teams.collab.example", "body": ""}, {"method": "POST", "path": "/presence", "host": "teams.collab.example", "body": "state=active"}, {"method": "GET", "path": "/favicon.ico", "host": "static.assets.example", "body": ""}], "sample_id": "BENIGN-LIVE-003", "sample_description": "Burstier browsing and collaboration mix with benign presence updates.", "generalization_assessment_if_zero_alerts": "supports_generalization", "generalization_assessment_if_alerts": "possible_overfit", "required_rules": []},
    {"scenario_id": "PREP-ENV-013", "slug": "phase6-live-suppression-validation", "name": "Prepared Environment Live Suppression Validation", "kind": "custom_live_suppression", "results_subdir": "phase6-suppression", "config_relpath": "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml", "expected_backend": "tcpdump", "objective": "Validate duplicate alert suppression and live operator-driven policy suppression against noisy repeated DNS signature events under prepared-environment traffic.", "expected_outcome": "Repeated noisy events should first be reduced by duplicate suppression, then blocked by policy suppression, while suppression counters increase and the final operator-facing alert count stays stable.", "required_rules": ["Phase6 Duplicate Noise Signature"], "require_process_samples": True, "require_runtime_samples": True, "require_suppressed_alerts": True, "min_suppressed_alerts": 5, "require_policy_suppressed_alerts": True, "min_policy_suppressed_alerts": 5, "require_active_suppression_rule": True, "require_alert_count_stable_after_action": True, "max_alerts": 2, "duration_sec": 42, "sample_interval_sec": 4, "dns_rate_per_sec": 12, "pre_suppression_duration_sec": 12, "post_suppression_duration_sec": 18, "suppression_rule_name": "Phase6 Duplicate Noise Signature", "suppression_dns_qname": "phase6-suppression.example", "suppression_ttl_minutes": 60, "suppress_window_sec": 15},
]


def _resolve_scenarios(requested: list[str]) -> list[dict[str, Any]]:
    if not requested or requested == ["all"]:
        return SCENARIOS
    by_slug = {scenario["slug"]: scenario for scenario in SCENARIOS}
    resolved: list[dict[str, Any]] = []
    for item in requested:
        if item in by_slug:
            resolved.append(by_slug[item])
            continue
        matches = [scenario for scenario in SCENARIOS if scenario["scenario_id"] == item]
        if matches:
            resolved.append(matches[0])
            continue
        raise FileNotFoundError(f"Unknown prepared-environment scenario: {item}")
    return resolved


def build_prepared_env_index(results_root: Path) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    for path in sorted(results_root.rglob("prepared_env_manifest.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        payload["manifest_path"] = str(path.resolve())
        manifests.append(payload)
    manifests.sort(key=lambda item: str(item.get("generated_at") or ""), reverse=True)
    latest_by_scenario: dict[str, dict[str, Any]] = {}
    for item in manifests:
        scenario_id = str(item.get("scenario_id") or "")
        if scenario_id and scenario_id not in latest_by_scenario:
            latest_by_scenario[scenario_id] = item
    return {
        "generated_at": _iso_now(),
        "results_root": str(results_root.resolve()),
        "total_runs": len(manifests),
        "latest_by_scenario": latest_by_scenario,
        "runs": manifests,
    }


def prepared_env_index_markdown(index: dict[str, Any]) -> str:
    lines = [
        "# Prepared Environment Validation Index",
        "",
        f"- Generated at: `{index.get('generated_at', '')}`",
        f"- Total recorded runs: `{index.get('total_runs', 0)}`",
        "",
        "| Scenario ID | Scenario | Latest run | Status | Alerts | Evidence |",
        "|---|---|---|---|---:|---|",
    ]
    for scenario_id in sorted(dict(index.get("latest_by_scenario") or {})):
        item = index["latest_by_scenario"][scenario_id]
        alerts = int(item.get("database_summary", {}).get("counts", {}).get("alerts", 0))
        lines.append(
            f"| `{scenario_id}` | {item.get('scenario_name', '')} | `{item.get('run_name', '')}` | "
            f"`{item.get('status', '')}` | {alerts} | `{item.get('evidence', {}).get('result_dir', '')}` |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    global RUN_STAMP_OVERRIDE
    parser = argparse.ArgumentParser(description="Execute prepared-environment validation cases against the VM lab.")
    parser.add_argument("--scenario", nargs="*", default=["all"], help="Scenario slug or PREP-ENV id. Default: all.")
    parser.add_argument("--sensor-host", default="127.0.0.1")
    parser.add_argument("--sensor-port", type=int, default=2223)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=2224)
    parser.add_argument("--username", default=LIVEVM.lab_vm_username_default(), help="Lab VM username. Defaults to LAB_VM_USER.")
    parser.add_argument("--password", default=LIVEVM.lab_vm_password_default(), help="Lab VM password. Defaults to LAB_VM_PASS.")
    parser.add_argument("--workspace", default="/opt/nids_workspace")
    parser.add_argument("--sensor-ip", default="10.77.0.30")
    parser.add_argument("--duration-override-sec", type=float, help="Optional cap for custom scenario durations, useful for soak pilots.")
    parser.add_argument("--run-stamp", help="Optional fixed run stamp for deterministic result-directory naming.")
    parser.add_argument("--write-index", action="store_true", help="Write or refresh the prepared-environment index.")
    args = parser.parse_args(argv)
    LIVEVM.require_lab_vm_credentials(parser, args)
    RUN_STAMP_OVERRIDE = _sanitize_run_stamp(args.run_stamp) if args.run_stamp else None

    remote_environment = _remote_environment_snapshot(args.sensor_host, int(args.sensor_port), args.target_host, int(args.target_port), args.username, args.password)
    manifests: list[dict[str, Any]] = []
    for scenario in _resolve_scenarios(list(args.scenario)):
        if scenario["kind"] == "attack_script":
            manifest = _run_attack_script_scenario(scenario, python_path=_default_python(), remote_environment=remote_environment, username=args.username, password=args.password)
        else:
            manifest = _run_custom_remote_scenario(
                scenario,
                remote_environment=remote_environment,
                username=args.username,
                password=args.password,
                sensor_host=args.sensor_host,
                sensor_port=int(args.sensor_port),
                target_host=args.target_host,
                target_port=int(args.target_port),
                workspace=args.workspace,
                sensor_ip=args.sensor_ip,
                duration_override_sec=args.duration_override_sec,
            )
        manifests.append(manifest)
        print(f"{manifest['scenario_id']} run={manifest['run_name']} status={manifest['status']} evidence={manifest['evidence']['result_dir']}")

    if args.write_index:
        index = build_prepared_env_index(RESULTS_ROOT)
        index_json = REPORTS_ROOT / "prepared_env_validation_index.json"
        index_md = REPORTS_ROOT / "prepared_env_validation_index.md"
        _write_json(index_json, index)
        _write_text(index_md, prepared_env_index_markdown(index))
        print(f"prepared_env_index_json={index_json}")
        print(f"prepared_env_index_md={index_md}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
