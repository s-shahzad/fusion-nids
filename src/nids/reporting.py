from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean
from typing import Any


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def _parse_iso(value: str | None) -> datetime | None:
    token = str(value or "").strip()
    if token == "":
        return None
    try:
        parsed = datetime.fromisoformat(token.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _to_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        if value is None:
            return default
        token = str(value).strip()
        if token == "":
            return default
        return float(token)
    except Exception:
        return default


def _is_attack_label(label: Any, attack_type: Any = None) -> bool:
    if str(attack_type or "").strip():
        return True
    token = str(label or "").strip().lower()
    return token not in {"", "none", "null", "0", "benign", "normal"}


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])

    ordered = sorted(float(item) for item in values)
    rank = max(0.0, min(100.0, float(pct))) / 100.0 * (len(ordered) - 1)
    lower = int(rank)
    upper = min(len(ordered) - 1, lower + 1)
    if upper == lower:
        return float(ordered[lower])
    fraction = rank - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def _score_summary(values: list[float]) -> dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
        }

    return {
        "count": len(values),
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "mean": round(float(mean(values)), 4),
        "p50": round(_percentile(values, 50), 4),
        "p90": round(_percentile(values, 90), 4),
        "p95": round(_percentile(values, 95), 4),
        "p99": round(_percentile(values, 99), 4),
    }


def _threshold_metrics(samples: list[tuple[float, bool]], threshold: float) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for score, is_attack in samples:
        predicted = float(score) >= float(threshold)
        if predicted and is_attack:
            tp += 1
        elif predicted and not is_attack:
            fp += 1
        elif (not predicted) and is_attack:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    return {
        "threshold": round(float(threshold), 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }


def _candidate_thresholds(values: list[float]) -> list[float]:
    grid = [round(step / 100.0, 2) for step in range(5, 100, 5)]
    observed = [round(_percentile(values, pct), 2) for pct in (50, 75, 80, 85, 90, 95, 97, 99)] if values else []
    return sorted({max(0.01, min(0.99, float(item))) for item in (grid + observed)})


def _scenario_grid(values: list[float], span_hours: float) -> list[dict[str, Any]]:
    if not values:
        return []

    safe_hours = max(1.0 / 60.0, float(span_hours))
    rows: list[dict[str, Any]] = []
    for threshold in (0.5, 0.6, 0.7, 0.8, 0.9):
        triggered = sum(1 for value in values if float(value) >= threshold)
        rows.append(
            {
                "threshold": threshold,
                "triggered_flows": triggered,
                "trigger_rate_per_hour": round(triggered / safe_hours, 2),
            }
        )
    return rows


def _recommend_thresholds(samples: list[tuple[float, bool]], summary: dict[str, Any]) -> dict[str, Any]:
    values = [float(score) for score, _ in samples]
    attacks = sum(1 for _, is_attack in samples if is_attack)
    benign = sum(1 for _, is_attack in samples if not is_attack)
    candidates = _candidate_thresholds(values)

    if int(summary.get("count") or 0) <= 0:
        return {
            "method": "no_score_data",
            "labeled_attack_samples": attacks,
            "labeled_benign_samples": benign,
            "balanced_threshold": None,
            "high_precision_threshold": None,
        }

    if attacks > 0 and benign > 0 and candidates:
        evaluations = [_threshold_metrics(samples, threshold) for threshold in candidates]
        balanced = max(
            evaluations,
            key=lambda row: (
                float(row["f1"]),
                float(row["accuracy"]),
                -float(row["false_positive_rate"]),
                float(row["precision"]),
            ),
        )

        precision_candidates = [row for row in evaluations if float(row["precision"]) >= 0.95 and int(row["tp"]) > 0]
        high_precision = (
            max(
                precision_candidates,
                key=lambda row: (
                    float(row["recall"]),
                    -float(row["false_positive_rate"]),
                    float(row["precision"]),
                ),
            )
            if precision_candidates
            else None
        )

        return {
            "method": "labeled_optimization",
            "labeled_attack_samples": attacks,
            "labeled_benign_samples": benign,
            "balanced_threshold": balanced,
            "high_precision_threshold": high_precision,
        }

    heuristic_threshold = max(0.55, float(summary.get("p95") or 0.0))
    return {
        "method": "distribution_heuristic",
        "labeled_attack_samples": attacks,
        "labeled_benign_samples": benign,
        "balanced_threshold": {
            "threshold": round(min(0.99, heuristic_threshold), 4),
            "precision": None,
            "recall": None,
            "f1": None,
            "false_positive_rate": None,
            "accuracy": None,
            "tp": None,
            "fp": None,
            "tn": None,
            "fn": None,
        },
        "high_precision_threshold": {
            "threshold": round(min(0.99, max(heuristic_threshold, float(summary.get("p99") or 0.0))), 4),
            "precision": None,
            "recall": None,
            "f1": None,
            "false_positive_rate": None,
            "accuracy": None,
            "tp": None,
            "fp": None,
            "tn": None,
            "fn": None,
        },
    }


def _extract_metadata(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        payload = json.loads(str(raw or "{}"))
        if isinstance(payload, dict):
            return payload
        return {}
    except Exception:
        return {}


def generate_incident_report(from_db: str | Path, out: str | Path) -> Path:
    """Generate markdown incident timeline summary from alerts/flows."""
    db_path = Path(from_db)
    out_path = Path(out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if not db_path.exists():
        out_path.write_text(
            f"# NIDS Incident Report\n\nGenerated: {generated}\n\nDatabase not found: `{db_path}`\n",
            encoding="utf-8",
        )
        return out_path

    with sqlite3.connect(str(db_path)) as conn:
        if not _table_exists(conn, "alerts"):
            out_path.write_text(
                f"# NIDS Incident Report\n\nGenerated: {generated}\n\nNo alerts table found.\n",
                encoding="utf-8",
            )
            return out_path

        alert_rows = conn.execute(
            """
            SELECT timestamp, sensor_id, src_ip, dst_ip, dst_port, proto,
                   severity, engine, rule_name, summary
            FROM alerts
            ORDER BY timestamp ASC
            """
        ).fetchall()

        flow_count = 0
        if _table_exists(conn, "flows"):
            flow_count = int(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0])

    severity_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()
    engine_counter: Counter[str] = Counter()

    for row in alert_rows:
        severity_counter[str(row[6] or "unknown").lower()] += 1
        engine_counter[str(row[7] or "unknown").lower()] += 1
        rule_counter[str(row[8] or "unknown")] += 1

    lines: list[str] = []
    lines.append("# NIDS Incident Report")
    lines.append("")
    lines.append(f"Generated: {generated}")
    lines.append("")

    lines.append("## Overview")
    lines.append("")
    lines.append(f"- Total flows: {flow_count}")
    lines.append(f"- Total alerts: {len(alert_rows)}")
    lines.append("")

    lines.append("## Alerts by Severity")
    lines.append("")
    if severity_counter:
        for severity, count in severity_counter.most_common():
            lines.append(f"- {severity}: {count}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Alerts by Engine")
    lines.append("")
    if engine_counter:
        for engine, count in engine_counter.most_common():
            lines.append(f"- {engine}: {count}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Top Rules")
    lines.append("")
    if rule_counter:
        for rule, count in rule_counter.most_common(10):
            lines.append(f"- {rule}: {count}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Timeline (Latest 100)")
    lines.append("")
    if alert_rows:
        for row in alert_rows[-100:]:
            timestamp, sensor, src_ip, dst_ip, dst_port, proto, severity, engine, rule_name, summary = row
            lines.append(
                f"- [{timestamp}] [{severity}] [{engine}] [{rule_name}] "
                f"{src_ip}:{dst_port} -> {dst_ip} ({proto}) | sensor={sensor} | {summary}"
            )
    else:
        lines.append("- No alerts captured.")

    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def generate_sla_weekly_summary(
    from_db: str | Path,
    out_json: str | Path,
    out_md: str | Path,
    lookback_days: int = 7,
) -> tuple[Path, Path]:
    """Generate weekly SLA KPI summary in JSON and Markdown."""
    db_path = Path(from_db)
    json_path = Path(out_json)
    md_path = Path(out_md)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    safe_lookback = max(1, int(lookback_days))
    window_start = now - timedelta(days=safe_lookback)

    payload: dict[str, Any] = {
        "generated_at": _to_iso(now),
        "lookback_days": safe_lookback,
        "window_start": _to_iso(window_start),
        "window_end": _to_iso(now),
        "totals": {
            "incidents": 0,
            "open": 0,
            "resolved": 0,
            "response_breaches": 0,
            "resolution_breaches": 0,
        },
        "rates": {
            "response_breach_rate": 0.0,
            "resolution_breach_rate": 0.0,
        },
        "kpis": {
            "mean_response_minutes": 0.0,
            "mean_resolution_minutes": 0.0,
        },
        "status_breakdown": {},
        "priority_breakdown": {},
        "overdue_trend": [],
    }

    if not db_path.exists():
        payload["error"] = f"database_not_found: {db_path}"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        md_path.write_text(
            "\n".join(
                [
                    "# NIDS SLA Weekly Summary",
                    "",
                    f"Generated: {_to_iso(now)}",
                    "",
                    f"Database not found: `{db_path}`",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return json_path, md_path

    response_actions = {
        "incident_assign",
        "incident_status_triage",
        "incident_status_investigating",
        "incident_status_contained",
        "incident_status_resolved",
    }

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        if not _table_exists(conn, "incidents"):
            payload["error"] = "incidents_table_missing"
            json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
            md_path.write_text(
                "\n".join(
                    [
                        "# NIDS SLA Weekly Summary",
                        "",
                        f"Generated: {_to_iso(now)}",
                        "",
                        "No incidents table found.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            return json_path, md_path

        incident_rows = conn.execute(
            """
            SELECT id, alert_id, created_at, timestamp, updated_at, status, owner,
                   priority, due_at, resolved_at, metadata
            FROM incidents
            ORDER BY id ASC
            """
        ).fetchall()

        action_rows: list[sqlite3.Row] = []
        if _table_exists(conn, "incident_actions"):
            action_rows = conn.execute(
                """
                SELECT timestamp, alert_id, action
                FROM incident_actions
                WHERE timestamp IS NOT NULL AND TRIM(timestamp) != ''
                ORDER BY timestamp ASC
                """
            ).fetchall()

    actions_by_alert: dict[int, list[tuple[datetime, str]]] = defaultdict(list)
    for row in action_rows:
        action_ts = _parse_iso(str(row["timestamp"] or ""))
        if action_ts is None:
            continue
        alert_id = _safe_int(row["alert_id"], 0)
        if alert_id <= 0:
            continue
        actions_by_alert[alert_id].append((action_ts, str(row["action"] or "")))

    status_counter: Counter[str] = Counter()
    priority_counter: Counter[str] = Counter()
    response_minutes_values: list[float] = []
    resolution_minutes_values: list[float] = []
    overdue_by_day: Counter[str] = Counter()

    total = 0
    open_count = 0
    resolved_count = 0
    response_breach_count = 0
    resolution_breach_count = 0

    for row in incident_rows:
        created_at = _parse_iso(str(row["created_at"] or ""))
        if created_at is None:
            created_at = _parse_iso(str(row["timestamp"] or ""))

        resolved_at = _parse_iso(str(row["resolved_at"] or ""))
        updated_at = _parse_iso(str(row["updated_at"] or ""))
        due_at = _parse_iso(str(row["due_at"] or ""))

        relevant_ts = created_at or updated_at or resolved_at
        if relevant_ts is not None and relevant_ts < window_start:
            continue

        total += 1

        status_token = str(row["status"] or "open").strip().lower() or "open"
        priority_token = str(row["priority"] or "low").strip().lower() or "low"

        status_counter[status_token] += 1
        priority_counter[priority_token] += 1

        if status_token == "resolved":
            resolved_count += 1
        else:
            open_count += 1

        metadata = _extract_metadata(row["metadata"])
        overdue_stage = max(0, _safe_int(metadata.get("sla_overdue_stage"), 0))
        response_breached = bool(metadata.get("sla_response_breached"))

        if response_breached:
            response_breach_count += 1

        resolution_breached = overdue_stage > 0
        if not resolution_breached and due_at is not None and resolved_at is not None and resolved_at > due_at:
            resolution_breached = True
        if not resolution_breached and due_at is not None and status_token != "resolved" and due_at < now:
            resolution_breached = True

        if resolution_breached:
            resolution_breach_count += 1
            bucket_dt = due_at or updated_at or created_at or now
            overdue_by_day[bucket_dt.date().isoformat()] += 1

        if created_at is not None:
            alert_id = _safe_int(row["alert_id"], 0)
            response_candidates: list[datetime] = []
            if alert_id > 0:
                for action_ts, action in actions_by_alert.get(alert_id, []):
                    if action in response_actions:
                        response_candidates.append(action_ts)
            if not response_candidates and status_token in {"triage", "investigating", "contained", "resolved"}:
                if updated_at is not None:
                    response_candidates.append(updated_at)

            if response_candidates:
                first_response = min(response_candidates)
                delta_min = max(0.0, (first_response - created_at).total_seconds() / 60.0)
                response_minutes_values.append(delta_min)

            if resolved_at is not None:
                resolution_delta_min = max(0.0, (resolved_at - created_at).total_seconds() / 60.0)
                resolution_minutes_values.append(resolution_delta_min)

    payload["totals"] = {
        "incidents": total,
        "open": open_count,
        "resolved": resolved_count,
        "response_breaches": response_breach_count,
        "resolution_breaches": resolution_breach_count,
    }

    if total > 0:
        payload["rates"] = {
            "response_breach_rate": round(response_breach_count / total, 4),
            "resolution_breach_rate": round(resolution_breach_count / total, 4),
        }

    payload["kpis"] = {
        "mean_response_minutes": round(float(mean(response_minutes_values)), 2) if response_minutes_values else 0.0,
        "mean_resolution_minutes": round(float(mean(resolution_minutes_values)), 2) if resolution_minutes_values else 0.0,
    }

    payload["status_breakdown"] = dict(status_counter)
    payload["priority_breakdown"] = dict(priority_counter)

    trend: list[dict[str, Any]] = []
    for idx in range(safe_lookback):
        day = (window_start + timedelta(days=idx)).date().isoformat()
        trend.append({"day": day, "count": int(overdue_by_day.get(day, 0))})
    payload["overdue_trend"] = trend

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")

    lines: list[str] = []
    lines.append("# NIDS SLA Weekly Summary")
    lines.append("")
    lines.append(f"Generated: {_to_iso(now)}")
    lines.append(f"Window: {_to_iso(window_start)} -> {_to_iso(now)}")
    lines.append("")

    lines.append("## Totals")
    lines.append("")
    lines.append(f"- Incidents: {total}")
    lines.append(f"- Open: {open_count}")
    lines.append(f"- Resolved: {resolved_count}")
    lines.append(f"- Response SLA breaches: {response_breach_count}")
    lines.append(f"- Resolution SLA breaches: {resolution_breach_count}")
    lines.append("")

    lines.append("## Rates")
    lines.append("")
    lines.append(f"- Response breach rate: {payload['rates']['response_breach_rate']:.2%}")
    lines.append(f"- Resolution breach rate: {payload['rates']['resolution_breach_rate']:.2%}")
    lines.append("")

    lines.append("## KPI")
    lines.append("")
    lines.append(f"- Mean response minutes: {payload['kpis']['mean_response_minutes']}")
    lines.append(f"- Mean resolution minutes: {payload['kpis']['mean_resolution_minutes']}")
    lines.append("")

    lines.append("## Status Breakdown")
    lines.append("")
    if status_counter:
        for key, value in status_counter.most_common():
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Priority Breakdown")
    lines.append("")
    if priority_counter:
        for key, value in priority_counter.most_common():
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Overdue Trend")
    lines.append("")
    for row in trend:
        lines.append(f"- {row['day']}: {row['count']}")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def generate_threshold_tuning_report(
    from_db: str | Path,
    out_json: str | Path,
    out_md: str | Path,
    lookback_days: int = 7,
) -> tuple[Path, Path]:
    """Generate score-distribution and threshold-tuning guidance from runtime flows."""
    db_path = Path(from_db)
    json_path = Path(out_json)
    md_path = Path(out_md)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    safe_lookback = max(1, int(lookback_days))
    window_start = now - timedelta(days=safe_lookback)

    payload: dict[str, Any] = {
        "generated_at": _to_iso(now),
        "lookback_days": safe_lookback,
        "window_start": _to_iso(window_start),
        "window_end": _to_iso(now),
        "totals": {
            "flows": 0,
            "alerts": 0,
            "labeled_flows": 0,
            "labeled_attack_flows": 0,
            "labeled_benign_flows": 0,
        },
        "score_stats": {},
        "threshold_recommendations": {},
        "recommended_config": {},
        "scenario_grid": {},
    }

    if not db_path.exists():
        payload["error"] = f"database_not_found: {db_path}"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        md_path.write_text(
            "\n".join(
                [
                    "# NIDS Threshold Tuning Report",
                    "",
                    f"Generated: {_to_iso(now)}",
                    "",
                    f"Database not found: `{db_path}`",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return json_path, md_path

    detector_columns = {
        "supervised_score": "ml.score_threshold",
        "unsupervised_score": "ml.unsupervised_alert_threshold",
        "unsupervised_isolation_score": "ml.unsupervised_component_threshold",
        "unsupervised_autoencoder_score": "ml.unsupervised_component_threshold",
        "fusion_score": "fusion.alert_threshold",
    }
    detector_values: dict[str, list[float]] = {key: [] for key in detector_columns}
    detector_samples: dict[str, list[tuple[float, bool]]] = {key: [] for key in detector_columns}
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        if not _table_exists(conn, "flows"):
            payload["error"] = "flows_table_missing"
            json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
            md_path.write_text(
                "\n".join(
                    [
                        "# NIDS Threshold Tuning Report",
                        "",
                        f"Generated: {_to_iso(now)}",
                        "",
                        "No flows table found.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            return json_path, md_path

        flow_columns = _table_columns(conn, "flows")
        selected_columns = [
            "timestamp",
            "label",
            "attack_type",
            "is_labeled",
            "supervised_score",
            "unsupervised_score",
            "unsupervised_isolation_score",
            "unsupervised_autoencoder_score",
            "fusion_score",
        ]
        select_sql = ", ".join(
            column if column in flow_columns else f"NULL AS {column}" for column in selected_columns
        )
        flow_rows = conn.execute(
            f"""
            SELECT {select_sql}
            FROM flows
            ORDER BY timestamp ASC
            """
        ).fetchall()

        alert_rows: list[sqlite3.Row] = []
        if _table_exists(conn, "alerts"):
            alert_rows = conn.execute(
                """
                SELECT timestamp
                FROM alerts
                ORDER BY timestamp ASC
                """
            ).fetchall()

    filtered_alerts = 0
    for row in alert_rows:
        row_ts = _parse_iso(str(row["timestamp"] or ""))
        if row_ts is None or row_ts < window_start or row_ts > now:
            continue
        filtered_alerts += 1

    for row in flow_rows:
        row_ts = _parse_iso(str(row["timestamp"] or ""))
        if row_ts is None or row_ts < window_start or row_ts > now:
            continue

        if first_ts is None or row_ts < first_ts:
            first_ts = row_ts
        if last_ts is None or row_ts > last_ts:
            last_ts = row_ts

        payload["totals"]["flows"] += 1

        is_labeled = bool(_safe_int(row["is_labeled"], 0)) or str(row["label"] or "").strip() != "" or str(
            row["attack_type"] or ""
        ).strip() != ""
        is_attack = _is_attack_label(row["label"], row["attack_type"])
        if is_labeled:
            payload["totals"]["labeled_flows"] += 1
            if is_attack:
                payload["totals"]["labeled_attack_flows"] += 1
            else:
                payload["totals"]["labeled_benign_flows"] += 1

        for key in detector_columns:
            score = _safe_float(row[key], None)
            if score is None:
                continue
            clipped = max(0.0, min(1.0, float(score)))
            detector_values[key].append(clipped)
            if is_labeled:
                detector_samples[key].append((clipped, is_attack))

    payload["totals"]["alerts"] = filtered_alerts

    if first_ts is not None and last_ts is not None:
        span_hours = max(1.0 / 60.0, (last_ts - first_ts).total_seconds() / 3600.0)
    else:
        span_hours = max(1.0, safe_lookback * 24.0)

    for detector, config_key in detector_columns.items():
        summary = _score_summary(detector_values[detector])
        recommendation = _recommend_thresholds(detector_samples[detector], summary)
        payload["score_stats"][detector] = summary
        payload["threshold_recommendations"][detector] = recommendation
        payload["scenario_grid"][detector] = _scenario_grid(detector_values[detector], span_hours)

        balanced = recommendation.get("balanced_threshold") or {}
        suggested = _safe_float(balanced.get("threshold"), None)
        if suggested is not None and int(summary.get("count") or 0) > 0:
            current = _safe_float(payload["recommended_config"].get(config_key), None)
            if current is None:
                payload["recommended_config"][config_key] = round(float(suggested), 4)
            else:
                payload["recommended_config"][config_key] = round(max(float(current), float(suggested)), 4)

    fusion_alert_threshold = _safe_float(payload["recommended_config"].get("fusion.alert_threshold"), None)
    fusion_summary = payload["score_stats"].get("fusion_score", {}) or {}
    if fusion_alert_threshold is not None:
        high_threshold = max(fusion_alert_threshold + 0.1, _safe_float(fusion_summary.get("p95"), 0.0) or 0.0, 0.8)
        critical_threshold = max(high_threshold + 0.08, _safe_float(fusion_summary.get("p99"), 0.0) or 0.0, 0.92)
        payload["recommended_config"]["fusion.high_threshold"] = round(min(0.99, high_threshold), 4)
        payload["recommended_config"]["fusion.critical_threshold"] = round(min(0.99, critical_threshold), 4)

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")

    lines: list[str] = []
    lines.append("# NIDS Threshold Tuning Report")
    lines.append("")
    lines.append(f"Generated: {_to_iso(now)}")
    lines.append(f"Window: {_to_iso(window_start)} -> {_to_iso(now)}")
    lines.append("")

    lines.append("## Coverage")
    lines.append("")
    lines.append(f"- Flows in window: {payload['totals']['flows']}")
    lines.append(f"- Alerts in window: {payload['totals']['alerts']}")
    lines.append(f"- Labeled flows: {payload['totals']['labeled_flows']}")
    lines.append(f"- Labeled attack flows: {payload['totals']['labeled_attack_flows']}")
    lines.append(f"- Labeled benign flows: {payload['totals']['labeled_benign_flows']}")
    lines.append("")

    lines.append("## Recommended Config")
    lines.append("")
    if payload["recommended_config"]:
        for key, value in sorted(payload["recommended_config"].items()):
            lines.append(f"- {key}: {value}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Detector Summaries")
    lines.append("")
    if payload["score_stats"]:
        for detector, summary in payload["score_stats"].items():
            lines.append(
                "- "
                + f"{detector}: count={summary['count']} min={summary['min']:.4f} max={summary['max']:.4f} "
                + f"mean={summary['mean']:.4f} p95={summary['p95']:.4f} p99={summary['p99']:.4f}"
            )
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Threshold Recommendations")
    lines.append("")
    if payload["threshold_recommendations"]:
        for detector, recommendation in payload["threshold_recommendations"].items():
            balanced = recommendation.get("balanced_threshold") or {}
            high_precision = recommendation.get("high_precision_threshold") or {}
            lines.append(
                "- "
                + f"{detector}: method={recommendation.get('method')} "
                + f"balanced={balanced.get('threshold')} "
                + f"f1={balanced.get('f1')} "
                + f"precision={balanced.get('precision')} "
                + f"recall={balanced.get('recall')}"
            )
            if high_precision:
                lines.append(
                    "  "
                    + f"high_precision={high_precision.get('threshold')} "
                    + f"precision={high_precision.get('precision')} "
                    + f"recall={high_precision.get('recall')}"
                )
    else:
        lines.append("- none")
    lines.append("")

    lines.append("## Scenario Grid")
    lines.append("")
    for detector, rows in payload["scenario_grid"].items():
        lines.append(f"- {detector}:")
        if not rows:
            lines.append("  no score data")
            continue
        for row in rows:
            lines.append(
                "  "
                + f"threshold={row['threshold']:.2f} "
                + f"triggered_flows={row['triggered_flows']} "
                + f"trigger_rate_per_hour={row['trigger_rate_per_hour']}"
            )
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
