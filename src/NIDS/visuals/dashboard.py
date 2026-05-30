from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from statistics import mean, median, pstdev
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse

from ..storage import IncidentStore, SQLiteStore
from ..utils import SlackWebhookNotifier
from .charts import build_all_figures
from .queries import build_analytics


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize_filter(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip()
    if token == "" or token.lower() in {"all", "any", "*"}:
        return None
    return token



def _safe_lookback(value: int | None, default: int = 5) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return min(24 * 60, max(1, parsed))

def _normalize_token(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip()
    return token if token else None

def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _list_available_sensors(conn: sqlite3.Connection) -> list[str]:
    sensors: set[str] = set()
    for table in ("alerts", "flows", "metrics"):
        if not _table_exists(conn, table):
            continue
        rows = conn.execute(
            f"""
            SELECT DISTINCT sensor_id
            FROM {table}
            WHERE sensor_id IS NOT NULL AND TRIM(sensor_id) != ''
            ORDER BY sensor_id ASC
            LIMIT 500
            """
        ).fetchall()
        for row in rows:
            token = str(row[0] or "").strip()
            if token:
                sensors.add(token)
    return sorted(sensors)

def _extract_bearer_token(authorization_header: str | None) -> str | None:
    token = _normalize_token(authorization_header)
    if token is None:
        return None
    if token.lower().startswith("bearer "):
        return _normalize_token(token[7:])
    return None


def _is_authorized_token(
    expected_token: str | None,
    query_token: str | None,
    header_token: str | None,
    authorization_header: str | None,
) -> bool:
    if expected_token is None:
        return True

    bearer_token = _extract_bearer_token(authorization_header)
    tokens = {
        _normalize_token(query_token),
        _normalize_token(header_token),
        bearer_token,
    }
    return expected_token in tokens

def _compute_anomaly_trend(alert_series: list[dict[str, Any]]) -> list[dict[str, Any]]:
    values: list[float] = []
    for point in alert_series:
        values.append(float(point.get("value", 0.0)))

    if not values:
        return []

    trend: list[dict[str, Any]] = []
    for idx, point in enumerate(alert_series):
        start = max(0, idx - 7)
        window = values[start : idx + 1]

        baseline = float(mean(window)) if window else 0.0
        sigma = float(pstdev(window)) if len(window) > 1 else 0.0
        spread = max(1.0, sigma * 2.0)

        upper = baseline + spread
        lower = max(0.0, baseline - spread)

        value = float(point.get("value", 0.0))
        trend.append(
            {
                "timestamp": str(point.get("timestamp") or ""),
                "value": value,
                "baseline": baseline,
                "upper": upper,
                "lower": lower,
                "is_spike": 1 if value > upper else 0,
            }
        )

    return trend


def _compute_drift_alerts(sensor_summary: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not sensor_summary:
        return []

    apm_values = [float(item.get("alerts_per_min", 0.0)) for item in sensor_summary]
    queue_values = [float(item.get("queue_size", 0.0)) for item in sensor_summary]
    lag_values = [float(item.get("ingest_lag_sec", 0.0)) for item in sensor_summary]

    median_apm = float(median(apm_values)) if apm_values else 0.0
    median_queue = float(median(queue_values)) if queue_values else 0.0
    median_lag = float(median(lag_values)) if lag_values else 0.0

    drift_alerts: list[dict[str, Any]] = []
    for item in sensor_summary:
        sensor = str(item.get("sensor_id") or "unknown")
        apm = float(item.get("alerts_per_min", 0.0))
        queue = float(item.get("queue_size", 0.0))
        lag = float(item.get("ingest_lag_sec", 0.0))

        reasons: list[str] = []
        drift_score = 0.0

        apm_threshold = max(5.0, median_apm * 2.0 + 1.0)
        queue_threshold = max(20.0, median_queue * 1.5 + 5.0)
        lag_threshold = max(1.0, median_lag * 1.8 + 0.25)

        if apm >= apm_threshold:
            reasons.append(f"alert-rate spike ({apm:.2f} >= {apm_threshold:.2f})")
            drift_score += 1.0
        if queue >= queue_threshold:
            reasons.append(f"queue pressure ({queue:.2f} >= {queue_threshold:.2f})")
            drift_score += 1.2
        if lag >= lag_threshold:
            reasons.append(f"ingest lag drift ({lag:.2f}s >= {lag_threshold:.2f}s)")
            drift_score += 1.3

        if not reasons:
            continue

        severity = "high" if drift_score >= 2.4 or lag >= 3.0 else "medium"
        drift_alerts.append(
            {
                "sensor_id": sensor,
                "severity": severity,
                "drift_score": round(drift_score, 2),
                "reasons": reasons,
            }
        )

    drift_alerts.sort(
        key=lambda item: (
            0 if str(item.get("severity", "")).lower() == "high" else 1,
            -float(item.get("drift_score", 0.0)),
            str(item.get("sensor_id", "")),
        )
    )
    return drift_alerts

def _build_realtime_payload(
    db_path: Path,
    lookback_minutes: int = 5,
    max_alerts: int = 10,
    sensor_id: str | None = None,
    severity: str | None = None,
    engine: str | None = None,
) -> dict[str, Any]:
    safe_lookback = _safe_lookback(lookback_minutes, default=5)
    sensor_filter = _normalize_filter(sensor_id)
    severity_filter = _normalize_filter(severity)
    engine_filter = _normalize_filter(engine)

    summary: dict[str, float] = {
        "events_per_sec": 0.0,
        "alerts_per_min": 0.0,
        "queue_size": 0.0,
        "ingest_lag_sec": 0.0,
        "total_alerts": 0.0,
        "suppressed_alerts": 0.0,
        "runtime_heartbeat": 0.0,
    }
    series: dict[str, list[dict[str, Any]]] = {
        "events_per_sec": [],
        "alerts_per_min": [],
        "queue_size": [],
        "ingest_lag_sec": [],
    }
    recent_alerts: list[dict[str, Any]] = []
    sensor_summary: list[dict[str, Any]] = []
    anomaly_trend: list[dict[str, Any]] = []
    drift_alerts: list[dict[str, Any]] = []

    if not db_path.exists():
        return {
            "generated_at": _utc_now_iso(),
            "lookback_minutes": safe_lookback,
            "summary": summary,
            "series": series,
            "recent_alerts": recent_alerts,
            "sensor_summary": sensor_summary,
            "anomaly_trend": anomaly_trend,
            "drift_alerts": drift_alerts,
            "available_sensors": [],
            "applied_filters": {
                "sensor_id": sensor_filter or "all",
                "severity": severity_filter or "all",
                "engine": engine_filter or "all",
            },
        }

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        available_sensors = _list_available_sensors(conn)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=safe_lookback)

        sensor_metric_latest: dict[str, dict[str, tuple[datetime | None, float]]] = {}

        if _table_exists(conn, "metrics"):
            if sensor_filter:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, sensor_id, metric_name, metric_value
                    FROM metrics
                    WHERE LOWER(sensor_id) = LOWER(?)
                    ORDER BY id DESC
                    LIMIT 5000
                    """,
                    (sensor_filter,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, sensor_id, metric_name, metric_value
                    FROM metrics
                    ORDER BY id DESC
                    LIMIT 5000
                    """
                ).fetchall()

            filtered_rows = list(reversed(rows))
            tracked = set(summary.keys())
            series_keys = set(series.keys())

            for row in filtered_rows:
                metric_name = str(row["metric_name"] or "")
                if metric_name not in tracked and metric_name not in series_keys:
                    continue

                timestamp = str(row["timestamp"] or "")
                parsed_ts = _parse_iso_datetime(timestamp)
                if parsed_ts is not None and parsed_ts < cutoff:
                    continue

                value = float(row["metric_value"] or 0.0)
                row_sensor = str(row["sensor_id"] or "unknown")

                if metric_name in summary:
                    summary[metric_name] = value
                if metric_name in series:
                    series[metric_name].append({"timestamp": timestamp, "value": value})

                sensor_slot = sensor_metric_latest.setdefault(row_sensor, {})
                previous = sensor_slot.get(metric_name)
                if previous is None:
                    sensor_slot[metric_name] = (parsed_ts, value)
                else:
                    prev_ts = previous[0]
                    if prev_ts is None or parsed_ts is None or parsed_ts >= prev_ts:
                        sensor_slot[metric_name] = (parsed_ts, value)

        alert_count_by_sensor: dict[str, int] = {}

        if _table_exists(conn, "alerts"):
            rows = conn.execute(
                """
                SELECT id, timestamp, sensor_id, severity, engine, rule_name, src_ip, dst_ip, dst_port, summary,
                       ack_status, acknowledged_by, acknowledged_at, is_suppressed, suppressed_until
                FROM alerts
                ORDER BY id DESC
                LIMIT 5000
                """
            ).fetchall()

            for row in rows:
                row_sensor = str(row["sensor_id"] or "unknown")
                row_severity = str(row["severity"] or "unknown")
                row_engine = str(row["engine"] or "unknown")

                if sensor_filter and row_sensor.lower() != sensor_filter.lower():
                    continue
                if severity_filter and row_severity.lower() != severity_filter.lower():
                    continue
                if engine_filter and row_engine.lower() != engine_filter.lower():
                    continue

                timestamp = str(row["timestamp"] or "")
                parsed_ts = _parse_iso_datetime(timestamp)
                if parsed_ts is not None and parsed_ts < cutoff:
                    continue

                alert_count_by_sensor[row_sensor] = int(alert_count_by_sensor.get(row_sensor, 0)) + 1

                if len(recent_alerts) < max_alerts:
                    recent_alerts.append(
                        {
                            "alert_id": int(row["id"]),
                            "timestamp": timestamp,
                            "sensor_id": row_sensor,
                            "severity": row_severity,
                            "engine": row_engine,
                            "rule_name": str(row["rule_name"] or "unknown_rule"),
                            "src_ip": str(row["src_ip"] or "unknown"),
                            "dst_ip": str(row["dst_ip"] or "unknown"),
                            "dst_port": row["dst_port"],
                            "summary": str(row["summary"] or ""),
                            "ack_status": str(row["ack_status"] or "new"),
                            "acknowledged_by": str(row["acknowledged_by"] or ""),
                            "acknowledged_at": str(row["acknowledged_at"] or ""),
                            "is_suppressed": int(row["is_suppressed"] or 0),
                            "suppressed_until": str(row["suppressed_until"] or ""),
                        }
                    )

        sensor_names = set(available_sensors) | set(sensor_metric_latest.keys()) | set(alert_count_by_sensor.keys())
        for name in sorted(sensor_names):
            metrics = sensor_metric_latest.get(name, {})
            sensor_summary.append(
                {
                    "sensor_id": name,
                    "events_per_sec": float(metrics.get("events_per_sec", (None, 0.0))[1]),
                    "alerts_per_min": float(metrics.get("alerts_per_min", (None, 0.0))[1]),
                    "queue_size": float(metrics.get("queue_size", (None, 0.0))[1]),
                    "ingest_lag_sec": float(metrics.get("ingest_lag_sec", (None, 0.0))[1]),
                    "alert_count": int(alert_count_by_sensor.get(name, 0)),
                }
            )

        sensor_summary.sort(
            key=lambda item: (
                -int(item.get("alert_count", 0)),
                -float(item.get("alerts_per_min", 0.0)),
                -float(item.get("events_per_sec", 0.0)),
                str(item.get("sensor_id", "")),
            )
        )

        anomaly_trend = _compute_anomaly_trend(series.get("alerts_per_min", []))
        drift_alerts = _compute_drift_alerts(sensor_summary)

    return {
        "generated_at": _utc_now_iso(),
        "lookback_minutes": safe_lookback,
        "summary": summary,
        "series": series,
        "recent_alerts": recent_alerts,
        "sensor_summary": sensor_summary[:20],
        "anomaly_trend": anomaly_trend,
        "drift_alerts": drift_alerts[:20],
        "available_sensors": available_sensors,
        "applied_filters": {
            "sensor_id": sensor_filter or "all",
            "severity": severity_filter or "all",
            "engine": engine_filter or "all",
        },
    }


def _dashboard_html() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NIDS Live Analytics Dashboard</title>
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    .nids-dash-root {
      --bg: #f7f9fc;
      --panel: #ffffff;
      --line: #d7dfea;
      --text: #1f2937;
      --muted: #64748b;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Arial, sans-serif;
      min-height: 100vh;
      margin: 0;
      padding: 1rem;
    }
    .nids-dash-root .wrap {
      max-width: 1300px;
      margin: 0 auto;
      display: grid;
      gap: 1rem;
    }
    .nids-dash-root .hero {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 14px;
      padding: 1rem;
      display: grid;
      gap: 0.8rem;
    }
    .nids-dash-root h1 {
      margin: 0 0 0.4rem;
      font-size: 1.45rem;
    }
    .nids-dash-root p {
      margin: 0;
      color: var(--muted);
    }
    .nids-dash-root .filters {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.6rem;
    }
    .nids-dash-root .filter {
      display: grid;
      gap: 0.2rem;
    }
    .nids-dash-root .filter label {
      font-size: 0.76rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .nids-dash-root .filter select {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 0.4rem 0.45rem;
      background: #fff;
      color: var(--text);
      font-size: 0.9rem;
    }
    .nids-dash-root .incident-controls {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 0.45rem;
      margin-bottom: 0.55rem;
    }
    .nids-dash-root .top-grid {
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    }
    .nids-dash-root .grid {
      display: grid;
      gap: 1rem;
    }
    .nids-dash-root .card {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 14px;
      padding: 0.75rem;
    }
    .nids-dash-root .card h2 {
      margin: 0 0 0.5rem;
      font-size: 0.98rem;
      font-weight: 600;
    }
    .nids-dash-root .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 0.5rem;
    }
    .nids-dash-root .stat {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 0.45rem 0.55rem;
      background: #f9fbff;
      display: grid;
      gap: 0.25rem;
    }
    .nids-dash-root .stat .label {
      font-size: 0.76rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .nids-dash-root .stat .value {
      font-size: 1rem;
      font-weight: 700;
      color: var(--text);
    }
    .nids-dash-root .alert-feed {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 0.45rem;
      max-height: 340px;
      overflow: auto;
    }
    .nids-dash-root .alert-item {
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 0.45rem 0.55rem;
      display: grid;
      gap: 0.22rem;
      background: #fff;
    }
    .nids-dash-root .alert-head {
      display: flex;
      justify-content: space-between;
      gap: 0.6rem;
      font-size: 0.78rem;
      color: var(--muted);
    }
    .nids-dash-root .alert-body {
      font-size: 0.86rem;
    }
    .nids-dash-root .alert-meta {
      font-size: 0.75rem;
      color: var(--muted);
    }
    .nids-dash-root .alert-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }
    .nids-dash-root .incident-bulk-controls {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      margin-bottom: 0.45rem;
    }
    .nids-dash-root .incident-edit-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 0.4rem;
      margin-top: 0.3rem;
    }
    .nids-dash-root .incident-edit-grid input,
    .nids-dash-root .incident-edit-grid select {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 0.28rem 0.4rem;
      font-size: 0.78rem;
      color: var(--text);
      background: #fff;
    }
    .nids-dash-root .incident-select {
      margin-right: 0.45rem;
      vertical-align: middle;
    }
    .nids-dash-root .alert-btn {
      border: 1px solid var(--line);
      background: #fff;
      color: var(--text);
      border-radius: 8px;
      padding: 0.28rem 0.52rem;
      font-size: 0.78rem;
      cursor: pointer;
    }
    .nids-dash-root .alert-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .nids-dash-root .sensor-table-wrap {
      overflow: auto;
    }
    .nids-dash-root .sensor-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }
    .nids-dash-root .sensor-table th,
    .nids-dash-root .sensor-table td {
      border-bottom: 1px solid var(--line);
      padding: 0.35rem 0.4rem;
      text-align: left;
      white-space: nowrap;
    }
    .nids-dash-root .sensor-table th {
      color: var(--muted);
      font-weight: 600;
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .nids-dash-root .muted {
      color: var(--muted);
      font-size: 0.86rem;
    }
    .nids-dash-root .plot {
      min-height: 500px;
    }
    .nids-dash-root .plot.compact {
      min-height: 280px;
    }
  </style>
</head>
<body class="nids-dash-root">
  <main class="wrap">
    <header class="hero">
      <div>
        <h1>Universal NIDS Live Analytics Dashboard</h1>
        <p id="stamp">Loading...</p>
      </div>
      <div class="filters">
        <div class="filter">
          <label for="filter-window">Time Window</label>
          <select id="filter-window">
            <option value="5">Last 5 min</option>
            <option value="15">Last 15 min</option>
            <option value="60">Last 60 min</option>
          </select>
        </div>
        <div class="filter">
          <label for="filter-severity">Severity</label>
          <select id="filter-severity">
            <option value="all">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div class="filter">
          <label for="filter-engine">Engine</label>
          <select id="filter-engine">
            <option value="all">All</option>
            <option value="signature">Signature</option>
            <option value="anomaly">Anomaly</option>
            <option value="ml">ML</option>
          </select>
        </div>
        <div class="filter">
          <label for="filter-sensor">Sensor</label>
          <select id="filter-sensor">
            <option value="all">All Sensors</option>
          </select>
        </div>
      </div>
    </header>

    <section class="top-grid">
      <article class="card">
        <h2>Realtime Status</h2>
        <div id="stats" class="stats-grid"></div>
      </article>
      <article class="card">
        <h2>Latest Alerts</h2>
        <ul id="alert-feed" class="alert-feed">
          <li class="muted">No alerts yet.</li>
        </ul>
      </article>
      <article class="card">
        <h2>Sensor Comparison</h2>
        <div class="sensor-table-wrap">
          <table class="sensor-table">
            <thead>
              <tr>
                <th>Sensor</th>
                <th>Alerts</th>
                <th>APM</th>
                <th>EPS</th>
                <th>Queue</th>
                <th>Lag(s)</th>
              </tr>
            </thead>
            <tbody id="sensor-table-body">
              <tr><td colspan="6" class="muted">No sensor data yet.</td></tr>
            </tbody>
          </table>
        </div>
      </article>
      <article class="card">
        <h2>Drift Alerts</h2>
        <ul id="drift-alert-feed" class="alert-feed">
          <li class="muted">No drift alerts.</li>
        </ul>
      </article>
      <article class="card">
        <h2>Incident Audit</h2>
        <ul id="audit-feed" class="alert-feed">
          <li class="muted">No actions yet.</li>
        </ul>
      </article>
      <article class="card">
        <h2>Incident Queue</h2>
        <div class="incident-controls">
          <div class="filter">
            <label for="incident-queue-filter">Queue</label>
            <select id="incident-queue-filter">
              <option value="all">All</option>
              <option value="open">Open</option>
              <option value="high">High Priority</option>
              <option value="overdue">Overdue</option>
              <option value="unassigned">Unassigned</option>
            </select>
          </div>
          <div class="filter">
            <label for="incident-status-filter">Status</label>
            <select id="incident-status-filter">
              <option value="all">All</option>
              <option value="open">Open</option>
              <option value="triage">Triage</option>
              <option value="investigating">Investigating</option>
              <option value="contained">Contained</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
          <div class="filter">
            <label for="incident-owner-filter">Owner</label>
            <select id="incident-owner-filter">
              <option value="all">All</option>
              <option value="me">Assigned to Me</option>
            </select>
          </div>
        </div>
        <div class="incident-bulk-controls">
          <button id="incident-select-visible" class="alert-btn" type="button">Select Visible</button>
          <button id="incident-clear-selection" class="alert-btn" type="button">Clear</button>
          <button id="incident-bulk-assign" class="alert-btn" type="button">Bulk Assign Me</button>
          <button id="incident-bulk-resolve" class="alert-btn" type="button">Bulk Resolve + Note</button>
        </div>
        <p id="incident-selection-meta" class="muted">Selected incidents: 0</p>
        <div id="incident-summary" class="stats-grid"></div>
        <ul id="incident-feed" class="alert-feed">
          <li class="muted">No incidents yet.</li>
        </ul>
      </article>
      <article class="card">
        <h2>Active Suppressions</h2>
        <ul id="suppression-feed" class="alert-feed">
          <li class="muted">No active suppressions.</li>
        </ul>
      </article>
    </section>

    <article class="card">
      <h2>Rolling Metrics</h2>
      <div id="plot-realtime" class="plot compact"></div>
    </article>

    <article class="card">
      <h2>Anomaly Trend Bands</h2>
      <div id="plot-anomaly-trend" class="plot compact"></div>
    </article>

    <section id="grid" class="grid"></section>
  </main>

  <script>
    const grid = document.getElementById('grid');
    const stamp = document.getElementById('stamp');
    const statsHost = document.getElementById('stats');
    const alertFeed = document.getElementById('alert-feed');
    const sensorTableBody = document.getElementById('sensor-table-body');
    const driftAlertFeed = document.getElementById('drift-alert-feed');
    const auditFeed = document.getElementById('audit-feed');
    const incidentFeed = document.getElementById('incident-feed');
    const incidentSummary = document.getElementById('incident-summary');
    const incidentSelectionMeta = document.getElementById('incident-selection-meta');
    const incidentQueueFilter = document.getElementById('incident-queue-filter');
    const incidentStatusFilter = document.getElementById('incident-status-filter');
    const incidentOwnerFilter = document.getElementById('incident-owner-filter');
    const incidentSelectVisibleBtn = document.getElementById('incident-select-visible');
    const incidentClearSelectionBtn = document.getElementById('incident-clear-selection');
    const incidentBulkAssignBtn = document.getElementById('incident-bulk-assign');
    const incidentBulkResolveBtn = document.getElementById('incident-bulk-resolve');
    const suppressionFeed = document.getElementById('suppression-feed');
    const realtimeHost = document.getElementById('plot-realtime');
    const anomalyTrendHost = document.getElementById('plot-anomaly-trend');
    const filterWindow = document.getElementById('filter-window');
    const filterSeverity = document.getElementById('filter-severity');
    const filterEngine = document.getElementById('filter-engine');
    const filterSensor = document.getElementById('filter-sensor');

    const initialParams = new URLSearchParams(window.location.search);
    const authToken = initialParams.get('token') || '';
    const actionToken = initialParams.get('action_token') || authToken;
    const actorName = initialParams.get('actor') || 'dashboard-user';
    const actorRole = (initialParams.get('role') || 'analyst').toLowerCase();
    const selectedIncidentIds = new Set();

    function ensureCard(id, title) {
      let card = document.getElementById('card-' + id);
      if (card) {
        return card.querySelector('.plot');
      }

      card = document.createElement('article');
      card.className = 'card';
      card.id = 'card-' + id;

      const heading = document.createElement('h2');
      heading.textContent = title;

      const plot = document.createElement('div');
      plot.className = 'plot';
      plot.id = 'plot-' + id;

      card.appendChild(heading);
      card.appendChild(plot);
      grid.appendChild(card);
      return plot;
    }

    function applyFiltersFromUrl() {
      const params = new URLSearchParams(window.location.search);
      if (params.has('lookback')) filterWindow.value = params.get('lookback');
      if (params.has('severity')) filterSeverity.value = params.get('severity');
      if (params.has('engine')) filterEngine.value = params.get('engine');
      if (params.has('sensor_id')) filterSensor.value = params.get('sensor_id');
      if (params.has('incident_queue')) incidentQueueFilter.value = params.get('incident_queue');
      if (params.has('incident_status')) incidentStatusFilter.value = params.get('incident_status');
      if (params.has('incident_owner')) incidentOwnerFilter.value = params.get('incident_owner');
    }

    function currentFilters() {
      return {
        lookback: filterWindow.value || '5',
        severity: filterSeverity.value || 'all',
        engine: filterEngine.value || 'all',
        sensor_id: filterSensor.value || 'all'
      };
    }

    function currentIncidentFilters() {
      return {
        queue: incidentQueueFilter.value || 'all',
        status_filter: incidentStatusFilter.value || 'all',
        owner: incidentOwnerFilter.value || 'all'
      };
    }

    function buildQuery(filters) {
      const query = new URLSearchParams();
      query.set('lookback', filters.lookback);
      if (filters.severity && filters.severity !== 'all') query.set('severity', filters.severity);
      if (filters.engine && filters.engine !== 'all') query.set('engine', filters.engine);
      if (filters.sensor_id && filters.sensor_id !== 'all') query.set('sensor_id', filters.sensor_id);
      if (authToken) query.set('token', authToken);
      return query;
    }

    function syncUrl(filters) {
      const queryParams = buildQuery(filters);
      const incidentFilters = currentIncidentFilters();
      if (incidentFilters.queue && incidentFilters.queue !== 'all') {
        queryParams.set('incident_queue', incidentFilters.queue);
      }
      if (incidentFilters.status_filter && incidentFilters.status_filter !== 'all') {
        queryParams.set('incident_status', incidentFilters.status_filter);
      }
      if (incidentFilters.owner && incidentFilters.owner !== 'all') {
        queryParams.set('incident_owner', incidentFilters.owner);
      }
      const query = queryParams.toString();
      const target = query ? `${window.location.pathname}?${query}` : window.location.pathname;
      history.replaceState(null, '', target);
    }

    function toIsoOrEmpty(localValue) {
      if (!localValue) return '';
      const parsed = new Date(localValue);
      if (Number.isNaN(parsed.getTime())) return '';
      return parsed.toISOString();
    }

    function toLocalDateTimeValue(isoValue) {
      if (!isoValue) return '';
      const parsed = new Date(isoValue);
      if (Number.isNaN(parsed.getTime())) return '';
      const year = parsed.getFullYear();
      const month = String(parsed.getMonth() + 1).padStart(2, '0');
      const day = String(parsed.getDate()).padStart(2, '0');
      const hours = String(parsed.getHours()).padStart(2, '0');
      const minutes = String(parsed.getMinutes()).padStart(2, '0');
      return `${year}-${month}-${day}T${hours}:${minutes}`;
    }

    function updateIncidentSelectionMeta() {
      incidentSelectionMeta.textContent = `Selected incidents: ${selectedIncidentIds.size}`;
    }

    function updateBulkControlState() {
      const canOperate = actorRole === 'analyst' || actorRole === 'admin';
      const hasSelection = selectedIncidentIds.size > 0;
      incidentSelectVisibleBtn.disabled = !canOperate;
      incidentClearSelectionBtn.disabled = !canOperate;
      incidentBulkAssignBtn.disabled = !canOperate || !hasSelection;
      incidentBulkResolveBtn.disabled = !canOperate || !hasSelection;
      updateIncidentSelectionMeta();
    }

    function updateSelectionFromVisible(rows) {
      const visibleIds = new Set((rows || []).map((row) => Number(row.incident_id || row.id || 0)).filter((id) => id > 0));
      for (const id of Array.from(selectedIncidentIds)) {
        if (!visibleIds.has(id)) {
          selectedIncidentIds.delete(id);
        }
      }
      updateBulkControlState();
    }

    function updateSelection(incidentId, selected) {
      if (incidentId <= 0) return;
      if (selected) {
        selectedIncidentIds.add(incidentId);
      } else {
        selectedIncidentIds.delete(incidentId);
      }
      updateBulkControlState();
    }

    function updateSensorOptions(sensors) {
      const previous = filterSensor.value || 'all';
      const normalized = Array.isArray(sensors) ? sensors : [];

      filterSensor.innerHTML = '';
      const base = document.createElement('option');
      base.value = 'all';
      base.textContent = 'All Sensors';
      filterSensor.appendChild(base);

      for (const sensor of normalized) {
        const token = String(sensor || '').trim();
        if (!token) continue;
        const option = document.createElement('option');
        option.value = token;
        option.textContent = token;
        filterSensor.appendChild(option);
      }

      const values = new Set(Array.from(filterSensor.options).map((option) => option.value));
      filterSensor.value = values.has(previous) ? previous : 'all';
    }

    function formatFloat(value, digits = 2) {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) return '0.00';
      return parsed.toFixed(digits);
    }

    function formatCount(value) {
      const parsed = Number(value);
      if (!Number.isFinite(parsed)) return '0';
      return String(Math.round(parsed));
    }

    function renderStats(summary) {
      const heartbeatAlive = Number(summary.runtime_heartbeat || 0) >= 1;
      const cards = [
        { label: 'Events / Sec', value: formatFloat(summary.events_per_sec, 2) },
        { label: 'Alerts / Min', value: formatFloat(summary.alerts_per_min, 2) },
        { label: 'Queue Size', value: formatCount(summary.queue_size) },
        { label: 'Ingest Lag (s)', value: formatFloat(summary.ingest_lag_sec, 2) },
        { label: 'Total Alerts', value: formatCount(summary.total_alerts) },
        { label: 'Suppressed', value: formatCount(summary.suppressed_alerts) },
        { label: 'Heartbeat', value: heartbeatAlive ? 'alive' : 'stale' }
      ];

      statsHost.innerHTML = '';
      for (const item of cards) {
        const box = document.createElement('div');
        box.className = 'stat';

        const label = document.createElement('span');
        label.className = 'label';
        label.textContent = item.label;

        const value = document.createElement('span');
        value.className = 'value';
        value.textContent = item.value;

        box.appendChild(label);
        box.appendChild(value);
        statsHost.appendChild(box);
      }
    }

    function buildActionHeaders() {
      const headers = {
        'content-type': 'application/json',
        'x-nids-actor': actorName,
        'x-nids-role': actorRole,
      };
      if (actionToken) {
        headers['x-nids-token'] = actionToken;
      }
      return headers;
    }

    async function postAlertAction(alertId, action, payload = {}) {
      if (!alertId) return;
      try {
        const query = buildQuery(currentFilters()).toString();
        const response = await fetch(`/api/alerts/${alertId}/${action}?${query}`, {
          method: 'POST',
          headers: buildActionHeaders(),
          body: JSON.stringify(payload || {}),
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || result.error || 'Action failed');
        }
        await refreshViaHttp(true);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    async function fetchAudit(limit = 20) {
      const query = buildQuery(currentFilters());
      query.set('limit', String(limit));

      const response = await fetch('/api/audit?' + query.toString());
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || payload.error || 'Audit API error');
      }
      renderAuditFeed(payload.actions || []);
    }

    async function fetchSuppressions(limit = 20) {
      const query = buildQuery(currentFilters());
      query.set('limit', String(limit));

      const response = await fetch('/api/suppressions?' + query.toString());
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || payload.error || 'Suppressions API error');
      }
      renderSuppressionFeed(payload.rules || []);
    }

    function buildIncidentQuery(limit = 30) {
      const query = buildQuery(currentFilters());
      const incidentFilters = currentIncidentFilters();
      query.set('limit', String(limit));
      query.set('queue', incidentFilters.queue || 'all');
      if (incidentFilters.status_filter && incidentFilters.status_filter !== 'all') {
        query.set('status_filter', incidentFilters.status_filter);
      }
      if (incidentFilters.owner === 'me') {
        query.set('owner', actorName);
      }
      return query;
    }

    async function fetchIncidents(limit = 30) {
      const response = await fetch('/api/incidents?' + buildIncidentQuery(limit).toString());
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || payload.error || 'Incidents API error');
      }
      renderIncidentSummary(payload.summary || {});
      renderIncidentFeed(payload.incidents || []);
    }

    async function postIncidentAssign(incidentId, payload = {}) {
      if (!incidentId) return;
      try {
        const query = buildQuery(currentFilters()).toString();
        const response = await fetch(`/api/incidents/${incidentId}/assign?${query}`, {
          method: 'POST',
          headers: buildActionHeaders(),
          body: JSON.stringify(payload || {}),
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || result.error || 'Assign failed');
        }
        await refreshViaHttp(true);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    async function postIncidentStatus(incidentId, payload = {}) {
      if (!incidentId) return;
      try {
        const query = buildQuery(currentFilters()).toString();
        const response = await fetch(`/api/incidents/${incidentId}/status?${query}`, {
          method: 'POST',
          headers: buildActionHeaders(),
          body: JSON.stringify(payload || {}),
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || result.error || 'Status update failed');
        }
        await refreshViaHttp(true);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    async function postIncidentBulk(payload = {}) {
      try {
        const query = buildQuery(currentFilters()).toString();
        const response = await fetch(`/api/incidents/bulk?${query}`, {
          method: 'POST',
          headers: buildActionHeaders(),
          body: JSON.stringify(payload || {}),
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || result.error || 'Bulk incident update failed');
        }
        await refreshViaHttp(true);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    async function postSuppressionRevoke(ruleId, payload = {}) {
      if (!ruleId) return;
      try {
        const query = buildQuery(currentFilters()).toString();
        const response = await fetch(`/api/suppressions/${ruleId}/revoke?${query}`, {
          method: 'POST',
          headers: buildActionHeaders(),
          body: JSON.stringify(payload || {}),
        });
        const result = await response.json();
        if (!response.ok) {
          throw new Error(result.detail || result.error || 'Revoke failed');
        }
        await refreshViaHttp(true);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    function renderAlertFeed(alerts) {
      alertFeed.innerHTML = '';
      if (!alerts || alerts.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'muted';
        empty.textContent = 'No alerts for selected filters.';
        alertFeed.appendChild(empty);
        return;
      }

      for (const item of alerts) {
        const li = document.createElement('li');
        li.className = 'alert-item';

        const head = document.createElement('div');
        head.className = 'alert-head';

        const left = document.createElement('span');
        left.textContent = `[${item.severity}] ${item.engine} :: ${item.rule_name}`;

        const right = document.createElement('span');
        right.textContent = `${item.sensor_id || 'sensor?'} | ${item.timestamp || ''}`;

        head.appendChild(left);
        head.appendChild(right);

        const body = document.createElement('div');
        body.className = 'alert-body';
        const src = item.src_ip || 'unknown';
        const dst = item.dst_ip || 'unknown';
        const port = item.dst_port !== null && item.dst_port !== undefined ? item.dst_port : '-';
        body.textContent = `${src} -> ${dst}:${port} | ${item.summary || ''}`;

        li.appendChild(head);
        li.appendChild(body);

        const meta = document.createElement('div');
        meta.className = 'alert-meta';
        const ackStatus = String(item.ack_status || 'new');
        const ackBy = String(item.acknowledged_by || '');
        const suppressActive = Number(item.is_suppressed || 0) === 1;
        const suppressUntil = String(item.suppressed_until || '');

        const statusTokens = [];
        statusTokens.push(`ack=${ackStatus}`);
        if (ackBy) statusTokens.push(`by=${ackBy}`);
        if (suppressActive) {
          statusTokens.push(`suppressed_until=${suppressUntil || 'set'}`);
        }
        meta.textContent = statusTokens.join(' | ');
        li.appendChild(meta);

        const alertId = Number(item.alert_id || 0);
        if (alertId > 0) {
          const actions = document.createElement('div');
          actions.className = 'alert-actions';

          const ackBtn = document.createElement('button');
          ackBtn.className = 'alert-btn';
          ackBtn.type = 'button';
          ackBtn.textContent = 'Ack';
          ackBtn.disabled = ackStatus.toLowerCase() === 'acknowledged';
          ackBtn.addEventListener('click', () => {
            postAlertAction(alertId, 'ack', { reason: 'acknowledged from dashboard' });
          });

          const suppressBtn = document.createElement('button');
          suppressBtn.className = 'alert-btn';
          suppressBtn.type = 'button';
          suppressBtn.textContent = 'Suppress 60m';
          suppressBtn.disabled = suppressActive;
          suppressBtn.addEventListener('click', () => {
            postAlertAction(alertId, 'suppress', {
              ttl_minutes: 60,
              reason: 'suppressed from dashboard',
            });
          });

          actions.appendChild(ackBtn);
          actions.appendChild(suppressBtn);
          li.appendChild(actions);
        }

        alertFeed.appendChild(li);
      }
    }

    function renderAuditFeed(rows) {
      auditFeed.innerHTML = '';
      if (!rows || rows.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'muted';
        empty.textContent = 'No actions yet.';
        auditFeed.appendChild(empty);
        return;
      }

      for (const row of rows) {
        const li = document.createElement('li');
        li.className = 'alert-item';

        const head = document.createElement('div');
        head.className = 'alert-head';

        const left = document.createElement('span');
        left.textContent = `${row.action || 'action'} #${row.alert_id || '-'}`;

        const right = document.createElement('span');
        right.textContent = `${row.actor || 'unknown'} (${row.actor_role || 'role?'})`;

        head.appendChild(left);
        head.appendChild(right);

        const body = document.createElement('div');
        body.className = 'alert-body';
        body.textContent = `${row.timestamp || ''} | ${row.reason || 'no reason'}`;

        li.appendChild(head);
        li.appendChild(body);
        auditFeed.appendChild(li);
      }
    }

    function renderSuppressionFeed(rows) {
      suppressionFeed.innerHTML = '';
      if (!rows || rows.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'muted';
        empty.textContent = 'No active suppressions.';
        suppressionFeed.appendChild(empty);
        return;
      }

      const canRevoke = actorRole === 'admin';
      for (const row of rows) {
        const li = document.createElement('li');
        li.className = 'alert-item';

        const head = document.createElement('div');
        head.className = 'alert-head';

        const left = document.createElement('span');
        left.textContent = `${row.engine || '*'} :: ${row.rule_name || '*'}`;

        const right = document.createElement('span');
        const until = String(row.suppressed_until || 'n/a');
        right.textContent = `rule#${row.id || '-'} | until=${until}`;

        head.appendChild(left);
        head.appendChild(right);

        const body = document.createElement('div');
        body.className = 'alert-body';
        const port = row.dst_port !== null && row.dst_port !== undefined ? row.dst_port : '*';
        body.textContent = `${row.src_ip || '*'} -> ${row.dst_ip || '*'}:${port} | proto=${row.proto || '*'} | sensor=${row.sensor_id || '*'}`;

        const meta = document.createElement('div');
        meta.className = 'alert-meta';
        meta.textContent = `by=${row.created_by || 'unknown'} (${row.created_role || 'role?'}) | ttl=${row.ttl_minutes || '-'}m | reason=${row.reason || 'n/a'}`;

        li.appendChild(head);
        li.appendChild(body);
        li.appendChild(meta);

        const ruleId = Number(row.id || 0);
        if (canRevoke && ruleId > 0) {
          const actions = document.createElement('div');
          actions.className = 'alert-actions';

          const revokeBtn = document.createElement('button');
          revokeBtn.className = 'alert-btn';
          revokeBtn.type = 'button';
          revokeBtn.textContent = 'Revoke';
          revokeBtn.addEventListener('click', () => {
            postSuppressionRevoke(ruleId, { reason: 'revoked from dashboard' });
          });

          actions.appendChild(revokeBtn);
          li.appendChild(actions);
        }

        suppressionFeed.appendChild(li);
      }
    }

    function renderIncidentSummary(summary) {
      const cards = [
        { label: 'Total', value: formatCount(summary.total || 0) },
        { label: 'Open', value: formatCount(summary.open || 0) },
        { label: 'Resolved', value: formatCount(summary.resolved || 0) },
        { label: 'Unassigned', value: formatCount(summary.unassigned || 0) },
        { label: 'Overdue', value: formatCount(summary.overdue || 0) },
        { label: 'High Priority', value: formatCount(summary.high_priority || 0) },
      ];

      incidentSummary.innerHTML = '';
      for (const item of cards) {
        const box = document.createElement('div');
        box.className = 'stat';

        const label = document.createElement('span');
        label.className = 'label';
        label.textContent = item.label;

        const value = document.createElement('span');
        value.className = 'value';
        value.textContent = item.value;

        box.appendChild(label);
        box.appendChild(value);
        incidentSummary.appendChild(box);
      }
    }

    function renderIncidentFeed(rows) {
      incidentFeed.innerHTML = '';
      if (!rows || rows.length === 0) {
        selectedIncidentIds.clear();
        updateBulkControlState();
        const empty = document.createElement('li');
        empty.className = 'muted';
        empty.textContent = 'No incidents for selected queue.';
        incidentFeed.appendChild(empty);
        return;
      }

      updateSelectionFromVisible(rows);
      const canOperate = actorRole === 'analyst' || actorRole === 'admin';

      for (const row of rows) {
        const li = document.createElement('li');
        li.className = 'alert-item';

        const incidentId = Number(row.incident_id || row.id || 0);
        const statusToken = String(row.status || 'open').toLowerCase();
        const ownerToken = String(row.owner || '').trim();
        const priorityToken = String(row.priority || 'low').toLowerCase();
        const dueToken = String(row.due_at || '').trim();
        const overdue = Number(row.is_overdue || 0) === 1;

        const head = document.createElement('div');
        head.className = 'alert-head';

        const left = document.createElement('span');
        const selector = document.createElement('input');
        selector.type = 'checkbox';
        selector.className = 'incident-select';
        selector.dataset.incidentId = String(incidentId);
        selector.disabled = !canOperate || incidentId <= 0;
        selector.checked = selectedIncidentIds.has(incidentId);
        selector.addEventListener('change', () => {
          updateSelection(incidentId, selector.checked);
        });
        left.appendChild(selector);
        left.appendChild(document.createTextNode(`[${priorityToken}] #${incidentId || '-'} :: ${row.rule_name || 'incident'}`));

        const right = document.createElement('span');
        right.textContent = `${row.sensor_id || 'sensor?'} | due=${dueToken || 'n/a'}`;

        head.appendChild(left);
        head.appendChild(right);

        const body = document.createElement('div');
        body.className = 'alert-body';
        body.textContent = row.summary || 'No summary available.';

        const meta = document.createElement('div');
        meta.className = 'alert-meta';
        const responseBreach = Number(row.sla_response_breached || 0) === 1;
        const overdueStage = Number(row.sla_overdue_stage || 0);
        const tokens = [
          `status=${statusToken}`,
          `owner=${ownerToken || 'unassigned'}`,
          `severity=${row.alert_severity || 'unknown'}`,
          `engine=${row.alert_engine || 'unknown'}`,
          `alert_id=${row.alert_id || '-'}`,
          `response_breach=${responseBreach ? 'YES' : 'no'}`,
          `overdue_stage=${overdueStage}`,
        ];
        if (overdue) {
          tokens.push('overdue=YES');
        }
        meta.textContent = tokens.join(' | ');

        li.appendChild(head);
        li.appendChild(body);
        li.appendChild(meta);

        if (canOperate && incidentId > 0) {
          const workflow = document.createElement('div');
          workflow.className = 'incident-edit-grid';

          const ownerInput = document.createElement('input');
          ownerInput.type = 'text';
          ownerInput.placeholder = 'owner';
          ownerInput.value = ownerToken;

          const prioritySelect = document.createElement('select');
          for (const token of ['low', 'medium', 'high', 'critical']) {
            const opt = document.createElement('option');
            opt.value = token;
            opt.textContent = `priority=${token}`;
            if (token === priorityToken) {
              opt.selected = true;
            }
            prioritySelect.appendChild(opt);
          }

          const dueInput = document.createElement('input');
          dueInput.type = 'datetime-local';
          dueInput.value = toLocalDateTimeValue(dueToken);

          const noteInput = document.createElement('input');
          noteInput.type = 'text';
          noteInput.placeholder = 'note';

          const saveBtn = document.createElement('button');
          saveBtn.className = 'alert-btn';
          saveBtn.type = 'button';
          saveBtn.textContent = 'Save Fields';
          saveBtn.addEventListener('click', () => {
            postIncidentAssign(incidentId, {
              owner: ownerInput.value.trim(),
              priority: prioritySelect.value,
              due_at: toIsoOrEmpty(dueInput.value),
              reason: noteInput.value.trim() || 'incident fields updated from dashboard',
            });
          });

          const resolveBtn = document.createElement('button');
          resolveBtn.className = 'alert-btn';
          resolveBtn.type = 'button';
          resolveBtn.textContent = 'Resolve + Note';
          resolveBtn.disabled = statusToken === 'resolved';
          resolveBtn.addEventListener('click', () => {
            const note = noteInput.value.trim() || 'resolved from dashboard';
            postIncidentStatus(incidentId, {
              status: 'resolved',
              reason: `resolution_note=${note}`,
            });
          });

          const transitions = [
            { label: 'Triage', value: 'triage' },
            { label: 'Investigate', value: 'investigating' },
            { label: 'Contain', value: 'contained' },
          ];

          const transitionActions = document.createElement('div');
          transitionActions.className = 'alert-actions';
          for (const transition of transitions) {
            const button = document.createElement('button');
            button.className = 'alert-btn';
            button.type = 'button';
            button.textContent = transition.label;
            button.disabled = statusToken === transition.value;
            button.addEventListener('click', () => {
              postIncidentStatus(incidentId, {
                status: transition.value,
                reason: noteInput.value.trim() || `set to ${transition.value} from dashboard`,
              });
            });
            transitionActions.appendChild(button);
          }

          workflow.appendChild(ownerInput);
          workflow.appendChild(prioritySelect);
          workflow.appendChild(dueInput);
          workflow.appendChild(noteInput);
          workflow.appendChild(saveBtn);
          workflow.appendChild(resolveBtn);

          li.appendChild(workflow);
          li.appendChild(transitionActions);
        }

        incidentFeed.appendChild(li);
      }

      updateBulkControlState();
    }

    function renderSensorSummary(rows) {
      sensorTableBody.innerHTML = '';
      if (!rows || rows.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 6;
        td.className = 'muted';
        td.textContent = 'No sensor data for selected filters.';
        tr.appendChild(td);
        sensorTableBody.appendChild(tr);
        return;
      }

      for (const row of rows) {
        const tr = document.createElement('tr');

        const cells = [
          row.sensor_id || 'unknown',
          formatCount(row.alert_count),
          formatFloat(row.alerts_per_min, 2),
          formatFloat(row.events_per_sec, 2),
          formatCount(row.queue_size),
          formatFloat(row.ingest_lag_sec, 2)
        ];

        for (const token of cells) {
          const td = document.createElement('td');
          td.textContent = String(token);
          tr.appendChild(td);
        }
        sensorTableBody.appendChild(tr);
      }
    }


    function renderDriftAlerts(rows) {
      driftAlertFeed.innerHTML = '';
      if (!rows || rows.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'muted';
        empty.textContent = 'No drift alerts.';
        driftAlertFeed.appendChild(empty);
        return;
      }

      for (const row of rows) {
        const li = document.createElement('li');
        li.className = 'alert-item';

        const head = document.createElement('div');
        head.className = 'alert-head';

        const left = document.createElement('span');
        left.textContent = `[${row.severity || 'medium'}] ${row.sensor_id || 'unknown'}`;

        const right = document.createElement('span');
        right.textContent = `score=${formatFloat(row.drift_score || 0, 2)}`;

        head.appendChild(left);
        head.appendChild(right);

        const body = document.createElement('div');
        body.className = 'alert-body';
        const reasons = Array.isArray(row.reasons) ? row.reasons.join(' | ') : '';
        body.textContent = reasons || 'Drift detected';

        li.appendChild(head);
        li.appendChild(body);
        driftAlertFeed.appendChild(li);
      }
    }

    function renderAnomalyTrend(rows) {
      if (!rows || rows.length === 0) {
        Plotly.react(
          anomalyTrendHost,
          [],
          {
            template: 'plotly_white',
            margin: { l: 45, r: 30, t: 18, b: 38 },
            annotations: [{ text: 'No trend data', showarrow: false, x: 0.5, y: 0.5, xref: 'paper', yref: 'paper' }],
          },
          { responsive: true, displayModeBar: false }
        );
        return;
      }

      const x = rows.map((item) => item.timestamp);
      const values = rows.map((item) => Number(item.value || 0));
      const baseline = rows.map((item) => Number(item.baseline || 0));
      const upper = rows.map((item) => Number(item.upper || 0));
      const lower = rows.map((item) => Number(item.lower || 0));

      const traces = [
        { x, y: values, mode: 'lines+markers', name: 'Alerts/Min', line: { width: 2 } },
        { x, y: baseline, mode: 'lines', name: 'Baseline', line: { width: 1.5, dash: 'dot' } },
        { x, y: upper, mode: 'lines', name: 'Upper Band', line: { width: 1, dash: 'dash' } },
        { x, y: lower, mode: 'lines', name: 'Lower Band', line: { width: 1, dash: 'dash' } },
      ];

      const layout = {
        template: 'plotly_white',
        margin: { l: 45, r: 30, t: 18, b: 38 },
        xaxis: { title: 'Time' },
        yaxis: { title: 'Alerts / Min' },
        legend: { orientation: 'h', x: 0, y: 1.15 }
      };

      Plotly.react(anomalyTrendHost, traces, layout, { responsive: true, displayModeBar: false });
    }
    function toSeriesPoints(rows) {
      if (!rows) return { x: [], y: [] };
      return {
        x: rows.map((point) => point.timestamp),
        y: rows.map((point) => Number(point.value || 0))
      };
    }

    function renderRealtimePlot(series) {
      const eps = toSeriesPoints(series.events_per_sec);
      const apm = toSeriesPoints(series.alerts_per_min);
      const queue = toSeriesPoints(series.queue_size);
      const lag = toSeriesPoints(series.ingest_lag_sec);

      const traces = [
        {
          x: eps.x,
          y: eps.y,
          mode: 'lines+markers',
          name: 'Events/Sec',
          line: { width: 2 }
        },
        {
          x: apm.x,
          y: apm.y,
          mode: 'lines',
          name: 'Alerts/Min',
          line: { width: 2 }
        },
        {
          x: queue.x,
          y: queue.y,
          mode: 'lines',
          name: 'Queue Size',
          yaxis: 'y2',
          line: { width: 1.5, dash: 'dot' }
        },
        {
          x: lag.x,
          y: lag.y,
          mode: 'lines',
          name: 'Ingest Lag (s)',
          yaxis: 'y2',
          line: { width: 1.5, dash: 'dash' }
        }
      ];

      const layout = {
        template: 'plotly_white',
        margin: { l: 45, r: 45, t: 18, b: 38 },
        xaxis: { title: 'Time' },
        yaxis: { title: 'Events / Alerts' },
        yaxis2: {
          title: 'Queue / Lag',
          overlaying: 'y',
          side: 'right'
        },
        legend: { orientation: 'h', x: 0, y: 1.15 }
      };

      Plotly.react(realtimeHost, traces, layout, { responsive: true, displayModeBar: false });
    }

    async function fetchFigures(filters) {
      const query = buildQuery(filters).toString();
      const figResponse = await fetch('/api/figures?' + query);
      const figPayload = await figResponse.json();
      if (!figResponse.ok) {
        throw new Error(figPayload.error || 'Figure API error');
      }

      for (const chart of figPayload.charts) {
        const plotHost = ensureCard(chart.slug, chart.title);
        Plotly.react(plotHost, chart.figure.data, chart.figure.layout, { responsive: true });
      }
    }

    function applyRealtimePayload(payload) {
      updateSensorOptions(payload.available_sensors || []);
      const mode = realtimeSocket ? 'websocket' : 'http';
      stamp.textContent = `Live mode: ${mode} | Last update: ${payload.generated_at}`;
      renderStats(payload.summary || {});
      renderAlertFeed(payload.recent_alerts || []);
      renderSensorSummary(payload.sensor_summary || []);
      renderDriftAlerts(payload.drift_alerts || []);
      renderRealtimePlot(payload.series || {});
      renderAnomalyTrend(payload.anomaly_trend || []);
    }

    async function refreshViaHttp(includeFigures = true) {
      try {
        const filters = currentFilters();
        syncUrl(filters);
        const query = buildQuery(filters).toString();

        const realtimeResponse = await fetch('/api/realtime?' + query);
        const realtimePayload = await realtimeResponse.json();
        if (!realtimeResponse.ok) {
          throw new Error(realtimePayload.error || 'Realtime API error');
        }

        applyRealtimePayload(realtimePayload);
        await fetchAudit(20);
        await fetchSuppressions(20);
        await fetchIncidents(30);
        if (includeFigures) {
          await fetchFigures(filters);
        }
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    async function refreshFiguresOnly() {
      try {
        await fetchFigures(currentFilters());
        await fetchAudit(20);
        await fetchSuppressions(20);
        await fetchIncidents(30);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    async function refreshIncidentsOnly() {
      try {
        const filters = currentFilters();
        syncUrl(filters);
        await fetchIncidents(30);
      } catch (error) {
        stamp.textContent = `Dashboard error: ${error.message}`;
      }
    }

    let realtimeSocket = null;
    let socketManuallyClosed = false;
    let pollingTimer = null;
    let figureTimer = null;
    let reconnectTimer = null;

    function stopPolling() {
      if (pollingTimer) {
        clearInterval(pollingTimer);
        pollingTimer = null;
      }
    }

    function startPolling() {
      stopPolling();
      refreshViaHttp(true);
      pollingTimer = setInterval(() => {
        refreshViaHttp(false);
      }, 5000);
    }

    function stopFigureRefresh() {
      if (figureTimer) {
        clearInterval(figureTimer);
        figureTimer = null;
      }
    }

    function startFigureRefresh() {
      stopFigureRefresh();
      figureTimer = setInterval(() => {
        refreshFiguresOnly();
      }, 30000);
    }

    function clearReconnectTimer() {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    }

    function buildWebSocketUrl(filters) {
      const query = buildQuery(filters).toString();
      const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
      return `${scheme}://${window.location.host}/ws/realtime?${query}`;
    }

    function disconnectRealtimeSocket(manual = true) {
      socketManuallyClosed = manual;
      if (realtimeSocket) {
        try {
          realtimeSocket.close();
        } catch (error) {
          // no-op
        }
        realtimeSocket = null;
      }
    }

    function scheduleReconnect() {
      clearReconnectTimer();
      reconnectTimer = setTimeout(() => {
        startRealtimeSocket();
      }, 5000);
    }

    function startRealtimeSocket() {
      const filters = currentFilters();
      syncUrl(filters);
      clearReconnectTimer();

      if (!('WebSocket' in window)) {
        stamp.textContent = 'WebSocket unavailable; using HTTP polling fallback.';
        startFigureRefresh();
        startPolling();
        return;
      }

      disconnectRealtimeSocket(true);
      const wsUrl = buildWebSocketUrl(filters);
      stamp.textContent = 'Connecting realtime stream...';
      socketManuallyClosed = false;
      realtimeSocket = new WebSocket(wsUrl);

      realtimeSocket.onopen = () => {
        stopPolling();
        startFigureRefresh();
        refreshFiguresOnly();
      };

      realtimeSocket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          applyRealtimePayload(payload);
        } catch (error) {
          stamp.textContent = `Dashboard error: ${error.message}`;
        }
      };

      realtimeSocket.onerror = () => {
        if (realtimeSocket) {
          realtimeSocket.close();
        }
      };

      realtimeSocket.onclose = () => {
        const manual = socketManuallyClosed;
        realtimeSocket = null;
        socketManuallyClosed = false;

        if (!manual) {
          stamp.textContent = 'Realtime stream disconnected; switching to HTTP fallback.';
          startFigureRefresh();
          startPolling();
          scheduleReconnect();
        }
      };
    }

    for (const element of [filterWindow, filterSeverity, filterEngine, filterSensor]) {
      element.addEventListener('change', () => {
        startRealtimeSocket();
      });
    }

    for (const element of [incidentQueueFilter, incidentStatusFilter, incidentOwnerFilter]) {
      element.addEventListener('change', () => {
        refreshIncidentsOnly();
      });
    }

    incidentSelectVisibleBtn.addEventListener('click', () => {
      for (const checkbox of incidentFeed.querySelectorAll('.incident-select')) {
        if (checkbox.disabled) continue;
        checkbox.checked = true;
        const incidentId = Number(checkbox.dataset.incidentId || 0);
        updateSelection(incidentId, true);
      }
      updateBulkControlState();
    });

    incidentClearSelectionBtn.addEventListener('click', () => {
      selectedIncidentIds.clear();
      for (const checkbox of incidentFeed.querySelectorAll('.incident-select')) {
        checkbox.checked = false;
      }
      updateBulkControlState();
    });

    incidentBulkAssignBtn.addEventListener('click', () => {
      const incidentIds = Array.from(selectedIncidentIds);
      if (incidentIds.length === 0) return;
      postIncidentBulk({
        incident_ids: incidentIds,
        owner: actorName,
        reason: 'bulk assigned from dashboard',
      });
    });

    incidentBulkResolveBtn.addEventListener('click', () => {
      const incidentIds = Array.from(selectedIncidentIds);
      if (incidentIds.length === 0) return;
      const note = window.prompt('Resolution note for selected incidents:', 'resolved from dashboard') || 'resolved from dashboard';
      postIncidentBulk({
        incident_ids: incidentIds,
        status: 'resolved',
        reason: `resolution_note=${note}`,
      });
    });

    window.addEventListener('beforeunload', () => {
      clearReconnectTimer();
      stopPolling();
      stopFigureRefresh();
      disconnectRealtimeSocket(true);
    });

    applyFiltersFromUrl();
    updateBulkControlState();
    startRealtimeSocket();
  </script>
</body>
</html>
"""


def create_dashboard_app(
    db_path: str | Path,
    api_token: str | None = None,
    action_token: str | None = None,
    notify_webhook: str | None = None,
    notify_timeout_sec: float | None = None,
    notify_max_retries: int | None = None,
    notify_backoff_sec: float | None = None,
    notify_max_backoff_sec: float | None = None,
    notify_min_interval_sec: float | None = None,
    notify_dead_letter: str | None = None,
    notify_dead_letter_max_bytes: int | None = None,
    notify_dead_letter_backup_count: int | None = None,
) -> FastAPI:
    source_db = Path(db_path)
    expected_token = _normalize_token(api_token)
    expected_action_token = _normalize_token(action_token) or expected_token
    notifier = SlackWebhookNotifier(
        webhook_url=_normalize_token(notify_webhook),
        timeout_sec=float(notify_timeout_sec) if notify_timeout_sec is not None else 3.0,
        max_retries=int(notify_max_retries) if notify_max_retries is not None else 2,
        backoff_sec=float(notify_backoff_sec) if notify_backoff_sec is not None else 0.5,
        max_backoff_sec=float(notify_max_backoff_sec) if notify_max_backoff_sec is not None else 4.0,
        min_interval_sec=float(notify_min_interval_sec) if notify_min_interval_sec is not None else 0.1,
        dead_letter_path=_normalize_token(notify_dead_letter),
        dead_letter_max_bytes=int(notify_dead_letter_max_bytes) if notify_dead_letter_max_bytes is not None else 10485760,
        dead_letter_backup_count=int(notify_dead_letter_backup_count) if notify_dead_letter_backup_count is not None else 5,
    )
    app = FastAPI(title="Universal NIDS Analytics Dashboard")

    @app.middleware("http")
    async def _set_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.plot.ly; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        return response

    bootstrap_store = IncidentStore(source_db)
    try:
        bootstrap_store.ensure_recent_incidents(limit=5000)
    except Exception:
        pass
    finally:
        bootstrap_store.close()

    def _enforce_request_auth(request: Request) -> None:
        if _is_authorized_token(
            expected_token,
            query_token=request.query_params.get("token"),
            header_token=request.headers.get("x-nids-token"),
            authorization_header=request.headers.get("authorization"),
        ):
            return
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    def _get_actor_context(request: Request, action: str) -> tuple[str, str]:
        actor = _normalize_token(request.headers.get("x-nids-actor")) or "dashboard-user"
        role = (_normalize_token(request.headers.get("x-nids-role")) or "viewer").lower()

        if expected_action_token is not None and not _is_authorized_token(
            expected_action_token,
            query_token=None,
            header_token=request.headers.get("x-nids-token"),
            authorization_header=request.headers.get("authorization"),
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized action token")

        allowed_roles = {
            "ack": {"analyst", "admin"},
            "suppress": {"admin"},
            "revoke": {"admin"},
            "assign": {"analyst", "admin"},
            "status": {"analyst", "admin"},
            "bulk": {"analyst", "admin"},
        }
        if role not in allowed_roles.get(action, set()):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role not allowed for action")

        return actor, role

    allowed_incident_priorities = {"low", "medium", "high", "critical"}
    allowed_incident_status = {"open", "triage", "investigating", "contained", "resolved"}

    def _validate_incident_priority(value: str | None) -> str | None:
        token = _normalize_token(value)
        if token is None:
            return None
        normalized = token.lower()
        if normalized not in allowed_incident_priorities:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid incident priority")
        return normalized

    def _validate_incident_status(value: str | None) -> str | None:
        token = _normalize_token(value)
        if token is None:
            return None
        normalized = token.lower()
        if normalized not in allowed_incident_status:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid incident status")
        return normalized

    def _validate_due_at(value: str | None) -> str | None:
        token = _normalize_token(value)
        if token is None:
            return None
        parsed = _parse_iso_datetime(token)
        if parsed is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid due_at timestamp")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home(request: Request) -> str:
        _enforce_request_auth(request)
        return _dashboard_html()

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        incident_subsystem = {"ready": False, "error": ""}
        if source_db.exists():
            try:
                with sqlite3.connect(str(source_db)) as conn:
                    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                    existing = {str(row[0]) for row in rows}
                    required = {"incidents", "incident_actions"}
                    missing = sorted(required - existing)
                    incident_subsystem = {
                        "ready": len(missing) == 0,
                        "missing_tables": missing,
                    }
            except Exception as exc:
                incident_subsystem = {"ready": False, "error": str(exc)}

        payload = {
            "status": "ok",
            "timestamp": _utc_now_iso(),
            "db_exists": source_db.exists(),
            "token_required": bool(expected_token),
            "action_token_required": bool(expected_action_token),
            "notifications": notifier.health_snapshot(),
            "incident_subsystem": incident_subsystem,
        }
        return JSONResponse(payload)

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        payload: dict[str, Any] = {
            "status": "ready",
            "timestamp": _utc_now_iso(),
            "db_exists": source_db.exists(),
            "required_tables": ["alerts", "flows", "metrics", "incident_actions", "suppression_rules", "incidents"],
            "missing_tables": [],
            "notifications": {
                "enabled": notifier.enabled,
                "dead_letter_enabled": notifier.dead_letter_path is not None,
                "dead_letter_max_bytes": notifier.dead_letter_max_bytes,
                "dead_letter_backup_count": notifier.dead_letter_backup_count,
            },
        }

        if not source_db.exists():
            payload["status"] = "not_ready"
            return JSONResponse(payload, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            with sqlite3.connect(str(source_db)) as conn:
                rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                existing = {str(row[0]) for row in rows}
                required = {"alerts", "flows", "metrics", "incident_actions", "suppression_rules", "incidents"}
                missing = sorted(required - existing)
                payload["missing_tables"] = missing
                payload["status"] = "ready" if not missing else "degraded"
        except Exception as exc:
            payload["status"] = "not_ready"
            payload["error"] = str(exc)
            return JSONResponse(payload, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

        return JSONResponse(payload)

    @app.get("/api/figures")
    async def api_figures(
        request: Request,
        lookback: int = 5,
        severity: str | None = None,
        engine: str | None = None,
        sensor_id: str | None = None,
    ) -> JSONResponse:
        _enforce_request_auth(request)
        analytics = build_analytics(
            source_db,
            lookback_minutes=_safe_lookback(lookback, default=5),
            sensor_id=sensor_id,
            severity=severity,
            engine=engine,
        )
        figures = build_all_figures(analytics)
        payload = {
            "generated_at": _utc_now_iso(),
            "charts": [
                {
                    "slug": chart.slug,
                    "title": chart.title,
                    "figure": chart.figure.to_plotly_json(),
                }
                for chart in figures
            ],
        }
        return JSONResponse(payload)

    @app.get("/api/realtime")
    async def api_realtime(
        request: Request,
        lookback: int = 5,
        severity: str | None = None,
        engine: str | None = None,
        sensor_id: str | None = None,
    ) -> JSONResponse:
        _enforce_request_auth(request)
        payload = _build_realtime_payload(
            source_db,
            lookback_minutes=_safe_lookback(lookback, default=5),
            max_alerts=10,
            sensor_id=sensor_id,
            severity=severity,
            engine=engine,
        )
        return JSONResponse(payload)

    @app.get("/api/audit")
    async def api_audit(request: Request, limit: int = 20) -> JSONResponse:
        _enforce_request_auth(request)
        store = SQLiteStore(source_db)
        try:
            actions = store.fetch_incident_actions(limit=limit)
        finally:
            store.close()
        return JSONResponse({"generated_at": _utc_now_iso(), "actions": actions})

    @app.get("/api/suppressions")
    async def api_suppressions(request: Request, limit: int = 20) -> JSONResponse:
        _enforce_request_auth(request)
        store = SQLiteStore(source_db)
        try:
            rules = store.fetch_suppression_rules(active_only=True, limit=limit)
        finally:
            store.close()
        return JSONResponse({"generated_at": _utc_now_iso(), "rules": rules})

    @app.get("/api/incidents")
    async def api_incidents(
        request: Request,
        limit: int = 50,
        queue: str | None = "all",
        status_filter: str | None = None,
        owner: str | None = None,
        priority: str | None = None,
        sensor_id: str | None = None,
        severity: str | None = None,
        engine: str | None = None,
    ) -> JSONResponse:
        _enforce_request_auth(request)
        store = IncidentStore(source_db)
        try:
            incidents = store.list_incidents(
                limit=limit,
                queue=queue,
                status=status_filter,
                owner=owner,
                priority=priority,
                sensor_id=sensor_id,
                severity=severity,
                engine=engine,
            )
            summary = store.incident_summary(
                status=status_filter,
                owner=owner,
                priority=priority,
                sensor_id=sensor_id,
                severity=severity,
                engine=engine,
            )
        finally:
            store.close()
        return JSONResponse({
            "generated_at": _utc_now_iso(),
            "queue": str(queue or "all"),
            "summary": summary,
            "incidents": incidents,
        })

    @app.post("/api/incidents/bulk")
    async def api_incident_bulk(request: Request) -> JSONResponse:
        _enforce_request_auth(request)
        actor, role = _get_actor_context(request, action="bulk")

        payload: dict[str, Any] = {}
        try:
            raw = await request.json()
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

        raw_ids = payload.get("incident_ids")
        if not isinstance(raw_ids, list):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="incident_ids must be a list")

        incident_ids: list[int] = []
        for value in raw_ids:
            try:
                parsed = int(value)
            except Exception:
                continue
            if parsed > 0:
                incident_ids.append(parsed)
        incident_ids = sorted(set(incident_ids))[:500]
        if not incident_ids:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid incident_ids supplied")

        owner_provided = "owner" in payload
        priority_provided = "priority" in payload
        due_provided = "due_at" in payload
        status_provided = "status" in payload

        owner_value = str(payload.get("owner") or "") if owner_provided else None
        priority_value = _validate_incident_priority(str(payload.get("priority") or "")) if priority_provided else None
        due_value = _validate_due_at(str(payload.get("due_at") or "")) if due_provided else None
        status_value = _validate_incident_status(str(payload.get("status") or "")) if status_provided else None
        reason = _normalize_token(str(payload.get("reason") or ""))
        if owner_value is not None and len(owner_value) > 128:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="owner too long")
        if reason and len(reason) > 512:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="reason too long")

        if not any([owner_provided, priority_provided, due_provided, status_provided]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No updates supplied")

        store = IncidentStore(source_db)
        try:
            updated: list[dict[str, Any]] = []
            missing: list[int] = []
            for incident_id in incident_ids:
                incident = store.update_incident(
                    int(incident_id),
                    actor=actor,
                    actor_role=role,
                    status=status_value if status_provided else None,
                    owner=owner_value if owner_provided else None,
                    priority=priority_value if priority_provided else None,
                    due_at=due_value if due_provided else None,
                    reason=reason,
                    metadata={"source": "dashboard_bulk_api"},
                )
                if incident is None:
                    missing.append(int(incident_id))
                    continue
                updated.append(incident)
        finally:
            store.close()

        if notifier.enabled:
            for incident in updated:
                notifier.notify_incident_update(incident, action="bulk_update", actor=actor)

        return JSONResponse(
            {
                "status": "ok",
                "action": "bulk",
                "actor": actor,
                "actor_role": role,
                "requested": incident_ids,
                "updated_count": len(updated),
                "missing": missing,
                "incidents": updated,
            }
        )

    @app.post("/api/incidents/{incident_id}/assign")
    async def api_incident_assign(incident_id: int, request: Request) -> JSONResponse:
        _enforce_request_auth(request)
        actor, role = _get_actor_context(request, action="assign")

        payload: dict[str, Any] = {}
        try:
            raw = await request.json()
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

        owner = _normalize_token(str(payload.get("owner") or "")) or actor
        priority = _validate_incident_priority(str(payload.get("priority") or ""))
        due_at = _validate_due_at(str(payload.get("due_at") or ""))
        reason = _normalize_token(str(payload.get("reason") or ""))
        if len(owner) > 128:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="owner too long")

        store = IncidentStore(source_db)
        try:
            incident = store.assign_incident(
                int(incident_id),
                actor=actor,
                actor_role=role,
                owner=owner,
                priority=priority,
                due_at=due_at,
                reason=reason,
                metadata={"source": "dashboard_api"},
            )
        finally:
            store.close()

        if incident is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        if notifier.enabled:
            notifier.notify_incident_update(incident, action="assign", actor=actor)

        return JSONResponse({
            "status": "ok",
            "action": "assign",
            "incident_id": int(incident_id),
            "actor": actor,
            "actor_role": role,
            "incident": incident,
        })

    @app.post("/api/incidents/{incident_id}/status")
    async def api_incident_status(incident_id: int, request: Request) -> JSONResponse:
        _enforce_request_auth(request)
        actor, role = _get_actor_context(request, action="status")

        payload: dict[str, Any] = {}
        try:
            raw = await request.json()
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

        status_value = _validate_incident_status(str(payload.get("status") or "")) or "triage"
        reason = _normalize_token(str(payload.get("reason") or ""))
        if reason and len(reason) > 512:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="reason too long")

        store = IncidentStore(source_db)
        try:
            incident = store.set_incident_status(
                int(incident_id),
                actor=actor,
                actor_role=role,
                status=status_value,
                reason=reason,
                metadata={"source": "dashboard_api"},
            )
        finally:
            store.close()

        if incident is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        if notifier.enabled:
            notifier.notify_incident_update(incident, action=f"status:{status_value}", actor=actor)

        return JSONResponse({
            "status": "ok",
            "action": "status",
            "incident_id": int(incident_id),
            "actor": actor,
            "actor_role": role,
            "incident": incident,
        })

    @app.post("/api/alerts/{alert_id}/ack")
    async def api_alert_ack(alert_id: int, request: Request) -> JSONResponse:
        _enforce_request_auth(request)
        actor, role = _get_actor_context(request, action="ack")

        payload: dict[str, Any] = {}
        try:
            raw = await request.json()
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

        reason = _normalize_token(str(payload.get("reason") or ""))

        store = SQLiteStore(source_db)
        try:
            changed = store.acknowledge_alert(
                int(alert_id),
                actor=actor,
                actor_role=role,
                reason=reason,
                metadata={"source": "dashboard_api"},
            )
            alert = store.fetch_alert(int(alert_id))
        finally:
            store.close()

        if not changed:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

        return JSONResponse(
            {
                "status": "ok",
                "action": "ack",
                "alert_id": int(alert_id),
                "actor": actor,
                "actor_role": role,
                "alert": alert,
            }
        )

    @app.post("/api/alerts/{alert_id}/suppress")
    async def api_alert_suppress(alert_id: int, request: Request) -> JSONResponse:
        _enforce_request_auth(request)
        actor, role = _get_actor_context(request, action="suppress")

        payload: dict[str, Any] = {}
        try:
            raw = await request.json()
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

        try:
            ttl_minutes = int(payload.get("ttl_minutes", 60))
        except Exception:
            ttl_minutes = 60
        ttl_minutes = max(1, min(24 * 60, ttl_minutes))

        reason = _normalize_token(str(payload.get("reason") or ""))

        store = SQLiteStore(source_db)
        try:
            suppression_rule = store.create_suppression_rule_from_alert(
                int(alert_id),
                actor=actor,
                actor_role=role,
                ttl_minutes=ttl_minutes,
                reason=reason,
                metadata={"source": "dashboard_api"},
            )
            alert = store.fetch_alert(int(alert_id))
        finally:
            store.close()

        if suppression_rule is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

        return JSONResponse(
            {
                "status": "ok",
                "action": "suppress",
                "alert_id": int(alert_id),
                "actor": actor,
                "actor_role": role,
                "ttl_minutes": ttl_minutes,
                "suppression_rule": suppression_rule,
                "alert": alert,
            }
        )

    @app.post("/api/suppressions/{rule_id}/revoke")
    async def api_revoke_suppression(rule_id: int, request: Request) -> JSONResponse:
        _enforce_request_auth(request)
        actor, role = _get_actor_context(request, action="revoke")

        payload: dict[str, Any] = {}
        try:
            raw = await request.json()
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

        reason = _normalize_token(str(payload.get("reason") or ""))

        store = SQLiteStore(source_db)
        try:
            changed = store.revoke_suppression_rule(
                int(rule_id),
                actor=actor,
                actor_role=role,
                reason=reason,
                metadata={"source": "dashboard_api"},
            )
            rule = store.fetch_suppression_rule(int(rule_id))
        finally:
            store.close()

        if not changed:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression rule not found or already inactive")

        return JSONResponse(
            {
                "status": "ok",
                "action": "revoke_suppress",
                "rule_id": int(rule_id),
                "actor": actor,
                "actor_role": role,
                "suppression_rule": rule,
            }
        )

    @app.websocket("/ws/realtime")
    async def ws_realtime(websocket: WebSocket) -> None:
        if not _is_authorized_token(
            expected_token,
            query_token=websocket.query_params.get("token"),
            header_token=websocket.headers.get("x-nids-token"),
            authorization_header=websocket.headers.get("authorization"),
        ):
            await websocket.close(code=4401)
            return

        await websocket.accept()
        try:
            query = websocket.query_params
            lookback = _safe_lookback(int(str(query.get("lookback") or "5")), default=5)
            severity = query.get("severity")
            engine = query.get("engine")
            sensor_id = query.get("sensor_id")

            while True:
                payload = _build_realtime_payload(
                    source_db,
                    lookback_minutes=lookback,
                    max_alerts=10,
                    sensor_id=sensor_id,
                    severity=severity,
                    engine=engine,
                )
                await websocket.send_json(payload)
                await asyncio.sleep(5)
        except (WebSocketDisconnect, RuntimeError):
            return
        except Exception:
            await websocket.close()

    return app


def run_dashboard(
    db_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    api_token: str | None = None,
    action_token: str | None = None,
    notify_webhook: str | None = None,
    notify_timeout_sec: float | None = None,
    notify_max_retries: int | None = None,
    notify_backoff_sec: float | None = None,
    notify_max_backoff_sec: float | None = None,
    notify_min_interval_sec: float | None = None,
    notify_dead_letter: str | None = None,
    notify_dead_letter_max_bytes: int | None = None,
    notify_dead_letter_backup_count: int | None = None,
) -> None:
    import uvicorn

    app = create_dashboard_app(
        db_path,
        api_token=api_token,
        action_token=action_token,
        notify_webhook=notify_webhook,
        notify_timeout_sec=notify_timeout_sec,
        notify_max_retries=notify_max_retries,
        notify_backoff_sec=notify_backoff_sec,
        notify_max_backoff_sec=notify_max_backoff_sec,
        notify_min_interval_sec=notify_min_interval_sec,
        notify_dead_letter=notify_dead_letter,
        notify_dead_letter_max_bytes=notify_dead_letter_max_bytes,
        notify_dead_letter_backup_count=notify_dead_letter_backup_count,
    )
    uvicorn.run(app, host=host, port=port)

