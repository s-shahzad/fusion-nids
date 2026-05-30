from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pandas as pd


@dataclass
class AnalyticsData:
    alerts: pd.DataFrame
    flows: pd.DataFrame
    alerts_per_minute: pd.DataFrame
    packets_per_second: pd.DataFrame
    top_sources: pd.DataFrame
    top_ports: pd.DataFrame
    severity_over_time: pd.DataFrame
    engine_share: pd.DataFrame
    heatmap: pd.DataFrame
    packet_lengths: pd.DataFrame
    burst_sizes: pd.DataFrame
    scatter_activity: pd.DataFrame
    sankey_links: pd.DataFrame
    network_edges: pd.DataFrame


def _empty_df(columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame(columns=columns)


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def _resolve_expr(columns: set[str], aliases: list[str], fallback: str = "NULL") -> str:
    for candidate in aliases:
        if candidate in columns:
            return candidate
    return fallback


def _normalize_filter(value: str | None) -> str | None:
    if value is None:
        return None
    token = str(value).strip()
    if token == "" or token.lower() in {"all", "any", "*"}:
        return None
    return token


def _load_alerts(conn: sqlite3.Connection) -> pd.DataFrame:
    if not _table_exists(conn, "alerts"):
        return _empty_df(
            [
                "timestamp",
                "sensor_id",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                "severity",
                "engine",
                "rule_name",
            ]
        )

    columns = _table_columns(conn, "alerts")
    query = f"""
        SELECT
          {_resolve_expr(columns, ['timestamp', 'ts', 'created_at'])} AS timestamp,
          {_resolve_expr(columns, ['sensor_id', 'sensor', 'source'])} AS sensor_id,
          {_resolve_expr(columns, ['src_ip', 'source_ip'])} AS src_ip,
          {_resolve_expr(columns, ['dst_ip', 'dest_ip', 'destination_ip'])} AS dst_ip,
          {_resolve_expr(columns, ['src_port', 'sport'])} AS src_port,
          {_resolve_expr(columns, ['dst_port', 'dport'])} AS dst_port,
          {_resolve_expr(columns, ['proto', 'protocol'])} AS proto,
          {_resolve_expr(columns, ['severity'])} AS severity,
          {_resolve_expr(columns, ['engine', 'category'])} AS engine,
          {_resolve_expr(columns, ['rule_name', 'rule'])} AS rule_name
        FROM alerts
    """

    df = pd.read_sql_query(query, conn)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"])

    for col in ["sensor_id", "src_ip", "dst_ip", "proto", "severity", "engine", "rule_name"]:
        if col in df.columns:
            df[col] = df[col].fillna("unknown").astype(str)

    for col in ["src_port", "dst_port"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def _load_flows_or_packets(conn: sqlite3.Connection) -> pd.DataFrame:
    source_table = None
    for candidate in ("flows", "packets"):
        if _table_exists(conn, candidate):
            source_table = candidate
            break

    if source_table is None:
        return _empty_df(
            [
                "timestamp",
                "sensor_id",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                "packet_len",
                "flow_packets",
            ]
        )

    columns = _table_columns(conn, source_table)
    query = f"""
        SELECT
          {_resolve_expr(columns, ['timestamp', 'ts', 'created_at'])} AS timestamp,
          {_resolve_expr(columns, ['sensor_id', 'sensor', 'source'])} AS sensor_id,
          {_resolve_expr(columns, ['src_ip', 'source_ip'])} AS src_ip,
          {_resolve_expr(columns, ['dst_ip', 'dest_ip', 'destination_ip'])} AS dst_ip,
          {_resolve_expr(columns, ['src_port', 'sport'])} AS src_port,
          {_resolve_expr(columns, ['dst_port', 'dport'])} AS dst_port,
          {_resolve_expr(columns, ['proto', 'protocol'])} AS proto,
          {_resolve_expr(columns, ['packet_len', 'pkt_len', 'length', 'bytes'])} AS packet_len,
          {_resolve_expr(columns, ['flow_packets', 'packet_count'])} AS flow_packets
        FROM {source_table}
    """

    df = pd.read_sql_query(query, conn)
    if df.empty:
        return df

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp"])

    for col in ["sensor_id", "src_ip", "dst_ip", "proto"]:
        if col in df.columns:
            df[col] = df[col].fillna("unknown").astype(str)

    for col in ["src_port", "dst_port", "packet_len", "flow_packets"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def _apply_filters(
    alerts: pd.DataFrame,
    flows: pd.DataFrame,
    lookback_minutes: int | None,
    sensor_id: str | None,
    severity: str | None,
    engine: str | None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    filtered_alerts = alerts.copy()
    filtered_flows = flows.copy()

    lookback = int(lookback_minutes or 0)
    if lookback > 0:
        cutoff = pd.Timestamp.now(tz="UTC") - pd.Timedelta(minutes=lookback)
        if not filtered_alerts.empty and "timestamp" in filtered_alerts.columns:
            filtered_alerts = filtered_alerts[filtered_alerts["timestamp"] >= cutoff]
        if not filtered_flows.empty and "timestamp" in filtered_flows.columns:
            filtered_flows = filtered_flows[filtered_flows["timestamp"] >= cutoff]

    sensor_filter = _normalize_filter(sensor_id)
    if sensor_filter:
        token = sensor_filter.lower()
        if not filtered_alerts.empty and "sensor_id" in filtered_alerts.columns:
            filtered_alerts = filtered_alerts[filtered_alerts["sensor_id"].str.lower() == token]
        if not filtered_flows.empty and "sensor_id" in filtered_flows.columns:
            filtered_flows = filtered_flows[filtered_flows["sensor_id"].str.lower() == token]

    severity_filter = _normalize_filter(severity)
    if severity_filter and not filtered_alerts.empty and "severity" in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[filtered_alerts["severity"].str.lower() == severity_filter.lower()]

    engine_filter = _normalize_filter(engine)
    if engine_filter and not filtered_alerts.empty and "engine" in filtered_alerts.columns:
        filtered_alerts = filtered_alerts[filtered_alerts["engine"].str.lower() == engine_filter.lower()]

    return filtered_alerts, filtered_flows


def _alerts_per_minute(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return _empty_df(["bucket", "alerts"])

    grouped = (
        alerts.set_index("timestamp")
        .resample("1min")
        .size()
        .rename("alerts")
        .reset_index()
        .rename(columns={"timestamp": "bucket"})
    )
    return grouped


def _packets_per_second(flows: pd.DataFrame) -> pd.DataFrame:
    if flows.empty:
        return _empty_df(["bucket", "packets"])

    grouped = (
        flows.set_index("timestamp")
        .resample("1s")
        .size()
        .rename("packets")
        .reset_index()
        .rename(columns={"timestamp": "bucket"})
    )
    return grouped


def _top_sources(alerts: pd.DataFrame, top_n: int) -> pd.DataFrame:
    if alerts.empty or "src_ip" not in alerts.columns:
        return _empty_df(["src_ip", "alert_count"])

    return (
        alerts.groupby("src_ip", dropna=False)
        .size()
        .rename("alert_count")
        .reset_index()
        .sort_values("alert_count", ascending=False)
        .head(top_n)
    )


def _top_ports(alerts: pd.DataFrame, top_n: int) -> pd.DataFrame:
    if alerts.empty or "dst_port" not in alerts.columns:
        return _empty_df(["dst_port", "alert_count"])

    valid = alerts.dropna(subset=["dst_port"]).copy()
    if valid.empty:
        return _empty_df(["dst_port", "alert_count"])

    valid["dst_port"] = valid["dst_port"].astype(int).astype(str)
    return (
        valid.groupby("dst_port")
        .size()
        .rename("alert_count")
        .reset_index()
        .sort_values("alert_count", ascending=False)
        .head(top_n)
    )


def _severity_over_time(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return _empty_df(["bucket", "severity", "alert_count"])

    frame = alerts.copy()
    frame["bucket"] = frame["timestamp"].dt.floor("1min")

    grouped = (
        frame.groupby(["bucket", "severity"], dropna=False)
        .size()
        .rename("alert_count")
        .reset_index()
        .sort_values("bucket")
    )
    return grouped


def _engine_share(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return _empty_df(["engine", "alert_count"])

    return (
        alerts.groupby("engine", dropna=False)
        .size()
        .rename("alert_count")
        .reset_index()
        .sort_values("alert_count", ascending=False)
    )


def _heatmap(alerts: pd.DataFrame, top_n: int) -> pd.DataFrame:
    if alerts.empty:
        return _empty_df(["src_ip", "dst_port", "count"])

    frame = alerts.dropna(subset=["src_ip", "dst_port"]).copy()
    if frame.empty:
        return _empty_df(["src_ip", "dst_port", "count"])

    frame["dst_port"] = frame["dst_port"].astype(int).astype(str)

    top_sources = frame.groupby("src_ip").size().nlargest(top_n).index
    top_ports = frame.groupby("dst_port").size().nlargest(top_n).index

    filtered = frame[frame["src_ip"].isin(top_sources) & frame["dst_port"].isin(top_ports)]

    return (
        filtered.groupby(["src_ip", "dst_port"])
        .size()
        .rename("count")
        .reset_index()
    )


def _packet_lengths(flows: pd.DataFrame) -> pd.DataFrame:
    if flows.empty or "packet_len" not in flows.columns:
        return _empty_df(["packet_len"])

    frame = flows.dropna(subset=["packet_len"]).copy()
    if frame.empty:
        return _empty_df(["packet_len"])

    frame = frame[(frame["packet_len"] > 0) & (frame["packet_len"] < 10000)]
    return frame[["packet_len"]]


def _burst_sizes(alerts_per_minute: pd.DataFrame) -> pd.DataFrame:
    if alerts_per_minute.empty:
        return _empty_df(["burst_size"])

    frame = alerts_per_minute.copy()
    frame = frame[frame["alerts"] > 0]
    if frame.empty:
        return _empty_df(["burst_size"])

    return frame.rename(columns={"alerts": "burst_size"})[["burst_size"]]


def _scatter_activity(alerts: pd.DataFrame, flows: pd.DataFrame, top_n: int) -> pd.DataFrame:
    packets_by_host = _empty_df(["src_ip", "packets", "unique_ports"])
    if not flows.empty and "src_ip" in flows.columns:
        frame = flows.copy()
        frame["dst_port"] = pd.to_numeric(frame.get("dst_port"), errors="coerce")
        packets_by_host = (
            frame.groupby("src_ip", dropna=False)
            .agg(
                packets=("src_ip", "size"),
                unique_ports=("dst_port", lambda series: int(series.dropna().nunique())),
            )
            .reset_index()
        )

    alerts_by_host = _empty_df(["src_ip", "alerts"])
    if not alerts.empty and "src_ip" in alerts.columns:
        alerts_by_host = (
            alerts.groupby("src_ip", dropna=False)
            .size()
            .rename("alerts")
            .reset_index()
        )

    merged = pd.merge(packets_by_host, alerts_by_host, on="src_ip", how="outer").fillna(0)
    if merged.empty:
        return _empty_df(["src_ip", "packets", "alerts", "unique_ports"])

    merged["packets"] = pd.to_numeric(merged["packets"], errors="coerce").fillna(0)
    merged["alerts"] = pd.to_numeric(merged["alerts"], errors="coerce").fillna(0)
    merged["unique_ports"] = pd.to_numeric(merged["unique_ports"], errors="coerce").fillna(0)

    merged = merged.sort_values(["alerts", "packets"], ascending=False).head(top_n)
    return merged[["src_ip", "packets", "alerts", "unique_ports"]]


def _sankey_links(alerts: pd.DataFrame, top_n: int = 30) -> pd.DataFrame:
    if alerts.empty:
        return _empty_df(["src_ip", "dst_ip", "dst_port", "count"])

    frame = alerts.dropna(subset=["src_ip", "dst_ip", "dst_port"]).copy()
    if frame.empty:
        return _empty_df(["src_ip", "dst_ip", "dst_port", "count"])

    frame["dst_port"] = frame["dst_port"].astype(int).astype(str)
    grouped = (
        frame.groupby(["src_ip", "dst_ip", "dst_port"])
        .size()
        .rename("count")
        .reset_index()
        .sort_values("count", ascending=False)
        .head(top_n)
    )
    return grouped


def _network_edges(alerts: pd.DataFrame, flows: pd.DataFrame, top_n: int = 50) -> pd.DataFrame:
    source = alerts if not alerts.empty else flows
    if source.empty:
        return _empty_df(["src_ip", "dst_ip", "count"])

    frame = source.dropna(subset=["src_ip", "dst_ip"]).copy()
    if frame.empty:
        return _empty_df(["src_ip", "dst_ip", "count"])

    grouped = (
        frame.groupby(["src_ip", "dst_ip"])
        .size()
        .rename("count")
        .reset_index()
        .sort_values("count", ascending=False)
        .head(top_n)
    )
    return grouped


def build_analytics(
    db_path: str | Path,
    top_n: int = 10,
    lookback_minutes: int | None = None,
    sensor_id: str | None = None,
    severity: str | None = None,
    engine: str | None = None,
) -> AnalyticsData:
    db_file = Path(db_path)
    if not db_file.exists():
        return AnalyticsData(
            alerts=_empty_df([]),
            flows=_empty_df([]),
            alerts_per_minute=_empty_df(["bucket", "alerts"]),
            packets_per_second=_empty_df(["bucket", "packets"]),
            top_sources=_empty_df(["src_ip", "alert_count"]),
            top_ports=_empty_df(["dst_port", "alert_count"]),
            severity_over_time=_empty_df(["bucket", "severity", "alert_count"]),
            engine_share=_empty_df(["engine", "alert_count"]),
            heatmap=_empty_df(["src_ip", "dst_port", "count"]),
            packet_lengths=_empty_df(["packet_len"]),
            burst_sizes=_empty_df(["burst_size"]),
            scatter_activity=_empty_df(["src_ip", "packets", "alerts", "unique_ports"]),
            sankey_links=_empty_df(["src_ip", "dst_ip", "dst_port", "count"]),
            network_edges=_empty_df(["src_ip", "dst_ip", "count"]),
        )

    with sqlite3.connect(str(db_file)) as conn:
        alerts = _load_alerts(conn)
        flows = _load_flows_or_packets(conn)

    alerts, flows = _apply_filters(
        alerts=alerts,
        flows=flows,
        lookback_minutes=lookback_minutes,
        sensor_id=sensor_id,
        severity=severity,
        engine=engine,
    )

    alerts_per_minute = _alerts_per_minute(alerts)
    packets_per_second = _packets_per_second(flows)

    return AnalyticsData(
        alerts=alerts,
        flows=flows,
        alerts_per_minute=alerts_per_minute,
        packets_per_second=packets_per_second,
        top_sources=_top_sources(alerts, top_n=top_n),
        top_ports=_top_ports(alerts, top_n=top_n),
        severity_over_time=_severity_over_time(alerts),
        engine_share=_engine_share(alerts),
        heatmap=_heatmap(alerts, top_n=top_n),
        packet_lengths=_packet_lengths(flows),
        burst_sizes=_burst_sizes(alerts_per_minute),
        scatter_activity=_scatter_activity(alerts, flows, top_n=max(15, top_n)),
        sankey_links=_sankey_links(alerts),
        network_edges=_network_edges(alerts, flows),
    )
