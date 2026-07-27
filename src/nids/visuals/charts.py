from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from .queries import AnalyticsData


@dataclass
class ChartSpec:
    slug: str
    title: str
    figure: go.Figure


def _empty_figure(title: str, message: str = "No data yet") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(
        text=message,
        showarrow=False,
        x=0.5,
        y=0.5,
        xref="paper",
        yref="paper",
        font={"size": 16},
    )
    fig.update_layout(title=title, template="plotly_white", height=420)
    return fig


def _finalize(fig: go.Figure, title: str, height: int = 460) -> go.Figure:
    fig.update_layout(
        template="plotly_white",
        title=title,
        margin={"l": 40, "r": 30, "t": 70, "b": 40},
        height=height,
    )
    return fig


def chart_time_series(data: AnalyticsData) -> go.Figure:
    if data.alerts_per_minute.empty and data.packets_per_second.empty:
        return _empty_figure("Alerts and Traffic Over Time")

    fig = make_subplots(specs=[[{"secondary_y": True}]])

    if not data.alerts_per_minute.empty:
        fig.add_trace(
            go.Scatter(
                x=data.alerts_per_minute["bucket"],
                y=data.alerts_per_minute["alerts"],
                mode="lines+markers",
                name="Alerts / Minute",
                line={"width": 2},
            ),
            secondary_y=False,
        )

    if not data.packets_per_second.empty:
        fig.add_trace(
            go.Scatter(
                x=data.packets_per_second["bucket"],
                y=data.packets_per_second["packets"],
                mode="lines",
                name="Packets / Second",
                line={"width": 1.6},
            ),
            secondary_y=True,
        )

    fig.update_xaxes(title_text="Time")
    fig.update_yaxes(title_text="Alerts / Min", secondary_y=False)
    fig.update_yaxes(title_text="Packets / Sec", secondary_y=True)
    return _finalize(fig, "Alerts and Traffic Over Time")


def chart_top_sources(data: AnalyticsData) -> go.Figure:
    if data.top_sources.empty:
        return _empty_figure("Top Source IPs by Alert Count")

    fig = px.bar(
        data.top_sources,
        x="src_ip",
        y="alert_count",
        labels={"src_ip": "Source IP", "alert_count": "Alerts"},
    )
    fig.update_xaxes(tickangle=-30)
    return _finalize(fig, "Top 10 Source IPs by Alert Count")


def chart_top_ports(data: AnalyticsData) -> go.Figure:
    if data.top_ports.empty:
        return _empty_figure("Top Destination Ports by Alert Count")

    fig = px.bar(
        data.top_ports,
        x="dst_port",
        y="alert_count",
        labels={"dst_port": "Destination Port", "alert_count": "Alerts"},
    )
    return _finalize(fig, "Top 10 Destination Ports by Alert Count")


def chart_severity_stacked(data: AnalyticsData) -> go.Figure:
    if data.severity_over_time.empty:
        return _empty_figure("Alerts by Severity Over Time")

    ordered = data.severity_over_time.copy()
    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    ordered["severity"] = ordered["severity"].astype(str).str.lower()

    fig = px.bar(
        ordered,
        x="bucket",
        y="alert_count",
        color="severity",
        category_orders={"severity": severity_order},
        labels={"bucket": "Time", "alert_count": "Alerts", "severity": "Severity"},
    )
    fig.update_layout(barmode="stack")
    return _finalize(fig, "Alerts by Severity Over Time (Stacked)")


def chart_engine_share(data: AnalyticsData) -> go.Figure:
    if data.engine_share.empty:
        return _empty_figure("Alert Share by Category")

    frame = data.engine_share.copy()
    frame["engine"] = frame["engine"].replace({"": "unknown"})

    fig = px.pie(
        frame,
        names="engine",
        values="alert_count",
        hole=0.5,
    )
    return _finalize(fig, "Alert Share by Category (Engine)")


def chart_heatmap(data: AnalyticsData) -> go.Figure:
    if data.heatmap.empty:
        return _empty_figure("Source IP vs Destination Port Heatmap")

    pivot = data.heatmap.pivot_table(
        index="src_ip",
        columns="dst_port",
        values="count",
        fill_value=0,
    )

    fig = go.Figure(
        data=go.Heatmap(
            z=pivot.values,
            x=list(pivot.columns),
            y=list(pivot.index),
            colorscale="Blues",
            colorbar={"title": "Count"},
        )
    )
    fig.update_xaxes(title="Destination Port")
    fig.update_yaxes(title="Source IP")
    return _finalize(fig, "Source IP vs Destination Port Frequency Heatmap")


def chart_histogram(data: AnalyticsData) -> go.Figure:
    if not data.packet_lengths.empty:
        fig = px.histogram(
            data.packet_lengths,
            x="packet_len",
            nbins=40,
            labels={"packet_len": "Packet Length (bytes)"},
        )
        fig.update_yaxes(title="Frequency")
        return _finalize(fig, "Packet Length Distribution")

    if not data.burst_sizes.empty:
        fig = px.histogram(
            data.burst_sizes,
            x="burst_size",
            nbins=30,
            labels={"burst_size": "Alerts per Minute"},
        )
        fig.update_yaxes(title="Frequency")
        return _finalize(fig, "Alert Burst Size Distribution")

    return _empty_figure("Distribution View")


def chart_scatter_activity(data: AnalyticsData) -> go.Figure:
    if data.scatter_activity.empty:
        return _empty_figure("Host Activity Scatter")

    frame = data.scatter_activity.copy()
    frame["size"] = frame["unique_ports"].clip(lower=1)

    fig = px.scatter(
        frame,
        x="packets",
        y="alerts",
        size="size",
        hover_name="src_ip",
        labels={
            "packets": "Packets",
            "alerts": "Alerts",
            "size": "Unique Ports",
        },
    )
    return _finalize(fig, "Host Activity Scatter (Packets vs Alerts)")


def chart_sankey(data: AnalyticsData) -> go.Figure:
    if data.sankey_links.empty:
        return _empty_figure("Traffic Sankey (Top Talkers)")

    frame = data.sankey_links.copy()

    src_nodes = [f"SRC:{value}" for value in frame["src_ip"].astype(str).unique()]
    dst_nodes = [f"DST:{value}" for value in frame["dst_ip"].astype(str).unique()]
    port_nodes = [f"PORT:{value}" for value in frame["dst_port"].astype(str).unique()]

    labels = src_nodes + dst_nodes + port_nodes
    index = {label: idx for idx, label in enumerate(labels)}

    link_source: list[int] = []
    link_target: list[int] = []
    link_value: list[int] = []

    src_to_dst = (
        frame.groupby(["src_ip", "dst_ip"])  # type: ignore[arg-type]
        ["count"]
        .sum()
        .reset_index()
    )
    for _, row in src_to_dst.iterrows():
        link_source.append(index[f"SRC:{row['src_ip']}"])
        link_target.append(index[f"DST:{row['dst_ip']}"])
        link_value.append(int(row["count"]))

    dst_to_port = (
        frame.groupby(["dst_ip", "dst_port"])  # type: ignore[arg-type]
        ["count"]
        .sum()
        .reset_index()
    )
    for _, row in dst_to_port.iterrows():
        link_source.append(index[f"DST:{row['dst_ip']}"])
        link_target.append(index[f"PORT:{row['dst_port']}"])
        link_value.append(int(row["count"]))

    fig = go.Figure(
        data=[
            go.Sankey(
                node={"label": labels, "pad": 16, "thickness": 14},
                link={"source": link_source, "target": link_target, "value": link_value},
            )
        ]
    )
    return _finalize(fig, "Sankey: Source IP -> Destination IP -> Destination Port", height=560)


def chart_network_graph(data: AnalyticsData, max_nodes: int = 24) -> go.Figure:
    if data.network_edges.empty:
        return _empty_figure("Communication Network Graph")

    edges = data.network_edges.copy()
    degree = {}
    for _, row in edges.iterrows():
        src = str(row["src_ip"])
        dst = str(row["dst_ip"])
        weight = float(row["count"])
        degree[src] = degree.get(src, 0.0) + weight
        degree[dst] = degree.get(dst, 0.0) + weight

    top_nodes = [node for node, _ in sorted(degree.items(), key=lambda item: item[1], reverse=True)[:max_nodes]]
    filtered = edges[edges["src_ip"].isin(top_nodes) & edges["dst_ip"].isin(top_nodes)].copy()

    if filtered.empty:
        return _empty_figure("Communication Network Graph")

    node_count = len(top_nodes)
    angles = np.linspace(0, 2 * np.pi, node_count, endpoint=False)
    positions = {
        node: (float(np.cos(angle)), float(np.sin(angle)))
        for node, angle in zip(top_nodes, angles, strict=False)
    }

    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for _, row in filtered.iterrows():
        src = str(row["src_ip"])
        dst = str(row["dst_ip"])
        x0, y0 = positions[src]
        x1, y1 = positions[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    node_x = []
    node_y = []
    node_text = []
    node_size = []

    for node in top_nodes:
        x, y = positions[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"{node}<br>Activity: {int(degree[node])}")
        node_size.append(max(10, min(48, 8 + degree[node] ** 0.45)))

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=edge_x,
            y=edge_y,
            mode="lines",
            line={"width": 1, "color": "#9ab5d8"},
            hoverinfo="skip",
            showlegend=False,
        )
    )
    fig.add_trace(
        go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            text=top_nodes,
            textposition="top center",
            hovertext=node_text,
            hoverinfo="text",
            marker={"size": node_size, "color": "#1f4f86", "line": {"width": 1, "color": "#dbe9fb"}},
            showlegend=False,
        )
    )

    fig.update_xaxes(showgrid=False, zeroline=False, visible=False)
    fig.update_yaxes(showgrid=False, zeroline=False, visible=False)
    return _finalize(fig, "Network Graph: Communication Topology", height=560)


def build_all_figures(data: AnalyticsData) -> list[ChartSpec]:
    return [
        ChartSpec("time_series_alerts_traffic", "Time Series: Alerts + Traffic", chart_time_series(data)),
        ChartSpec("top_source_ips", "Top Source IPs", chart_top_sources(data)),
        ChartSpec("top_destination_ports", "Top Destination Ports", chart_top_ports(data)),
        ChartSpec("severity_stacked_over_time", "Severity Over Time", chart_severity_stacked(data)),
        ChartSpec("engine_share_donut", "Engine Share Donut", chart_engine_share(data)),
        ChartSpec("src_vs_dstport_heatmap", "Source vs Port Heatmap", chart_heatmap(data)),
        ChartSpec("distribution_histogram", "Distribution Histogram", chart_histogram(data)),
        ChartSpec("host_activity_scatter", "Host Activity Scatter", chart_scatter_activity(data)),
        ChartSpec("traffic_sankey", "Traffic Sankey", chart_sankey(data)),
        ChartSpec("network_graph", "Network Graph", chart_network_graph(data)),
    ]
