from __future__ import annotations

import sqlite3
from pathlib import Path

import plotly.graph_objects as go

import src.NIDS.visuals.export as export_module
from src.NIDS.storage.sqlite_store import SQLiteStore
from src.NIDS.visuals.charts import build_all_figures
from src.NIDS.visuals.export import ExportedChart, export_fig, generate_index_page, run_visual_export
from src.NIDS.visuals.queries import build_analytics


def _seed_analytics_db(db_path: Path) -> None:
    store = SQLiteStore(db_path)
    try:
        for alert in (
            {
                "timestamp": "2026-03-08T13:00:00+00:00",
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:test-a.pcap",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.10",
                "src_port": 51001,
                "dst_port": 443,
                "proto": "TCP",
                "severity": "high",
                "engine": "signature",
                "rule_name": "TLS Alert",
                "summary": "alert a",
                "is_labeled": 0,
            },
            {
                "timestamp": "2026-03-08T13:00:30+00:00",
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:test-a.pcap",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.20",
                "src_port": 51002,
                "dst_port": 80,
                "proto": "TCP",
                "severity": "medium",
                "engine": "anomaly",
                "rule_name": "HTTP Burst",
                "summary": "alert b",
                "is_labeled": 0,
            },
            {
                "timestamp": "2026-03-08T13:01:00+00:00",
                "sensor_id": "sensor-b",
                "dataset_source": "pcap:test-b.pcap",
                "src_ip": "10.0.0.2",
                "dst_ip": "192.0.2.20",
                "src_port": 51003,
                "dst_port": 80,
                "proto": "TCP",
                "severity": "low",
                "engine": "signature",
                "rule_name": "HTTP Alert",
                "summary": "alert c",
                "is_labeled": 0,
            },
        ):
            store.insert_alert(alert)

        for flow in (
            {
                "timestamp": "2026-03-08T13:00:00+00:00",
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:test-a.pcap",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.10",
                "src_port": 51001,
                "dst_port": 443,
                "proto": "TCP",
                "packet_len": 128,
                "packet_count": 3,
            },
            {
                "timestamp": "2026-03-08T13:00:01+00:00",
                "sensor_id": "sensor-a",
                "dataset_source": "pcap:test-a.pcap",
                "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.20",
                "src_port": 51002,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 256,
                "packet_count": 2,
            },
            {
                "timestamp": "2026-03-08T13:01:00+00:00",
                "sensor_id": "sensor-b",
                "dataset_source": "pcap:test-b.pcap",
                "src_ip": "10.0.0.2",
                "dst_ip": "192.0.2.20",
                "src_port": 51003,
                "dst_port": 80,
                "proto": "TCP",
                "packet_len": 512,
                "packet_count": 4,
            },
        ):
            store.insert_flow(flow)
    finally:
        store.close()


def test_build_analytics_aggregates_alerts_and_flows(tmp_path: Path) -> None:
    db_path = tmp_path / "analytics.db"
    _seed_analytics_db(db_path)

    analytics = build_analytics(db_path, top_n=5)

    assert len(analytics.alerts) == 3
    assert len(analytics.flows) == 3
    assert int(analytics.alerts_per_minute["alerts"].sum()) == 3
    assert int(analytics.packets_per_second["packets"].sum()) == 3
    assert analytics.top_sources.iloc[0]["src_ip"] == "10.0.0.1"
    assert int(analytics.top_sources.iloc[0]["alert_count"]) == 2
    assert set(analytics.top_ports["dst_port"].tolist()) == {"443", "80"}
    assert not analytics.heatmap.empty
    assert not analytics.sankey_links.empty
    assert not analytics.network_edges.empty


def test_build_analytics_normalizes_alias_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "alias.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE alerts(
                ts TEXT,
                sensor TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                sport INTEGER,
                dport INTEGER,
                protocol TEXT,
                severity TEXT,
                category TEXT,
                rule TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE packets(
                created_at TEXT,
                source TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                sport INTEGER,
                dport INTEGER,
                protocol TEXT,
                bytes INTEGER,
                flow_packets INTEGER
            )
            """
        )
        conn.execute(
            """
            INSERT INTO alerts(ts, sensor, source_ip, dest_ip, sport, dport, protocol, severity, category, rule)
            VALUES ('2026-03-08T13:10:00+00:00', 'sensor-c', '10.0.0.9', '192.0.2.99', 40404, 8443, 'tcp', 'high', 'signature', 'Legacy Rule')
            """
        )
        conn.execute(
            """
            INSERT INTO packets(created_at, source, source_ip, destination_ip, sport, dport, protocol, bytes, flow_packets)
            VALUES ('2026-03-08T13:10:00+00:00', 'sensor-c', '10.0.0.9', '192.0.2.99', 40404, 8443, 'tcp', 300, 7)
            """
        )
        conn.commit()

    analytics = build_analytics(db_path)

    assert analytics.alerts.iloc[0]["sensor_id"] == "sensor-c"
    assert analytics.alerts.iloc[0]["engine"] == "signature"
    assert analytics.flows.iloc[0]["packet_len"] == 300
    assert analytics.flows.iloc[0]["flow_packets"] == 7


def test_build_all_figures_handles_populated_and_empty_datasets(tmp_path: Path) -> None:
    db_path = tmp_path / "analytics.db"
    _seed_analytics_db(db_path)

    populated = build_all_figures(build_analytics(db_path))
    empty = build_all_figures(build_analytics(tmp_path / "missing.db"))

    assert len(populated) == 10
    assert all(spec.figure.data or spec.figure.layout.annotations for spec in populated)
    assert len(empty) == 10
    assert all(spec.figure.layout.annotations for spec in empty)


def test_export_fig_writes_html_and_tolerates_png_failure(tmp_path: Path) -> None:
    class FakeFigure:
        def write_html(self, output_path: str, **_kwargs: object) -> None:
            Path(output_path).write_text("<html>fixture</html>", encoding="utf-8")

        def write_image(self, _output_path: str) -> None:
            raise RuntimeError("kaleido unavailable")

    html_path = tmp_path / "chart.html"
    png_path = tmp_path / "chart.png"

    html_written, png_written = export_fig(FakeFigure(), html_path, png_path)
    assert html_written == html_path
    assert png_written is None
    assert html_path.exists()


def test_run_visual_export_generates_index_and_chart_manifest(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "analytics.db"
    output_dir = tmp_path / "visuals"
    _seed_analytics_db(db_path)

    def fake_export(fig: go.Figure, html_path: Path, png_path: Path) -> tuple[Path, Path]:
        del fig
        html_path.write_text("<html>chart</html>", encoding="utf-8")
        png_path.write_bytes(b"png")
        return html_path, png_path

    monkeypatch.setattr(export_module, "export_fig", fake_export)

    index_path, exports = run_visual_export(db_path, output_dir)
    index_text = index_path.read_text(encoding="utf-8")

    assert index_path.exists()
    assert len(exports) == 10
    assert all((output_dir / item.html_file).exists() for item in exports)
    assert all((output_dir / item.png_file).exists() for item in exports)
    assert "Universal NIDS Graphical Analytics" in index_text
    assert "time_series_alerts_traffic.html" in index_text


def test_generate_index_page_links_chart_assets(tmp_path: Path) -> None:
    index_path = generate_index_page(
        tmp_path,
        [
            ExportedChart(
                slug="chart-a",
                title="Chart A",
                html_file="chart-a.html",
                png_file="chart-a.png",
            )
        ],
    )
    html = index_path.read_text(encoding="utf-8")
    assert index_path.exists()
    assert 'href="chart-a.html"' in html
    assert 'href="chart-a.png"' in html
