from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from src.NIDS.config import RuntimeConfig
from src.NIDS.pipeline.runtime import run_local_pipeline


def _rules_file(tmp_path: Path) -> Path:
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
- name: Local Pipeline Signature
  match:
    proto: TCP
    dst_ports: [80]
    payload_contains: ["evil"]
  action: alert
  severity: high
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return rules_path


def _runtime_config(
    tmp_path: Path,
    *,
    pcap_dir: Path,
    interface: str | None = None,
    adapters: dict[str, object] | None = None,
) -> RuntimeConfig:
    return RuntimeConfig(
        interface=interface,
        pcap_dir=pcap_dir,
        rules_path=_rules_file(tmp_path),
        output_dir=tmp_path / "output",
        pipeline={"queue_max_size": 64, "metrics_interval_sec": 1, "replay_delay_ms": 0},
        detection={
            "dos_packets_per_sec_threshold": 10,
            "scan_ports_threshold": 2,
            "scan_window_sec": 12,
            "zscore_enabled": False,
            "anomaly_cooldown_sec": 0,
            "suppress_window_sec": 0,
        },
        ml={"unsupervised": False, "model_path": str(tmp_path / "missing-model.pkl")},
        adapters=adapters or {},
        fusion={"enabled": True},
        maintenance={"enabled": False},
        notifications={"enabled": False},
    )


@pytest.mark.integration
def test_run_local_pipeline_replays_pcap_and_generates_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pcap_path = tmp_path / "fixture.pcap"
    packet = (
        IP(src="10.0.0.5", dst="192.0.2.25")
        / TCP(sport=51515, dport=80, flags="PA")
        / Raw(load=b"evil local flow")
    )
    wrpcap(str(pcap_path), [packet])

    result = run_local_pipeline(
        cfg=_runtime_config(tmp_path, pcap_dir=pcap_path),
        sensor_id="local-sensor",
    )

    assert result.db_path.exists()
    assert result.report_path.exists()
    assert result.visual_index_path.exists()
    assert result.flow_count == 1
    assert result.alert_count >= 1
    assert result.chart_count >= 1

    with sqlite3.connect(str(result.db_path)) as conn:
        flow_count = int(conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0])
        alert_count = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        assert flow_count == 1
        assert alert_count >= 1

    output = capsys.readouterr().out
    assert "local-pipeline[ingest]" in output
    assert "local-pipeline[preprocess]" in output
    assert "local-pipeline[detect]" in output
    assert "local-pipeline[store]" in output
    assert "local-pipeline[report]" in output
    assert "local-pipeline[visualize]" in output
    assert "local-pipeline[done]" in output


def test_run_local_pipeline_rejects_non_local_sources(tmp_path: Path) -> None:
    pcap_path = tmp_path / "fixture.pcap"
    pcap_path.write_bytes(b"pcap-placeholder")

    with pytest.raises(ValueError, match="live capture"):
        run_local_pipeline(
            cfg=_runtime_config(tmp_path, pcap_dir=pcap_path, interface="Ethernet"),
            sensor_id="local-sensor",
        )

    with pytest.raises(ValueError, match="adapter ingest"):
        run_local_pipeline(
            cfg=_runtime_config(
                tmp_path,
                pcap_dir=pcap_path,
                adapters={"suricata": {"enabled": True, "path": str(tmp_path / "eve.json")}},
            ),
            sensor_id="local-sensor",
        )
