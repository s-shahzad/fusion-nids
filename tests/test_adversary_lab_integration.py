from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import yaml

from src.NIDS.adversary_lab import generate_bundle, offline_replay_profile
from src.NIDS.ingest.offline import run_suricata_eve


REPO_ROOT = Path(__file__).resolve().parents[1]


def _runtime_config(tmp_path: Path, *, enable_campaign: bool = False, enable_exfiltration: bool = False) -> Path:
    config_path = tmp_path / "runtime.yml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "pipeline": {
                    "metrics_interval_sec": 1,
                    "replay_delay_ms": 0,
                },
                "detection": {
                    "zscore_enabled": False,
                    "anomaly_cooldown_sec": 0,
                },
                "ml": {
                    "model_path": str(tmp_path / "missing_model.pkl"),
                    "unsupervised": False,
                },
                "fusion": {
                    "enabled": False,
                    "emit_alerts": False,
                },
                "detectors": {
                    "campaign_behavior": {
                        "enabled": enable_campaign,
                        "window_sec": 120,
                        "alert_cooldown_sec": 300,
                        "distributed_scan_min_sources": 3,
                        "distributed_scan_min_ports": 6,
                        "coordinated_probe_min_sources": 3,
                        "coordinated_probe_min_targets": 3,
                    },
                    "exfiltration_behavior": {
                        "enabled": enable_exfiltration,
                        "alert_cooldown_sec": 300,
                        "dns_entropy_threshold": 3.2,
                        "dns_min_label_length": 12,
                        "long_subdomain_threshold": 30,
                        "timing_window_sec": 120,
                        "timing_min_events": 5,
                        "timing_min_interval_sec": 1.0,
                        "timing_max_cv": 0.05,
                        "timing_small_payload_max_bytes": 220,
                        "outbound_window_sec": 120,
                        "outbound_min_events": 6,
                        "outbound_min_distinct_destinations": 2,
                        "outbound_dominant_ratio": 0.7,
                        "outbound_max_avg_payload": 220,
                    },
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return config_path


def test_adversary_lab_port_scan_bundle_integrates_with_offline_runtime(tmp_path: Path) -> None:
    manifest = generate_bundle(
        scenario_name="port_scan_pattern",
        output_root=tmp_path / "bundles",
        policy=offline_replay_profile(),
        run_stamp="pytest",
    )
    bundle_dir = Path(manifest["bundle_dir"])
    config_path = _runtime_config(tmp_path)
    output_dir = tmp_path / "runtime_output"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "nids",
            "run",
            "--pcap-dir",
            str(bundle_dir / "port-scan-pattern.pcap"),
            "--labels",
            str(bundle_dir / "labels.csv"),
            "--rules",
            str(REPO_ROOT / "rules" / "rules.yml"),
            "--output-dir",
            str(output_dir),
            "--config",
            str(config_path),
            "--sensor-id",
            "pytest-adversary-lab",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    with sqlite3.connect(str(output_dir / "nids.db")) as conn:
        flow_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        labels = conn.execute("SELECT DISTINCT label, attack_type FROM flows").fetchall()
        rule_names = {row[0] for row in conn.execute("SELECT rule_name FROM alerts").fetchall()}

    assert flow_count >= 28
    assert labels == [("lab_generated", "lab_generated:port_scan_pattern")]
    assert "Suspicious Port Scan" in rule_names
    assert "Port Scan Threshold" in rule_names


def test_adversary_lab_suricata_emulator_preserves_lab_labels(tmp_path: Path) -> None:
    manifest = generate_bundle(
        scenario_name="exfiltration_pattern",
        output_root=tmp_path / "bundles",
        policy=offline_replay_profile(),
        run_stamp="pytest",
    )
    suricata_path = Path(manifest["suricata_eve_path"])

    async def _collect() -> list[dict[str, object]]:
        queue: asyncio.Queue[dict[str, object] | None] = asyncio.Queue()
        stop_event = asyncio.Event()
        await run_suricata_eve(suricata_path, queue, stop_event, sensor_id="pytest-suricata")
        items: list[dict[str, object]] = []
        while not queue.empty():
            item = queue.get_nowait()
            if item is not None:
                items.append(item)
        return items

    events = asyncio.run(_collect())
    assert events
    assert events[0]["label"] == "lab_generated"
    assert str(events[0]["attack_type"]).startswith("lab_generated:")
    assert str(events[0]["dataset_source"]).startswith("suricata:")


def test_adversary_lab_campaign_bundle_supports_optional_behavioral_detectors(tmp_path: Path) -> None:
    manifest = generate_bundle(
        scenario_name="campaign_chain_pattern",
        output_root=tmp_path / "bundles",
        policy=offline_replay_profile(),
        run_stamp="pytest",
    )
    bundle_dir = Path(manifest["bundle_dir"])
    config_path = _runtime_config(tmp_path, enable_campaign=True, enable_exfiltration=True)
    output_dir = tmp_path / "campaign_output"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "nids",
            "run",
            "--pcap-dir",
            str(bundle_dir / "campaign-chain-pattern.pcap"),
            "--labels",
            str(bundle_dir / "labels.csv"),
            "--rules",
            str(REPO_ROOT / "rules" / "rules.yml"),
            "--output-dir",
            str(output_dir),
            "--config",
            str(config_path),
            "--sensor-id",
            "pytest-adversary-campaign",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    with sqlite3.connect(str(output_dir / "nids.db")) as conn:
        rule_names = {row[0] for row in conn.execute("SELECT rule_name FROM alerts").fetchall()}
        labels = conn.execute("SELECT DISTINCT label, attack_type FROM flows").fetchall()

    assert labels == [("lab_generated", "lab_generated:campaign_chain_pattern")]
    assert "Distributed Port Scan Campaign" in rule_names
    assert "HTTP Login Brute Force Threshold" in rule_names
    assert "Linux Archive Exfiltration" in rule_names
