from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.NIDS.reporting import generate_threshold_tuning_report
from src.NIDS.storage.sqlite_store import SQLiteStore


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _seed_threshold_db(db_path: Path) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    store = SQLiteStore(db_path)
    try:
        benign_rows = [
            (0.12, 0.18, 0.16, 0.2, 0.15),
            (0.18, 0.22, 0.2, 0.24, 0.2),
            (0.28, 0.35, 0.3, 0.38, 0.32),
        ]
        attack_rows = [
            (0.84, 0.72, 0.69, 0.76, 0.8),
            (0.9, 0.82, 0.79, 0.86, 0.91),
            (0.96, 0.94, 0.91, 0.96, 0.97),
        ]

        all_rows = [(False, row) for row in benign_rows] + [(True, row) for row in attack_rows]
        for offset, (is_attack, scores) in enumerate(all_rows):
            supervised, unsupervised, isolation, autoencoder, fusion = scores
            store.insert_flow(
                {
                    "timestamp": _iso(now - timedelta(hours=6 - offset)),
                    "sensor_id": "sensor-threshold",
                    "dataset_source": "pcap:threshold-test",
                    "src_ip": f"10.0.0.{offset + 1}",
                    "dst_ip": "8.8.8.8",
                    "src_port": 40000 + offset,
                    "dst_port": 443,
                    "proto": "TCP",
                    "packet_len": 100 + offset,
                    "packet_count": 1,
                    "label": "attack" if is_attack else "normal",
                    "attack_type": "dos" if is_attack else None,
                    "is_labeled": 1,
                    "supervised_score": supervised,
                    "unsupervised_score": unsupervised,
                    "unsupervised_isolation_score": isolation,
                    "unsupervised_autoencoder_score": autoencoder,
                    "fusion_score": fusion,
                }
            )

        for index in range(3):
            store.insert_alert(
                {
                    "timestamp": _iso(now - timedelta(hours=index)),
                    "sensor_id": "sensor-threshold",
                    "dataset_source": "pcap:threshold-test",
                    "src_ip": f"10.0.0.{index + 1}",
                    "dst_ip": "8.8.8.8",
                    "src_port": 50000 + index,
                    "dst_port": 443,
                    "proto": "TCP",
                    "severity": "medium",
                    "engine": "fusion",
                    "rule_name": "Threshold Test",
                    "summary": "threshold alert",
                    "is_labeled": 0,
                }
            )
    finally:
        store.close()


def test_generate_threshold_tuning_report_handles_missing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.db"
    json_path = tmp_path / "reports" / "thresholds.json"
    md_path = tmp_path / "reports" / "thresholds.md"

    out_json, out_md = generate_threshold_tuning_report(
        from_db=db_path,
        out_json=json_path,
        out_md=md_path,
        lookback_days=7,
    )

    assert out_json == json_path
    assert out_md == md_path

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert "database_not_found" in str(payload.get("error") or "")

    markdown = md_path.read_text(encoding="utf-8")
    assert "NIDS Threshold Tuning Report" in markdown
    assert "Database not found" in markdown


def test_generate_threshold_tuning_report_recommends_thresholds(tmp_path: Path) -> None:
    db_path = tmp_path / "nids.db"
    _seed_threshold_db(db_path)

    json_path = tmp_path / "reports" / "threshold_tuning.json"
    md_path = tmp_path / "reports" / "threshold_tuning.md"

    generate_threshold_tuning_report(
        from_db=db_path,
        out_json=json_path,
        out_md=md_path,
        lookback_days=7,
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))

    totals = payload.get("totals", {})
    assert int(totals.get("flows") or 0) == 6
    assert int(totals.get("alerts") or 0) == 3
    assert int(totals.get("labeled_flows") or 0) == 6
    assert int(totals.get("labeled_attack_flows") or 0) == 3
    assert int(totals.get("labeled_benign_flows") or 0) == 3

    stats = payload.get("score_stats", {})
    assert int(stats["supervised_score"]["count"]) == 6
    assert float(stats["fusion_score"]["p95"]) >= 0.9

    recommendations = payload.get("threshold_recommendations", {})
    assert recommendations["supervised_score"]["method"] == "labeled_optimization"
    assert float(recommendations["supervised_score"]["balanced_threshold"]["threshold"]) >= 0.3
    assert float(recommendations["fusion_score"]["balanced_threshold"]["threshold"]) >= 0.3

    config = payload.get("recommended_config", {})
    assert float(config["ml.score_threshold"]) >= 0.3
    assert float(config["ml.unsupervised_alert_threshold"]) >= 0.3
    assert float(config["fusion.alert_threshold"]) >= 0.3
    assert float(config["fusion.high_threshold"]) >= float(config["fusion.alert_threshold"])
    assert float(config["fusion.critical_threshold"]) >= float(config["fusion.high_threshold"])

    scenario_grid = payload.get("scenario_grid", {})
    assert len(scenario_grid["supervised_score"]) == 5

    markdown = md_path.read_text(encoding="utf-8")
    assert "NIDS Threshold Tuning Report" in markdown
    assert "Recommended Config" in markdown
    assert "ml.score_threshold" in markdown
