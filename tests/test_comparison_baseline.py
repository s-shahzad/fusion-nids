from __future__ import annotations

import json
from pathlib import Path

from src.NIDS.adversary import comparison_baseline as baseline


class _FakeResult:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.alerts_jsonl_path = output_dir / "alerts.jsonl"
        self.flow_count = 10
        self.alert_count = 2
        self.metric_count = 3


def test_run_comparison_baseline_builds_four_modes(tmp_path: Path, monkeypatch) -> None:
    base_config = tmp_path / "base.yml"
    base_config.write_text(
        "ml:\n  unsupervised: true\nfusion:\n  enabled: true\n",
        encoding="utf-8",
    )
    rules = tmp_path / "rules.yml"
    rules.write_text("- name: t\n", encoding="utf-8")
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"pcap")
    model = tmp_path / "model.pkl"
    model.write_bytes(b"model")
    ground_truth = tmp_path / "gt.json"
    ground_truth.write_text('{"expected_detections":[]}', encoding="utf-8")

    def fake_run_local_pipeline(*, cfg, labels_path, sensor_id, report_out, visual_out, ground_truth_path):
        output_dir = cfg.output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "alerts.jsonl").write_text(
            json.dumps({"engine": "signature"}) + "\n" + json.dumps({"engine": "ml"}) + "\n",
            encoding="utf-8",
        )
        (output_dir / "metrics.json").write_text(
            json.dumps(
                {
                    "totals": {"tp": 1, "fp": 1, "fn": 0},
                    "metrics": {"precision": 0.5, "recall": 1.0, "f1": 0.6667},
                }
            ),
            encoding="utf-8",
        )
        return _FakeResult(output_dir)

    monkeypatch.setattr(baseline, "run_local_pipeline", fake_run_local_pipeline)

    payload = baseline.run_comparison_baseline(
        pcap_path=pcap,
        base_config_path=base_config,
        base_rules_path=rules,
        ground_truth_path=ground_truth,
        output_root=tmp_path / "runs",
        model_path=model,
    )

    assert [row["mode"] for row in payload["modes"]] == [
        "signature_only",
        "anomaly_only",
        "ml_only",
        "hybrid_tuned",
    ]
    assert all(row["tp"] == 1 for row in payload["modes"])
    assert (tmp_path / "runs" / "empty_rules.yml").exists()


def test_write_comparison_baseline_is_deterministic(tmp_path: Path) -> None:
    payload = {
        "pcap_path": "sample.pcap",
        "ground_truth_path": "gt.json",
        "assumptions": ["a", "b"],
        "modes": [
            {
                "mode": "signature_only",
                "notes": "note",
                "flows": 10,
                "alerts": 2,
                "tp": 1,
                "fp": 1,
                "fn": 0,
                "precision": 0.5,
                "recall": 1.0,
                "f1": 0.6667,
                "runtime_sec": 0.2,
                "flows_per_sec": 50.0,
            }
        ],
    }

    json_path, md_path = baseline.write_comparison_baseline(
        payload=payload,
        out_json=tmp_path / "comparison_baseline.json",
        out_md=tmp_path / "comparison_baseline.md",
    )

    assert json.loads(json_path.read_text(encoding="utf-8"))["pcap_path"] == "sample.pcap"
    markdown = md_path.read_text(encoding="utf-8")
    assert "| Mode | Flows | Alerts | TP | FP | FN | Precision | Recall | F1 | Runtime (s) | Flow/s |" in markdown
    assert "signature_only" in markdown


def test_run_comparison_baseline_resets_mode_run_dirs(tmp_path: Path, monkeypatch) -> None:
    base_config = tmp_path / "base.yml"
    base_config.write_text("ml:\n  unsupervised: true\n", encoding="utf-8")
    rules = tmp_path / "rules.yml"
    rules.write_text("- name: t\n", encoding="utf-8")
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"pcap")

    stale_dir = tmp_path / "runs" / "hybrid_tuned" / "run"
    stale_dir.mkdir(parents=True, exist_ok=True)
    (stale_dir / "stale.txt").write_text("old", encoding="utf-8")

    def fake_run_local_pipeline(*, cfg, labels_path, sensor_id, report_out, visual_out, ground_truth_path):
        output_dir = cfg.output_dir.resolve()
        assert not (output_dir / "stale.txt").exists()
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "alerts.jsonl").write_text("", encoding="utf-8")
        (output_dir / "metrics.json").write_text(
            json.dumps({"totals": {"tp": 0, "fp": 0, "fn": 0}, "metrics": {"precision": 0.0, "recall": 0.0, "f1": 0.0}}),
            encoding="utf-8",
        )
        return _FakeResult(output_dir)

    monkeypatch.setattr(baseline, "run_local_pipeline", fake_run_local_pipeline)

    baseline.run_comparison_baseline(
        pcap_path=pcap,
        base_config_path=base_config,
        base_rules_path=rules,
        ground_truth_path=None,
        output_root=tmp_path / "runs",
        model_path=None,
    )
