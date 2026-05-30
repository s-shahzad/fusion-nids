from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.NIDS import cli as cli_module


@dataclass
class _ScanSummary:
    scanned: int = 0
    inserted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    processed: int = 0
    errors: int = 0


def test_main_run_dispatches_runtime(monkeypatch, tmp_path: Path) -> None:
    calls: dict[str, object] = {}

    def fake_build_runtime_config(args):
        calls["args"] = args
        return {"runtime": "cfg"}

    def fake_run_runtime(*, cfg, labels_path, sensor_id):
        calls["cfg"] = cfg
        calls["labels_path"] = labels_path
        calls["sensor_id"] = sensor_id

    monkeypatch.setattr(cli_module, "build_runtime_config", fake_build_runtime_config)
    monkeypatch.setattr(cli_module, "run_runtime", fake_run_runtime)

    labels_path = tmp_path / "labels.csv"
    labels_path.write_text("label\nattack\n", encoding="utf-8")

    result = cli_module.main(
        [
            "run",
            "--config",
            "config/nids.yml",
            "--rules",
            "rules/rules.yml",
            "--output-dir",
            str(tmp_path / "output"),
            "--labels",
            str(labels_path),
            "--sensor-id",
            "sensor-cli",
        ]
    )

    assert result == 0
    assert calls["cfg"] == {"runtime": "cfg"}
    assert calls["labels_path"] == labels_path.resolve()
    assert calls["sensor_id"] == "sensor-cli"


def test_main_train_dispatches_and_prints_summary(monkeypatch, capsys) -> None:
    calls: dict[str, object] = {}

    def fake_train_from_db(**kwargs):
        calls.update(kwargs)
        return {"samples_total": 12, "accuracy": 0.91, "f1_weighted": 0.9}

    monkeypatch.setattr(cli_module, "train_from_db", fake_train_from_db)

    result = cli_module.main(
        [
            "train",
            "--from-db",
            "output/nids.db",
            "--out",
            "models/model.pkl",
            "--metrics-json",
            "reports/ml_metrics.json",
            "--metrics-md",
            "reports/ml_metrics.md",
        ]
    )

    assert result == 0
    assert calls == {
        "db_path": "output/nids.db",
        "out_model": "models/model.pkl",
        "metrics_json": "reports/ml_metrics.json",
        "metrics_md": "reports/ml_metrics.md",
    }
    assert "train: samples=12 accuracy=0.9100 f1=0.9000" in capsys.readouterr().out


def test_main_evaluate_dispatches_and_prints_summary(monkeypatch, capsys) -> None:
    calls: dict[str, object] = {}

    def fake_evaluate_model(**kwargs):
        calls.update(kwargs)
        return {"samples": 8, "accuracy": 0.875, "f1_weighted": 0.82}

    monkeypatch.setattr(cli_module, "evaluate_model", fake_evaluate_model)

    result = cli_module.main(
        [
            "evaluate",
            "--from-db",
            "output/nids.db",
            "--model",
            "models/model.pkl",
            "--out",
            "reports/ml_evaluation.json",
        ]
    )

    assert result == 0
    assert calls == {
        "db_path": "output/nids.db",
        "model_path": "models/model.pkl",
        "output_json": "reports/ml_evaluation.json",
    }
    assert "evaluate: samples=8 accuracy=0.8750 f1=0.8200" in capsys.readouterr().out


def test_main_report_dispatches(monkeypatch, capsys, tmp_path: Path) -> None:
    out_path = tmp_path / "reports" / "summary.md"

    def fake_generate_incident_report(*, from_db, out):
        assert from_db == "output/nids.db"
        assert out == str(out_path)
        return out_path

    monkeypatch.setattr(cli_module, "generate_incident_report", fake_generate_incident_report)

    result = cli_module.main(["report", "--from-db", "output/nids.db", "--out", str(out_path)])

    assert result == 0
    assert f"report: generated {out_path}" in capsys.readouterr().out


def test_main_threshold_report_dispatches(monkeypatch, capsys, tmp_path: Path) -> None:
    json_path = tmp_path / "reports" / "threshold.json"
    md_path = tmp_path / "reports" / "threshold.md"

    def fake_generate_threshold_tuning_report(*, from_db, out_json, out_md, lookback_days):
        assert from_db == "output/nids.db"
        assert out_json == str(json_path)
        assert out_md == str(md_path)
        assert lookback_days == 5
        return json_path, md_path

    monkeypatch.setattr(cli_module, "generate_threshold_tuning_report", fake_generate_threshold_tuning_report)

    result = cli_module.main(
        [
            "threshold-report",
            "--from-db",
            "output/nids.db",
            "--out-json",
            str(json_path),
            "--out-md",
            str(md_path),
            "--lookback-days",
            "5",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert f"threshold-report: generated {json_path}" in output
    assert f"threshold-report: generated {md_path}" in output


def test_main_artifact_commands_dispatch(monkeypatch, capsys, tmp_path: Path) -> None:
    scan_calls: dict[str, object] = {}
    watch_calls: dict[str, object] = {}
    report_calls: dict[str, object] = {}
    processed_dir = tmp_path / "processed"
    quarantine_dir = tmp_path / "quarantine"

    def fake_run_artifact_scan(**kwargs):
        scan_calls.update(kwargs)
        return _ScanSummary(scanned=3, inserted=2, duplicates=1, quarantined=1, processed=1, errors=0)

    def fake_run_artifact_watch(**kwargs):
        watch_calls.update(kwargs)

    def fake_generate_artifact_report(*, db_path, out_path):
        report_calls["db_path"] = db_path
        report_calls["out_path"] = out_path
        return tmp_path / "reports" / "artifacts.md"

    monkeypatch.setattr(cli_module, "run_artifact_scan", fake_run_artifact_scan)
    monkeypatch.setattr(cli_module, "run_artifact_watch", fake_run_artifact_watch)
    monkeypatch.setattr(cli_module, "generate_artifact_report", fake_generate_artifact_report)

    scan_result = cli_module.main(
        [
            "artifact-scan",
            "--path",
            "artifacts/incoming",
            "--recursive",
            "--db",
            "output/nids.db",
            "--jsonl",
            "output/artifacts.jsonl",
            "--processed-dir",
            str(processed_dir),
            "--quarantine-dir",
            str(quarantine_dir),
        ]
    )
    assert scan_result == 0
    assert scan_calls == {
        "path": "artifacts/incoming",
        "recursive": True,
        "db_path": "output/nids.db",
        "jsonl_path": "output/artifacts.jsonl",
        "processed_dir": str(processed_dir),
        "quarantine_dir": str(quarantine_dir),
    }

    watch_result = cli_module.main(
        [
            "artifact-watch",
            "--path",
            "artifacts/incoming",
            "--recursive",
            "--interval",
            "3",
            "--db",
            "output/nids.db",
            "--jsonl",
            "output/artifacts.jsonl",
            "--processed-dir",
            str(processed_dir),
            "--quarantine-dir",
            str(quarantine_dir),
        ]
    )
    assert watch_result == 0
    assert watch_calls == {
        "path": "artifacts/incoming",
        "recursive": True,
        "interval_sec": 3,
        "db_path": "output/nids.db",
        "jsonl_path": "output/artifacts.jsonl",
        "processed_dir": str(processed_dir),
        "quarantine_dir": str(quarantine_dir),
    }

    report_result = cli_module.main(
        [
            "artifact-report",
            "--from-db",
            "output/nids.db",
            "--out",
            "reports/artifacts/summary.md",
        ]
    )
    assert report_result == 0
    assert report_calls == {
        "db_path": "output/nids.db",
        "out_path": "reports/artifacts/summary.md",
    }

    output = capsys.readouterr().out
    assert "artifact-scan: scanned=3 inserted=2 duplicates=1 quarantined=1 processed=1 errors=0" in output
    assert "artifact-report: generated" in output


def test_main_thesis_docs_dispatches(monkeypatch, capsys, tmp_path: Path) -> None:
    calls: dict[str, object] = {}

    def fake_generate_thesis_documents(*, repo_root, out_md, out_docx):
        calls["repo_root"] = repo_root
        calls["out_md"] = out_md
        calls["out_docx"] = out_docx
        return {"markdown": str(tmp_path / "docs" / "thesis.md"), "docx": str(tmp_path / "docs" / "thesis.docx")}

    monkeypatch.setattr(cli_module, "generate_thesis_documents", fake_generate_thesis_documents)

    result = cli_module.main(
        [
            "thesis-docs",
            "--repo-root",
            ".",
            "--out-md",
            str(tmp_path / "docs" / "master.md"),
            "--out-docx",
            str(tmp_path / "docs" / "master.docx"),
        ]
    )

    assert result == 0
    assert calls["repo_root"] == Path(".")
    assert calls["out_md"] == str(tmp_path / "docs" / "master.md")
    assert calls["out_docx"] == str(tmp_path / "docs" / "master.docx")
    output = capsys.readouterr().out
    assert "thesis-docs: markdown=" in output
    assert "thesis-docs: docx=" in output
