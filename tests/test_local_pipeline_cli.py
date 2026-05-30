from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import src.NIDS.cli as cli_module


@dataclass
class _LocalResult:
    db_path: Path
    flow_count: int
    alert_count: int
    metric_count: int
    report_path: Path
    visual_index_path: Path
    chart_count: int


def test_main_run_local_dispatches_local_pipeline(monkeypatch, tmp_path: Path, capsys) -> None:
    calls: dict[str, object] = {}

    def fake_build_runtime_config(args):
        calls["args"] = args
        return {"runtime": "cfg"}

    def fake_run_local_pipeline(*, cfg, labels_path, sensor_id, report_out, visual_out):
        calls["cfg"] = cfg
        calls["labels_path"] = labels_path
        calls["sensor_id"] = sensor_id
        calls["report_out"] = report_out
        calls["visual_out"] = visual_out
        return _LocalResult(
            db_path=tmp_path / "output" / "nids.db",
            flow_count=4,
            alert_count=2,
            metric_count=1,
            report_path=tmp_path / "output" / "summary.md",
            visual_index_path=tmp_path / "output" / "graphs" / "index.html",
            chart_count=10,
        )

    monkeypatch.setattr(cli_module, "build_runtime_config", fake_build_runtime_config)
    monkeypatch.setattr(cli_module, "run_local_pipeline", fake_run_local_pipeline)

    labels_path = tmp_path / "labels.csv"
    labels_path.write_text("label\nattack\n", encoding="utf-8")
    report_out = tmp_path / "reports" / "summary.md"
    visual_out = tmp_path / "reports" / "graphs"

    result = cli_module.main(
        [
            "run-local",
            "--pcap-dir",
            str(tmp_path / "fixture.pcap"),
            "--labels",
            str(labels_path),
            "--sensor-id",
            "sensor-local-cli",
            "--report-out",
            str(report_out),
            "--visual-out",
            str(visual_out),
        ]
    )

    assert result == 0
    assert calls["cfg"] == {"runtime": "cfg"}
    assert calls["labels_path"] == labels_path.resolve()
    assert calls["sensor_id"] == "sensor-local-cli"
    assert calls["report_out"] == report_out.resolve()
    assert calls["visual_out"] == visual_out.resolve()

    output = capsys.readouterr().out
    assert f"run-local: db={tmp_path / 'output' / 'nids.db'}" in output
    assert "run-local: flows=4 alerts=2 metrics=1" in output
    assert f"run-local: report={tmp_path / 'output' / 'summary.md'}" in output
    assert f"run-local: visuals={tmp_path / 'output' / 'graphs' / 'index.html'} charts=10" in output


def test_main_run_local_returns_readable_error(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setattr(cli_module, "build_runtime_config", lambda _args: {"runtime": "cfg"})
    monkeypatch.setattr(
        cli_module,
        "run_local_pipeline",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("runtime stage failed: synthetic failure")),
    )

    result = cli_module.main(["run-local", "--pcap-dir", str(tmp_path / "fixture.pcap")])

    assert result == 2
    assert "run-local: error: runtime stage failed: synthetic failure" in capsys.readouterr().out
