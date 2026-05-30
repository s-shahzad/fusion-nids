from __future__ import annotations

from pathlib import Path

from scripts import run_local_triage


def test_main_writes_to_run_folder_and_prints_success(tmp_path: Path, monkeypatch, capsys) -> None:
    run_dir = tmp_path / "sample-run"
    run_dir.mkdir()
    triage_path = run_dir / "triage_sample-run.json"
    report_path = run_dir / "triage_sample-run_report.md"

    def fake_generate_outputs(run_dir: Path, out_dir: Path) -> list[Path]:
        assert out_dir == run_dir
        return [triage_path]

    def fake_generate_report(path: Path) -> Path:
        assert path == triage_path
        return report_path

    monkeypatch.setattr(run_local_triage.generate_local_triage, "generate_outputs", fake_generate_outputs)
    monkeypatch.setattr(run_local_triage.generate_local_triage_report, "generate_report", fake_generate_report)
    monkeypatch.setattr("sys.argv", ["run_local_triage.py", str(run_dir)])

    assert run_local_triage.main() == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        f"Triage generated: {triage_path}\n"
        f"Report generated: {report_path}\n"
        f"Delivery complete: {run_dir}"
    )
