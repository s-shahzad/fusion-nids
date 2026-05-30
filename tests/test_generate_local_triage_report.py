from __future__ import annotations

import json
from pathlib import Path

from scripts import generate_local_triage_report


def test_generate_report_writes_markdown_in_same_run_folder(tmp_path: Path) -> None:
    run_dir = tmp_path / "sample-run"
    run_dir.mkdir()
    triage_path = run_dir / "triage_sample-run.json"
    triage_path.write_text(
        json.dumps(
            {
                "alert_summary": "Suspicious outbound traffic was detected.",
                "severity_assessment": "High severity.",
                "likely_cause": "Possible exfiltration attempt.",
                "recommended_action": "Inspect the host and block the session if unauthorized.",
            }
        ),
        encoding="utf-8",
    )

    report_path = generate_local_triage_report.generate_report(triage_path)

    assert report_path == run_dir / "triage_sample-run_report.md"
    text = report_path.read_text(encoding="utf-8")
    assert "# Local NIDS Triage Report: sample-run" in text
    assert "## Alert Summary" in text
    assert "Suspicious outbound traffic was detected." in text
    assert "## Severity" in text
    assert "High severity." in text
    assert "## Cause" in text
    assert "Possible exfiltration attempt." in text
    assert "## Recommended Action" in text
    assert "Inspect the host and block the session if unauthorized." in text
