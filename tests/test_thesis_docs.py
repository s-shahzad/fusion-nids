from __future__ import annotations

import json
from pathlib import Path

from src.NIDS.thesis import generate_thesis_documents


def test_generate_thesis_documents(tmp_path: Path) -> None:
    (tmp_path / "src" / "NIDS" / "artifacts" / "parsers").mkdir(parents=True)
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "NIDS_TestLab" / "reports").mkdir(parents=True)
    (tmp_path / "src" / "NIDS" / "artifacts" / "parsers" / "csv_parser.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "NIDS" / "artifacts" / "parsers" / "json_parser.py").write_text("", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("scapy>=2.5.0\npython-docx>=1.1.2\n", encoding="utf-8")
    (tmp_path / "reports" / "ml_metrics.json").write_text(
        json.dumps(
            {
                "samples_total": 25000,
                "accuracy": 0.99536,
                "f1_weighted": 0.99559,
                "algorithms": ["random_forest", "xgboost"],
                "feature_columns": ["packet_len", "dst_port"],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "reports" / "ml_evaluation.json").write_text(
        json.dumps({"samples": 25000, "accuracy": 0.99784, "f1_weighted": 0.99792}),
        encoding="utf-8",
    )
    (tmp_path / "NIDS_TestLab" / "reports" / "attack_test_ledger.json").write_text(
        json.dumps(
            {
                "completed_network_detections": [{"attack_case": "DNS burst / DGA-like activity", "status": "pass"}],
                "completed_static_families": [{"family": "ransomware", "status": "pass"}],
                "completed_os_defense_cases": [{"attack_case": "Ubuntu cron persistence + suspicious HTTP beacon", "status": "pass"}],
                "concurrent_overlap_runs": [{"run_name": "overlap-run", "status": "partial", "finding": "partial overlap evidence"}],
                "remaining_attack_families": ["Beaconing / C2"],
                "remaining_os_defense_cases": ["Windows safe-only posture validation"],
            }
        ),
        encoding="utf-8",
    )

    outputs = generate_thesis_documents(repo_root=tmp_path)

    markdown = Path(outputs["markdown"]).read_text(encoding="utf-8")
    assert "# 2. Abstract" in markdown
    assert "# 15. Current System Version" in markdown
    assert (tmp_path / "documentation" / "architecture.md").exists()
    assert (tmp_path / "thesis" / "nids_thesis.tex").exists()
    assert Path(outputs["docx"]).exists()
