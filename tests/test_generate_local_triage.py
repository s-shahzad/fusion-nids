from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts import generate_local_triage


def test_render_digest_and_generate_outputs(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    alerts = [
        {
            "timestamp": "2024-03-10T20:20:30+00:00",
            "severity": "critical",
            "engine": "fusion",
            "rule_name": "Hybrid Fusion Decision",
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 22,
            "proto": "TCP",
            "summary": "Hybrid fusion score=0.58 agreement=3 components=signature, supervised, unsupervised",
            "fusion_label": "attack",
            "predicted_attack_type": "dos",
        },
        {
            "timestamp": "2024-03-10T20:20:31+00:00",
            "severity": "high",
            "engine": "signature",
            "rule_name": "HTTP Suspicious Keyword",
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 80,
            "proto": "TCP",
            "summary": "Rule matched: HTTP Suspicious Keyword",
            "fusion_label": "benign",
            "predicted_attack_type": None,
        },
    ]
    (run_dir / "alerts.jsonl").write_text("\n".join(json.dumps(row) for row in alerts), encoding="utf-8")

    flows = [
        {
            "timestamp": "2024-03-10T20:20:00+00:00",
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 80,
            "proto": "TCP",
            "packet_rate_dst": 3,
            "fusion_label": "benign",
            "prediction_score": 0.9,
            "payload_preview": "GET /benign HTTP/1.1",
        }
    ]
    (run_dir / "flows.jsonl").write_text("\n".join(json.dumps(row) for row in flows), encoding="utf-8")

    (run_dir / "summary.md").write_text("# Existing Summary\n\nSample report body.\n", encoding="utf-8")

    monkeypatch.setattr(
        generate_local_triage,
        "query_db_summary",
        lambda path: {
            "table_counts": {"alerts": 2, "flows": 1},
            "top_rules": [("Hybrid Fusion Decision", 1)],
            "severity_counts": {"critical": 1, "high": 1},
            "engine_counts": {"fusion": 1, "signature": 1},
        },
    )

    def fake_invoke(prompt: str, session_id: str) -> str:
        assert "Use only this local evidence." in prompt
        assert "Top 3 alerts:" in prompt
        assert "Focus only on the top 3 ranked alerts shown below." in prompt
        assert "Return exactly one JSON object" in prompt
        assert session_id.startswith("local-triage-run-")
        return json.dumps(
            {
                "alert_summary": "Alert summary body",
                "severity_assessment": "High severity with moderate confidence.",
                "likely_cause": "Likely coordinated scan and suspicious HTTP activity.",
                "recommended_action": "Validate source intent and isolate the target if activity persists.",
            }
        )

    monkeypatch.setattr(generate_local_triage, "invoke_nids_triage", fake_invoke)

    out_dir = run_dir / "triage"
    created = generate_local_triage.generate_outputs(run_dir, out_dir)

    assert [path.name for path in created] == ["triage_run.json"]
    payload = json.loads((out_dir / "triage_run.json").read_text(encoding="utf-8"))
    assert payload == {
        "alert_summary": "Alert summary body",
        "severity_assessment": "High severity with moderate confidence.",
        "likely_cause": "Likely coordinated scan and suspicious HTTP activity.",
        "recommended_action": "Validate source intent and isolate the target if activity persists.",
    }


def test_dedupe_and_prioritize_alerts_prefers_high_value_unique_alerts() -> None:
    alerts = [
        {
            "timestamp": "2024-03-10T20:20:31+00:00",
            "severity": "low",
            "rule_name": "Noise",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "dst_port": 80,
        },
        {
            "timestamp": "2024-03-10T20:20:32+00:00",
            "severity": "critical",
            "rule_name": "Fusion",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4",
            "dst_port": 22,
            "fusion_score": 0.95,
        },
        {
            "timestamp": "2024-03-10T20:20:33+00:00",
            "severity": "critical",
            "rule_name": "Fusion",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4",
            "dst_port": 22,
            "fusion_score": 0.90,
        },
    ]

    selected = generate_local_triage.dedupe_and_prioritize_alerts(alerts)

    assert len(selected) == 3
    assert selected[0]["rule_name"] == "Fusion"
    assert selected[0]["severity"] == "critical"


def test_generate_outputs_falls_back_to_local_triage_payload(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    alerts = [
        {
            "timestamp": "2024-03-10T20:20:30+00:00",
            "severity": "critical",
            "engine": "fusion",
            "rule_name": "Hybrid Fusion Decision",
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 22,
            "proto": "TCP",
            "summary": "Hybrid fusion score=0.58",
        },
        {
            "timestamp": "2024-03-10T20:20:31+00:00",
            "severity": "high",
            "engine": "signature",
            "rule_name": "HTTP Suspicious Keyword",
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 80,
            "proto": "TCP",
            "summary": "Rule matched",
        },
        {
            "timestamp": "2024-03-10T20:20:32+00:00",
            "severity": "medium",
            "engine": "anomaly",
            "rule_name": "Port Scan Threshold",
            "src_ip": "10.77.0.20",
            "dst_ip": "10.77.0.30",
            "dst_port": 25,
            "proto": "TCP",
            "summary": "Source touched many ports",
        },
    ]
    (run_dir / "alerts.jsonl").write_text("\n".join(json.dumps(row) for row in alerts), encoding="utf-8")
    (run_dir / "flows.jsonl").write_text("", encoding="utf-8")

    monkeypatch.setattr(generate_local_triage, "invoke_nids_triage", lambda prompt, session_id: (_ for _ in ()).throw(RuntimeError("no ai")))

    created = generate_local_triage.generate_outputs(run_dir, run_dir)
    payload = json.loads(created[0].read_text(encoding="utf-8"))

    assert "Hybrid Fusion Decision" in payload["likely_cause"]
    assert "highest-ranked 3 alerts" in payload["severity_assessment"]


def test_invoke_nids_triage_uses_partial_output_and_terminates_on_timeout(monkeypatch) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 4321
            self.returncode = None

        def communicate(self, timeout: int) -> tuple[str, str]:
            raise subprocess.TimeoutExpired(
                cmd=["fake"],
                timeout=timeout,
                output='{"result":{"payloads":[{"text":"{\\"alert_summary\\": \\"Body\\", \\"severity_assessment\\": \\"High\\", \\"likely_cause\\": \\"Cause\\", \\"recommended_action\\": \\"Action\\"}"}]}}',
                stderr="",
            )

        def wait(self, timeout: int) -> int:
            self.returncode = -9
            return self.returncode

        def poll(self) -> None:
            return None

    killed: list[int] = []

    monkeypatch.setattr(generate_local_triage, "CANONICAL_TRIAGE_CMD", Path(__file__).resolve())
    monkeypatch.setattr(generate_local_triage.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(generate_local_triage, "_terminate_process_tree", lambda proc: killed.append(proc.pid))

    text = generate_local_triage.invoke_nids_triage(prompt="hello", session_id="abc")

    assert json.loads(text) == {
        "alert_summary": "Body",
        "severity_assessment": "High",
        "likely_cause": "Cause",
        "recommended_action": "Action",
    }
    assert killed == [4321]
