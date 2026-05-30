from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_module(module_name: str, script_name: str):
    script_path = REPO_ROOT / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_metric_db(path: Path, rows: list[tuple[str, str, float]]) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE metrics(timestamp TEXT, metric_name TEXT, metric_value REAL)")
        conn.executemany("INSERT INTO metrics(timestamp, metric_name, metric_value) VALUES (?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()


def test_parse_runtime_log_text_extracts_backend_and_drop_evidence() -> None:
    module = _load_module("prepared_env_validation_parse", "prepared_env_validation.py")
    payload = module.parse_runtime_log_text(
        "\n".join(
            [
                "live-capture: backend=tcpdump requested_backend=tcpdump interface=enp0s3 sensor_id=nids-ubuntu-sensor",
                "live-capture: starting tcpdump capture interface=enp0s3 tcpdump_bin=/usr/bin/tcpdump snaplen=0 bpf_filter=<none>",
                "live-capture: dropped 12 packets due to full queue",
                'live-capture: telemetry {"backend":"tcpdump","packets_received":30,"packets_parsed":24,"packets_ignored":6,"packets_enqueued":20,"packets_processed":18,"packets_dropped_queue":4,"total_dropped_packets":7,"loss_percentage":23.3333,"queue_depth_peak":1,"burst_rate_packets_per_sec_peak":444.4,"tcpdump_packets_captured":30,"tcpdump_packets_received_by_filter":30,"tcpdump_packets_dropped_by_kernel":3}',
            ]
        )
    )

    assert payload["backend_runs"][0]["resolved_backend"] == "tcpdump"
    assert payload["tcpdump_starts"][0]["tcpdump_bin"] == "/usr/bin/tcpdump"
    assert payload["dropped_packets"] == 7
    assert payload["telemetry_snapshots"][0]["packets_processed"] == 18
    assert payload["telemetry"]["loss_percentage"] == 23.3333
    assert payload["traceback_detected"] is False


def test_parse_json_blob_handles_prompt_noise() -> None:
    module = _load_module("prepared_env_validation_json_blob", "prepared_env_validation.py")
    payload = module._parse_json_blob("password prompt\r\n{\"id\": 7, \"rule_name\": \"Phase6 Duplicate Noise Signature\"}")

    assert payload["id"] == 7
    assert payload["rule_name"] == "Phase6 Duplicate Noise Signature"


def test_build_prepared_env_index_uses_latest_run_per_scenario(tmp_path: Path) -> None:
    module = _load_module("prepared_env_validation_index", "prepared_env_validation.py")
    first = tmp_path / "run-a"
    second = tmp_path / "run-b"
    first.mkdir()
    second.mkdir()

    (first / "prepared_env_manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T14:00:00+00:00",
                "scenario_id": "PREP-ENV-001",
                "scenario_name": "First",
                "run_name": "run-a",
                "status": "partial",
                "database_summary": {"counts": {"alerts": 1}},
                "evidence": {"result_dir": str(first)},
            }
        ),
        encoding="utf-8",
    )
    (second / "prepared_env_manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T15:00:00+00:00",
                "scenario_id": "PREP-ENV-001",
                "scenario_name": "First",
                "run_name": "run-b",
                "status": "pass",
                "database_summary": {"counts": {"alerts": 3}},
                "evidence": {"result_dir": str(second)},
            }
        ),
        encoding="utf-8",
    )

    index = module.build_prepared_env_index(tmp_path)
    markdown = module.prepared_env_index_markdown(index)

    assert index["total_runs"] == 2
    assert index["latest_by_scenario"]["PREP-ENV-001"]["run_name"] == "run-b"
    assert "run-b" in markdown


def test_build_verdict_uses_metric_summary_when_runtime_telemetry_is_missing() -> None:
    module = _load_module("prepared_env_validation_verdict", "prepared_env_validation.py")
    verdict = module._build_verdict(
        {
            "expected_backend": "tcpdump",
            "require_capture_metrics": True,
            "require_drop": True,
            "min_packets_received": 300,
            "required_rules": [],
        },
        execution_ok=True,
        db_summary={"counts": {"alerts": 0}, "rule_counts": {}},
        runtime_summary={
            "backend_runs": [{"resolved_backend": "tcpdump"}],
            "dropped_packets": 0,
            "telemetry": {},
            "traceback_detected": False,
        },
        extras={
            "metric_summary": {
                "metrics": {
                    "live_packets_received": {"last_value": 8127.0},
                    "live_packets_dropped_total": {"last_value": 8115.0},
                }
            }
        },
    )

    assert verdict["status"] == "pass"
    assert verdict["observed_dropped_packets"] == 8115


def test_build_prepared_env_index_reads_nested_phase_directories(tmp_path: Path) -> None:
    module = _load_module("prepared_env_validation_nested_index", "prepared_env_validation.py")
    nested = tmp_path / "phase5-soak" / "run-a"
    nested.mkdir(parents=True)
    (nested / "prepared_env_manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-03-12T18:00:00+00:00",
                "scenario_id": "PREP-ENV-007",
                "scenario_name": "Extended Soak",
                "run_name": "phase5-soak/run-a",
                "status": "pass",
                "database_summary": {"counts": {"alerts": 0}},
                "evidence": {"result_dir": str(nested)},
            }
        ),
        encoding="utf-8",
    )

    index = module.build_prepared_env_index(tmp_path)

    assert index["total_runs"] == 1
    assert index["latest_by_scenario"]["PREP-ENV-007"]["run_name"] == "phase5-soak/run-a"


def test_summarize_metric_series_includes_suppression_metrics(tmp_path: Path) -> None:
    module = _load_module("prepared_env_validation_metrics", "prepared_env_validation.py")
    db_path = tmp_path / "nids.db"
    _write_metric_db(
        db_path,
        [
            ("2026-03-12T18:00:00+00:00", "total_alerts", 1.0),
            ("2026-03-12T18:00:00+00:00", "suppressed_alerts", 3.0),
            ("2026-03-12T18:00:00+00:00", "policy_suppressed_alerts", 1.0),
            ("2026-03-12T18:00:05+00:00", "suppressed_alerts", 7.0),
            ("2026-03-12T18:00:05+00:00", "policy_suppressed_alerts", 4.0),
        ],
    )

    summary = module._summarize_metric_series(db_path)

    assert summary["metrics"]["suppressed_alerts"]["last_value"] == 7.0
    assert summary["metrics"]["policy_suppressed_alerts"]["max_value"] == 4.0
    assert summary["metrics"]["total_alerts"]["first_value"] == 1.0


def test_build_verdict_requires_suppression_evidence() -> None:
    module = _load_module("prepared_env_validation_suppression_verdict", "prepared_env_validation.py")

    verdict = module._build_verdict(
        {
            "expected_backend": "tcpdump",
            "required_rules": ["Phase6 Duplicate Noise Signature"],
            "require_suppressed_alerts": True,
            "min_suppressed_alerts": 2,
            "require_policy_suppressed_alerts": True,
            "min_policy_suppressed_alerts": 1,
            "require_active_suppression_rule": True,
            "require_alert_count_stable_after_action": True,
        },
        execution_ok=True,
        db_summary={"counts": {"alerts": 1}, "rule_counts": {"Phase6 Duplicate Noise Signature": 1}},
        runtime_summary={
            "backend_runs": [{"resolved_backend": "tcpdump"}],
            "dropped_packets": 0,
            "telemetry": {},
            "traceback_detected": False,
        },
        extras={
            "metric_summary": {
                "metrics": {
                    "suppressed_alerts": {"last_value": 5.0},
                    "policy_suppressed_alerts": {"last_value": 3.0},
                }
            },
            "suppression_validation": {
                "suppression_state_after": {"active_rules": 1},
                "pre_suppression_counts": {"alerts": 1},
                "post_suppression_counts": {"alerts": 1},
            },
        },
    )

    assert verdict["status"] == "pass"


def test_build_verdict_uses_derived_suppression_counts_when_metrics_are_missing() -> None:
    module = _load_module("prepared_env_validation_suppression_derived", "prepared_env_validation.py")

    verdict = module._build_verdict(
        {
            "expected_backend": "tcpdump",
            "required_rules": ["Phase6 Duplicate Noise Signature"],
            "require_suppressed_alerts": True,
            "min_suppressed_alerts": 10,
            "require_policy_suppressed_alerts": True,
            "min_policy_suppressed_alerts": 5,
            "require_active_suppression_rule": True,
            "require_alert_count_stable_after_action": True,
        },
        execution_ok=True,
        db_summary={"counts": {"alerts": 1}, "rule_counts": {"Phase6 Duplicate Noise Signature": 1}},
        runtime_summary={
            "backend_runs": [{"resolved_backend": "tcpdump"}],
            "dropped_packets": 0,
            "telemetry": {},
            "traceback_detected": False,
        },
        extras={
            "metric_summary": {"metrics": {}},
            "suppression_validation": {
                "derived_total_suppressions_min": 22,
                "derived_policy_suppressions_min": 11,
                "suppression_state_after": {"active_rules": 1},
                "pre_suppression_counts": {"alerts": 1},
                "post_suppression_counts": {"alerts": 1},
            },
        },
    )

    assert verdict["status"] == "pass"


def test_write_manifest_includes_environment_expected_and_actual(tmp_path: Path) -> None:
    module = _load_module("prepared_env_validation_manifest_fields", "prepared_env_validation.py")
    result_dir = tmp_path / "run"
    result_dir.mkdir()

    scenario = {
        "scenario_id": "PREP-ENV-011",
        "name": "Prepared Environment Benign SaaS Polling Mix",
        "kind": "custom_benign_soak",
        "objective": "Validate broader benign adjudication against a SaaS polling sample.",
        "expected_backend": "tcpdump",
        "expected_outcome": "The tuned profile should remain quiet on this broader benign sample.",
        "sample_id": "BENIGN-LIVE-002",
    }

    manifest = module._write_phase4_manifest(
        scenario,
        run_name="phase6-benign/phase6-benign-saas-polling-20260312-180000",
        result_dir=result_dir,
        config_relpath="NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml",
        capture_config={},
        remote_environment={"sensor": {"hostname": "nids-ubuntu-sensor"}, "target": {"hostname": "nids-ubuntu-target"}},
        execution={"kind": "custom_remote_validation", "duration_sec": 12.3, "returncode": 0},
        db_summary={"counts": {"flows": 144, "alerts": 0}, "rule_counts": {}},
        runtime_summary={"backend_runs": [{"resolved_backend": "tcpdump"}], "telemetry": {}, "traceback_detected": False},
        extras={"sample_id": "BENIGN-LIVE-002", "analyst_adjudication": {"classification": "cleared_after_tuning"}},
        verdict={"status": "pass", "issues": []},
    )

    summary_text = (result_dir / "prepared_env_summary.md").read_text(encoding="utf-8")

    assert manifest["environment"].startswith("Windows orchestration host")
    assert manifest["expected_outcome"] == "The tuned profile should remain quiet on this broader benign sample."
    assert "BENIGN-LIVE-002" in manifest["actual_outcome"]
    assert "## Environment" in summary_text
    assert "## Expected Outcome" in summary_text
    assert "## Actual Outcome" in summary_text


def test_sync_sensor_files_includes_jsonl_store(monkeypatch) -> None:
    module = _load_module("prepared_env_validation_sync_jsonl", "prepared_env_validation.py")
    uploaded: list[str] = []

    def _fake_upload_file(sensor_ssh, local_path, remote_path, sudo_password=None):  # type: ignore[no-untyped-def]
        del sensor_ssh, local_path, sudo_password
        uploaded.append(str(remote_path))

    monkeypatch.setattr(module.LIVEVM, "_upload_file", _fake_upload_file)

    module._sync_sensor_files(
        object(),
        "NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml",
        "placeholder-password",
    )

    assert any(path.endswith("/src/NIDS/storage/jsonl_store.py") for path in uploaded)


def test_build_soak_analysis_captures_phase10_comparison_fields(tmp_path: Path) -> None:
    module = _load_module("prepared_env_validation_soak_analysis", "prepared_env_validation.py")
    result_dir = tmp_path / "soak"
    result_dir.mkdir()
    (result_dir / "runtime.log").write_text("warning: transient note\n", encoding="utf-8")

    analysis = module._build_soak_analysis(
        db_summary={
            "counts": {"flows": 37598, "alerts": 3},
            "engine_counts": {"anomaly": 2, "ml": 1},
        },
        runtime_summary={"nonzero_exit_lines": [], "traceback_detected": False},
        extras={
            "executed_duration_sec": 21600.0,
            "reload_latency_sec": 13.329,
            "process_samples": [
                {"cpu_percent": 100.0, "rss_kib": 320000},
                {"cpu_percent": 140.0, "rss_kib": 543268},
            ],
            "runtime_samples": [
                {"db_bytes": 100, "alerts_jsonl_bytes": 0, "flows_jsonl_bytes": 200, "metrics_jsonl_bytes": 30, "total_result_bytes": 400},
                {"db_bytes": 500, "alerts_jsonl_bytes": 40, "flows_jsonl_bytes": 900, "metrics_jsonl_bytes": 70, "total_result_bytes": 1500},
            ],
            "metric_summary": {"metrics": {"events_per_sec": {"samples": 3}}},
            "alert_details": [
                {
                    "id": 1,
                    "timestamp": "2026-03-13T01:33:56+00:00",
                    "engine": "anomaly",
                    "rule_name": "DoS Rate Threshold",
                    "is_suppressed": False,
                    "extra": {"dos_episode_key": "10.77.0.30|UDP"},
                },
                {
                    "id": 2,
                    "timestamp": "2026-03-13T01:33:58+00:00",
                    "engine": "anomaly",
                    "rule_name": "DoS Rate Threshold",
                    "is_suppressed": False,
                    "extra": {"dos_episode_key": "10.77.0.30|UDP"},
                },
                {
                    "id": 3,
                    "timestamp": "2026-03-13T01:34:12+00:00",
                    "engine": "ml",
                    "rule_name": "Hybrid Unsupervised Anomaly Score",
                    "is_suppressed": False,
                    "extra": {"unsupervised_episode_key": "10.0.0.10|10.0.0.20|ICMP|0"},
                },
            ],
        },
        result_dir=result_dir,
    )

    assert analysis["peak_cpu_percent"] == 140.0
    assert analysis["avg_cpu_percent"] == 120.0
    assert analysis["sqlite_peak_bytes"] == 500
    assert analysis["flows_jsonl_peak_bytes"] == 900
    assert analysis["operator_visible_dos_alerts"] == 2
    assert analysis["unsupervised_emitted_alerts"] == 1
    assert analysis["warning_line_count"] == 1
    assert analysis["dos_reopen_loop_detected"] is True
    assert analysis["notable_burst_windows"][0]["alert_count"] == 3
