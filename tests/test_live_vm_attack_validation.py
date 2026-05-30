from __future__ import annotations

import argparse
import importlib.util
import sqlite3
from pathlib import Path

import pytest


def _load_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "live_vm_attack_validation.py"
    spec = importlib.util.spec_from_file_location("live_vm_attack_validation", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load live_vm_attack_validation module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_attack_jobs_includes_concurrent_http_and_scan_cases() -> None:
    module = _load_module()
    args = argparse.Namespace(
        sensor_ip="10.77.0.30",
        dns_count=32,
        dns_delay_sec=0.08,
        dns_flood_rate_per_sec=150.0,
        dns_flood_duration_sec=4.0,
        dns_flood_qname="flood.test",
        scan_start_port=5000,
        scan_port_count=40,
        scan_delay_sec=0.05,
        udp_flood_packets=0,
        udp_flood_port=9999,
        udp_flood_payload_bytes=256,
        udp_flood_rate_per_sec=0.0,
        udp_flood_duration_sec=0.0,
        ssh_attempts=8,
        ssh_attempt_delay_sec=0.35,
        rdp_attempts=6,
        rdp_attempt_delay_sec=0.4,
        http_login_attempts=4,
        http_login_port=80,
        http_login_uri="/login",
        http_login_attempt_delay_sec=0.9,
        http_keyword_requests=3,
        http_keyword_port=0,
        http_keyword_uri="/shell",
        http_keyword_request_delay_sec=0.6,
    )

    jobs = module._build_attack_jobs(args)
    names = {job["name"] for job in jobs}

    assert "dns-burst" in names
    assert "dns-flood" in names
    assert "tcp-scan" in names
    assert "ssh-bruteforce" in names
    assert "rdp-bruteforce" in names
    assert "http-login-bruteforce" in names
    assert "http-keyword" in names
    assert next(job for job in jobs if job["name"] == "http-keyword")["port"] == 80


def test_write_validation_summary_marks_pass_and_miss(tmp_path: Path) -> None:
    module = _load_module()
    db_path = tmp_path / "nids.db"

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE alerts(rule_name TEXT, engine TEXT, severity TEXT)")
    conn.execute("CREATE TABLE flows(id INTEGER PRIMARY KEY)")
    conn.executemany(
        "INSERT INTO alerts(rule_name, engine, severity) VALUES (?, ?, ?)",
        [
            ("DNS Burst / DGA-like Activity", "anomaly", "medium"),
            ("DNS Burst / DGA-like Activity", "anomaly", "medium"),
            ("Port Scan Threshold", "anomaly", "high"),
        ],
    )
    conn.executemany("INSERT INTO flows(id) VALUES (?)", [(1,), (2,), (3,)])
    conn.commit()
    conn.close()

    jobs = [
        {
            "name": "dns-burst",
            "label": "DNS Burst / DGA-like Activity",
            "expected_rules": ["DNS Burst / DGA-like Activity"],
        },
        {
            "name": "http-login-bruteforce",
            "label": "HTTP Login Brute Force",
            "expected_rules": ["HTTP Login Brute Force Threshold"],
        },
    ]

    json_path, md_path = module._write_validation_summary(tmp_path, jobs, concurrent=True)

    assert json_path.exists()
    assert md_path.exists()
    md_text = md_path.read_text(encoding="utf-8")
    assert "Mode: `concurrent`" in md_text
    assert "| DNS Burst / DGA-like Activity |" in md_text
    assert "`pass`" in md_text
    assert "`miss`" in md_text


def test_lab_vm_secret_defaults_use_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    monkeypatch.setenv("LAB_VM_USER", "env-user")
    monkeypatch.setenv("LAB_VM_PASS", "env-pass")

    assert module.lab_vm_username_default() == "env-user"
    assert module.lab_vm_password_default() == "env-pass"
