from __future__ import annotations

from copy import deepcopy
from typing import Any


_BASE_RUNTIME = {
    "config": "NIDS_TestLab/config/offline_replay_profile.yml",
    "rules": "rules/rules.yml",
    "model_path": "models/model.pkl",
    "sensor_id": "nids-phase17-ai-replay",
    "use_model": True,
    "enable_unsupervised": True,
    "metrics_interval": 1,
    "threshold_lookback_days": 3650,
}


_SCENARIOS: dict[str, dict[str, Any]] = {
    "slow_scan": {
        "scenario_id": "LAB-AI-001",
        "name": "AI Robustness Slow Scan",
        "slug": "ai-slow-scan",
        "description": "Low-rate TCP sweep intended to reduce anomaly intensity while still exercising the replay path.",
        "objective": "Evaluate how the system responds when scan activity is spread out to reduce threshold pressure.",
        "environment": {"primary_mode": "offline_replay"},
        "runtime": deepcopy(_BASE_RUNTIME),
        "expected": {
            "required_rules": ["Suspicious Port Scan"],
            "expected_engines": ["signature"],
            "fusion_behavior": "Fusion is not required; this scenario is meant to test reduced-evidence scan behavior.",
            "ground_truth": {
                "expected_detections": [
                    {"label": "slow_scan_signature", "count": 1, "match_any": ["Suspicious Port Scan"]},
                ],
                "expected_misses": ["Port Scan Threshold", "Hybrid Fusion Decision"],
            },
            "max_alerts": 3,
            "weakness_tested": "Low-rate scan behavior intended to reduce anomaly agreement.",
        },
        "network": {
            "components": [
                {
                    "kind": "tcp_scan",
                    "src_ip": "10.77.0.41",
                    "dst_ip": "10.77.0.30",
                    "src_port_start": 41000,
                    "start_port": 1,
                    "count": 27,
                    "extra_ports": [3389],
                    "start_time_sec": 0.0,
                    "interval_ms": 800,
                }
            ]
        },
    },
    "burst_then_idle": {
        "scenario_id": "LAB-AI-002",
        "name": "AI Robustness Burst Then Idle",
        "slug": "ai-burst-then-idle",
        "description": "Short, intense UDP burst followed by silence to test brief pressure behavior.",
        "objective": "Evaluate whether short-lived burst behavior still produces stable replay evidence without relying on sustained traffic.",
        "environment": {"primary_mode": "offline_replay"},
        "runtime": {**deepcopy(_BASE_RUNTIME), "use_model": False, "enable_unsupervised": False},
        "expected": {
            "required_rules": ["DoS Rate Threshold"],
            "expected_engines": ["anomaly"],
            "fusion_behavior": "Fusion is not expected because this scenario intentionally exercises one strong anomaly path.",
            "ground_truth": {
                "expected_detections": [
                    {"label": "burst_dos", "count": 1, "match_any": ["DoS Rate Threshold"]},
                ],
                "expected_misses": ["Hybrid Fusion Decision"],
            },
            "weakness_tested": "Burst activity that may try to exploit short observation windows.",
        },
        "network": {
            "components": [
                {
                    "kind": "udp_flood",
                    "src_ip": "10.77.0.42",
                    "dst_ip": "10.77.0.30",
                    "src_port_start": 42000,
                    "dst_port": 9999,
                    "count": 260,
                    "payload_size": 220,
                    "start_time_sec": 0.0,
                    "interval_ms": 2,
                }
            ]
        },
    },
    "mimic_normal": {
        "scenario_id": "LAB-AI-003",
        "name": "AI Robustness Mimic Normal",
        "slug": "ai-mimic-normal",
        "description": "Benign-shaped DNS and HTTP traffic intended to resemble routine polling.",
        "objective": "Evaluate whether benign-shaped replay traffic remains quiet under the tuned offline profile.",
        "environment": {"primary_mode": "offline_replay"},
        "runtime": deepcopy(_BASE_RUNTIME),
        "expected": {
            "required_rules": [],
            "expected_engines": [],
            "fusion_behavior": "Fusion is not expected; the scenario is meant to stay below alert conditions.",
            "ground_truth": {
                "expected_detections": [],
                "expected_misses": [
                    "Suspicious Port Scan",
                    "DoS Rate Threshold",
                    "DNS Burst / DGA-like Activity",
                    "Hybrid Fusion Decision",
                ],
            },
            "max_alerts": 0,
            "weakness_tested": "Traffic shaping that tries to resemble benign polling and health-check patterns.",
        },
        "network": {
            "components": [
                {
                    "kind": "benign_dns",
                    "src_ip": "10.77.0.43",
                    "dst_ip": "10.77.0.30",
                    "src_port_start": 53000,
                    "qname": "status.portal.example",
                    "count": 12,
                    "start_time_sec": 0.0,
                    "interval_ms": 400,
                },
                {
                    "kind": "benign_http_get",
                    "src_ip": "10.77.0.43",
                    "dst_ip": "10.77.0.30",
                    "src_port_start": 44000,
                    "dst_port": 8080,
                    "uri": "/health",
                    "count": 8,
                    "start_time_sec": 0.2,
                    "interval_ms": 500,
                },
            ]
        },
    },
    "partial_signal": {
        "scenario_id": "LAB-AI-004",
        "name": "AI Robustness Partial Signal",
        "slug": "ai-partial-signal",
        "description": "Single-engine suspicious HTTP keyword replay intended to avoid broader agreement.",
        "objective": "Evaluate how the system records suspicious traffic when only a signature-style signal is deliberately present.",
        "environment": {"primary_mode": "offline_replay"},
        "runtime": {**deepcopy(_BASE_RUNTIME), "use_model": False, "enable_unsupervised": False},
        "expected": {
            "required_rules": ["HTTP Suspicious Keyword"],
            "expected_engines": ["signature"],
            "fusion_behavior": "Fusion is not expected because the scenario is intentionally limited to a partial signal.",
            "ground_truth": {
                "expected_detections": [
                    {"label": "partial_signature", "count": 1, "match_any": ["HTTP Suspicious Keyword"]},
                ],
                "expected_misses": ["Hybrid Fusion Decision"],
            },
            "weakness_tested": "Single-signal behavior designed to avoid multi-engine agreement.",
        },
        "network": {
            "components": [
                {
                    "kind": "http_keyword",
                    "src_ip": "10.77.0.44",
                    "dst_ip": "10.77.0.30",
                    "src_port_start": 45000,
                    "dst_port": 8080,
                    "uri": "/shell?cmd.exe=whoami",
                    "count": 1,
                    "start_time_sec": 0.0,
                    "interval_ms": 100,
                }
            ]
        },
    },
    "alert_flood": {
        "scenario_id": "LAB-AI-005",
        "name": "AI Robustness Alert Flood",
        "slug": "ai-alert-flood",
        "description": "Repeated suspicious HTTP keyword requests intended to create many signature-level alerts without stronger agreement.",
        "objective": "Evaluate alert volume and reviewability when many low-confidence signature signals are generated in one replay window.",
        "environment": {"primary_mode": "offline_replay"},
        "runtime": {**deepcopy(_BASE_RUNTIME), "use_model": False, "enable_unsupervised": False},
        "expected": {
            "required_rules": ["HTTP Suspicious Keyword"],
            "expected_engines": ["signature"],
            "fusion_behavior": "Fusion is not expected; the scenario is meant to stress alert volume with limited signal diversity.",
            "ground_truth": {
                "expected_detections": [
                    {"label": "alert_flood_signature", "count": 6, "match_any": ["HTTP Suspicious Keyword"]},
                ],
                "expected_misses": ["Hybrid Fusion Decision"],
            },
            "weakness_tested": "High-volume low-confidence replay intended to stress triage review.",
        },
        "network": {
            "components": [
                {
                    "kind": "http_keyword",
                    "src_ip": "10.77.0.45",
                    "dst_ip": "10.77.0.30",
                    "src_port_start": 46000,
                    "dst_port": 8080,
                    "uri": "/shell?cmd.exe=whoami&tool=powershell",
                    "count": 6,
                    "start_time_sec": 0.0,
                    "interval_ms": 120,
                }
            ]
        },
    },
}


def list_ai_scenarios() -> list[str]:
    return sorted(_SCENARIOS)


def get_ai_scenario_definition(name: str) -> dict[str, Any]:
    key = str(name or "").strip()
    if key not in _SCENARIOS:
        raise KeyError(f"Unknown AI scenario: {key}")
    return deepcopy(_SCENARIOS[key])
