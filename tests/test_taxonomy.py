from __future__ import annotations

import json
from pathlib import Path

from src.NIDS.adversary.taxonomy import get_scenario_taxonomy, taxonomy_summary_markdown, write_taxonomy_bundle


def test_known_scenario_taxonomy_mapping_is_stable() -> None:
    taxonomy = get_scenario_taxonomy(
        {
            "name": "AI Robustness Partial Signal",
            "slug": "ai-partial-signal",
            "expected": {
                "weakness_tested": "Single-signal behavior designed to avoid multi-engine agreement.",
                "expected_engines": ["signature"],
            },
        }
    )

    assert taxonomy["attack_family"] == "suspicious_command_activity"
    assert taxonomy["behavior_category"] == "single_signal_trigger"
    assert taxonomy["primary_detection_path"] == "signature_only"
    assert taxonomy["expected_engines"] == ["signature"]
    assert taxonomy["notes"] == []


def test_unmapped_taxonomy_falls_back_cleanly() -> None:
    taxonomy = get_scenario_taxonomy({"name": "Unknown Scenario", "slug": "unknown-scenario", "expected": {}})

    assert taxonomy["attack_family"] == "unmapped"
    assert taxonomy["severity"] == "unknown"
    assert "taxonomy_unmapped:unknown-scenario" in taxonomy["notes"]


def test_write_taxonomy_bundle_is_deterministic_shape(tmp_path: Path) -> None:
    json_path, md_path = write_taxonomy_bundle(
        definition={
            "name": "Port Scan Offline Replay",
            "slug": "port-scan-offline",
            "expected": {
                "weakness_tested": "Baseline scan validation.",
                "expected_engines": ["signature", "anomaly"],
            },
        },
        out_json=tmp_path / "taxonomy_map.json",
        out_md=tmp_path / "taxonomy_summary.md",
    )

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = md_path.read_text(encoding="utf-8")

    assert set(payload) == {
        "scenario_name",
        "taxonomy_key",
        "attack_family",
        "behavior_category",
        "weakness_tested",
        "primary_detection_path",
        "expected_engines",
        "expected_alert_pattern",
        "severity",
        "mitre_like_tags",
        "internal_tags",
        "notes",
    }
    assert "# Taxonomy Summary: Port Scan Offline Replay" in markdown
    assert taxonomy_summary_markdown(payload) == markdown
