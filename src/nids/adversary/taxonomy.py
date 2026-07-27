from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _safe_slug(value: str) -> str:
    token = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    while "--" in token:
        token = token.replace("--", "-")
    return token.strip("-")


_TAXONOMY_MAP: dict[str, dict[str, Any]] = {
    "ai-slow-scan": {
        "attack_family": "reconnaissance",
        "behavior_category": "low_rate_scan",
        "primary_detection_path": "signature_primary",
        "expected_alert_pattern": "single_or_low_count_scan_alerts",
        "severity": "medium",
        "mitre_like_tags": ["reconnaissance", "scan_behavior", "evasion_style"],
        "internal_tags": ["ai_robustness", "threshold_avoidance"],
    },
    "ai-burst-then-idle": {
        "attack_family": "denial_of_service",
        "behavior_category": "burst_activity",
        "primary_detection_path": "anomaly_primary",
        "expected_alert_pattern": "short_burst_threshold_alert",
        "severity": "high",
        "mitre_like_tags": ["impact", "dos_behavior", "timing_variation"],
        "internal_tags": ["ai_robustness", "window_pressure"],
    },
    "ai-mimic-normal": {
        "attack_family": "benign_mimicry",
        "behavior_category": "traffic_shaping",
        "primary_detection_path": "no_alert_expected",
        "expected_alert_pattern": "quiet_or_zero_alerts",
        "severity": "low",
        "mitre_like_tags": ["evasion_style", "benign_mimicry"],
        "internal_tags": ["ai_robustness", "normality_mimic"],
    },
    "ai-partial-signal": {
        "attack_family": "suspicious_command_activity",
        "behavior_category": "single_signal_trigger",
        "primary_detection_path": "signature_only",
        "expected_alert_pattern": "single_signature_alert_without_fusion",
        "severity": "medium",
        "mitre_like_tags": ["command_execution_theme", "partial_visibility"],
        "internal_tags": ["ai_robustness", "single_engine"],
    },
    "ai-alert-flood": {
        "attack_family": "alert_saturation",
        "behavior_category": "low_confidence_volume",
        "primary_detection_path": "signature_repetition",
        "expected_alert_pattern": "many_signature_alerts_without_fusion",
        "severity": "medium",
        "mitre_like_tags": ["defense_evasion_theme", "alert_flooding"],
        "internal_tags": ["ai_robustness", "triage_pressure"],
    },
    "port-scan-offline": {
        "attack_family": "reconnaissance",
        "behavior_category": "network_scan",
        "primary_detection_path": "signature_plus_anomaly",
        "expected_alert_pattern": "scan_signature_and_threshold_alerts",
        "severity": "medium",
        "mitre_like_tags": ["reconnaissance", "scan_behavior"],
        "internal_tags": ["standard_lab", "baseline_validation"],
    },
    "http-login-bruteforce-offline": {
        "attack_family": "credential_access",
        "behavior_category": "bruteforce_login",
        "primary_detection_path": "anomaly_primary",
        "expected_alert_pattern": "login_threshold_alerts",
        "severity": "high",
        "mitre_like_tags": ["credential_access", "repeated_auth_attempts"],
        "internal_tags": ["standard_lab", "baseline_validation"],
    },
    "flood-burst-offline": {
        "attack_family": "denial_of_service",
        "behavior_category": "dns_burst_and_flood",
        "primary_detection_path": "anomaly_primary",
        "expected_alert_pattern": "burst_and_rate_threshold_alerts",
        "severity": "high",
        "mitre_like_tags": ["impact", "dos_behavior", "burst_activity"],
        "internal_tags": ["standard_lab", "baseline_validation"],
    },
    "mixed-traffic-offline": {
        "attack_family": "multi_vector",
        "behavior_category": "mixed_benign_and_malicious",
        "primary_detection_path": "multi_engine",
        "expected_alert_pattern": "mixed_rule_and_threshold_alerts",
        "severity": "high",
        "mitre_like_tags": ["multi_stage_theme", "mixed_activity"],
        "internal_tags": ["standard_lab", "baseline_validation"],
    },
    "artifact-network-correlation-offline": {
        "attack_family": "correlated_suspicious_activity",
        "behavior_category": "network_plus_artifact_review",
        "primary_detection_path": "signature_plus_artifact_triage",
        "expected_alert_pattern": "signature_alerts_with_high_risk_artifacts",
        "severity": "high",
        "mitre_like_tags": ["suspicious_command_activity", "artifact_correlation"],
        "internal_tags": ["standard_lab", "artifact_correlation"],
    },
}


def taxonomy_key(definition: dict[str, Any]) -> str:
    for candidate in (
        definition.get("slug"),
        definition.get("scenario_name"),
        definition.get("name"),
        definition.get("scenario_id"),
    ):
        token = _safe_slug(str(candidate or ""))
        if token:
            return token
    return "unmapped"


def get_scenario_taxonomy(definition: dict[str, Any]) -> dict[str, Any]:
    key = taxonomy_key(definition)
    expected = dict(definition.get("expected") or {})
    mapped = dict(_TAXONOMY_MAP.get(key) or {})
    notes: list[str] = []
    if not mapped:
        mapped = {
            "attack_family": "unmapped",
            "behavior_category": "unmapped",
            "primary_detection_path": "unknown",
            "expected_alert_pattern": "unspecified",
            "severity": "unknown",
            "mitre_like_tags": [],
            "internal_tags": [],
        }
        notes.append(f"taxonomy_unmapped:{key}")

    return {
        "scenario_name": str(definition.get("scenario_name") or definition.get("name") or definition.get("scenario_id") or key),
        "taxonomy_key": key,
        "attack_family": str(mapped["attack_family"]),
        "behavior_category": str(mapped["behavior_category"]),
        "weakness_tested": str(expected.get("weakness_tested") or definition.get("weakness_tested") or "Not specified."),
        "primary_detection_path": str(mapped["primary_detection_path"]),
        "expected_engines": [str(item) for item in (expected.get("expected_engines") or []) if str(item).strip()],
        "expected_alert_pattern": str(mapped["expected_alert_pattern"]),
        "severity": str(mapped["severity"]),
        "mitre_like_tags": [str(item) for item in (mapped.get("mitre_like_tags") or []) if str(item).strip()],
        "internal_tags": [str(item) for item in (mapped.get("internal_tags") or []) if str(item).strip()],
        "notes": notes,
    }


def taxonomy_summary_markdown(taxonomy: dict[str, Any]) -> str:
    lines = [
        f"# Taxonomy Summary: {taxonomy.get('scenario_name', 'scenario')}",
        "",
        f"- Attack family: `{taxonomy.get('attack_family', '')}`",
        f"- Behavior category: `{taxonomy.get('behavior_category', '')}`",
        f"- Weakness tested: {taxonomy.get('weakness_tested', '')}",
        f"- Primary detection path: `{taxonomy.get('primary_detection_path', '')}`",
        f"- Expected engines: {', '.join(f'`{item}`' for item in (taxonomy.get('expected_engines') or [])) or 'none'}",
        f"- Expected alert pattern: `{taxonomy.get('expected_alert_pattern', '')}`",
        f"- Severity: `{taxonomy.get('severity', '')}`",
        f"- MITRE-like tags: {', '.join(f'`{item}`' for item in (taxonomy.get('mitre_like_tags') or [])) or 'none'}",
        f"- Internal tags: {', '.join(f'`{item}`' for item in (taxonomy.get('internal_tags') or [])) or 'none'}",
    ]
    if taxonomy.get("notes"):
        lines.extend(["", "## Notes", ""])
        for note in taxonomy.get("notes") or []:
            lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def write_taxonomy_bundle(
    *,
    definition: dict[str, Any],
    out_json: str | Path,
    out_md: str | Path,
) -> tuple[Path, Path]:
    taxonomy = get_scenario_taxonomy(definition)
    json_path = Path(out_json)
    md_path = Path(out_md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(taxonomy, indent=2, ensure_ascii=True), encoding="utf-8")
    md_path.write_text(taxonomy_summary_markdown(taxonomy), encoding="utf-8")
    return json_path, md_path
