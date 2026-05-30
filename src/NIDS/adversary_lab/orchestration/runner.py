from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.utils import wrpcap

from ...pipeline.parser import parse_packet
from ..log_emulators import build_normalized_events, build_suricata_events, build_zeek_records
from ..models import LAB_GENERATED_LABEL, LabelEntry, SafetyPolicy, ScenarioMaterial
from ..profiles.defaults import offline_replay_profile
from ..safety import safety_summary, validate_material
from ..scenarios import available_scenarios, build_named_scenario


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp_now() -> str:
    return _utc_now().strftime("%Y%m%d-%H%M%S")


def _safe_slug(value: str) -> str:
    token = "".join(ch.lower() if ch.isalnum() else "-" for ch in value.strip())
    while "--" in token:
        token = token.replace("--", "-")
    return token.strip("-") or "scenario"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(_json_safe_row(row), ensure_ascii=True) + "\n")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _json_safe_row(row: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, (bytes, bytearray)):
            payload[key] = bytes(value)[:256].decode("utf-8", errors="ignore")
            payload[f"{key}_bytes"] = len(value)
        else:
            payload[key] = value
    return payload


def _labels_for_material(material: ScenarioMaterial, pcap_name: str) -> list[dict[str, str]]:
    entries = material.label_entries or [LabelEntry(attack_type=material.attack_type, label=LAB_GENERATED_LABEL)]
    return [entry.as_csv_row(pcap_name) for entry in entries]


def _write_labels(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "pcap_file",
        "start_time",
        "end_time",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "label",
        "attack_type",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    proto_counts: dict[str, int] = {}
    for event in events:
        proto = str(event.get("proto") or "UNKNOWN").upper()
        proto_counts[proto] = proto_counts.get(proto, 0) + 1
    return {
        "event_count": len(events),
        "proto_counts": proto_counts,
        "first_timestamp": str(events[0].get("timestamp") or "") if events else "",
        "last_timestamp": str(events[-1].get("timestamp") or "") if events else "",
    }


def _build_readme(
    *,
    bundle_dir: Path,
    material: ScenarioMaterial,
    pcap_name: str,
    policy: SafetyPolicy,
) -> str:
    return "\n".join(
        [
            f"# {material.name}",
            "",
            "WARNING: This bundle is lab-generated replay material only.",
            "",
            f"- Scenario ID: `{material.scenario_id}`",
            f"- Attack type: `{material.attack_type}`",
            f"- Safety policy: `{policy.name}`",
            f"- Offline bundle only: `{policy.offline_bundle_only}`",
            f"- Pcap: `{pcap_name}`",
            f"- Labels: `labels.csv`",
            f"- Suricata-like log: `suricata_eve.jsonl`",
            f"- Zeek-like log: `zeek_conn.jsonl`",
            "",
            "## Purpose",
            "",
            material.description,
            "",
            "## Guardrails",
            "",
            f"- {policy.banner}",
            "- Do not direct these artifacts at live external targets.",
            "- Use only offline replay, localhost, containers, or explicitly isolated lab CIDRs.",
            "- All labels and attack types are marked as lab-generated.",
            "",
            "## Existing Ingest Paths",
            "",
            "Offline replay:",
            f"`python -m nids run --pcap-dir {bundle_dir / pcap_name} --labels {bundle_dir / 'labels.csv'} --config NIDS_TestLab/config/offline_replay_profile.yml --rules rules/rules.yml --output-dir {bundle_dir / 'runtime_output'} --sensor-id adversary-lab`",
            "",
            "Suricata-style adapter replay:",
            f"`python -m nids run --enable-suricata --suricata-log {bundle_dir / 'suricata_eve.jsonl'} --config config/nids.yml --rules rules/rules.yml --output-dir {bundle_dir / 'suricata_output'} --sensor-id adversary-lab-suricata`",
            "",
            "Zeek-style adapter replay:",
            f"`python -m nids run --enable-zeek --zeek-log {bundle_dir / 'zeek_conn.jsonl'} --config config/nids.yml --rules rules/rules.yml --output-dir {bundle_dir / 'zeek_output'} --sensor-id adversary-lab-zeek`",
            "",
            "## Notes",
            "",
            *[f"- {note}" for note in material.notes],
            "",
        ]
    )


def list_scenarios() -> list[str]:
    return available_scenarios()


def generate_bundle(
    *,
    scenario_name: str,
    output_root: str | Path,
    policy: SafetyPolicy | None = None,
    run_stamp: str | None = None,
) -> dict[str, Any]:
    material = build_named_scenario(scenario_name)
    active_policy = policy or offline_replay_profile()
    validate_material(material, active_policy)

    stamp = run_stamp or _stamp_now()
    scenario_slug = _safe_slug(scenario_name)
    bundle_dir = Path(output_root).resolve() / f"{scenario_slug}-{stamp}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    pcap_name = f"{scenario_slug}.pcap"
    pcap_path = bundle_dir / pcap_name
    wrpcap(str(pcap_path), material.packets)

    labels = _labels_for_material(material, pcap_name)
    labels_path = bundle_dir / "labels.csv"
    _write_labels(labels_path, labels)

    dataset_source = f"pcap:{pcap_name}"
    normalized_events = build_normalized_events(
        material.packets,
        dataset_source=dataset_source,
        label=LAB_GENERATED_LABEL,
        attack_type=material.attack_type,
    )
    _write_jsonl(bundle_dir / "normalized_events.jsonl", normalized_events)
    _write_jsonl(bundle_dir / "suricata_eve.jsonl", build_suricata_events(normalized_events))
    _write_jsonl(bundle_dir / "zeek_conn.jsonl", build_zeek_records(normalized_events))

    manifest = {
        "generated_at": _utc_now().isoformat(timespec="seconds"),
        "scenario_id": material.scenario_id,
        "scenario_name": material.name,
        "scenario_key": scenario_name,
        "attack_type": material.attack_type,
        "lab_generated": True,
        "label": LAB_GENERATED_LABEL,
        "description": material.description,
        "tags": list(material.tags),
        "notes": list(material.notes),
        "target_ips": list(material.target_ips),
        "bundle_dir": str(bundle_dir),
        "pcap_path": str(pcap_path),
        "labels_path": str(labels_path),
        "normalized_events_path": str((bundle_dir / "normalized_events.jsonl").resolve()),
        "suricata_eve_path": str((bundle_dir / "suricata_eve.jsonl").resolve()),
        "zeek_conn_path": str((bundle_dir / "zeek_conn.jsonl").resolve()),
        "packet_count": len(material.packets),
        "event_summary": _event_summary(normalized_events),
        "safety_policy": safety_summary(active_policy),
        "metadata": dict(material.metadata),
    }
    _write_json(bundle_dir / "manifest.json", manifest)
    _write_text(
        bundle_dir / "README.md",
        _build_readme(bundle_dir=bundle_dir, material=material, pcap_name=pcap_name, policy=active_policy),
    )
    return manifest
