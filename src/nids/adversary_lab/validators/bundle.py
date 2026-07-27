from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def validate_bundle(bundle_dir: str | Path) -> dict[str, Any]:
    root = Path(bundle_dir).resolve()
    manifest_path = root / "manifest.json"
    labels_path = root / "labels.csv"
    pcap_files = sorted(root.glob("*.pcap"))
    normalized_path = root / "normalized_events.jsonl"
    suricata_path = root / "suricata_eve.jsonl"
    zeek_path = root / "zeek_conn.jsonl"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    with labels_path.open("r", encoding="utf-8", newline="") as handle:
        labels = list(csv.DictReader(handle))

    return {
        "bundle_dir": str(root),
        "manifest_exists": manifest_path.exists(),
        "labels_exists": labels_path.exists(),
        "pcap_files": [str(item.name) for item in pcap_files],
        "normalized_exists": normalized_path.exists(),
        "suricata_exists": suricata_path.exists(),
        "zeek_exists": zeek_path.exists(),
        "label_rows": len(labels),
        "attack_types": sorted({str(row.get("attack_type") or "") for row in labels if str(row.get("attack_type") or "")}),
        "lab_generated": bool(manifest.get("lab_generated")),
    }
