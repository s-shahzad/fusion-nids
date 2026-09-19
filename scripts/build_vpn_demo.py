"""Build offline demo evidence with the real signature engine; send no packets."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.nids.detect.signature import SignatureEngine


def build_evidence() -> dict:
    engine = SignatureEngine(ROOT / "demo/vpn/demo-rule.yml")
    event = {
        "proto": "TCP", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
        "src_port": 51000, "dst_port": 3389, "dataset_source": "vpn-demo",
        "payload": b"",
    }
    alerts = engine.detect(event, {})
    benign = engine.detect({**event, "dst_port": 443}, {})
    if len(alerts) != 1 or benign:
        raise RuntimeError("Demo detector contract failed; do not publish fixture")
    return {
        "mode": "synthetic-offline", "engine": "Fusion NIDS SignatureEngine",
        "description": "Saved output of a real detector using synthetic input; not live traffic.",
        "positive_alert_count": len(alerts), "negative_alert_count": len(benign),
        "alerts": alerts,
        "event": {key: value for key, value in event.items() if key != "payload"},
    }


if __name__ == "__main__":
    evidence = build_evidence()
    target = ROOT / "demo/vpn/evidence.json"
    target.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("PASS: synthetic restricted-port event -> 1 alert; benign HTTPS event -> 0 alerts")
