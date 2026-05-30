from __future__ import annotations

import json
from pathlib import Path

from src.NIDS.threat_intel import IPReputationProvider, IntelCache, ThreatIntelEnricher


def test_ip_reputation_provider_loads_inline_and_file_indicators(tmp_path: Path) -> None:
    indicator_path = tmp_path / "indicators.json"
    indicator_path.write_text(
        json.dumps(
            {
                "indicators": [
                    {
                        "ip": "203.0.113.10",
                        "source": "fixture-file",
                        "severity": "high",
                        "category": "c2",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    provider = IPReputationProvider(
        indicators_path=indicator_path,
        inline_indicators=[
            {
                "ip": "198.51.100.20",
                "source": "fixture-inline",
                "severity": "medium",
                "category": "scanner",
            }
        ],
    )

    assert provider.lookup("203.0.113.10")["source"] == "fixture-file"
    assert provider.lookup("198.51.100.20")["source"] == "fixture-inline"
    assert provider.lookup("192.0.2.10") is None


def test_intel_cache_persists_entries(tmp_path: Path) -> None:
    cache_path = tmp_path / "intel_cache.json"
    cache = IntelCache(cache_path=cache_path, ttl_sec=300)
    cache.set("dst:203.0.113.10", {"found": True, "indicator": {"ip": "203.0.113.10"}})

    reloaded = IntelCache(cache_path=cache_path, ttl_sec=300)
    entry = reloaded.get("dst:203.0.113.10")

    assert entry is not None
    assert entry["indicator"]["ip"] == "203.0.113.10"


def test_threat_intel_enricher_enriches_existing_alerts_and_emits_match_alert() -> None:
    enricher = ThreatIntelEnricher(
        {
            "enabled": True,
            "emit_match_alerts": True,
            "cooldown_sec": 600,
            "inline_indicators": [
                {
                    "ip": "203.0.113.10",
                    "source": "fixture-inline",
                    "severity": "high",
                    "category": "malicious_infrastructure",
                }
            ],
        }
    )

    flow_record = {
        "timestamp": "2026-03-14T15:00:00+00:00",
        "src_ip": "10.10.10.10",
        "dst_ip": "203.0.113.10",
    }
    alerts = [
        {
            "engine": "signature",
            "severity": "medium",
            "rule_name": "Existing Signature",
            "summary": "base alert",
            "extra": {"existing": True},
        }
    ]

    enriched = enricher.process(flow_record, alerts)

    assert len(enriched) == 2
    assert enriched[0]["extra"]["threat_intel"]["matches"][0]["ip"] == "203.0.113.10"
    assert any(alert["engine"] == "threat_intel" for alert in enriched)
