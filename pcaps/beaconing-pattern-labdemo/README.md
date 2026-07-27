# Beaconing Pattern Simulation

WARNING: This bundle is lab-generated replay material only.

- Scenario ID: `ADVLAB-003`
- Attack type: `lab_generated:beaconing_pattern`
- Safety policy: `offline-replay-only`
- Offline bundle only: `True`
- Pcap: `beaconing-pattern.pcap`
- Labels: `labels.csv`
- Suricata-like log: `suricata_eve.jsonl`
- Zeek-like log: `zeek_conn.jsonl`

## Purpose

Regular periodic callback traffic to a documentation-only collector address.

## Guardrails

- Lab-generated adversary emulation only. Generate artifacts only for offline replay, localhost, containers, or explicitly configured isolated lab CIDRs.
- Do not direct these artifacts at live external targets.
- Use only offline replay, localhost, containers, or explicitly isolated lab CIDRs.
- All labels and attack types are marked as lab-generated.

## Existing Ingest Paths

Offline replay:
`python -m nids run --pcap-dir pcaps\beaconing-pattern-labdemo\beaconing-pattern.pcap --labels pcaps\beaconing-pattern-labdemo\labels.csv --config lab/config/offline_replay_profile.yml --rules rules/rules.yml --output-dir pcaps\beaconing-pattern-labdemo\runtime_output --sensor-id adversary-lab`

Suricata-style adapter replay:
`python -m nids run --enable-suricata --suricata-log pcaps\beaconing-pattern-labdemo\suricata_eve.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\beaconing-pattern-labdemo\suricata_output --sensor-id adversary-lab-suricata`

Zeek-style adapter replay:
`python -m nids run --enable-zeek --zeek-log pcaps\beaconing-pattern-labdemo\zeek_conn.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\beaconing-pattern-labdemo\zeek_output --sensor-id adversary-lab-zeek`

## Notes

- Uses documentation-only destination IP space.
- Intended to validate timing-aware behavioral detectors.
