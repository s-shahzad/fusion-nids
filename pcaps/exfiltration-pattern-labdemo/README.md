# Exfiltration-Like Transfer Simulation

WARNING: This bundle is lab-generated replay material only.

- Scenario ID: `ADVLAB-004`
- Attack type: `lab_generated:exfiltration_pattern`
- Safety policy: `offline-replay-only`
- Offline bundle only: `True`
- Pcap: `exfiltration-pattern.pcap`
- Labels: `labels.csv`
- Suricata-like log: `suricata_eve.jsonl`
- Zeek-like log: `zeek_conn.jsonl`

## Purpose

Dummy DNS and HTTP transfer patterns that resemble covert data egress without using real data.

## Guardrails

- Lab-generated adversary emulation only. Generate artifacts only for offline replay, localhost, containers, or explicitly configured isolated lab CIDRs.
- Do not direct these artifacts at live external targets.
- Use only offline replay, localhost, containers, or explicitly isolated lab CIDRs.
- All labels and attack types are marked as lab-generated.

## Existing Ingest Paths

Offline replay:
`python -m nids run --pcap-dir pcaps\exfiltration-pattern-labdemo\exfiltration-pattern.pcap --labels pcaps\exfiltration-pattern-labdemo\labels.csv --config lab/config/offline_replay_profile.yml --rules rules/rules.yml --output-dir pcaps\exfiltration-pattern-labdemo\runtime_output --sensor-id adversary-lab`

Suricata-style adapter replay:
`python -m nids run --enable-suricata --suricata-log pcaps\exfiltration-pattern-labdemo\suricata_eve.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\exfiltration-pattern-labdemo\suricata_output --sensor-id adversary-lab-suricata`

Zeek-style adapter replay:
`python -m nids run --enable-zeek --zeek-log pcaps\exfiltration-pattern-labdemo\zeek_conn.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\exfiltration-pattern-labdemo\zeek_output --sensor-id adversary-lab-zeek`

## Notes

- Only dummy strings are transmitted.
- No files, secrets, or live external targets are involved.
