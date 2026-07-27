# Campaign-Style Chained Simulation

WARNING: This bundle is lab-generated replay material only.

- Scenario ID: `ADVLAB-007`
- Attack type: `lab_generated:campaign_chain_pattern`
- Safety policy: `offline-replay-only`
- Offline bundle only: `True`
- Pcap: `campaign-chain-pattern.pcap`
- Labels: `labels.csv`
- Suricata-like log: `suricata_eve.jsonl`
- Zeek-like log: `zeek_conn.jsonl`

## Purpose

Recon, mock auth abuse, beaconing, and dummy exfiltration-like flows chained into one offline lab scenario.

## Guardrails

- Lab-generated adversary emulation only. Generate artifacts only for offline replay, localhost, containers, or explicitly configured isolated lab CIDRs.
- Do not direct these artifacts at live external targets.
- Use only offline replay, localhost, containers, or explicitly isolated lab CIDRs.
- All labels and attack types are marked as lab-generated.

## Existing Ingest Paths

Offline replay:
`python -m nids run --pcap-dir pcaps\campaign-chain-pattern-labdemo\campaign-chain-pattern.pcap --labels pcaps\campaign-chain-pattern-labdemo\labels.csv --config lab/config/offline_replay_profile.yml --rules rules/rules.yml --output-dir pcaps\campaign-chain-pattern-labdemo\runtime_output --sensor-id adversary-lab`

Suricata-style adapter replay:
`python -m nids run --enable-suricata --suricata-log pcaps\campaign-chain-pattern-labdemo\suricata_eve.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\campaign-chain-pattern-labdemo\suricata_output --sensor-id adversary-lab-suricata`

Zeek-style adapter replay:
`python -m nids run --enable-zeek --zeek-log pcaps\campaign-chain-pattern-labdemo\zeek_conn.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\campaign-chain-pattern-labdemo\zeek_output --sensor-id adversary-lab-zeek`

## Notes

- All behavior is synthetic and lab-generated.
- No exploit, shell, persistence, or unauthorized access logic is included.
