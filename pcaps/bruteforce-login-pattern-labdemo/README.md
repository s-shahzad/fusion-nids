# Brute-Force Login Pattern Simulation

WARNING: This bundle is lab-generated replay material only.

- Scenario ID: `ADVLAB-002`
- Attack type: `lab_generated:bruteforce_login_pattern`
- Safety policy: `offline-replay-only`
- Offline bundle only: `True`
- Pcap: `bruteforce-login-pattern.pcap`
- Labels: `labels.csv`
- Suricata-like log: `suricata_eve.jsonl`
- Zeek-like log: `zeek_conn.jsonl`

## Purpose

Repeated failed HTTP login attempts against a mock localhost service.

## Guardrails

- Lab-generated adversary emulation only. Generate artifacts only for offline replay, localhost, containers, or explicitly configured isolated lab CIDRs.
- Do not direct these artifacts at live external targets.
- Use only offline replay, localhost, containers, or explicitly isolated lab CIDRs.
- All labels and attack types are marked as lab-generated.

## Existing Ingest Paths

Offline replay:
`python -m nids run --pcap-dir pcaps\bruteforce-login-pattern-labdemo\bruteforce-login-pattern.pcap --labels pcaps\bruteforce-login-pattern-labdemo\labels.csv --config lab/config/offline_replay_profile.yml --rules rules/rules.yml --output-dir pcaps\bruteforce-login-pattern-labdemo\runtime_output --sensor-id adversary-lab`

Suricata-style adapter replay:
`python -m nids run --enable-suricata --suricata-log pcaps\bruteforce-login-pattern-labdemo\suricata_eve.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\bruteforce-login-pattern-labdemo\suricata_output --sensor-id adversary-lab-suricata`

Zeek-style adapter replay:
`python -m nids run --enable-zeek --zeek-log pcaps\bruteforce-login-pattern-labdemo\zeek_conn.jsonl --config config/nids.yml --rules rules/rules.yml --output-dir pcaps\bruteforce-login-pattern-labdemo\zeek_output --sensor-id adversary-lab-zeek`

## Notes

- No credential theft or service access is performed.
- The bundle only replays failed-login-shaped traffic against a mock endpoint.
