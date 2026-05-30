# Safe Adversary Emulation Framework

Date: March 14, 2026

## Purpose

The adversary-lab framework adds a safe, lab-only way to generate hostile-pattern
traffic for Universal NIDS validation without introducing exploit code,
malware, credential theft, persistence, propagation, or unauthorized access
logic.

The framework is designed to strengthen validation of:

- existing signature detection
- existing anomaly detection
- optional campaign-behavior detection
- optional exfiltration-behavior detection
- offline replay and adapter-ingest paths
- evidence labeling and analyst interpretation

## Safety Boundary

The framework is intentionally constrained.

- default mode is offline bundle generation only
- generated outputs are replay artifacts, not live attack execution
- supported target spaces are:
  - localhost
  - private lab ranges
  - documentation-only IP ranges
  - explicitly configured isolated lab CIDRs
- all generated evidence is labeled `lab_generated`
- every generated scenario uses dummy data only

The framework does not implement:

- exploit weaponization
- shell delivery
- credential theft
- persistence
- propagation
- destructive actions
- internet targeting
- stealth for real-world misuse

## Module Layout

- `src/NIDS/adversary_lab/scenarios/`
- `src/NIDS/adversary_lab/traffic_generators/`
- `src/NIDS/adversary_lab/log_emulators/`
- `src/NIDS/adversary_lab/validators/`
- `src/NIDS/adversary_lab/profiles/`
- `src/NIDS/adversary_lab/orchestration/`

## Supported Scenarios

1. `port_scan_pattern`
   - TCP SYN sweep against a mock internal target
   - useful for existing scan signature/anomaly validation
2. `bruteforce_login_pattern`
   - repeated failed login-shaped HTTP posts to localhost/mock service paths
   - useful for HTTP login brute-force threshold validation
3. `beaconing_pattern`
   - periodic callback-style HTTP traffic to documentation-only collector space
   - useful for timing-pattern validation
4. `exfiltration_pattern`
   - dummy high-entropy DNS queries plus staged archive-upload-shaped HTTP posts
   - useful for exfiltration and signature validation
5. `lateral_sequence_pattern`
   - internal service probing across multiple hosts without any real access logic
   - useful for campaign and internal sequencing analysis
6. `protocol_anomaly_pattern`
   - malformed-input replay material for parser and anomaly validation
   - generated only as offline artifacts
7. `campaign_chain_pattern`
   - recon plus auth abuse plus beaconing plus exfil-like transfer in one chained bundle
   - useful for higher-order behavioral validation

## Generated Artifacts

Each generated bundle includes:

- one `.pcap` file for offline replay
- `labels.csv` for offline flow labeling
- `normalized_events.jsonl`
- `suricata_eve.jsonl`
- `zeek_conn.jsonl`
- `manifest.json`
- `README.md`

This means one scenario can be replayed through:

- offline PCAP ingest
- Suricata-style JSON adapter ingest
- Zeek-style JSON adapter ingest

## Evidence Labeling

Generated traffic is marked for analysts and validation tooling.

- `label`: `lab_generated`
- `attack_type`: `lab_generated:<scenario_name>`
- manifest field: `lab_generated: true`

This keeps generated evidence clearly separated from organic traffic and from
historical retained evidence.

## How To Run

List supported scenarios:

```powershell
python scripts/run_adversary_lab.py --list
```

Generate one bundle:

```powershell
python scripts/run_adversary_lab.py --scenario port_scan_pattern
```

Generate with an explicit isolated lab CIDR profile:

```powershell
python scripts/run_adversary_lab.py --scenario campaign_chain_pattern --profile explicit-lab-cidrs --lab-cidr 10.77.0.0/24
```

Replay through the existing offline ingest path:

```powershell
python -m nids run --pcap-dir <bundle>.pcap --labels labels.csv --config NIDS_TestLab/config/offline_replay_profile.yml --rules rules/rules.yml --output-dir runtime_output --sensor-id adversary-lab
```

## Validation Value

The framework improves validation coverage without changing core runtime logic.

- it strengthens repeatable adversarial-pattern replay
- it exercises behavioral modules under controlled conditions
- it improves labeling discipline for lab-generated evidence
- it keeps detector validation inside a legally safer, non-destructive workflow

## Operational Rule

Treat the adversary-lab framework as research validation infrastructure only.
Do not use it against real systems, third-party services, external networks, or
unauthorized targets.
