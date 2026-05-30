# Quantum Readiness Plan

Last updated: March 12, 2026

This plan is intentionally conservative. It does not assume unrealistic quantum capabilities or immediate migration of every NIDS component. It focuses on crypto agility, evidence integrity, and long-lived security data that could be exposed to harvest-now-decrypt-later risk [7][8][9].

## Scope

The NIDS project currently depends on:

- transport security provided by the platform stack for dashboard/API and webhook delivery
- hashes for artifact identification and evidence correlation
- serialized model artifacts and baseline snapshots
- reports, logs, and validation evidence that may need long retention

## Realistic Risks

### Harvest-Now-Decrypt-Later

Stored traffic captures, archived lab evidence, and any retained sensitive telemetry may be exposed later if today’s public-key protections are broken by future quantum-capable adversaries. This matters most for long-lived or high-sensitivity data.

### Long-Term Log Integrity

Hashing alone is not provenance. If reports, JSONL outputs, and exported evidence bundles need multi-year trust, they should be signed and accompanied by retained verification metadata.

### Model and Baseline Integrity

This repository stores model files and unsupervised baseline snapshots. Those artifacts need provenance controls so an operator can verify what model or baseline was used for a given validation run.

### Artifact Authenticity

Static triage results, quarantine decisions, and evidence packages should be attributable to a known code and ruleset version, not just to file hashes.

## Planning Principles

1. Prefer crypto agility over hard-coded algorithm assumptions.
2. Treat retained telemetry and evidence as future-sensitive data.
3. Separate short-term operational controls from long-term migration work.
4. Protect integrity of models, rules, reports, and evidence bundles alongside confidentiality concerns.

## Near-Term Actions

### 1. Inventory Cryptographic Touchpoints

Track where the project depends on cryptographic trust today:

- webhook/API transport security
- dashboard/API token handling
- model artifact storage
- unsupervised baseline snapshots
- report and evidence package retention

### 2. Add Evidence Manifests

For major validation bundles, store:

- file list
- SHA-256 hash set
- rules version
- model version
- runtime config profile
- test run timestamp

This is not a full PQC migration, but it improves future integrity verification.

### 3. Make Model and Rules Provenance Explicit

Attach model metadata and ruleset metadata to generated reports and lab evidence so future reviewers know exactly what detection package produced a result.

### 4. Minimize Retention of Sensitive Raw Data

Retain only the raw packet captures and sensitive artifacts that are operationally justified. Summaries, counts, and non-sensitive derived metrics are less exposed to future decryption risk.

## Medium-Term Actions

### 1. Track Platform Readiness for PQC

Monitor the underlying crypto stacks used by:

- Python/OpenSSL packaging
- operating system TLS implementations
- webhook endpoints and reverse proxies
- any future remote-control or evidence-signing services

### 2. Plan for Signature and Timestamp Agility

Where evidence authenticity matters, plan for versioned signing and timestamping so algorithm upgrades can be introduced without breaking verification history.

### 3. Separate Integrity from Confidentiality Decisions

Some artifacts need integrity proof even if confidentiality is lower sensitivity. Logs, reports, and model files fall into this category.

## Out of Scope

- No claim that the current NIDS gains “quantum-resistant detection.”
- No claim that PQC alone solves insider abuse, traffic analysis, or unsafe model handling.
- No assumption that immediate migration is practical for every dependency in this repository.

## Practical Recommendation

Treat quantum readiness here as an evidence-integrity and crypto-agility program first. The next concrete step is to add manifest metadata and signing strategy to lab result bundles, then track upstream platform readiness for future PQC-capable transport and verification workflows.

## References

[7] *Post-Quantum Cryptography Project*, National Institute of Standards and Technology, https://csrc.nist.gov/projects/post-quantum-cryptography

[8] *NIST Releases First 3 Finalized Post-Quantum Encryption Standards*, National Institute of Standards and Technology, https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards

[9] NIST IR 8547 (Initial Public Draft), *Transition to Post-Quantum Cryptography Standards*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/ir/8547/ipd
