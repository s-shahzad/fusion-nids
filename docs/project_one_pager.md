# Universal NIDS

**Tagline:** Hybrid intrusion detection with evidence-backed lab validation.

## Summary

Universal NIDS is a hybrid intrusion detection workspace that combines live packet capture, offline PCAP replay, optional Suricata/Zeek ingest, static artifact triage, multi-engine detection, retained evidence, and analyst-facing reporting in one repository.

## Architecture Summary

`ingest -> parse and normalize -> feature extraction -> signature/anomaly/ML scoring -> fusion -> suppression -> SQLite/JSONL retention -> dashboard, charts, and reports`

## Major Features

- Live interface capture plus offline replay in the same pipeline
- Signature, anomaly, supervised ensemble, optional unsupervised scoring, and fusion-based alerting
- SQLite and JSONL evidence retention
- Dashboard and report generation for analyst review
- Static artifact intake and triage without file execution
- Repeatable offline lab scenarios and prepared-environment validation helpers

## Validation Milestones

| Milestone | Current state |
|---|---|
| Phase 1 testing expansion | Complete |
| Phase 2 operational validation scaffolding | Complete |
| Phase 3 offline lab execution evidence | Complete |
| Phase 4 prepared-environment validation | Complete |
| Phase 5 live tuning and adjudication | Complete |

## Current Metrics

| Measure | Result |
|---|---:|
| Total collected tests | `152` |
| Default suite result | `144 passed, 8 deselected` |
| Active pytest warnings | `0` |
| Coverage | `79.16%` |
| Coverage floor | `72%` |
| Latest offline scenario passes | `5` |
| Latest prepared-environment passes | `10` |
| Total prepared-environment manifests | `17` |
| Tuned benign soak outcome | `1416` flows, `0` alerts |
| Soak pilot outcome | `4742` flows, `0` alerts, `13.251s` restart latency in a `900s` pilot |

## Validation Highlights

- `PREP-ENV-003` retained queue-depth and packet-loss evidence under live pressure.
- `PREP-ENV-005` reduced the exercised benign-soak sample to `0` alerts after targeted tuning.
- `PREP-ENV-008` through `PREP-ENV-010` validated restart-based operator workflows for rule refresh, model swap, and configuration override.
- `LAB-SCN-005` retained network and artifact evidence together, including `2` quarantined high-risk artifacts.

## Current Readiness

Current verdict: `Conditional go for a controlled pre-deployment candidate`

This is evidence-backed engineering work with a strong lab story. It should not yet be presented as a production deployment or a finished commercial security platform.

## Roadmap Snapshot

- Complete the full `6` to `12` hour prepared-environment soak
- Broaden benign false-positive adjudication beyond the current tuned sample
- Add a suppression-focused prepared-environment exercise
- Decide whether restart-based maintenance is sufficient or whether hot reload is required
- Prepare redacted evidence exports, diagrams, and demo assets for publication and public showcase use

## Publication / Showcase / Release Goals

- Publication:
  - convert the current validation record into a paper, poster, or thesis-ready narrative
- Showcase:
  - present the project as a hybrid NIDS with evidence-backed validation
- Release:
  - position the repository as research-first and open-source-first
- Future monetization:
  - explore training and consulting only after readiness boundaries, support scope, and evidence packaging are clearer
