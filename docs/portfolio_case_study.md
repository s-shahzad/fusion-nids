# Universal NIDS: Building A Hybrid Intrusion Detection Workspace With Evidence-Backed Validation

## Problem

Many IDS projects look convincing in a demo but are harder to defend under technical scrutiny. A classifier may score well on a dataset, yet the surrounding system can still lack repeatable validation, retained evidence, operator workflow support, and clear boundaries around what has and has not been proven. That gap matters in cybersecurity work, where a project needs to show not only what it can detect, but how it behaves in realistic scenarios and how honestly it handles residual risk.

## Approach

Universal NIDS was built as a hybrid intrusion detection workspace rather than a single detector. The project combines live packet capture, offline replay, optional adapter ingest, static artifact analysis, multi-engine detection, retained evidence, and analyst-facing reporting in one repository. Just as importantly, the project was developed with a validation-first mindset: repeatable scenarios, prepared-environment runs, false-positive adjudication, and readiness documentation were treated as first-class outputs rather than afterthoughts.

## Architecture

The core pipeline is:

`ingest -> parse and normalize -> feature extraction -> signature/anomaly/ML scoring -> fusion -> suppression -> SQLite/JSONL retention -> dashboard, charts, and reports`

This architecture supports:

- live interface capture
- offline PCAP replay
- optional Suricata/Zeek JSON ingest
- signature detection
- statistical anomaly detection
- supervised ensemble scoring
- optional unsupervised scoring
- fusion-based alerting
- static artifact triage without file execution

The result is a workspace that can be used for engineering, demo, research, and evidence review, not only one-off alert generation.

## Validation

The project is supported by multiple validation layers rather than a single benchmark number.

### Software Validation

- `152` tests collected
- `144` passed, `8` deselected in the default suite
- `0` active pytest warnings
- `79.16%` coverage with a `72%` enforced floor

### Scenario Validation

- `5` latest offline lab scenarios passed
- `10` latest prepared-environment scenarios passed across `17` retained manifests

### Prepared-Environment Highlights

- `PREP-ENV-003` retained queue-pressure evidence with `8127` packets received, `23` processed, `8100` dropped, and `99.6678%` loss
- `PREP-ENV-005` documented a false-positive issue, applied a narrow tuning change, and reran the exercised benign sample to `1416` flows with `0` alerts
- `PREP-ENV-008` through `PREP-ENV-010` validated restart-based rule refresh, model swap, and configuration override workflows

### Evidence Packaging

The project retains scenario results as structured bundles with manifests, summaries, logs, SQLite or JSONL output, reports, and indexes. One of the strongest examples is `LAB-SCN-005`, which retained `7` flows, `1` network alert, `4` artifact rows, and `2` quarantined high-risk artifacts in one evidence package.

## Results

The strongest outcome is not a single score. It is the combination of:

- a working hybrid IDS architecture
- a broader test and coverage baseline
- repeatable offline scenario execution
- prepared-environment live validation
- documented false-positive tuning
- restart-based operator workflow evidence

There is also useful offline supervised-evaluation evidence in the current repo, including `0.99784` accuracy and `0.99792` weighted F1 on `25000` labeled flows. Those numbers are helpful, but they are presented here as offline evaluation evidence rather than as a substitute for live validation.

## Current Status

The current verdict is a `conditional go for a controlled pre-deployment candidate`.

That means the project is beyond prototype-only validation and strong enough for:

- portfolio presentation
- technical interviews
- thesis or paper preparation
- controlled demos
- open-source research-first release planning

It does not yet mean:

- production-ready deployment
- full operational signoff
- zero-downtime maintenance validation
- universal benign-traffic confidence

## Next Steps

- complete the full `6` to `12` hour prepared-environment soak beyond the current `900s` pilot
- broaden benign false-positive adjudication beyond the current tuned sample
- add a suppression-specific prepared-environment exercise
- decide whether restart-based maintenance is sufficient or whether hot reload is required
- curate redacted public evidence packs, figures, and screenshots for publication and showcase use

## Why This Case Study Works

The project stands out because it treats validation evidence as part of the engineering deliverable. Instead of stopping at a model metric or dashboard screenshot, it shows how a hybrid IDS can be built, tested, challenged, tuned, and documented with clear claims and clear limits. That makes it stronger as a paper, case study, portfolio project, and interview topic than a more polished but less defensible demo.
