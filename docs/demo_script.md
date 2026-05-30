# Demo Script

## General Demo Rules

- Present the project as evidence-backed and research-first.
- Do not say "production-ready."
- Do not imply zero false positives or zero downtime.
- Keep the distinction clear between:
  - implemented
  - validated
  - still in progress

## Suggested Demo Assets

- `docs/project_one_pager.md`
- `docs/current_status.md`
- `NIDS_TestLab/reports/lab_execution_index.md`
- `NIDS_TestLab/reports/prepared_env_validation_index.md`
- one prepared-environment bundle from `PREP-ENV-003`
- one tuning bundle from `PREP-ENV-005`
- one evidence bundle from `LAB-SCN-005`
- dashboard screenshot or live dashboard if already safe to show

## 5-Minute Demo

### 0:00 - 0:45 Opening Explanation

"Universal NIDS is a hybrid intrusion detection workspace that combines live capture, offline replay, multi-engine detection, retained evidence, and analyst-facing reporting. The main point of the project is not only to detect suspicious traffic, but to validate the system in a way that is repeatable and honest about its current boundaries."

### 0:45 - 1:30 Architecture Summary

Show the pipeline:

`ingest -> parse -> features -> signature/anomaly/ML -> fusion -> storage -> dashboard and reports`

Call out that the repo supports live capture, offline replay, optional Suricata/Zeek ingest, and static artifact analysis.

### 1:30 - 2:20 Prepared-Environment Scenario

Use `PREP-ENV-003`.

Talk track:

"This scenario intentionally forced queue pressure on a live prepared environment. The value is that the system retained the degraded behavior instead of hiding it: `8127` packets were received, `23` were processed, `8100` were dropped, and the measured loss was `99.6678%`."

### 2:20 - 3:05 Tuning / Adjudication Example

Use `PREP-ENV-005`.

Talk track:

"The earlier benign soak produced unsupervised-only false positives. Instead of pretending the issue did not exist, the project documents the analyst assessment, the tuning change, and the rerun. The tuned rerun recorded `1416` flows with `0` alerts for the exercised sample."

### 3:05 - 4:00 Evidence Bundle Example

Use `LAB-SCN-005`.

Talk track:

"This bundle shows why the project is useful for analyst review. It retained both network and artifact evidence together: `7` flows, `1` network alert, `4` artifact rows, and `2` quarantined high-risk artifacts."

### 4:00 - 5:00 Current Readiness Verdict And Roadmap

"The current verdict is a controlled pre-deployment candidate, not a production deployment. The biggest open items are a full `6` to `12` hour soak, broader benign-traffic adjudication, and a decision on whether restart-based maintenance is sufficient or hot reload is required."

## 10-Minute Technical Walkthrough

### 0:00 - 1:00 Opening Explanation

"This project is a hybrid NIDS workspace designed to connect detection logic with validation evidence. I want to show the architecture, one live prepared-environment example, one tuning example, and how the evidence is organized."

### 1:00 - 2:30 Architecture Summary

- live capture and offline replay feed the same normalized pipeline
- detection combines signature, anomaly, supervised, optional unsupervised, and fusion
- outputs are retained in SQLite and JSONL
- dashboard, charts, and reports sit on top of the retained evidence
- artifact static analysis can be correlated with network activity

### 2:30 - 4:15 Prepared-Environment Scenario

Use `PREP-ENV-003`.

Points to make:

- prepared Ubuntu sensor VM
- live capture path
- explicit loss accounting
- evidence retained for analyst review
- useful because it shows behavior under stress, not only success paths

### 4:15 - 5:45 Tuning / Adjudication Example

Use `PREP-ENV-005`.

Points to make:

- phase 4 benign sample produced false positives
- the issue was traced to a single unsupervised component dominating the decision
- tuning changed the requirement for active unsupervised agreement
- rerun showed `0` alerts across `1416` flows for the exercised sample
- broader benign review is still pending

### 5:45 - 7:15 Evidence Bundle Explanation

Use `LAB-SCN-005`.

Points to make:

- one bundle can contain network evidence plus artifact triage
- this makes the project easier to demo, review, and defend in a paper or interview
- the bundle retained `2` quarantined high-risk artifacts in addition to the network alert

### 7:15 - 8:30 Validation Snapshot

- `152` collected tests
- `144` passed, `8` deselected
- `79.16%` coverage under a `72%` floor
- `5` latest offline scenario passes
- `10` latest prepared-environment passes across `17` manifests

### 8:30 - 10:00 Current Readiness Verdict And Future Roadmap

- current verdict: controlled pre-deployment candidate
- strongest evidence:
  - repeatable scenarios
  - live prepared-environment validation
  - false-positive tuning record
  - restart-based operator workflows
- next steps:
  - full-duration soak
  - broader benign adjudication
  - suppression-specific live evidence
  - product decision on maintenance workflow expectations

## 20-Minute Presentation

### 0:00 - 2:00 Opening Explanation

"This presentation is about a hybrid intrusion detection workspace and, more importantly, how it was validated. The goal is to show a project that moves beyond a single dashboard or classifier and toward a repository with repeatable evidence, documented tuning, and honest release boundaries."

### 2:00 - 5:00 Architecture Summary

Cover:

- live capture
- offline replay
- optional Suricata/Zeek ingest
- parsing and feature extraction
- signature and anomaly engines
- supervised ensemble and optional unsupervised scoring
- fusion, suppression, and retained outputs
- dashboard, charts, reports, and artifact correlation

### 5:00 - 8:00 Offline Scenario Story

Use `LAB-SCN-001` through `LAB-SCN-005` at a high level.

Key message:

"The offline suite gives repeatable scenario evidence across several attack families and also includes an artifact-correlation case. This makes the project easier to test, present, and compare over time."

### 8:00 - 11:00 Prepared-Environment Scenario Story

Use `PREP-ENV-003`.

Key message:

"Prepared-environment validation is where the project becomes more defensible. It captures how the system behaves under a real execution path, including stress. In this case, the scenario preserved queue and drop evidence rather than hiding it."

### 11:00 - 13:30 Tuning / Adjudication Story

Use `PREP-ENV-005`.

Key message:

"The project does not present tuning as magic. It shows the false-positive issue, the operator reasoning, the narrow tuning change, and the rerun result. That is much closer to real detection engineering than simply reporting a threshold number."

### 13:30 - 15:30 Operator Workflow Story

Use `PREP-ENV-008`, `PREP-ENV-009`, and `PREP-ENV-010`.

Key message:

"Rule refresh, model swap, and config override have all been validated, but as restart-based workflows. That is an implemented and validated capability. Zero-downtime reload is not currently a validated claim."

### 15:30 - 17:00 Soak Story

Use `PREP-ENV-007`.

Key message:

"The soak story is promising but intentionally incomplete. The current evidence is a `900s` pilot with `4742` flows, `0` alerts, and `13.251s` restart latency. The target is still `21600s`, so the honest claim is pilot evidence, not full operational signoff."

### 17:00 - 18:30 Evidence Bundle Explanation

Use `LAB-SCN-005` or one prepared-environment bundle.

Key message:

"One strength of the project is that the outputs are easy to audit: manifests, summaries, reports, logs, SQLite, JSONL, and artifact evidence live together in structured bundles."

### 18:30 - 20:00 Current Verdict And Roadmap

"Today I would position this as a research-first, open-source-ready project with evidence-backed validation. The current release story is strong enough for publication prep, portfolio use, and controlled pre-deployment review. The next milestones are the full-duration soak, broader benign-corpus validation, a suppression-specific live exercise, and a clear decision on whether restart-based maintenance is sufficient for the intended deployment profile."
