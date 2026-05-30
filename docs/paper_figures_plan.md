# Paper Figures Plan

## Purpose

This plan defines the minimum figure set needed to turn the current paper draft into a submission-ready manuscript. The figures below are chosen to match the current repository state and should stay aligned with the evidence-backed, research-first framing of the project.

## Figure Set Overview

| Figure ID | Working title | Purpose | Current source inputs | Status |
|---|---|---|---|---|
| Fig. 1 | Hybrid NIDS Architecture | Show the end-to-end system structure | `thesis/diagrams/system_architecture.mmd`, `documentation/architecture.md` | Draftable now |
| Fig. 2 | Layered Validation Workflow | Show how testing, offline scenarios, prepared environments, and readiness review fit together | `docs/testing_validation_master.md`, `docs/current_status.md` | Draftable now |
| Fig. 3 | Scenario And Evidence Workflow | Show how a scenario run becomes a retained evidence bundle | `scripts/run_lab_scenario.py`, `scripts/prepared_env_validation.py`, `docs/evidence_inventory.md` | Draftable now |
| Fig. 4 | False-Positive Tuning And Adjudication | Show phase 4 benign false positives, tuning change, and phase 5 rerun outcome | `docs/false_positive_analysis.md`, `PREP-ENV-005` bundle | Draftable now |
| Fig. 5 | Soak And Performance Evidence Snapshot | Show the current soak pilot and runtime metrics without overstating maturity | `PREP-ENV-007`, `reports/graphs/`, `docs/current_status.md` | Draftable now |
| Fig. 6 | Deployment-Readiness Summary | Show validated capabilities, open gaps, and current verdict | `docs/deployment_readiness_checklist.md`, `docs/current_status.md`, `state/project_status.json` | Draftable now |

## Figure 1: Hybrid NIDS Architecture

### Goal

Provide a clean system diagram for the paper introduction and architecture section.

### Content

- live capture path
- offline PCAP replay path
- optional Suricata/Zeek adapter ingest
- parser and feature extraction
- signature engine
- statistical anomaly engine
- supervised ensemble
- optional unsupervised path
- fusion and suppression
- SQLite and JSONL retention
- dashboard, charts, reports, and artifact static analysis

### Source Material

- `thesis/diagrams/system_architecture.mmd`
- `documentation/architecture.md`

### Recommended Output

- one clean PNG or SVG export for paper use
- one simplified variant if a poster or slide version is needed

### Caption Draft

"Architecture of the hybrid intrusion detection workspace, showing ingestion, feature extraction, multi-engine detection, fusion, retention, and analyst-facing outputs."

## Figure 2: Layered Validation Workflow

### Goal

Show that the project is validated through multiple layers, not only a model evaluation step.

### Content

- default pytest suite and coverage gate
- extended marker-based slices
- offline scenario execution
- prepared-environment validation
- analyst adjudication
- deployment-readiness review

### Source Material

- `docs/testing_validation_master.md`
- `docs/current_status.md`
- `state/project_status.json`

### Recommended Visual Form

- staircase diagram or left-to-right pipeline
- emphasize the current validated counts:
  - `152` collected tests
  - `144` passed, `8` deselected
  - `79.16%` coverage
  - `5` offline scenario passes
  - `10` latest prepared-environment passes across `17` manifests

### Caption Draft

"Layered validation workflow used to assess the workspace, from deterministic software tests to repeatable scenarios, prepared-environment execution, and readiness review."

## Figure 3: Scenario And Evidence Workflow

### Goal

Explain how a scenario execution produces a reusable evidence package.

### Content

- select scenario
- run offline or prepared-environment path
- capture runtime outputs
- generate reports and indexes
- retain manifest, logs, SQLite, JSONL, charts, and summaries
- use bundle for analyst review, demo, or paper evidence

### Source Material

- `scripts/run_lab_scenario.py`
- `scripts/prepared_env_validation.py`
- `docs/evidence_inventory.md`
- `NIDS_TestLab/reports/lab_execution_index.md`
- `NIDS_TestLab/reports/prepared_env_validation_index.md`

### Recommended Visual Form

- flow diagram with one bundle box at the end
- optional callouts listing:
  - manifest
  - summary markdown
  - runtime log
  - SQLite / JSONL
  - charts
  - operator notes

### Caption Draft

"Scenario-to-evidence workflow, showing how offline and prepared-environment runs are converted into retained, reviewable evidence bundles."

## Figure 4: False-Positive Tuning And Adjudication

### Goal

Show the most defensible tuning story in the current repo state.

### Content

- phase 4 benign soak produced unsupervised-only alerts
- root cause: single active unsupervised component dominating the decision
- tuning change: minimum active unsupervised components raised to `2`
- phase 5 tuned rerun result: `1416` flows, `0` alerts
- caution note: exercised sample cleared, not universal benign guarantee

### Source Material

- `docs/false_positive_analysis.md`
- `NIDS_TestLab/results/phase4-live-benign-soak-20260312-143826/`
- `NIDS_TestLab/results/phase5-tuning/phase5-benign-soak-tuned-20260312-163849/`

### Recommended Visual Form

- before/after comparison figure
- two-panel timeline or alert-count comparison

### Caption Draft

"False-positive tuning and adjudication for the exercised benign-soak sample. The tuned rerun removed the observed unsupervised-only alerts without being presented as a universal benign-traffic guarantee."

## Figure 5: Soak And Performance Evidence Snapshot

### Goal

Present the current performance and soak evidence honestly.

### Content

- `PREP-ENV-007` pilot duration: `900s`
- target duration: `21600s`
- `4742` flows
- `0` alerts
- restart latency: `13.251s`
- peak RSS: `322080 KiB`
- storage growth to `6066099` bytes

### Source Material

- `docs/current_status.md`
- `NIDS_TestLab/reports/prepared_env_validation_index.md`
- `reports/graphs/`

### Recommended Visual Form

- compact metric card layout or single summary chart
- add a visible label that this is a pilot, not a completed full-duration soak

### Caption Draft

"Prepared-environment soak and performance snapshot for the current `900s` pilot. The figure summarizes observed stability metrics without claiming completion of the planned `6` to `12` hour soak."

## Figure 6: Deployment-Readiness Summary

### Goal

Summarize the current release boundary in one figure.

### Content

- validated now:
  - repeatable offline scenarios
  - prepared-environment live validation
  - queue-loss accounting
  - tuned benign-soak rerun
  - restart-based rule/model/config workflows
- still open:
  - full-duration soak
  - broader benign adjudication
  - suppression-specific live evidence
  - hot-reload decision
- verdict:
  - controlled pre-deployment candidate

### Source Material

- `docs/deployment_readiness_checklist.md`
- `docs/current_status.md`
- `docs/project_one_pager.md`

### Recommended Visual Form

- traffic-light or status-matrix figure
- avoid product-style maturity scoring that implies production readiness

### Caption Draft

"Current readiness summary showing which validation areas are evidence-backed, which remain open, and why the current posture is a controlled pre-deployment candidate rather than a production-ready release."

## Figure Production Guidance

- Prefer SVG or high-resolution PNG.
- Keep labels short and paper-friendly.
- Use the same terminology used in the docs:
  - prepared-environment
  - restart-based
  - evidence-backed
  - controlled pre-deployment candidate
- Redact local usernames, tokens, and non-public host details in any screenshot-derived figure.
- Keep all figure source notes so later paper revisions can be traced back to repo evidence.

## Suggested Order In Paper

1. Hybrid NIDS Architecture
2. Layered Validation Workflow
3. Scenario And Evidence Workflow
4. False-Positive Tuning And Adjudication
5. Soak And Performance Evidence Snapshot
6. Deployment-Readiness Summary
