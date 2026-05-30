# Paper Outline

## Title Options

1. Evidence-Driven Validation of a Hybrid Intrusion Detection Workspace in Prepared Network Environments
2. A Hybrid Network Intrusion Detection Workspace with Repeatable Offline and Prepared-Environment Validation
3. Prepared-Environment Validation for a Hybrid Intrusion Detection System with Fusion-Based Alerting
4. From Offline Replay to Prepared Live Capture: Validation of a Hybrid NIDS Workspace
5. An Evidence-Backed Hybrid NIDS for Live Capture, Offline Replay, and Analyst Tuning

## Working Thesis

This paper should present the project as a hybrid intrusion detection workspace that combines multiple detection methods with repeatable evidence collection. The strongest paper angle is not "production deployment," but rather a practical validation study showing how code-level testing, offline replay, prepared-environment execution, false-positive adjudication, and operator workflow evidence were brought together in one repository.

## 1. Abstract

- Use one of the drafts in `docs/paper_abstract_draft.md`.
- State the architecture briefly: live capture, offline replay, optional adapters, artifact analysis, hybrid detection, fusion, storage, and visualization.
- State the evaluation frame clearly: layered code testing plus scenario-based lab evidence plus prepared-environment evidence.
- Include only grounded metrics:
  - `152` collected tests
  - `144` passed, `8` deselected
  - `79.16%` coverage with a `72%` enforced floor
  - `5` latest offline scenario passes
  - `10` latest prepared-environment scenario passes across `17` recorded manifests
- End with the current boundary: controlled pre-deployment review, not full production signoff.

## 2. Introduction

- Introduce the operational gap between benchmark-oriented IDS work and evidence-backed deployment preparation.
- Explain why a single detection mode is often insufficient in mixed traffic conditions.
- Motivate a hybrid workspace that supports:
  - signature detection
  - statistical anomaly detection
  - supervised ML
  - optional unsupervised ML
  - fusion-based decisions
  - artifact-assisted analyst review
- Position the paper around validation discipline and operator usefulness rather than novel model theory.

## 3. Problem Statement

- Practical IDS projects often stop at model metrics or isolated demos.
- Real deployment preparation requires evidence for:
  - runtime stability
  - prepared-environment execution
  - false-positive handling
  - operator workflows
  - retained artifacts and reports
- State the research problem as: how to validate a hybrid NIDS workspace in a way that is repeatable, evidence-backed, and honest about residual risk.

## 4. Related Work Placeholder

- Compare against:
  - signature-only IDS studies
  - anomaly/ML IDS papers focused on benchmark datasets
  - cyber range and lab validation papers
  - SOC workflow and evidence-retention literature
- Reserve space to discuss:
  - NIDS evaluation on labeled traffic datasets
  - threat-informed validation and ATT&CK-aligned exercises
  - operational monitoring guidance from NIST and CISA
- Important framing:
  - current work is not claiming a novel model family
  - the contribution is the integrated architecture plus validation method

## 5. System Architecture

- Describe the end-to-end flow:
  - live capture
  - offline PCAP replay
  - optional Suricata/Zeek JSON adapters
  - parsing and normalization
  - feature extraction
  - signature, anomaly, supervised, and optional unsupervised scoring
  - fusion
  - suppression
  - SQLite/JSONL persistence
  - dashboard, charts, and reports
  - optional artifact static analysis
- Include the repo-backed architecture diagrams in `thesis/diagrams/system_architecture.mmd` and `thesis/diagrams/threat_workflow.mmd`.
- Clarify that artifact analysis is static-only and does not execute submitted files.

## 6. Detection Methodology

- Signature engine:
  - YAML-driven rules for known behavior patterns
- Statistical anomaly engine:
  - threshold logic
  - EWMA and z-score style heuristics
  - burst detection
- Supervised ML:
  - ensemble of `RandomForest`, `ExtraTrees`, `HistGradientBoosting`, and `XGBoost` when available
- Optional unsupervised path:
  - `IsolationForest`
  - shallow autoencoder
  - warmup calibration
- Fusion layer:
  - combines detector outputs into a single risk decision
- Important wording:
  - do not present unsupervised tuning as universally solved
  - do not claim real-time hot reload

## 7. Data Sources

- Offline scenario bundles in `NIDS_TestLab/scenarios/` and `NIDS_TestLab/results/phase3-*`
- Prepared-environment runs indexed in `NIDS_TestLab/reports/prepared_env_validation_index.md`
- Runtime persistence:
  - `output/nids.db`
  - `output/alerts.jsonl`
  - `output/flows.jsonl`
  - `output/metrics.jsonl`
- Artifact fixtures and quarantine evidence from `LAB-SCN-005`
- Offline model reports:
  - `reports/ml_metrics.json`
  - `reports/ml_evaluation.json`
- Note any dataset-specific model numbers as offline evaluation results, not live operational accuracy claims.

## 8. Validation Methodology

- Layer 1: default deterministic pytest suite and coverage gate
- Layer 2: extended `slow`, `live`, `environment`, and `lab` slices
- Layer 3: repeatable offline scenario execution through `scripts/run_lab_scenario.py`
- Layer 4: prepared-environment execution and indexing through `scripts/prepared_env_validation.py`
- Layer 5: analyst adjudication and deployment-readiness review
- Current grounded evidence:
  - default suite: `144 passed, 8 deselected`
  - warnings: `0`
  - coverage: `79.16%`
  - offline scenarios: `5` latest passes
  - prepared-environment scenarios: `10` latest passes across `17` total recorded manifests

## 9. Lab Scenarios

- Offline scenarios:
  - `LAB-SCN-001` port scan replay
  - `LAB-SCN-002` HTTP login brute force replay
  - `LAB-SCN-003` flood and burst replay
  - `LAB-SCN-004` mixed benign and malicious traffic
  - `LAB-SCN-005` artifact and network correlation
- Prepared-environment scenarios:
  - `PREP-ENV-001` live `tcpdump` port scan
  - `PREP-ENV-002` live `scapy` DNS burst
  - `PREP-ENV-003` queue pressure and loss accounting
  - `PREP-ENV-004` malformed packet handling
  - `PREP-ENV-005` tuned benign soak
  - `PREP-ENV-006` restart and recovery
  - `PREP-ENV-007` extended soak pilot
  - `PREP-ENV-008` rule refresh
  - `PREP-ENV-009` model swap
  - `PREP-ENV-010` config override

## 10. Results

Suggested results split:

### 10.1 Software Validation Results

| Measure | Current result |
|---|---:|
| Total collected tests | `152` |
| Default suite | `144 passed, 8 deselected` |
| Active pytest warnings | `0` |
| Coverage | `79.16%` |
| Coverage floor | `72%` |
| `pytest -m "live and environment"` | `3 passed` |
| `pytest -m slow` | `4 passed` |
| `pytest -m lab` | `1 passed` |

### 10.2 Offline Scenario Results

| Scenario group | Current result |
|---|---:|
| Latest offline scenarios passed | `5` |
| Recorded offline manifests | `6` |
| `LAB-SCN-005` artifact correlation | `7` flows, `1` network alert, `4` artifact rows, `2` quarantined artifacts |

### 10.3 Prepared-Environment Results

| Scenario | Current result |
|---|---|
| `PREP-ENV-003` | `8127` received, `23` processed, `8100` dropped, `99.6678%` loss, queue peak `1` |
| `PREP-ENV-005` | `1416` flows, `0` alerts after tuning |
| `PREP-ENV-007` | `4742` flows, `0` alerts, restart latency `13.251s`, `900s` pilot toward `21600s` target |
| `PREP-ENV-008` | `332` flows, `1` post-refresh signature alert |
| `PREP-ENV-009` | `330` flows, `2` anomaly alerts across pre/post phases |
| `PREP-ENV-010` | `394` flows, `0` alerts across baseline-to-tuned config change |

### 10.4 Offline Supervised Model Results

Use only with clear wording such as:

- offline evaluation report accuracy: `0.99784`
- offline evaluation weighted F1: `0.99792`
- evaluated on `25000` labeled flows

Add a sentence stating that these are offline evaluation numbers and do not replace live prepared-environment evidence.

## 11. False Positive Tuning

- Focus the section on `PREP-ENV-005`.
- Explain the phase 4 false positives:
  - unsupervised-only alerts on benign status polling and routine DNS
- Describe the tuning change:
  - added `ml.unsupervised_min_active_components`
  - set the tuned live profile to require at least `2` active unsupervised components
- Present the outcome:
  - phase 5 tuned rerun: `1416` flows, `0` alerts
- Keep the conclusion narrow:
  - cleared for the exercised benign soak sample only
  - broader benign corpora still needed

## 12. Limitations

- The strongest operational limitation is soak duration:
  - `PREP-ENV-007` is a `900s` pilot against a `21600s` target
- Benign adjudication is narrow:
  - current tuned evidence is strong for the exercised sample, not a universal guarantee
- Operator workflows are restart-based:
  - validated for rule refresh, model swap, and config override
  - not validated as zero-downtime hot reload
- Platform validation is uneven:
  - Windows is the first-class lab host
  - Linux is the primary runtime target
  - macOS is not yet a first-class validated host path
- This paper should not make claims about production deployment, autonomous response, or quantum-enabled detection.

## 13. Future Work

- Complete a full `6` to `12` hour prepared-environment soak
- Expand benign corpora and longer observation windows for false-positive adjudication
- Add a dedicated suppression-specific prepared-environment scenario
- Decide whether hot reload is a required engineering target
- Add public-facing redacted evidence exports for publication supplements
- Expand cross-platform runtime validation for Linux and, later, macOS

## 14. Conclusion

- Re-state the main claim:
  - the project demonstrates a hybrid NIDS workspace with layered evidence-backed validation
- Emphasize the practical value:
  - repeatable scenario bundles
  - prepared-environment evidence
  - operator workflow evidence
  - disciplined boundaries around readiness claims
- End with the current verdict:
  - suitable for controlled pre-deployment review
  - not yet fully deployment-signed-off
