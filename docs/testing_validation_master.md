# NIDS Workspace Testing and Validation Master Record

Last updated: March 14, 2026

## 1. Test Strategy Overview

This repository now uses a layered validation model intended to support both day-to-day engineering and pre-deployment security validation:

- Fast default pytest for deterministic unit and local integration coverage.
- Coverage-gated CI for pull requests.
- Extended `integration` and `slow` validation for nightly or manual runs.
- Explicit `lab` validation for `NIDS_TestLab` assets and operator-driven end-to-end exercises.
- Prepared-environment live evidence collection for real sensor-VM capture and recovery validation.

The strategy is aligned to NIST guidance for structured security testing, incident readiness, and evidence handling, plus MITRE ATT&CK threat-informed validation and CISA logging and monitoring guidance [1][2][3][4][5][6].

## 2. Scope

In scope:

- `src/NIDS` runtime, CLI, ingest, parser, feature extraction, detection, ML, storage, reporting, artifact analysis, and visualization paths.
- Safe Python utilities under `scripts/`.
- `NIDS_TestLab` asset integrity, offline scenario execution, and prepared-environment workflow integration.
- CI evidence artifacts: coverage, JUnit XML, HTML/XML coverage reports, and validation summaries.

Out of scope for the default PR suite:

- Hardware-dependent packet capture against arbitrary host interfaces.
- Long-duration soak and operator-attended live lab execution.
- Production deployment packaging, host hardening, or infrastructure-as-code outside the repository.

## 3. Current Evidence Summary

| Item | Current result | Evidence |
|---|---|---|
| Total collected tests | `157` | local pytest collection under current marker policy |
| Default fast suite | `149 passed, 8 deselected` | `artifacts/test-results/junit-local.xml` |
| `live` + `environment` suite | `3 passed` | manual local `pytest -m "live and environment"` run |
| `slow` performance suite | `4 passed` | manual local `pytest -m slow` run |
| `lab` suite | `1 passed` | manual local `pytest -m lab` run; CI target `artifacts/test-results/junit-lab.xml` |
| Coverage | `79.16%` total, threshold `72.00%` enforced | `artifacts/coverage/coverage.xml`, `artifacts/coverage/html/index.html` |
| Warning status | `0` active pytest warnings; Scapy DNS deprecation warning retired | `tests/test_parser.py` run output |
| Phase 10 focused prep validation | `16 passed` | manual local `pytest tests/test_prepared_env_validation.py tests/test_ml_unsupervised.py` |
| Workflow split | Fast PR workflow plus nightly/manual extended workflow | `.github/workflows/ci.yml`, `.github/workflows/validation-extended.yml` |
| Phase 3 offline lab evidence | `5` latest scenario passes; `7` total recorded manifests | `NIDS_TestLab/reports/lab_execution_index.json`, `NIDS_TestLab/reports/lab_execution_index.md` |
| Prepared-environment evidence | `13` latest scenarios recorded; `13` pass and `0` partial across `36` total manifests | `NIDS_TestLab/reports/prepared_env_validation_index.json`, `NIDS_TestLab/reports/prepared_env_validation_index.md` |
| Phase 10 PREP-ENV-007 rerun | `pass`; `87533` flows, `0` alerts, `21600.0s`, peak RSS `409444 KiB`, peak CPU `107.0%`, reload latency `13.335s` | `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/` |

## 4. Test Levels

- Unit: isolated logic, schema handling, parsing, scoring, and reporting functions.
- Integration: cross-module paths using local fixtures, temporary SQLite databases, synthetic PCAPs, and subprocess smoke checks.
- CLI: direct command dispatch and behavior tests for `run`, `train`, `evaluate`, `report`, `threshold-report`, `artifact-*`, and `thesis-docs`.
- Storage: SQLite and JSONL schema creation, migration-safe behavior, persistence, and incident/suppression actions.
- Artifact: parser correctness, storage, duplicate handling, quarantine movement, and markdown report generation.
- Visualization: query shaping, chart generation, dashboard data, and export bundle output.
- Live/environment: host-capability-dependent packet capture validation kept out of default CI.
- Performance and resilience: lightweight operational smoke validation now exists under `slow`; longer prepared-lab evidence is kept separate.
- Lab/E2E: `NIDS_TestLab` offline replay and prepared-environment execution against the VM topology.

## 5. Execution Model

Fast local / PR path:

```bash
pytest
pytest --cov=src/NIDS --cov-config=.coveragerc --cov-report=term-missing:skip-covered --cov-report=xml --cov-report=html
```

Extended local validation:

```bash
pytest -m "(integration or slow) and not live and not environment and not lab"
pytest -m "live and environment"
pytest -m slow
pytest -m lab
python scripts/run_lab_scenario.py --scenario all --write-index
python scripts/prepared_env_validation.py --scenario all --write-index
```

Marker policy:

- `slow`: longer-running validations, skipped by default.
- `lab`: environment-dependent or lab-specific validation, skipped by default.
- `integration`: realistic local cross-module tests safe for non-lab environments.
- `live`: packet capture or streaming validation that requires prepared host capabilities.
- `environment`: tests that depend on host permissions, interfaces, or platform setup outside standard CI.

## 6. Detailed Test Inventory

Inventory is maintained at deterministic pytest-suite level. Function-level evidence is captured in `artifacts/test-results/junit-local.xml` and CI JUnit artifacts.

### 6.1 Detection, Pipeline, and Runtime

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| DET-ANOM-001 | Anomaly scoring and threshold behavior | `src/NIDS/detect/anomaly.py` | Unit | Verify anomaly feature handling and alert logic | Synthetic flow dictionaries | `pytest tests/test_anomaly.py` | Stable anomaly output and expected threshold behavior | `tests/test_anomaly.py`; `artifacts/test-results/junit-local.xml` | Pass |
| DET-FUS-001 | Fusion decision logic | `src/NIDS/detect/fusion.py` | Unit | Validate score fusion and label agreement handling | Synthetic detection outputs | `pytest tests/test_fusion.py` | Expected fusion label, score, and agreement count | `tests/test_fusion.py`; `artifacts/test-results/junit-local.xml` | Pass |
| DET-SIG-001 | Signature detection paths | `src/NIDS/detect/signature.py` | Unit | Verify rule matching and alert shaping | Rule fixtures and synthetic events | `pytest tests/test_signature.py` | Correct rule hits and summaries | `tests/test_signature.py`; `artifacts/test-results/junit-local.xml` | Pass |
| DET-SUP-001 | Suppression matcher behavior | `src/NIDS/detect/suppression.py` | Unit | Ensure suppression routing suppresses only expected alerts | Synthetic alerts and suppression state | `pytest tests/test_suppression.py` | Expected suppression decision only on matching alerts | `tests/test_suppression.py`; `artifacts/test-results/junit-local.xml` | Pass |
| PIPE-PARSE-001 | Packet parser coverage | `src/NIDS/pipeline/parser.py` | Unit | Validate packet parsing, DNS extraction, and payload field handling | Scapy packets | `pytest tests/test_parser.py` | Normalized events produced from supported packets | `tests/test_parser.py`; `artifacts/test-results/junit-local.xml` | Pass |
| PIPE-FEAT-001 | Feature extraction coverage | `src/NIDS/pipeline/features.py` | Unit | Ensure normalized feature fields are produced consistently | Synthetic packet/event payloads | `pytest tests/test_features.py` | Feature vector fields match expected values | `tests/test_features.py`; `artifacts/test-results/junit-local.xml` | Pass |
| PIPE-INT-001 | Integrated pipeline flow | parser, features, detection integration | Integration | Verify cross-module event-to-alert pipeline behavior | Synthetic packets/events | `pytest tests/test_integration_pipeline.py` | End-to-end pipeline produces expected flow/alert artifacts | `tests/test_integration_pipeline.py`; `artifacts/test-results/junit-local.xml` | Pass |
| CFG-001 | Config maintenance behavior | `src/NIDS/config.py` | Unit | Validate config merge and maintenance-safe defaults | YAML and override inputs | `pytest tests/test_config_maintenance.py` | Config assembly remains deterministic and backward compatible | `tests/test_config_maintenance.py`; `artifacts/test-results/junit-local.xml` | Pass |
| RUNTIME-001 | Runtime maintenance controls | `src/NIDS/runtime.py` | Unit | Verify maintenance-oriented runtime behavior | Temporary SQLite output and runtime stubs | `pytest tests/test_runtime_maintenance.py` | Runtime maintenance path completes cleanly | `tests/test_runtime_maintenance.py`; `artifacts/test-results/junit-local.xml` | Pass |

### 6.2 ML and Model Lifecycle

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| ML-DIRECT-001 | Direct ML dataset, training, and evaluation coverage | `src/NIDS/ml/dataset_loader.py`, `src/NIDS/ml/feature_builder.py`, `src/NIDS/ml/featureset.py`, `src/NIDS/ml/train.py`, `src/NIDS/ml/evaluate.py` | Unit / Integration | Cover normal paths, malformed input, missing columns, schema drift, empty datasets, and SQLite-backed fixtures | Temporary SQLite databases, monkeypatched model helpers, deterministic seeds | `pytest tests/test_ml_direct.py` | Training and evaluation succeed on valid data and fail safely on empty or malformed data | `tests/test_ml_direct.py`; `artifacts/test-results/junit-local.xml` | Pass |
| ML-ROUTER-001 | Detection ML router behavior | `src/NIDS/detect/ml.py` | Unit | Verify routing and prediction caching behavior | Synthetic alert/flow inputs | `pytest tests/test_ml_router.py` | Correct model routing and prediction behavior | `tests/test_ml_router.py`; `artifacts/test-results/junit-local.xml` | Pass |
| ML-UNSUP-001 | Unsupervised detection behavior | `src/NIDS/detect/ml_unsupervised.py` | Unit | Validate unsupervised scoring and label paths | Synthetic model inputs | `pytest tests/test_ml_unsupervised.py` | Expected unsupervised labels and scores | `tests/test_ml_unsupervised.py`; `artifacts/test-results/junit-local.xml` | Pass |
| ML-SUP-001 | Supervised ensemble behavior | `src/NIDS/ml/supervised_ensemble.py` | Unit | Validate ensemble fit/predict paths and output shape | Small deterministic training frames | `pytest tests/test_supervised_ensemble.py` | Consistent ensemble behavior under deterministic inputs | `tests/test_supervised_ensemble.py`; `artifacts/test-results/junit-local.xml` | Pass |

### 6.3 Storage, Incident Handling, Reporting, and Notifications

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| STO-DIRECT-001 | Direct SQLite and JSONL persistence coverage | `src/NIDS/storage/sqlite_store.py`, `src/NIDS/storage/jsonl_store.py` | Integration | Verify schema creation, inserts, reads, incident persistence, suppression lifecycle, ML/fusion fields, migration-safe behavior, and multi-handle assumptions | Temporary SQLite DBs and JSONL output dirs | `pytest tests/test_storage_direct.py` | Records persist correctly and legacy schemas are upgraded safely | `tests/test_storage_direct.py`; `artifacts/test-results/junit-local.xml` | Pass |
| STO-MAINT-001 | Retention and health maintenance | `src/NIDS/storage/sqlite_store.py` | Unit | Validate health snapshot and retention pruning | Aged alert/flow/metric rows | `pytest tests/test_storage_maintenance.py` | Old rows prune correctly and health snapshot reflects remaining data | `tests/test_storage_maintenance.py`; `artifacts/test-results/junit-local.xml` | Pass |
| IR-ACT-001 | Incident action lifecycle | `src/NIDS/storage/sqlite_store.py` incident action paths | Unit | Verify acknowledge and action recording semantics | Temporary alert rows | `pytest tests/test_incident_actions.py` | Incident actions are persisted for expected state changes | `tests/test_incident_actions.py`; `artifacts/test-results/junit-local.xml` | Pass |
| IR-STORE-001 | Incident store workflows and SLA escalation | `src/NIDS/storage/incident_store.py` | Integration | Validate incident creation, assignment, SLA policy handling, and summaries | Temporary SQLite alert store | `pytest tests/test_incident_store.py` | Incident records transition correctly and SLA escalations are emitted | `tests/test_incident_store.py`; `artifacts/test-results/junit-local.xml` | Pass |
| REPORT-SLA-001 | SLA report generation | `src/NIDS/reporting.py` incident/SLA paths | Unit | Verify SLA-oriented reporting output | Temporary runtime DB fixtures | `pytest tests/test_reporting_sla.py` | SLA report output matches stored incident state | `tests/test_reporting_sla.py`; `artifacts/test-results/junit-local.xml` | Pass |
| REPORT-THRESH-001 | Threshold report generation | `src/NIDS/reporting.py` threshold paths | Unit | Validate threshold report output and summary fields | Temporary DB data | `pytest tests/test_threshold_report.py` | Threshold report renders expected metrics and tables | `tests/test_threshold_report.py`; `artifacts/test-results/junit-local.xml` | Pass |
| NOTIFY-001 | Notification utilities | `src/NIDS/utils/notifications.py` | Unit | Verify notification routing and safety behavior | Monkeypatched transports | `pytest tests/test_notifications.py` | Notification payloads route cleanly without unintended failures | `tests/test_notifications.py`; `artifacts/test-results/junit-local.xml` | Pass |

### 6.4 Ingest, CLI, and Safe Script Utilities

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| CLI-001 | CLI smoke and dispatch coverage | `src/NIDS/cli.py` | CLI | Directly validate `run`, `train`, `evaluate`, `report`, `threshold-report`, `artifact-*`, and `thesis-docs` command routing | Monkeypatched command handlers, `capsys` | `pytest tests/test_cli.py` | CLI subcommands dispatch the correct runtime functions and emit stable output | `tests/test_cli.py`; `artifacts/test-results/junit-local.xml` | Pass |
| INGEST-DIRECT-001 | Offline and adapter ingest coverage | `src/NIDS/ingest/offline.py`, `src/NIDS/ingest/live.py` | Integration | Validate PCAP replay, label application, Suricata/Zeek adapter normalization, queue/drop behavior, and mocked scapy live capture | Synthetic PCAPs, JSON lines, monkeypatched live sniffer | `pytest tests/test_ingest_direct.py` | Offline and mocked live ingest paths produce normalized events and safe drop accounting | `tests/test_ingest_direct.py`; `artifacts/test-results/junit-local.xml` | Pass |
| INGEST-LIVE-001 | Live ingest backend dispatch | `src/NIDS/ingest/live.py` | Unit | Verify backend resolution and dispatcher behavior | Monkeypatched backend functions | `pytest tests/test_live_ingest.py` | Correct backend selection and dispatcher calls | `tests/test_live_ingest.py`; `artifacts/test-results/junit-local.xml` | Pass |
| LAB-SCRIPT-001 | Live VM validation script logic | `scripts/live_vm_attack_validation.py` | Unit | Validate attack-job construction and summary generation helpers without requiring live VMs | Imported script module and temporary SQLite DB | `pytest tests/test_live_vm_attack_validation.py` | Script emits correct attack plan and validation summary structure | `tests/test_live_vm_attack_validation.py`; `artifacts/test-results/junit-local.xml` | Pass |
| SCRIPT-SMOKE-001 | Safe Python utility smoke tests | `scripts/*.py` selected Python utilities | Integration | Validate `--help` CLI availability and safe fixture DB generation | Subprocess calls, temporary output DB | `pytest tests/test_scripts_smoke.py` | Utility entrypoints run safely and fixture generator creates expected rows | `tests/test_scripts_smoke.py`; `artifacts/test-results/junit-local.xml` | Pass |
| LAB-RUNNER-001 | Lab scenario runner and index coverage | `scripts/run_lab_scenario.py`, `scripts/summarize_lab_results.py` | Integration | Validate repeatable scenario execution, bundle-local artifact handling, and execution-index generation | Temporary YAML scenarios, SQLite output, synthetic PCAP and artifact fixtures | `pytest tests/test_lab_scenario_runner.py` | Scenario runner produces self-contained evidence bundles and the execution index summarizes the latest run correctly | `tests/test_lab_scenario_runner.py`; `NIDS_TestLab/reports/lab_execution_index.md` | Pass |
| PREP-ENV-AUTO-001 | Prepared-environment helper coverage | `scripts/prepared_env_validation.py` | Integration | Validate runtime-log parsing and prepared-environment latest-run index generation | Temporary manifest fixtures and synthetic runtime-log text | `pytest tests/test_prepared_env_validation.py` | Prepared-environment helper logic extracts backend/drop evidence and indexes the newest run per scenario | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/reports/prepared_env_validation_index.md` | Pass |
| PREP-ENV-AUTO-002 | Prepared-environment verdict fallback coverage | `scripts/prepared_env_validation.py` | Integration | Validate verdict fallback to persisted live metric series when final runtime-log telemetry is absent | Temporary manifest fixtures and synthetic metric summaries | `pytest tests/test_prepared_env_validation.py` | Verdict logic accepts observed packet and drop evidence from stored metrics and does not rely only on `runtime.log` telemetry | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/results/phase5-tuning/` | Pass |
| PREP-ENV-AUTO-003 | Prepared-environment nested-index coverage | `scripts/prepared_env_validation.py` | Integration | Validate index generation for nested phase directories such as `phase5-soak/` and `phase5-operator/` | Temporary nested manifest fixtures | `pytest tests/test_prepared_env_validation.py` | Prepared-environment indexing discovers the newest scenario runs under nested result directories | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/reports/prepared_env_validation_index.md` | Pass |

### 6.5 Artifact Analysis and Reporting

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| ART-ANALYZE-001 | Artifact analyzer risk scoring | `src/NIDS/artifacts/analyzer.py` | Unit | Verify hashing, lightweight risk scoring, and suspicious text handling | Synthetic executable/binary fixtures | `pytest tests/test_artifact_analyzer.py` | Analyzer emits expected risk level and suspicious reasons | `tests/test_artifact_analyzer.py`; `artifacts/test-results/junit-local.xml` | Pass |
| ART-PIPE-001 | Artifact parser, storage, intake, and report coverage | `src/NIDS/artifacts/intake.py`, `src/NIDS/artifacts/report.py`, `src/NIDS/artifacts/storage.py`, parser modules under `src/NIDS/artifacts/parsers` | Integration | Validate CSV, JSON, HTML, Python, EXE, ZIP, DOCX, PDF, and XLSX handling; duplicate detection; quarantine movement; JSONL/SQLite persistence; artifact report output; watcher stop behavior | Temporary files, small synthetic documents, archives, and DBs | `pytest tests/test_artifact_pipeline.py` | Parsers extract metadata safely; scan moves files correctly; duplicates are recorded; high-risk files are quarantined; report output is generated | `tests/test_artifact_pipeline.py`; `artifacts/test-results/junit-local.xml` | Pass |

### 6.6 Visualization, Dashboard, and Documentation

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| DASH-RT-001 | Dashboard realtime APIs and behavior | `src/NIDS/visuals/dashboard.py` | Integration | Validate realtime dashboard data exposure and operator-facing controls | Temporary SQLite fixtures and API requests | `pytest tests/test_dashboard_realtime.py` | Dashboard endpoints respond with correct data and control behavior | `tests/test_dashboard_realtime.py`; `artifacts/test-results/junit-local.xml` | Pass |
| VIS-FILTER-001 | Dashboard analytics filtering | `src/NIDS/visuals/queries.py` | Unit | Verify sensor/severity/engine filter behavior | Temporary SQLite analytics fixture | `pytest tests/test_visual_filters.py` | Filters return correctly narrowed analytics datasets | `tests/test_visual_filters.py`; `artifacts/test-results/junit-local.xml` | Pass |
| VIS-DIRECT-001 | Visualization query, chart, and export coverage | `src/NIDS/visuals/queries.py`, `src/NIDS/visuals/charts.py`, `src/NIDS/visuals/export.py` | Integration | Validate query correctness, alias handling, chart shaping, HTML/PNG export behavior, and index generation | Temporary SQLite analytics DB, monkeypatched export writer | `pytest tests/test_visuals_direct.py` | Queries, figures, and export bundle render expected outputs | `tests/test_visuals_direct.py`; `artifacts/test-results/junit-local.xml` | Pass |
| DOC-THESIS-001 | Thesis/document generation path | `src/NIDS/thesis.py` | Unit | Verify thesis/document export behavior remains stable | Temporary output fixtures | `pytest tests/test_thesis_docs.py` | Thesis documentation output is generated without regressions | `tests/test_thesis_docs.py`; `artifacts/test-results/junit-local.xml` | Pass |

### 6.7 Lab Asset Integrity

| Test ID | Test name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected outcome | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|
| LAB-ASSET-001 | NIDS_TestLab asset integrity | `NIDS_TestLab` structure and summary files | Lab | Verify required lab directories, scripts, README, and JSON summaries are present and parseable | On-repo lab bundle | `pytest -m lab` | Lab bundle is intact and ready for manual/nightly execution | `tests/test_lab_assets.py`; future CI `artifacts/test-results/junit-lab.xml`; `NIDS_TestLab/reports/` | Pass |

### 6.8 Phase 2 Operational Additions

Every new phase-2 and phase-4-support test below records the module, objective, environment, expected behavior, and evidence location.

| Test ID | Test suite | Module | Objective | Environment | Expected behavior | Evidence location | Current status |
|---|---|---|---|---|---|---|---|
| LIVE-OPS-001 | `tests/test_live_capture_operational.py` | `src/NIDS/ingest/live.py` | Validate tcpdump pipe capture, FIFO packet streaming, interface capture, burst handling, and backend failure reporting | prepared host only; excluded from default CI | live capture paths either stream packets correctly or fail noisily without hanging the runtime | `tests/test_live_capture_operational.py` | Pass |
| RUNTIME-OPS-001 | `tests/test_runtime_operational.py` | `src/NIDS/runtime.py`, `src/NIDS/config.py` | Validate runtime assembly, config precedence, rule loading, ML loading, startup/shutdown, and producer error handling | default local / CI-safe | runtime assembles configured producers, closes resources, and handles interrupt/error paths predictably | `tests/test_runtime_operational.py`; `artifacts/test-results/junit-local.xml` | Pass |
| DASH-OPS-001 | `tests/test_dashboard_operational.py` | `src/NIDS/visuals/dashboard.py` | Validate figures, audit/suppression query paths, websocket auth/streaming, and uvicorn delegation | default local / CI-safe | dashboard query paths return expected data and websocket/auth behavior remains bounded and deterministic | `tests/test_dashboard_operational.py`; `artifacts/test-results/junit-local.xml` | Pass |
| PERF-PIPE-001 | `tests/test_performance_pipeline.py` | `src/NIDS/ingest/offline.py`, `src/NIDS/runtime.py`, `src/NIDS/storage/sqlite_store.py`, `src/NIDS/storage/jsonl_store.py` | Validate lightweight replay throughput, detection latency, write pressure, and bounded memory growth | manual or nightly `slow` execution | replay/write paths stay within safe deterministic smoke thresholds and do not show runaway memory behavior | `tests/test_performance_pipeline.py` | Pass |
| PREP-ENV-AUTO-001 | `tests/test_prepared_env_validation.py` | `scripts/prepared_env_validation.py` | Validate prepared-environment manifest indexing and runtime-log evidence parsing | default local / CI-safe | the helper script records the latest scenario run correctly and preserves backend/drop evidence from runtime logs | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/reports/prepared_env_validation_index.md` | Pass |
| PREP-ENV-AUTO-002 | `tests/test_prepared_env_validation.py` | `scripts/prepared_env_validation.py` | Validate prepared-environment verdict fallback to persisted live metric summaries | default local / CI-safe | the helper script treats stored live metrics as authoritative evidence even when end-of-run telemetry is missing from `runtime.log` | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/results/phase5-tuning/` | Pass |
| PREP-ENV-AUTO-003 | `tests/test_prepared_env_validation.py` | `scripts/prepared_env_validation.py` | Validate prepared-environment nested phase-directory indexing | default local / CI-safe | the helper script discovers nested result bundles for `phase5-soak/` and `phase5-operator/` in the latest-run index | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/reports/prepared_env_validation_index.md` | Pass |

### 6.9 Phase 3 Executed Lab Scenarios

Every scenario below now has recorded evidence in `NIDS_TestLab/results/` and is indexed by `NIDS_TestLab/reports/lab_execution_index.md`.

| Scenario ID | Scenario name | Module under test | Type | Objective | Fixture/input | Execution steps | Expected result | Actual result | Evidence/log/report path | Current status |
|---|---|---|---|---|---|---|---|---|---|---|
| LAB-SCN-001 | Port Scan Offline Replay | `NIDS_TestLab/scenarios/lab-scn-001-port-scan.yml`, `scripts/run_lab_scenario.py`, runtime/detection pipeline | Lab / E2E | Verify scan traffic produces signature, anomaly, and fusion evidence suitable for analyst review | Synthetic TCP scan PCAP generated into the scenario bundle | `python scripts/run_lab_scenario.py --scenario lab-scn-001-port-scan --write-index` | Port-scan rules fire, anomaly evidence appears, fusion may trigger, and reports are retained | Pass. `33` flows and `5` alerts recorded; signature, anomaly, and fusion triggered; suppression unchanged | `NIDS_TestLab/results/phase3-port-scan-offline-20260312-032633/`; `NIDS_TestLab/reports/lab_execution_index.md` | Pass |
| LAB-SCN-002 | HTTP Login Brute Force Offline Replay | `NIDS_TestLab/scenarios/lab-scn-002-http-login-bruteforce.yml`, `scripts/run_lab_scenario.py`, runtime/detection pipeline | Lab / E2E | Verify repeated login abuse patterns generate threshold-based evidence and retained reports | Synthetic HTTP login-abuse PCAP generated into the scenario bundle | `python scripts/run_lab_scenario.py --scenario lab-scn-002-http-login-bruteforce --write-index` | Brute-force threshold alert is retained with stable chronology and severity | Pass. `14` flows and `1` alert recorded; anomaly triggered; suppression unchanged | `NIDS_TestLab/results/phase3-http-login-bruteforce-offline-20260312-032715/`; `NIDS_TestLab/reports/lab_execution_index.md` | Pass |
| LAB-SCN-003 | Flood And Burst Offline Replay | `NIDS_TestLab/scenarios/lab-scn-003-flood-burst.yml`, `scripts/run_lab_scenario.py`, runtime/detection pipeline | Lab / E2E | Verify bursty DNS and UDP flood traffic surface anomaly and ML evidence without runtime instability | Synthetic DNS burst plus UDP flood PCAP generated into the scenario bundle | `python scripts/run_lab_scenario.py --scenario lab-scn-003-flood-burst --write-index` | Burst/flood rules and anomaly/ML evidence appear, with fusion when detections agree | Pass. Latest Phase 9 rerun again recorded `296` flows and `5` alerts; anomaly, ML, and fusion triggered; suppression unchanged | `NIDS_TestLab/results/phase9-flood-burst-offline-20260313-160502/`; `NIDS_TestLab/reports/lab_execution_index.md` | Pass |
| LAB-SCN-004 | Mixed Benign And Malicious Offline Replay | `NIDS_TestLab/scenarios/lab-scn-004-mixed-traffic.yml`, `scripts/run_lab_scenario.py`, runtime/detection pipeline | Lab / E2E | Verify mixed benign/malicious traffic produces a coherent alert chronology across multiple attack families | Synthetic blended PCAP with benign HTTP/DNS plus malicious scan and brute-force activity | `python scripts/run_lab_scenario.py --scenario lab-scn-004-mixed-traffic --write-index` | Mixed replay produces reviewable chronology with signature, anomaly, and fusion evidence | Pass. `82` flows and `8` alerts recorded; signature, anomaly, and fusion triggered; suppression unchanged | `NIDS_TestLab/results/phase3-mixed-traffic-offline-20260312-032936/`; `NIDS_TestLab/reports/lab_execution_index.md` | Pass |
| LAB-SCN-005 | Artifact And Network Correlation Offline Replay | `NIDS_TestLab/scenarios/lab-scn-005-artifact-network-correlation.yml`, `scripts/run_lab_scenario.py`, runtime plus artifact pipeline | Lab / E2E | Verify suspicious artifacts and suspicious network activity are retained together in one self-contained evidence package | Synthetic suspicious HTTP PCAP plus staged HTML, PowerShell, JSON, and CSV artifact fixtures | `python scripts/run_lab_scenario.py --scenario lab-scn-005-artifact-network-correlation --write-index` | Signature alert plus artifact triage are retained together, with quarantine evidence inside the bundle | Pass. Latest run recorded `7` flows, `1` network alert, and `4` artifact rows; `2` high-risk artifacts quarantined inside the scenario bundle | `NIDS_TestLab/results/phase3-artifact-network-correlation-offline-20260312-033521/`; `NIDS_TestLab/reports/lab_execution_index.md` | Pass |

### 6.10 Prepared-Environment Executed Scenarios

Every scenario below has recorded evidence in `NIDS_TestLab/results/` and is indexed by `NIDS_TestLab/reports/prepared_env_validation_index.md`.

| Scenario ID | Scenario name | Environment | Objective | Execution status | Expected outcome | Actual outcome | Evidence path | Verdict | Blocker if incomplete |
|---|---|---|---|---|---|---|---|---|---|
| PREP-ENV-001 | Prepared Environment Tcpdump FIFO Port Scan | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate the live `tcpdump`-to-pipeline path on the sensor VM with a real NIC-backed port scan. | Executed | The sensor runtime should observe backend `tcpdump`, process the live scan, write evidence, and alert without runtime failure. | `160` flows and `1` anomaly alert recorded. Rule fired: `Port Scan Threshold` (`1`). Signature, ML, and fusion were not observed; suppression did not change output. | `NIDS_TestLab/results/phase4-live-tcpdump-portscan-20260312-143507/` | Pass | None. |
| PREP-ENV-002 | Prepared Environment Direct NIC Scapy DNS Burst | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `scapy` | Validate direct NIC capture through the `scapy` backend on the sensor VM with a live DNS burst. | Executed | The runtime should observe backend `scapy`, process the burst, and retain evidence without hanging or permission failure. | `90` flows and `1` anomaly alert recorded. Rule fired: `DNS Burst / DGA-like Activity` (`1`). | `NIDS_TestLab/results/phase4-live-scapy-direct-dns-burst-20260312-143612/` | Pass | None. |
| PREP-ENV-003 | Prepared Environment Queue Pressure And Loss Accounting | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` with queue size `1` | Force queue pressure under live capture and quantify packet loss without crashing the runtime. | Executed | Explicit packet counters, queue depth, and loss percentage should be retained for analyst review. | `23` flows recorded with `8127` packets received, `23` processed, `8100` dropped, `99.6678%` loss, and queue depth peak `1`. | `NIDS_TestLab/results/phase5-tuning/phase5-loss-accounting-dns-flood-20260312-163750/` | Pass | None for the executed queue-loss objective. |
| PREP-ENV-004 | Prepared Environment Malformed Packet Handling | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate that malformed UDP or DNS-like traffic does not crash the live runtime and that valid traffic in the same run is still processed. | Executed | The runtime should survive malformed input and still retain evidence for the valid portion of the run. | `60` flows and `1` anomaly alert recorded. `12` malformed packets were sent and no runtime traceback was recorded. | `NIDS_TestLab/results/phase4-live-malformed-dns-20260312-144346/` | Pass | None. |
| PREP-ENV-005 | Prepared Environment Benign Soak After Live Tuning | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Rerun the benign sample after live unsupervised tuning and record analyst adjudication. | Executed | The benign sample should complete without the prior high-severity unsupervised alerts. | `1404` flows and `0` alerts recorded. The exercised sample stayed clear again on the Phase 7 rerun. | `NIDS_TestLab/results/phase5-tuning/phase5-benign-soak-tuned-20260312-200047/` | Pass | Clears the exercised sample only. |
| PREP-ENV-006 | Prepared Environment Restart And Recovery | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` across a stop/restart cycle | Validate that the live runtime can be stopped and restarted against the same output directory while preserving recoverable evidence. | Executed | Both pre-restart and post-restart activity should be retained in the same evidence bundle without corruption or runtime crash. | `144` cumulative flows and `2` anomaly alerts recorded. Rules fired: `DNS Burst / DGA-like Activity` (`1`) and `Port Scan Threshold` (`1`). | `NIDS_TestLab/results/phase4-live-restart-recovery-20260312-143955/` | Pass | None. |
| PREP-ENV-007 | Prepared Environment Full-Duration Soak | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Run the full prepared-environment soak for the target `6` to `12` hour window, record resource and storage growth, and verify midpoint restart stability under the tuned deployment profile. | Executed | The full-duration soak should remain alert-free on the tuned profile, retain resource and storage growth evidence across the full window, and survive the midpoint restart with continued flow growth. | Latest Phase 10 rerun recorded `87533` flows and `0` alerts. Executed duration `21600.0s`; peak RSS `409444 KiB`; peak CPU `107.0%`; runtime total-result peak `5741514577` bytes; local bundle size `103291016` bytes; reload latency `13.335s`. The earlier Phase 8 baseline remains available for historical comparison in `phase6-soak/phase6-full-duration-soak-20260312-203803/`. | `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/` | Pass | None for the scenario execution itself; release-candidate promotion still depends on explaining the remaining storage high-water accounting. |
| PREP-ENV-008 | Prepared Environment Operator Rule Refresh | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Validate restart-based rule refresh while live DNS traffic is active. | Executed | The custom DNS signature should begin matching only after the refresh. | `321` flows and `1` signature alert recorded. The custom rule count increased from `0` before refresh to `1` after refresh and reload latency remained `13.238s`. | `NIDS_TestLab/results/phase5-operator/phase5-operator-rule-refresh-20260312-201250/` | Pass | None. |
| PREP-ENV-009 | Prepared Environment Operator Model Swap | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Validate restart-based supervised model swap during live traffic. | Executed | Flow continuity and detection continuity should persist after the model-path swap. | `330` flows and `2` anomaly alerts recorded across pre/post phases with reload latency `13.201s`. | `NIDS_TestLab/results/phase5-operator/phase5-operator-model-swap-20260312-164422/` | Pass | None for the restart-based swap path. |
| PREP-ENV-010 | Prepared Environment Operator Config Override | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, baseline-to-tuned live profile via `tcpdump` | Validate restart-based config override from the baseline live profile to the tuned live profile while benign traffic remains active. | Executed | Flow continuity should persist across the config swap and the tuned benign sample should stay quiet. | `394` flows and `0` alerts recorded with reload latency `13.268s`; flow growth persisted across the profile swap. | `NIDS_TestLab/results/phase5-operator/phase5-operator-config-override-20260312-164850/` | Pass | None for the restart-based override path. |
| PREP-ENV-011 | Prepared Environment Benign SaaS Polling Mix | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate tuned unsupervised behavior against a broader benign sample dominated by recurring SaaS/API polling, resolver lookups, and low-rate HTTP health checks. | Executed | The tuned profile should stay alert-free across this broader benign SaaS polling mix while retaining process and runtime evidence. | Latest Phase 9 rerun recorded `1622` flows and `0` alerts. Benign sample `BENIGN-LIVE-002` completed with adjudication `cleared_after_phase9_tuning`; generalization assessment remains `supports_generalization`. | `NIDS_TestLab/results/phase6-benign/phase6-benign-saas-polling-20260313-161149/` | Pass | None for this exercised sample. |
| PREP-ENV-012 | Prepared Environment Benign Browsing And Collaboration Mix | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate tuned unsupervised behavior against a burstier benign browsing and collaboration sample rather than only status polling. | Executed | The tuned profile should remain alert-free on this broader benign browsing and collaboration sample while capturing process and runtime trends. | Latest Phase 9 rerun recorded `1814` flows and `0` alerts. The earlier residual benign false positive did not reproduce on the updated profile. | `NIDS_TestLab/results/phase6-benign/phase6-benign-browsing-collaboration-20260313-160630/` | Pass | Historical residual alert retained for reference only; the next full soak must confirm the improvement under long duration. |
| PREP-ENV-013 | Prepared Environment Live Suppression Validation | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate duplicate alert suppression and live operator-driven policy suppression against noisy repeated DNS signature events under prepared-environment traffic. | Executed | Repeated noisy events should first be reduced by duplicate suppression, then blocked by policy suppression, while suppression counters increase and final operator-facing volume stays stable. | `69` flows and `1` operator-visible signature alert recorded; final alert volume remained `1`, active suppression rules reached `1`, derived duplicate suppressions reached `25`, and derived policy suppressions reached `35`. | `NIDS_TestLab/results/phase6-suppression/phase6-live-suppression-validation-20260312-203539/` | Pass | None for the executed suppression objective. |

Phase 8 completed execution:

- `PREP-ENV-007` real full-duration soak completed after launching on `2026-03-12T16:38:00.9866539-04:00`.
- Launch evidence: `NIDS_TestLab/reports/phase8/prep-env-007-full-soak-20260312-163800.launch.json`
- Completed result path: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260312-203803/`
- Status at this update: completed with `partial` verdict, `37598` flows, `19` alerts, `21600.0s`, and reload latency `13.329s`.

Phase 10 completed execution:

- `PREP-ENV-007` rerun closed after launch on `2026-03-13T16:50:43.0365799Z`.
- Launch evidence: `NIDS_TestLab/reports/phase10/prep-env-007-rerun-20260313-165040.launch.json`
- Completed result path: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`
- Status at this update: completed with `pass` verdict, `87533` flows, `0` alerts, `21600.0s`, peak RSS `409444 KiB`, peak CPU `107.0%`, runtime total-result peak `5741514577` bytes, local bundle size `103291016` bytes, and reload latency `13.335s`.

## 7. Coverage Summary

Coverage is now first-class CI evidence:

- `.coveragerc` enables branch coverage for `src/NIDS`.
- Current enforced minimum: `72%`.
- Local measured total after the current evidence refresh: `79.16%`.
- Terminal summary, XML, and HTML reports are all generated.
- Current default-suite warning count: `0`.

Generated evidence:

- `artifacts/coverage/coverage.xml`
- `artifacts/coverage/html/index.html`
- `artifacts/test-results/junit-local.xml`

High-value coverage gains from this increment:

- Direct CLI coverage added.
- Direct ML data/train/evaluate coverage added.
- Direct storage and migration-safe behavior coverage added.
- Direct offline ingest and mocked live path coverage added.
- Direct artifact parser/storage/intake/report coverage added.
- Direct visualization query/chart/export coverage added.
- Safe script-entry smoke coverage added.
- Deeper runtime orchestration and dashboard query coverage added.
- Lightweight performance and live-capture operational suites added outside the default fast path.
- Repeatable offline and prepared-environment evidence indexing added.

## 8. CI Workflow Summary

### Standard PR workflow

File: `.github/workflows/ci.yml`

- Installs dependencies, including `pytest-cov`.
- Runs the default fast pytest suite with coverage enforcement.
- Produces terminal coverage summary, XML coverage, HTML coverage, and JUnit XML.
- Uploads coverage and test-result artifacts.

### Nightly / manual extended workflow

File: `.github/workflows/validation-extended.yml`

- Runs a broader Python validation job on schedule or workflow dispatch.
- Executes the extended `integration` and `slow` slices outside the default PR gate while excluding `live`, `environment`, and `lab` markers.
- Uploads extended JUnit XML plus validation artifacts.
- Supports an optional self-hosted Windows lab job with `run_lab_validation=true`.
- Publishes lab outputs from `artifacts/lab/` and `NIDS_TestLab/reports/`.

## 9. Real-Time and Lab Validation Plan

Real-time and pre-deployment validation now includes both offline and prepared-environment evidence. The current state is documented in:

- `docs/lab_validation_plan.md`
- `docs/test_matrix.md`
- `docs/deployment_readiness_checklist.md`
- `docs/platform_support_matrix.md`
- `docs/quantum_readiness_plan.md`

Completed in the current environment:

- offline replay validation for port scan, brute force, flood, mixed traffic, and artifact-plus-network correlation
- prepared-environment validation for live `tcpdump`, live `scapy`, malformed-packet handling, restart recovery, queue-loss accounting, tuned benign soak, broader benign adjudication, live suppression validation, operator workflows, a soak pilot, and a completed full-duration soak closure
- per-scenario evidence bundles with manifests, logs, SQLite, JSONL, report output, and metrics where applicable
- consolidated execution indexing in:
  - `NIDS_TestLab/reports/lab_execution_index.md`
  - `NIDS_TestLab/reports/prepared_env_validation_index.md`
- maintenance decision support documented in `docs/maintenance_strategy_decision.md`
- release-candidate freeze material captured in `release/rc1/README.md` and `release/rc1/freeze_manifest.json`

Still required for deployment promotion:

- explanation of the completed Phase 10 runtime high-water storage figure `5741514577` versus the retained final bundle size `103291016`
- interpretation of the transient queue/loss metric maxima captured during the completed rerun so the long-run evidence story is internally consistent
- hot reload, or an equivalent zero-downtime strategy, before any deployment that requires uninterrupted coverage

## 10. Known Gaps and Residual Risks

Current strengths:

- Fast suite is materially broader and now exercises the highest-priority missing modules directly.
- Coverage is enforced and above the initial threshold.
- CI and documentation now distinguish between default fast validation and optional lab validation.

Residual gaps:

- the completed Phase 10 rerun closed the original alert-quality concern, but `runtime_total_result_peak_bytes` still rose to `5741514577` while the retained local bundle closed near `103291016`, so storage accounting remains unresolved for stronger promotion claims
- the completed Phase 10 metric series also recorded transient maxima in queue/loss-related fields even though the final values and retained runtime log stayed clean; that interpretation gap should be resolved before claiming release-candidate readiness
- `src/NIDS/runtime.py` and `src/NIDS/visuals/dashboard.py` are now better supported by six-hour evidence, but the long-run resource story is still not fully closed until the storage and metric-accounting issue is explained
- Operator maintenance is validated only through restart-based workflows. `docs/maintenance_strategy_decision.md` supports restart-based workflows for a controlled candidate, but zero-downtime reload remains a feature gap for uninterrupted coverage.
- macOS remains documented but not validated as a first-class prepared-environment host.

## 11. Deployment Readiness Criteria

The repository should be considered deployment-ready only when all of the following are true:

1. Default fast suite passes with coverage above the enforced floor.
2. Extended `integration` and `slow` validations are run for the release candidate.
3. Offline and prepared-environment evidence are current for the intended deployment profile.
4. Known warnings are either fixed or tracked with owner and retirement plan.
5. Reports, storage outputs, and operational recovery steps are validated for the intended deployment profile.
6. Residual false-positive and false-negative risks are recorded from realistic validation data.

Current verdict:

- `Conditional go for a controlled pre-deployment candidate`
- `Not promoted to Release Candidate ready for controlled deployment and publication support`
- Reason: code-level testing, CI controls, offline evidence, queue-loss accounting, broader benign adjudication, live suppression evidence, restart-based operator workflow evidence, and an `rc1` freeze are now in place. The completed Phase 10 rerun materially improved the long-duration soak outcome to `87533` flows and `0` alerts with lower CPU and RSS, but release-candidate promotion is still blocked because the runtime high-water storage figure and related long-run metric interpretation are not yet sufficiently explained, and uninterrupted-coverage deployments still require a zero-downtime maintenance strategy.

## 12. Supporting Documents

- `docs/test_matrix.md`
- `docs/lab_validation_plan.md`
- `docs/deployment_readiness_checklist.md`
- `docs/platform_support_matrix.md`
- `docs/quick_start_resume.md`
- `docs/current_status.md`
- `docs/next_actions.md`
- `docs/quantum_readiness_plan.md`
- `docs/references.md`

## 13. References

[1] NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/115/final

[2] NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/61/r3/final

[3] *MITRE ATT&CK Enterprise Matrix*, MITRE ATT&CK, https://attack.mitre.org/matrices/enterprise/

[4] *ATT&CK Evaluations: Emulation and Evaluation Guide*, MITRE Engenuity, https://info.mitre-engenuity.org/att-ckevaluations-emulation-and-evaluation-guide

[5] *Best Practices for Event Logging and Threat Detection*, Cybersecurity and Infrastructure Security Agency and partners, https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection

[6] *Guidance for SIEM and SOAR Implementation*, Cybersecurity and Infrastructure Security Agency, https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation
