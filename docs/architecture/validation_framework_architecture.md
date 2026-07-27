# Validation Framework Architecture

## Component Description

Universal NIDS uses a layered validation framework rather than a single test type. The repository combines unit and integration tests, offline scenario execution, prepared-environment VM validation, operator workflow validation, and long-duration soak evidence collection.

## ASCII Validation Diagram

```text
Pytest Layer
  |-- unit
  |-- integration
  |-- live/environment
  |-- slow
  `-- lab
          |
          v
Scenario Execution Layer
  |-- run_lab_scenario.py
  |-- summarize_lab_results.py
  `-- prepared_env_validation.py
          |
          v
Evidence Bundles
  |-- manifest / prepared_env_manifest
  |-- summary markdown
  |-- metrics JSON
  |-- copied SQLite / JSONL / logs / reports
          |
          v
Indexes + Readiness Docs
  |-- lab_execution_index
  |-- prepared_env_validation_index
  |-- testing_validation_master
  |-- deployment_readiness_checklist
```

## Module Relationships

- `tests/` covers deterministic unit and local integration behavior across runtime, ingest, ML, storage, artifact, dashboard, and script helpers.
- `scripts/run_lab_scenario.py` drives offline scenario execution.
- `scripts/summarize_lab_results.py` and indexed report files summarize offline execution history.
- `scripts/prepared_env_validation.py` orchestrates VM-based prepared-environment scenarios and writes the prepared-environment index.
- `docs/testing_validation_master.md` and `docs/lab_validation_plan.md` define the evidence model and current status.
- `state/project_status.json` carries summarized project state for status synchronization.

## Data Flow Explanation

### Fast Test Path

The default pytest suite validates:

- parser and feature logic
- detector behavior
- storage correctness
- CLI dispatch
- dashboard query paths
- artifact pipeline behavior

This provides reproducible local and CI evidence.

### Offline Lab Scenarios

Offline scenarios under `NIDS_TestLab/scenarios/` replay known traffic mixes and produce:

- scenario manifests
- summary markdown
- metrics JSON
- copied outputs and reports

These are indexed for historical comparison.

### Prepared-Environment Validation

`scripts/prepared_env_validation.py` defines explicit prepared-environment scenarios such as:

- live capture backend validation
- queue-loss accounting
- malformed-packet handling
- benign adjudication
- operator restart workflows
- suppression validation
- long-duration soak

Each run creates a timestamped bundle and may refresh the global prepared-environment index.

### Readiness Closure

Readiness documents aggregate test totals, scenario results, soak findings, and deployment verdicts into a consistent state model.

## Key Files / Modules

- `tests/`
- `scripts/run_lab_scenario.py`
- `scripts/summarize_lab_results.py`
- `scripts/prepared_env_validation.py`
- `docs/testing_validation_master.md`
- `docs/lab_validation_plan.md`
- `docs/deployment_readiness_checklist.md`
- `state/project_status.json`

## Operational Purpose

The validation framework exists to keep engineering claims bounded by evidence. It supports research discussion, controlled pre-deployment evaluation, and future hardening without collapsing everything into one test mode.

## Future Extension Points

- stronger automated comparison of baseline versus rerun evidence bundles
- richer validation metadata exports for publication and release reviews
- more formal scenario-to-requirement traceability
- automated evidence-quality checks before status promotion
