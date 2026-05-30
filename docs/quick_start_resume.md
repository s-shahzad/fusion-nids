# Quick Start Resume

Use this file at the start of a new engineering session.

## Read First

1. `state/project_status.json`
2. `docs/current_status.md`
3. `docs/next_actions.md`
4. `docs/testing_validation_master.md`
5. `docs/lab_validation_plan.md`
6. `docs/false_positive_analysis.md`
7. `docs/maintenance_strategy_decision.md`
8. `phase8_partial_soak_analysis.md`
9. `phase8_alert_review.md`
10. `phase9_remediation_plan.md`
11. `docs/phase9_false_positive_tuning.md`
12. `docs/phase9_resource_review.md`
13. `docs/phase9_soak_rebaseline.md`
14. `NIDS_TestLab/reports/lab_execution_index.md`
15. `NIDS_TestLab/reports/prepared_env_validation_index.md`

## Current Baseline

- Default suite: `149 passed, 8 deselected`
- Active pytest warnings: `0`
- Coverage: `79.16%`
- Minimum enforced coverage: `72%`
- Phase 9 targeted unit rerun: `17 passed, 4 deselected`
- Phase 10 focused orchestration validation: `16 passed`
- Latest offline lab evidence:
  - `5` passing latest scenario runs in `NIDS_TestLab/reports/lab_execution_index.md`
  - `7` total recorded offline scenario manifests
- Latest prepared-environment evidence:
  - `13` latest scenario runs in `NIDS_TestLab/reports/prepared_env_validation_index.md`
  - `12` pass, `1` partial in the latest-per-scenario view
  - `35` total recorded prepared-environment manifests

Latest long-duration validation on record:

- `PREP-ENV-007` full-duration soak completed after launching on `2026-03-12T16:38:00.9866539-04:00`
- launch record: `NIDS_TestLab/reports/phase8/prep-env-007-full-soak-20260312-163800.launch.json`
- completed result directory: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260312-203803/`
- final result: `partial`, `37598` flows, `19` alerts, `21600.0s`, reload latency `13.329s`

Phase 9 reruns now on record:

- `LAB-SCN-003`: `pass`, `296` flows, `5` alerts
- `PREP-ENV-011`: `pass`, `1622` flows, `0` alerts
- `PREP-ENV-012`: `pass`, `1814` flows, `0` alerts
- `PHASE9-DOS-BURST-001`: `pass`, `2410` flows, `1` `DoS Rate Threshold` alert

Active Phase 10 rerun:

- `PREP-ENV-007`: launched at `2026-03-13T16:50:43.0365799Z`
- run stamp: `20260313-165040`
- launch record: `NIDS_TestLab/reports/phase10/prep-env-007-rerun-20260313-165040.launch.json`
- planned result directory: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`

Prepared-environment execution in this repo should use the project virtualenv. The system `python` on this host does not currently carry the lab dependencies needed by `scripts/prepared_env_validation.py`.

## Most Useful Commands

```bash
pytest
pytest --cov=src/NIDS --cov-config=.coveragerc --cov-report=term-missing:skip-covered --cov-report=xml --cov-report=html
.\.venv\Scripts\python.exe -m pytest tests/test_anomaly.py tests/test_ml_unsupervised.py tests/test_storage_direct.py tests/test_performance_pipeline.py
.\.venv\Scripts\python.exe scripts/run_lab_scenario.py --scenario lab-scn-003-flood-burst --run-prefix phase9
.\.venv\Scripts\python.exe scripts/prepared_env_validation.py --scenario PREP-ENV-011 PREP-ENV-012 --write-index
.\.venv\Scripts\python.exe scripts/live_vm_attack_validation.py --config-relpath NIDS_TestLab/config/live_vm_phase5_tuned_profile.yml --run-name phase9-live-dos-burst-validation-YYYYMMDD-HHMMSS --dns-count 0 --dns-flood-rate-per-sec 220 --dns-flood-duration-sec 14 --ssh-attempts 0 --rdp-attempts 0 --http-login-attempts 0 --http-keyword-requests 0 --udp-flood-packets 0 --warmup-sec 4 --settle-sec 6
.\.venv\Scripts\python.exe scripts/prepared_env_validation.py --scenario PREP-ENV-007 --write-index
```

## Primary Open Goal

Keep the repository at `Conditional go for a controlled pre-deployment candidate`, let the active Phase 10 full-duration soak rerun close on the updated profile, and only then revisit release-candidate promotion. `PREP-ENV-012` no longer reproduces on the current rerun set, but the long-duration soak still has to confirm that the broader false-positive and resource picture is genuinely improved.
