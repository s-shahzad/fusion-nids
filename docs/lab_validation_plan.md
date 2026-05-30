# Lab Validation Plan

Last updated: March 13, 2026

This plan defines the end-to-end validation work that remains outside the default fast pytest suite. It uses a threat-informed, evidence-driven model consistent with NIST testing guidance, incident-response considerations, ATT&CK-aligned evaluation, and CISA logging expectations [1][2][3][4][5][6].

## Objectives

- Validate realistic detection behavior under mixed benign and malicious traffic.
- Confirm that signature, anomaly, supervised, unsupervised, and fusion outputs remain explainable under concurrent attack conditions.
- Collect reproducible evidence bundles suitable for pre-deployment review.
- Keep environment-heavy validation separated from normal PR execution.

## Execution Framework

Offline and prepared-environment execution use these repository-native helpers:

- `scripts/run_lab_scenario.py`
- `scripts/summarize_lab_results.py`
- `scripts/prepared_env_validation.py`
- scenario definitions under `NIDS_TestLab/scenarios/`
- prepared-environment profiles under `NIDS_TestLab/config/`
- result bundles under `NIDS_TestLab/results/`
- consolidated indexes under:
  - `NIDS_TestLab/reports/lab_execution_index.json`
  - `NIDS_TestLab/reports/lab_execution_index.md`
  - `NIDS_TestLab/reports/prepared_env_validation_index.json`
  - `NIDS_TestLab/reports/prepared_env_validation_index.md`

Each result bundle records:

- `manifest.json` or `prepared_env_manifest.json`
- `summary.md` or `prepared_env_summary.md`
- `metrics.json` or `prepared_env_metrics.json`
- copied runtime logs, SQLite, JSONL, and generated reports where available
- expected result, actual result, evidence path, and verdict

## Executed Evidence

Phase 3 offline execution on the current Windows host:

```bash
python scripts/run_lab_scenario.py --scenario all --write-index
```

Phase 5 through Phase 8 prepared-environment execution on the current Windows host against the Ubuntu sensor and target VMs:

```bash
python scripts/prepared_env_validation.py --scenario PREP-ENV-003 --write-index
python scripts/prepared_env_validation.py --scenario PREP-ENV-005 --write-index
python scripts/prepared_env_validation.py --scenario PREP-ENV-008 PREP-ENV-009 PREP-ENV-010 --write-index
python scripts/prepared_env_validation.py --scenario PREP-ENV-007 --duration-override-sec 900 --write-index
python scripts/prepared_env_validation.py --scenario PREP-ENV-011 PREP-ENV-012 PREP-ENV-013 --write-index
.\.venv\Scripts\python.exe scripts/prepared_env_validation.py --scenario PREP-ENV-005 PREP-ENV-011 PREP-ENV-012 --write-index
.\.venv\Scripts\python.exe scripts/prepared_env_validation.py --scenario PREP-ENV-008 PREP-ENV-013 --write-index
```

The current indexes now show:

- `5` latest offline scenario passes with `6` total recorded offline manifests
- `13` latest prepared-environment scenarios with `12` pass and `1` partial across `35` recorded prepared-environment manifests

## Offline Scenario Catalog

| Scenario ID | Scenario name | Environment | Objective | Execution status | Expected outcome | Actual outcome | Evidence path | Verdict | Blocker if incomplete |
|---|---|---|---|---|---|---|---|---|---|
| LAB-SCN-001 | Port Scan Offline Replay | Windows host, `offline_replay` | Confirm that scan-style traffic produces signature, anomaly, and fusion evidence suitable for analyst review. | Executed | Port-scan rules fire, anomaly evidence appears, fusion may trigger, reports are written. | `33` flows and `5` alerts recorded. Rules fired: `Suspicious Port Scan` (`3`), `Port Scan Threshold` (`1`), `Hybrid Fusion Decision` (`1`). | `NIDS_TestLab/results/phase3-port-scan-offline-20260312-032633/` | Pass | None. |
| LAB-SCN-002 | HTTP Login Brute Force Offline Replay | Windows host, `offline_replay` | Confirm that repeated login abuse patterns generate brute-force evidence with stable severity and chronology. | Executed | Brute-force thresholding should alert and timeline/report outputs should be retained. | `14` flows and `1` alert recorded. Rule fired: `HTTP Login Brute Force Threshold` (`1`). | `NIDS_TestLab/results/phase3-http-login-bruteforce-offline-20260312-032715/` | Pass | None. |
| LAB-SCN-003 | Flood And Burst Offline Replay | Windows host, `offline_replay` | Confirm that bursty DNS and UDP flood patterns surface anomaly and ML evidence without runtime instability. | Executed | Burst/flood rules and anomaly/ML evidence should appear, with fusion when detections agree. | Latest Phase 9 rerun again recorded `296` flows and `5` alerts. Rules fired: `DNS Burst / DGA-like Activity`, `DoS Rate Threshold`, `Hybrid Unsupervised Anomaly Score`, and `Hybrid Fusion Decision`. | `NIDS_TestLab/results/phase9-flood-burst-offline-20260313-160502/` | Pass | Confirms the updated code path still surfaces attack evidence. |
| LAB-SCN-004 | Mixed Benign And Malicious Offline Replay | Windows host, `offline_replay` | Confirm that mixed traffic retains true-positive visibility while preserving a reviewable timeline across multiple attack families. | Executed | Mixed benign and malicious traffic should produce a coherent alert chronology and fusion evidence without suppression side effects. | `82` flows and `8` alerts recorded across scan, brute-force, and mixed fusion paths. | `NIDS_TestLab/results/phase3-mixed-traffic-offline-20260312-032936/` | Pass | None. |
| LAB-SCN-005 | Artifact And Network Correlation Offline Replay | Windows host, `offline_replay` | Confirm that suspicious artifacts and suspicious network activity can be retained together in a single evidence package. | Executed | Signature alert plus high-risk artifact triage should be retained together, with quarantine evidence rooted in the scenario bundle. | Latest run recorded `7` flows, `1` network alert, and `4` artifact rows with quarantine evidence inside the bundle. | `NIDS_TestLab/results/phase3-artifact-network-correlation-offline-20260312-033521/` | Pass | None. |

## Prepared-Environment Scenario Catalog

| Scenario ID | Scenario name | Environment | Objective | Execution status | Expected outcome | Actual outcome | Evidence path | Verdict | Blocker if incomplete |
|---|---|---|---|---|---|---|---|---|---|
| PREP-ENV-001 | Prepared Environment Tcpdump FIFO Port Scan | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate the live `tcpdump`-to-pipeline path on the sensor VM with a real NIC-backed port scan. | Executed | The sensor runtime should observe backend `tcpdump`, process the live scan, write evidence, and alert without runtime failure. | `160` flows and `1` alert recorded. Rule fired: `Port Scan Threshold` (`1`). | `NIDS_TestLab/results/phase4-live-tcpdump-portscan-20260312-143507/` | Pass | None. |
| PREP-ENV-002 | Prepared Environment Direct NIC Scapy DNS Burst | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `scapy` | Validate direct NIC capture through the `scapy` backend on the sensor VM with a live DNS burst. | Executed | The runtime should observe backend `scapy`, process the burst, and retain evidence without hanging or permission failure. | `90` flows and `1` alert recorded. Rule fired: `DNS Burst / DGA-like Activity` (`1`). | `NIDS_TestLab/results/phase4-live-scapy-direct-dns-burst-20260312-143612/` | Pass | None. |
| PREP-ENV-003 | Prepared Environment Queue Pressure And Loss Accounting | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` with queue size `1` | Force queue pressure under live capture and quantify packet loss without crashing the runtime. | Executed | Explicit packet counters, queue depth, and loss percentage should be retained for analyst review. | `23` flows recorded with `8127` packets received, `23` processed, `8100` dropped, `99.6678%` loss, and queue depth peak `1`. | `NIDS_TestLab/results/phase5-tuning/phase5-loss-accounting-dns-flood-20260312-163750/` | Pass | None for the executed queue-loss objective. |
| PREP-ENV-004 | Prepared Environment Malformed Packet Handling | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate that malformed UDP or DNS-like traffic does not crash the live runtime and that valid traffic in the same run is still processed. | Executed | The runtime should survive malformed input and still retain evidence for the valid portion of the run. | `60` flows and `1` anomaly alert recorded. `12` malformed packets were sent and no runtime traceback was recorded. | `NIDS_TestLab/results/phase4-live-malformed-dns-20260312-144346/` | Pass | None. |
| PREP-ENV-005 | Prepared Environment Benign Soak After Live Tuning | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Rerun the benign sample after live unsupervised tuning and record analyst adjudication. | Executed | The benign sample should complete without the prior high-severity unsupervised alerts. | `1404` flows and `0` alerts recorded. The exercised sample stayed clear again on the Phase 7 rerun. | `NIDS_TestLab/results/phase5-tuning/phase5-benign-soak-tuned-20260312-200047/` | Pass | Clears the exercised sample only. |
| PREP-ENV-006 | Prepared Environment Restart And Recovery | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` across a stop/restart cycle | Validate that the live runtime can be stopped and restarted against the same output directory while preserving recoverable evidence. | Executed | Both pre-restart and post-restart activity should be retained in the same evidence bundle without corruption or runtime crash. | `144` cumulative flows and `2` anomaly alerts recorded with separate phase-one and phase-two counts. | `NIDS_TestLab/results/phase4-live-restart-recovery-20260312-143955/` | Pass | None. |
| PREP-ENV-007 | Prepared Environment Full-Duration Soak | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Run the full prepared-environment soak for the target `6` to `12` hour window, record resource and storage growth, and verify midpoint restart stability under the tuned deployment profile. | Executed | The full-duration soak should remain alert-free on the tuned profile, retain resource and storage growth evidence across the full window, and survive the midpoint restart with continued flow growth. | `37598` flows and `19` alerts recorded. Executed duration `21600.0s`; peak RSS `543268 KiB`; recorded storage growth `1343554193` bytes; reload latency `13.329s`. Earlier `900s` pilot remains available for historical comparison in `phase5-soak/phase5-extended-soak-20260312-165051/`. | `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260312-203803/` | Partial | Completed, but not acceptable for release-candidate promotion until alert volume is reduced or explicitly bounded for the intended deployment envelope. |
| PREP-ENV-008 | Prepared Environment Operator Rule Refresh | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Validate restart-based rule refresh while live DNS traffic is active. | Executed | The custom DNS signature should begin matching only after the refresh. | `321` flows and `1` signature alert recorded. The custom rule count increased from `0` before refresh to `1` after refresh and reload latency remained `13.238s`. | `NIDS_TestLab/results/phase5-operator/phase5-operator-rule-refresh-20260312-201250/` | Pass | None. |
| PREP-ENV-009 | Prepared Environment Operator Model Swap | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Validate restart-based supervised model swap during live traffic. | Executed | Flow continuity and detection continuity should persist after the model-path swap. | `330` flows and `2` anomaly alerts recorded across pre/post phases with reload latency `13.201s`. | `NIDS_TestLab/results/phase5-operator/phase5-operator-model-swap-20260312-164422/` | Pass | None for the restart-based swap path. |
| PREP-ENV-010 | Prepared Environment Operator Config Override | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, baseline-to-tuned live profile via `tcpdump` | Validate restart-based config override from the baseline live profile to the tuned live profile while benign traffic remains active. | Executed | Flow continuity should persist across the config swap and the tuned benign sample should stay quiet. | `394` flows and `0` alerts recorded with reload latency `13.268s`; flow growth persisted across the profile swap. | `NIDS_TestLab/results/phase5-operator/phase5-operator-config-override-20260312-164850/` | Pass | None for the restart-based override path. |
| PREP-ENV-011 | Prepared Environment Benign SaaS Polling Mix | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate tuned unsupervised behavior against a broader benign sample dominated by recurring SaaS/API polling, resolver lookups, and low-rate HTTP health checks. | Executed | The tuned profile should stay alert-free across this broader benign SaaS polling mix while retaining process and runtime evidence. | Latest Phase 9 rerun recorded `1622` flows and `0` alerts. Benign sample `BENIGN-LIVE-002` remained clear on the updated profile. | `NIDS_TestLab/results/phase6-benign/phase6-benign-saas-polling-20260313-161149/` | Pass | Supports generalization of the updated Phase 9 profile. |
| PREP-ENV-012 | Prepared Environment Benign Browsing And Collaboration Mix | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate tuned unsupervised behavior against a burstier benign browsing and collaboration sample rather than only status polling. | Executed | The tuned profile should remain alert-free on this broader benign browsing and collaboration sample while capturing process and runtime trends. | Latest Phase 9 rerun recorded `1814` flows and `0` alerts. The earlier residual benign false positive did not reproduce on the updated profile. | `NIDS_TestLab/results/phase6-benign/phase6-benign-browsing-collaboration-20260313-160630/` | Pass | Improved on rerun; full-soak confirmation still pending. |
| PREP-ENV-013 | Prepared Environment Live Suppression Validation | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Validate duplicate alert suppression and live operator-driven policy suppression against noisy repeated DNS signature events under prepared-environment traffic. | Executed | Repeated noisy events should first be reduced by duplicate suppression, then blocked by policy suppression, while suppression counters increase and final operator-facing volume stays stable. | `69` flows and `1` operator-visible signature alert recorded; final alert count remained `1`, active suppression rules reached `1`, derived duplicate suppressions reached `25`, and derived policy suppressions reached `35`. | `NIDS_TestLab/results/phase6-suppression/phase6-live-suppression-validation-20260312-203539/` | Pass | None for the executed suppression objective. |

Phase 8 completed execution:

- `PREP-ENV-007` real full-duration soak completed after launching on `2026-03-12T16:38:00.9866539-04:00`.
- Launch evidence: `NIDS_TestLab/reports/phase8/prep-env-007-full-soak-20260312-163800.launch.json`
- Completed result path: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260312-203803/`
- Status at this update: completed with `partial` verdict, `37598` flows, `19` alerts, `21600.0s`, and reload latency `13.329s`.

## Required Evidence Fields

Every recorded scenario bundle now captures:

- scenario ID
- generated timestamp
- objective
- host and VM environment metadata
- primary execution mode
- rules, engine, and severity counts
- expected result
- actual result
- pass, fail, or partial verdict
- evidence path

## Recommended Run Order

1. Run the default fast suite with coverage.
2. Run the extended non-lab suite.
3. Validate lab assets.
4. Refresh offline scenario evidence.
5. Refresh prepared-environment evidence with `scripts/prepared_env_validation.py`.
6. Review the consolidated indexes.
7. Fold final verdicts back into `docs/testing_validation_master.md` and `docs/deployment_readiness_checklist.md`.

## Workflow Placement

- PR / default CI: `.github/workflows/ci.yml`
- Nightly / manual extended validation: `.github/workflows/validation-extended.yml`
- Manual or prepared-host environment capture validation: `pytest -m "live and environment"`
- Manual prepared-environment execution: `scripts/prepared_env_validation.py`

## Current Lab Readiness

- All five phase 3 offline scenarios have current passing evidence bundles.
- Prepared-environment evidence now exists for live capture, queue-loss accounting, tuned benign soak, broader benign adjudication, restart recovery, rule refresh, model swap, config override, live suppression validation, an extended soak pilot, and a completed full-duration soak closure.
- Result indexing is repeatable through `scripts/summarize_lab_results.py` and `scripts/prepared_env_validation.py`.
- Hash-pinned release-candidate freeze material now exists in `release/rc1/README.md` and `release/rc1/freeze_manifest.json`.

## Remaining Blockers

- Completion of the active Phase 10 `PREP-ENV-007` full-duration rerun `20260313-165040` on the Phase 9 candidate to confirm the prior `19`-alert partial result is materially improved.
- Confirmation that the improved `PREP-ENV-011` and `PREP-ENV-012` short-run behavior also holds across the completed long-duration rerun window.
- Hot reload, or an equivalent zero-downtime maintenance strategy, before any deployment that cannot tolerate the measured restart window.

## References

[1] NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/115/final

[2] NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/61/r3/final

[3] *MITRE ATT&CK Enterprise Matrix*, MITRE ATT&CK, https://attack.mitre.org/matrices/enterprise/

[4] *ATT&CK Evaluations: Emulation and Evaluation Guide*, MITRE Engenuity, https://info.mitre-engenuity.org/att-ckevaluations-emulation-and-evaluation-guide

[5] *Best Practices for Event Logging and Threat Detection*, Cybersecurity and Infrastructure Security Agency and partners, https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection

[6] *Guidance for SIEM and SOAR Implementation*, Cybersecurity and Infrastructure Security Agency, https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation
