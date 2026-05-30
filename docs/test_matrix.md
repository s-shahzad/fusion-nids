# Test Matrix

Last updated: March 12, 2026

This matrix separates the fast default suite from heavier operational validation so the repository stays practical for local work and PRs while still supporting evidence-backed pre-deployment review [1][2][5][6].

## Current Baseline

| Metric | Current value | Notes |
|---|---:|---|
| Total collected tests | `152` | Includes default, `slow`, `live`, `environment`, and `lab` slices |
| Default result | `144 passed, 8 deselected` | Default selection excludes `slow`, `lab`, `live`, and `environment` |
| Active pytest warnings | `0` | Scapy DNS deprecation warning retired in `src/NIDS/pipeline/parser.py` |
| Coverage | `79.16%` | Enforced threshold `72%` |
| Live/environment result | `3 passed` | Manual explicit run on the current host |
| Slow performance result | `4 passed` | Manual explicit run |
| Lab result | `1 passed` | Asset-integrity slice |
| Offline lab execution evidence | `5` latest scenarios passed | `NIDS_TestLab/reports/lab_execution_index.md` |
| Prepared-environment evidence | `10` latest scenarios recorded: `10` pass across `17` total manifests | `NIDS_TestLab/reports/prepared_env_validation_index.md` |

## Suite Layers

| Layer | Scope | Command | Evidence |
|---|---|---|---|
| Fast default | unit + safe integration + CLI + dashboard | `pytest` | `artifacts/test-results/junit-local.xml` |
| Coverage-gated | same as fast default with XML/HTML coverage | `pytest --cov=src/NIDS --cov-config=.coveragerc --cov-report=term-missing:skip-covered --cov-report=xml --cov-report=html` | `artifacts/coverage/coverage.xml`, `artifacts/coverage/html/` |
| Extended non-lab | broader integration and slow paths | `pytest -m "(integration or slow) and not live and not environment and not lab"` | `artifacts/test-results/junit-integration.xml` |
| Environment capture | prepared-host validation for live capture paths | `pytest -m "live and environment"` | local operator evidence and prepared-host artifacts |
| Lab asset integrity | lab bundle integrity and runner prerequisites | `pytest -m lab` | `artifacts/test-results/junit-lab.xml`, `NIDS_TestLab/reports/` |
| Offline lab execution evidence | repeatable end-to-end offline scenario execution | `python scripts/run_lab_scenario.py --scenario all --write-index` | `NIDS_TestLab/results/`, `NIDS_TestLab/reports/lab_execution_index.json`, `NIDS_TestLab/reports/lab_execution_index.md` |
| Prepared-environment evidence | live VM and real-interface validation bundles | `python scripts/prepared_env_validation.py --scenario all --write-index` | `NIDS_TestLab/results/`, `NIDS_TestLab/reports/prepared_env_validation_index.json`, `NIDS_TestLab/reports/prepared_env_validation_index.md` |

## Operational and Lab Automation Tests

| Test ID | Test suite | Module | Objective | Environment | Expected behavior | Evidence |
|---|---|---|---|---|---|---|
| LIVE-OPS-001 | `tests/test_live_capture_operational.py` | `src/NIDS/ingest/live.py` | Validate tcpdump/FIFO packet streaming, burst handling, and backend failure reporting | Prepared host only; excluded from default CI | FIFO/tcpdump paths enqueue packets correctly, count drops under burst pressure, and surface backend errors without unsafe hangs | `tests/test_live_capture_operational.py` |
| RUNTIME-OPS-001 | `tests/test_runtime_operational.py` | `src/NIDS/runtime.py`, `src/NIDS/config.py` | Validate runtime pipeline assembly, config precedence, rule/model loading, startup/shutdown, and producer error handling | Default local / CI-safe | Runtime assembles configured producers, closes resources cleanly, and handles configuration and interrupt paths predictably | `tests/test_runtime_operational.py`; `artifacts/test-results/junit-local.xml` |
| DASH-OPS-001 | `tests/test_dashboard_operational.py` | `src/NIDS/visuals/dashboard.py` | Validate figures, audit/suppression query paths, websocket auth/streaming, and uvicorn delegation | Default local / CI-safe | Dashboard endpoints return expected data, reject unauthorized websocket clients, and delegate startup correctly | `tests/test_dashboard_operational.py`; `artifacts/test-results/junit-local.xml` |
| PERF-PIPE-001 | `tests/test_performance_pipeline.py` | `src/NIDS/ingest/offline.py`, `src/NIDS/runtime.py`, `src/NIDS/storage/sqlite_store.py`, `src/NIDS/storage/jsonl_store.py` | Validate lightweight throughput, detection latency, write pressure, and bounded memory growth | Manual or nightly `slow` run | Replay and write paths stay within safe deterministic smoke thresholds | `tests/test_performance_pipeline.py` |
| LAB-RUNNER-001 | `tests/test_lab_scenario_runner.py` | `scripts/run_lab_scenario.py`, `scripts/summarize_lab_results.py` | Validate repeatable scenario execution, bundle-local artifact handling, and execution-index generation | Default local / CI-safe | Scenario bundles contain manifests, summaries, SQLite evidence, and artifact paths rooted inside the scenario result directory | `tests/test_lab_scenario_runner.py`; `NIDS_TestLab/reports/lab_execution_index.md` |
| PREP-ENV-AUTO-001 | `tests/test_prepared_env_validation.py` | `scripts/prepared_env_validation.py` | Validate prepared-environment runtime-log parsing and latest-run index generation | Default local / CI-safe | Prepared-environment helper logic extracts backend/drop evidence and surfaces the newest run per scenario in the generated index | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/reports/prepared_env_validation_index.md` |
| PREP-ENV-AUTO-002 | `tests/test_prepared_env_validation.py` | `scripts/prepared_env_validation.py` | Validate verdict fallback to persisted live metric series when final runtime-log telemetry is absent | Default local / CI-safe | Prepared-environment verdict logic still recognizes received packets and observed drops from stored metrics | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/results/phase5-tuning/` |
| PREP-ENV-AUTO-003 | `tests/test_prepared_env_validation.py` | `scripts/prepared_env_validation.py` | Validate nested phase-directory indexing for prepared-environment evidence bundles | Default local / CI-safe | The prepared-environment index discovers bundles under nested directories such as `phase5-soak/` and `phase5-operator/` | `tests/test_prepared_env_validation.py`; `NIDS_TestLab/reports/prepared_env_validation_index.md` |

## Phase 3 Executed Lab Scenarios

| Scenario ID | Scenario | Environment | Latest status | Result summary | Evidence |
|---|---|---|---|---|---|
| LAB-SCN-001 | Port Scan Offline Replay | Windows host, `offline_replay` | Pass | `33` flows, `5` alerts; signature + anomaly + fusion triggered; suppression unchanged | `NIDS_TestLab/results/phase3-port-scan-offline-20260312-032633/` |
| LAB-SCN-002 | HTTP Login Brute Force Offline Replay | Windows host, `offline_replay` | Pass | `14` flows, `1` alert; anomaly triggered; suppression unchanged | `NIDS_TestLab/results/phase3-http-login-bruteforce-offline-20260312-032715/` |
| LAB-SCN-003 | Flood And Burst Offline Replay | Windows host, `offline_replay` | Pass | `296` flows, `5` alerts; anomaly + ML + fusion triggered; suppression unchanged | `NIDS_TestLab/results/phase3-flood-burst-offline-20260312-032754/` |
| LAB-SCN-004 | Mixed Benign And Malicious Offline Replay | Windows host, `offline_replay` | Pass | `82` flows, `8` alerts; signature + anomaly + fusion triggered; suppression unchanged | `NIDS_TestLab/results/phase3-mixed-traffic-offline-20260312-032936/` |
| LAB-SCN-005 | Artifact And Network Correlation Offline Replay | Windows host, `offline_replay` | Pass | `7` flows, `1` network alert, `4` artifact rows; signature triggered; `2` high-risk artifacts quarantined inside the bundle | `NIDS_TestLab/results/phase3-artifact-network-correlation-offline-20260312-033521/` |

## Phase 4 Prepared-Environment Scenarios

| Scenario ID | Scenario | Environment | Latest status | Result summary | Evidence |
|---|---|---|---|---|---|
| PREP-ENV-001 | Tcpdump FIFO Port Scan | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Pass | `160` flows, `1` anomaly alert; backend observed `tcpdump`; signature/ML/fusion not observed; suppression unchanged | `NIDS_TestLab/results/phase4-live-tcpdump-portscan-20260312-143507/` |
| PREP-ENV-002 | Direct NIC Scapy DNS Burst | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `scapy` | Pass | `90` flows, `1` anomaly alert; backend observed `scapy`; signature/ML/fusion not observed; suppression unchanged | `NIDS_TestLab/results/phase4-live-scapy-direct-dns-burst-20260312-143612/` |
| PREP-ENV-003 | Queue Pressure And Loss Accounting | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` with queue size `1` | Pass | `23` flows, `0` alerts; `8127` packets received, `23` processed, `8100` dropped, `99.6678%` loss; queue depth peak `1`; suppression unchanged | `NIDS_TestLab/results/phase5-tuning/phase5-loss-accounting-dns-flood-20260312-163750/` |
| PREP-ENV-004 | Malformed Packet Handling | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` | Pass | `60` flows, `1` anomaly alert; malformed packets did not crash runtime; valid DNS burst still processed; signature/ML/fusion not observed; suppression unchanged | `NIDS_TestLab/results/phase4-live-malformed-dns-20260312-144346/` |
| PREP-ENV-005 | Tuned Benign Soak And Adjudication | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Pass | `1416` flows, `0` alerts; prior phase 4 unsupervised false positives reduced to zero for the exercised benign soak sample | `NIDS_TestLab/results/phase5-tuning/phase5-benign-soak-tuned-20260312-163849/` |
| PREP-ENV-006 | Restart And Recovery | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live NIC capture via `tcpdump` across a stop/restart cycle | Pass | `144` cumulative flows, `2` anomaly alerts; phase-one and phase-two counts retained; restart preserved evidence in the same output directory | `NIDS_TestLab/results/phase4-live-restart-recovery-20260312-143955/` |
| PREP-ENV-007 | Extended Soak Pilot | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Pass for pilot | `4742` flows, `0` alerts; midpoint restart latency `13.251s`; peak RSS `322080 KiB`; storage grew to `6066099` bytes; executed `900s` against a `21600s` target | `NIDS_TestLab/results/phase5-soak/phase5-extended-soak-20260312-165051/` |
| PREP-ENV-008 | Operator Rule Refresh | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Pass | `332` flows, `1` post-refresh signature alert; reload latency `13.384s`; custom DNS rule count increased from `0` to `1` | `NIDS_TestLab/results/phase5-operator/phase5-operator-rule-refresh-20260312-164238/` |
| PREP-ENV-009 | Operator Model Swap | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, tuned live profile via `tcpdump` | Pass | `330` flows, `2` anomaly alerts across pre/post phases; reload latency `13.201s`; flow count continued after restart against the alternate model path | `NIDS_TestLab/results/phase5-operator/phase5-operator-model-swap-20260312-164422/` |
| PREP-ENV-010 | Operator Config Override | Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, baseline-to-tuned live profile via `tcpdump` | Pass | `394` flows, `0` alerts; reload latency `13.268s`; flow continuity preserved across the config swap from `live_vm_profile.yml` to `live_vm_phase5_tuned_profile.yml` | `NIDS_TestLab/results/phase5-operator/phase5-operator-config-override-20260312-164850/` |

## Marker Policy

| Marker | Purpose | Default selection |
|---|---|---|
| `integration` | realistic local cross-module validation | included unless also `slow`, `live`, `environment`, or `lab` are excluded by expression |
| `slow` | lightweight performance or longer-running validation | excluded |
| `lab` | dedicated lab asset or VM validation | excluded |
| `live` | live-capture or packet-streaming validation | excluded |
| `environment` | host-capability-dependent validation | excluded |

## Platform Notes

- Windows is the strongest current orchestration host for the VirtualBox and PowerShell lab workflow used by the prepared-environment runs.
- Linux remains the strongest target platform for direct packet capture and remote attack simulation; the prepared-environment evidence now includes Ubuntu sensor and target VMs.
- macOS remains conditional for core runtime and capture; it is not yet a first-class prepared-lab host.
- See `docs/platform_support_matrix.md` for the full audit.

## References

[1] NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/115/final

[2] NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/61/r3/final

[5] *Best Practices for Event Logging and Threat Detection*, Cybersecurity and Infrastructure Security Agency and partners, https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection

[6] *Guidance for SIEM and SOAR Implementation*, Cybersecurity and Infrastructure Security Agency, https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation
