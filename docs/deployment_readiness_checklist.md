# Deployment Readiness Checklist

Use this checklist before promoting the repository from development validation to a deployment candidate. The gates reflect testing, logging, operational, and incident-readiness expectations described by NIST and CISA guidance [1][2][5][6].

Last evidence refresh: March 14, 2026

## Quality Gates

- [x] Default pytest suite passes with no unexpected failures. Evidence: `149 passed, 8 deselected`.
- [x] Coverage remains above the enforced CI threshold in `.coveragerc`. Evidence: `79.16%`, threshold `72%`.
- [x] Extended safe validation has been run for the current candidate. Evidence: `pytest -m slow` returned `4 passed`; `pytest -m "live and environment"` returned `3 passed`; `pytest -m lab` returned `1 passed`.
- [x] Prepared-environment live capture has been executed against the intended VirtualBox sensor VM. Evidence: `PREP-ENV-001` through `PREP-ENV-013` in `NIDS_TestLab/reports/prepared_env_validation_index.md`.
- [x] Packet-loss and queue-drop behavior are evidenced under live pressure for the current prepared-environment profile. Evidence: `PREP-ENV-003` recorded `8127` packets received, `23` processed, `8100` dropped, and `99.6678%` loss in `NIDS_TestLab/results/phase5-tuning/phase5-loss-accounting-dns-flood-20260312-163750/`.
- [x] The previous Scapy DNS deprecation warning has been fixed. Current default pytest warning count: `0`.

## Detection and Data Quality

- [x] Signature, anomaly, ML, and fusion paths are exercised on representative inputs. Evidence: `docs/testing_validation_master.md`, `NIDS_TestLab/reports/lab_execution_index.md`, and `NIDS_TestLab/reports/prepared_env_validation_index.md`.
- [x] Suppression behavior has been reviewed under realistic mixed-traffic and live-noise conditions. Evidence: latest `PREP-ENV-013` retained live suppression-rule state, derived duplicate suppressions `25`, derived policy suppressions `35`, and final operator-visible alert volume `1`.
- [x] False-positive review is recorded for the tuned deployment profile. Evidence: `docs/false_positive_analysis.md`, `PREP-ENV-005`, `PREP-ENV-011`, and `PREP-ENV-012`.
- [x] SQLite and JSONL outputs have been inspected for schema completeness and field integrity. Evidence: direct storage tests plus per-scenario SQLite/JSONL artifacts in `NIDS_TestLab/results/`.
- [x] Artifact triage pipeline is verified for supported file types and unsupported-file behavior. Evidence: `tests/test_artifact_pipeline.py` and `LAB-SCN-005`.

## Operational Readiness

- [x] Runtime startup is validated with both offline replay and prepared live-capture profiles. Evidence: all five latest phase 3 bundles plus prepared-environment scenarios `PREP-ENV-001` through `PREP-ENV-013`.
- [x] Config override paths, rule refresh, and model swap procedures are exercised under live lab conditions. Evidence: `PREP-ENV-008`, `PREP-ENV-009`, and `PREP-ENV-010`.
- [x] A hash-pinned release-candidate freeze exists for the evaluated profile. Evidence: `release/rc1/README.md` and `release/rc1/freeze_manifest.json`.
- [x] Dashboard, visualization, and report generation succeed against current output data. Evidence: direct visualization and dashboard tests plus generated scenario reports.
- [x] Retention, prune, and vacuum procedures are tested on a non-production copy. Evidence: storage maintenance tests and CI coverage.
- [x] Restart recovery with preserved output state has been validated in the lab. Evidence: `PREP-ENV-006` and the midpoint restart in `PREP-ENV-007`.
- [x] Restart-based maintenance has a documented release recommendation. Evidence: `docs/maintenance_strategy_decision.md`, `PREP-ENV-007`, `PREP-ENV-008`, `PREP-ENV-009`, and `PREP-ENV-010`.
- [ ] The completed longer-duration soak result is acceptable for promotion of the intended deployment profile. Current state: the completed Phase 10 `PREP-ENV-007` rerun passed with `87533` flows, `0` alerts, peak RSS `409444 KiB`, peak CPU `107.0%`, local bundle size `103291016` bytes, and reload latency `13.335s`; however, `runtime_total_result_peak_bytes` reached `5741514577` and the long-run queue/loss metric maxima still need interpretation, so the promotion condition is not yet closed.

## Security and Incident Readiness

- [x] Threat-informed scenarios are mapped to ATT&CK-aligned behavior families where practical. Evidence: `docs/lab_validation_plan.md`.
- [x] Logging and alert evidence is retained in reproducible locations. Evidence: `NIDS_TestLab/results/`, `prepared_env_manifest.json`, `prepared_env_summary.md`, SQLite, JSONL, and report artifacts.
- [x] Incident-response handoff artifacts are available. Evidence: per-run `serious_test_report.md`, `threshold_tuning.md`, `attack_validation_summary.json`, and bundle manifests.
- [x] Residual risks are documented with evidence paths and next actions. Evidence: `docs/current_status.md`, `docs/next_actions.md`, `docs/false_positive_analysis.md`, and `docs/maintenance_strategy_decision.md`.

## Release Artifacts

- [x] Coverage XML and HTML reports are generated.
- [x] JUnit XML is available for the current validation run.
- [x] `docs/testing_validation_master.md` is updated with current offline and prepared-environment evidence.
- [x] `docs/test_matrix.md`, `docs/lab_validation_plan.md`, and this checklist reflect the current process and latest evidence.

## Current Verdict

Conditional go for a controlled pre-deployment candidate.

Not promoted to release candidate ready for controlled deployment and publication support.

What is evidence-backed now:

- fast CI-gated validation with enforced coverage
- hash-pinned `rc1` freeze material for professor review and paper drafting
- live queue-loss accounting on the prepared sensor VM
- broader benign adjudication across the tuned benign samples, including Phase 9 reruns where `PREP-ENV-011` and `PREP-ENV-012` both cleared on the updated profile
- live suppression validation under noisy repeated signature traffic with final operator-visible alert volume held at `1`
- restart-based operator workflows for rule refresh, model swap, and config override, with a documented maintenance recommendation
- completed Phase 8 soak evidence in `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260312-203803/`
- completed Phase 10 rerun evidence in `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/` with `87533` flows, `0` alerts, `107.0%` peak CPU, and `13.335s` reload latency
- Phase 9 focused reruns that preserved attack detection in `LAB-SCN-003`, cleared `PREP-ENV-012`, and bounded a focused live DoS burst to `1` operator-visible `DoS Rate Threshold` alert
- Phase 10 rerun orchestration completed with deterministic run stamp `20260313-165040` and retained evidence in `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`

What still blocks real-world deployment:

- explanation of the completed Phase 10 runtime high-water storage figure versus the retained local bundle size and per-file artifact sizes
- interpretation of the transient queue/loss-related metric maxima captured during the completed rerun
- hot reload, or an equivalent zero-downtime strategy, if uninterrupted detection coverage is required

## References

[1] NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/115/final

[2] NIST SP 800-61 Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/61/r3/final

[3] *MITRE ATT&CK Enterprise Matrix*, MITRE ATT&CK, https://attack.mitre.org/matrices/enterprise/

[4] *ATT&CK Evaluations: Emulation and Evaluation Guide*, MITRE Engenuity, https://info.mitre-engenuity.org/att-ckevaluations-emulation-and-evaluation-guide

[5] *Best Practices for Event Logging and Threat Detection*, Cybersecurity and Infrastructure Security Agency and partners, https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection

[6] *Guidance for SIEM and SOAR Implementation*, Cybersecurity and Infrastructure Security Agency, https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation
