# Current Status

Last updated: March 14, 2026

## Completed

- Phase 1 testing expansion is complete.
- Phase 2 operational validation scaffolding is complete.
- Phase 3 offline lab execution evidence is complete.
- Phase 4 prepared-environment validation is complete and retained for historical comparison.
- Phase 5 live tuning and adjudication is complete.
- Phase 6 soak, benign-adjudication, suppression, and maintenance documentation is complete.
- Phase 7 release-candidate hardening is complete as a documentation-backed freeze and rerun pass, not as a promotion.
- Phase 8 soak closure is complete with the original `PREP-ENV-007` recorded as `partial`.
- Phase 9 remediation is complete for the targeted tuning and rerun scope.
- Phase 10 full soak rerun closeout is complete:
  - run stamp: `20260313-165040`
  - scenario result: `pass`
  - duration: `21600.0s`
  - flows: `87533`
  - alerts: `0`
  - peak RSS: `409444 KiB`
  - peak CPU: `107.0%`
  - average CPU: `104.96%`
  - restart latency: `13.335s`
- Phase 11B platform hardening and operational readiness is complete:
  - hardcoded lab password defaults removed from the main lab scripts
  - secret loading centralized through environment-backed helpers
  - Docker build boundaries tightened with `.dockerignore` and a narrowed `Dockerfile`
  - historical repo docs and indexes scrubbed of the retired shared lab password
  - evidence-governance configuration surface clarified in `config/nids.yml`
- Phase 12 advanced detection expansion is complete:
  - campaign behavior detection added as an optional module
  - exfiltration behavior detection added as an optional module
  - threat-intelligence enrichment added as an optional module
  - existing detector behavior remains unchanged when the new modules are disabled
- Phase 13 legal-safe core and provenance lockdown is complete:
  - provenance-unclear legacy trees were moved under `_archive/provenance_review_pending/phase13_20260314/`
  - the archived trees are excluded from the clean active platform boundary
  - active dependency declarations were aligned with actual maintained imports, including `paramiko`
  - provenance, release-boundary, Scapy-review, and legal-safe development rules were documented
  - active runtime and validation entry points do not import from the archived legacy trees
- Phase 14A safe adversary emulation framework is complete:
  - a new `src/NIDS/adversary_lab/` module area now generates lab-only offline replay bundles
  - seven safe scenarios were added for scan, auth abuse, beaconing, exfiltration-like flow, lateral sequencing, protocol anomalies, and chained campaign validation
  - generated artifacts include labeled PCAP, labels CSV, Suricata-style logs, and Zeek-style logs
  - safety guardrails restrict the framework to offline replay, localhost, documentation ranges, private lab ranges, or explicitly configured lab CIDRs
  - generated evidence is explicitly marked as `lab_generated`
- Phase 14B cloud-first architecture and validation is complete:
  - a single-node cloud profile was added through `config/nids_cloud_single_node.yml`
  - `docker-compose.cloud-single-node.yml` keeps the dashboard loopback-bound and disabled by default unless the dashboard profile is explicitly enabled
  - cloud storage boundaries now separate runtime output, runtime logs, runtime reports, lab-generated bundles, replay staging, manifests, and archived outputs
  - `scripts/cloud_validation_workflow.py` stages only `lab_generated` replay bundles, emits reproducible run plans, and provides bounded replay-staging cleanup
  - the Docker image now includes the runtime and dashboard entrypoint scripts explicitly and the cloud build context excludes `cloud_data/`
  - existing detector, ML, fusion, and storage behavior remains unchanged outside the new cloud-specific profile and helper layer
- Phase 15A Oracle VM deployment workflow preparation is complete:
  - Oracle-targeted deployment runbooks were added for first boot, deployment steps, operations, and cleanup
  - local SSH, bundle, bootstrap, run, status, collect, and cleanup helpers were added under `scripts/`
  - native PowerShell helper equivalents were added so the Oracle workflow can be executed from this Windows workstation without requiring WSL or Git Bash
  - a project-local Oracle deployment template now lives under `deployment/oracle_vm.env.example`, with the real `deployment/oracle_vm.env` intentionally ignored from Git
  - the bounded remote project root was standardized at `/opt/universal-nids` with the existing Phase 14B `cloud_data/` separation preserved beneath it
  - deployment sync now supports conservative `rsync`, bounded deployment-bundle upload, or remote `git` clone without requiring Codex to directly control Oracle resources
  - replay validation remains the recommended first remote execution path and still uses the existing `lab_generated` bundle staging helper
  - the dashboard remains disabled unless explicitly enabled and loopback-only even when enabled
  - generated cloud data, deployment bundles, and collected Oracle VM evidence now stay out of Git by default
  - existing detector, ML, fusion, parsing, storage, and adversary-lab behavior remains unchanged

## Current Metrics

- Total pytest items collected: `195`
- Default selected tests: `187`
- Default deselected tests: `8`
- Default result: `187 passed, 8 deselected`
- Active pytest warnings: `0`
- Last measured coverage: `79.16%`
- Coverage floor: `72%`
- Phase 9 targeted unit rerun: `17 passed, 4 deselected`
- Phase 10 focused orchestration rerun: `16 passed`
- Phase 14A adversary-lab focused validation: `9 passed`
- Phase 14B cloud-focused validation slice: `19 passed`
- Phase 15A Oracle deployment-prep validation slice: `11 passed`
- Latest offline scenario latest-status view: `5` pass
- Total recorded offline scenario manifests: `7`
- Latest prepared-environment latest-status view: `13` pass, `0` partial
- Total recorded prepared-environment manifests: `36`

## Latest Validation Evidence

Offline evidence index:

- `NIDS_TestLab/reports/lab_execution_index.md`

Prepared-environment evidence index:

- `NIDS_TestLab/reports/prepared_env_validation_index.md`

Latest high-value reruns:

- `LAB-SCN-003` flood and burst offline replay: pass, `296` flows, `5` alerts. `DoS Rate Threshold`, `DNS Burst / DGA-like Activity`, `Hybrid Unsupervised Anomaly Score`, and `Hybrid Fusion Decision` still fired on the updated code path. Evidence: `NIDS_TestLab/results/phase9-flood-burst-offline-20260313-160502/`.
- `PREP-ENV-011` benign SaaS polling mix: pass, `1622` flows, `0` alerts on the updated tuned live profile. Evidence: `NIDS_TestLab/results/phase6-benign/phase6-benign-saas-polling-20260313-161149/`.
- `PREP-ENV-012` benign browsing and collaboration mix: pass, `1814` flows, `0` alerts on the updated tuned live profile. Evidence: `NIDS_TestLab/results/phase6-benign/phase6-benign-browsing-collaboration-20260313-160630/`.
- `PHASE9-DOS-BURST-001` focused live DoS burst validation: pass, `2410` flows, `1` `DoS Rate Threshold` alert across the whole burst window. Evidence: `NIDS_TestLab/results/phase9-live-dos-burst-validation-20260313-161100/`.
- `PREP-ENV-007` Phase 10 rerun: pass, `87533` flows, `0` alerts, `21600.0s`, `409444 KiB` peak RSS, `107.0%` peak CPU, `13.335s` reload latency. Evidence: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`.

Long-duration soak history:

- Phase 8 baseline `PREP-ENV-007`: partial, `37598` flows, `19` alerts, peak RSS `543268 KiB`, peak CPU `161%`, recorded storage growth `1343554193` bytes, reload latency `13.329s`.
- Phase 10 rerun `PREP-ENV-007`: pass, `87533` flows, `0` alerts, peak RSS `409444 KiB`, peak CPU `107.0%`, runtime total-result peak `5741514577` bytes, local bundle size `103291016` bytes, reload latency `13.335s`.

## Provenance Boundary

Clean active platform boundary:

- `nids/`
- `src/NIDS/`
- maintained `scripts/`
- `config/`
- `rules/`
- `models/`
- `tests/`
- `Dockerfile`
- `.dockerignore`
- `requirements.txt`
- active release, provenance, and compliance documents

Archived and excluded pending review:

- `_archive/provenance_review_pending/phase13_20260314/`

This archived area contains the legacy `CAPSTON`, `merged_unique`, `original_sources`, and old Flask dashboard trees that are no longer part of the maintained runtime boundary.

## Current Readiness

The repository now qualifies as a `research Release Candidate`.

This is a research and professor-review posture, not a public or commercial release claim.

The repository is now also prepared for the first manual Oracle VM deployment execution under the existing single-node cloud profile.

Why the status advanced:

- the Phase 10 rerun completed cleanly with `87533` flows and `0` alerts
- the earlier Phase 8 alert-storm and benign-unsupervised issues did not recur
- the Phase 10 storage discrepancy was reconciled as remote high-water accounting plus transient process-scoped files, not retained `~5.7 GB` evidence growth
- Phase 11B removed hardcoded shared lab password defaults from the primary automation entry points and tightened the packaging boundary
- Phase 13 established a clean active-platform boundary and isolated provenance-unclear legacy content away from the maintained runtime path
- Phase 14A added a bounded adversary-emulation layer for stronger lab validation without changing the core runtime or detector behavior
- Phase 14B added a bounded single-node cloud deployment profile, a separate storage boundary for runtime versus replay inputs, and a reproducible remote replay workflow without exposing the dashboard publicly by default
- Phase 15A added the Oracle-specific SSH/bootstrap/run/status/collect/cleanup workflow needed to execute that bounded cloud profile on a real Ubuntu VM from the local workstation, including native Windows PowerShell entrypoints alongside the Bash helpers
- the prior `19`-alert soak failure did not recur
- DoS alert fan-out did not recur
- unsupervised benign alert emission did not recur
- peak CPU and peak RSS both improved materially
- restart behavior stayed within the existing controlled-scope evidence band

What is still intentionally bounded:

- the repository is not yet positioned as a public or commercial release
- third-party distribution review is still open, especially for `scapy`
- hot reload or equivalent zero-downtime maintenance is still required for uninterrupted-coverage claims
- archived provenance-pending trees remain in the repo for review history but stay outside the clean active boundary
- historical evidence artifacts still need explicit public/private release-boundary decisions
- the adversary-lab framework is intentionally lab-only and must not be treated as offensive tooling or general-purpose traffic generation for external environments
- the cloud profile is intentionally single-node and validation-oriented; it is not a claim of public exposure, high availability, or multi-node orchestration
- the Oracle VM workflow is prepared, but the first retained remote Oracle validation evidence is still pending execution

## Remaining Blockers

- Finalize the public/private distribution boundary and complete the remaining third-party license review, especially for `scapy`.
- Decide which historical evidence bundles and generated indexes remain internal-only versus sanitized for any future public release package.
- Keep archived provenance-pending trees excluded from release bundles unless they are independently reviewed and accepted.
- Restart-based maintenance remains acceptable for research and controlled internal use only. Hot reload or equivalent zero-downtime maintenance is still required for uninterrupted-coverage claims.
- Cloud deployment remains bounded to a single-node validation posture; the first Oracle VM replay-validation evidence and longer-run storage-lifecycle evidence still need to be collected on the prepared cloud profile.

## Next Recommended Phase

`Phase 15B - First Oracle VM Validation Execution and Operational Evidence`
