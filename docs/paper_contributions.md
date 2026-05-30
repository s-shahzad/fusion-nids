# Paper Contributions

## Scope Note

The contribution statements below are intentionally conservative. They are aligned to the current repository state and should be safe to defend in a paper, thesis chapter, poster, or conference submission.

## Concrete Contributions

| Contribution | Safe claim | Current evidence |
|---|---|---|
| Hybrid detection architecture | The project implements a unified detection workspace that combines signature logic, statistical anomaly detection, supervised ML, optional unsupervised anomaly scoring, and fusion-based decision support. | `README.md`, `documentation/architecture.md`, `src/NIDS/detect/` |
| Multi-source ingestion and retention | The workspace supports live capture, offline PCAP replay, optional Suricata/Zeek adapters, SQLite/JSONL retention, and analyst-facing dashboard/report generation in one pipeline. | `README.md`, `src/NIDS/ingest/`, `src/NIDS/storage/`, `src/NIDS/visuals/` |
| Evidence-driven offline lab validation | The repository includes repeatable offline scenario execution with indexed evidence bundles across port scan, brute force, burst/flood, mixed traffic, and artifact-correlation cases. | `scripts/run_lab_scenario.py`, `NIDS_TestLab/reports/lab_execution_index.md` |
| Prepared-environment execution model | The project records prepared-environment validation manifests and latest-run indexing for live capture, malformed-input handling, recovery, queue-loss accounting, tuning, and operator workflows. | `scripts/prepared_env_validation.py`, `NIDS_TestLab/reports/prepared_env_validation_index.md` |
| Queue-pressure and loss-accounting evidence | The validation record does not hide degraded live behavior; it explicitly retains queue-depth and packet-loss outcomes under stress. | `PREP-ENV-003`, `docs/current_status.md` |
| False-positive tuning with analyst adjudication | The repository includes a documented false-positive investigation, a targeted tuning change, and a rerun showing the exercised benign-soak sample reduced to `0` alerts. | `docs/false_positive_analysis.md`, `PREP-ENV-005` |
| Restart-based operator workflow validation | Rule refresh, model swap, and configuration override are validated as restart-based workflows with retained pre/post evidence and latency measurements. | `PREP-ENV-008`, `PREP-ENV-009`, `PREP-ENV-010` |
| Resumable validation and indexing framework | Validation outputs are organized as bundles with manifests and consolidated indexes, which makes the project easier to audit, resume, and present. | `scripts/summarize_lab_results.py`, `scripts/prepared_env_validation.py` |
| Layered software validation baseline | The codebase is supported by a deterministic default pytest suite, marker-based extended slices, and enforced coverage. | `docs/testing_validation_master.md`, `.github/workflows/ci.yml`, `.github/workflows/validation-extended.yml` |

## Implemented and Validated

- Hybrid runtime pipeline from ingest through storage and reporting
- Repeatable offline scenario execution
- Prepared-environment validation across `10` latest passing scenarios
- Queue-loss accounting under live pressure
- False-positive tuning for the exercised benign-soak sample
- Restart-based maintenance workflows for rule, model, and config changes
- Default software-validation baseline of `152` collected tests, `144` passed, `8` deselected, and `79.16%` coverage

## Implemented but Only Partially Validated

- Longer-duration operational stability:
  - `PREP-ENV-007` is a `900s` pilot toward a `21600s` target
- Benign-traffic generalization:
  - current tuning evidence is strong for the exercised sample, not for all benign traffic
- Broader suppression behavior under live noisy traffic:
  - no dedicated suppression-focused prepared-environment scenario is yet recorded
- Cross-platform deployment posture:
  - Windows is the first-class lab host; Linux is the main runtime target; macOS is not first-class validated

## Planned or Future Work

- Full `6` to `12` hour prepared-environment soak evidence
- Broader benign-corpus adjudication
- Dedicated suppression validation under mixed live traffic
- A decision on whether hot reload is required beyond restart-based workflows
- More public-facing redacted evidence packages for publication supplements or demos

## Paper-Safe Wording

Use phrasing such as:

- "evidence-backed prepared-environment validation"
- "controlled pre-deployment review posture"
- "restart-based operator workflow validation"
- "false-positive tuning for the exercised benign-soak sample"
- "offline supervised evaluation report"

Avoid phrasing such as:

- "production-ready"
- "zero false positives"
- "hot reload validated"
- "general deployment signoff"
- "quantum-enabled capability"
