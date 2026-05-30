# Evidence Inventory

## Baseline Snapshot

Use the following as the current public-facing baseline unless newer validated evidence replaces it:

- `152` collected tests
- `144` passed, `8` deselected
- `0` active pytest warnings
- `79.16%` coverage with a `72%` floor
- `5` latest offline lab scenario passes
- `10` latest prepared-environment scenario passes across `17` recorded manifests
- `PREP-ENV-005`: `1416` flows, `0` alerts after tuning
- `PREP-ENV-007`: `4742` flows, `0` alerts, `13.251s` restart latency in a `900s` pilot

## Inventory Structure

| Evidence category | Current source of truth | Recommended public-facing location | What should be captured | Current state | Missing |
|---|---|---|---|---|---|
| Architecture diagrams | `thesis/diagrams/` | `docs/assets/diagrams/` or `assets/diagrams/` | exported system architecture, workflow diagrams, version/date stamp | Mermaid sources exist | exported PNG/SVG copies not yet organized |
| Dashboard screenshots | live dashboard during prepared or replay runs | `assets/screenshots/dashboard/` | overview, alert feed, status cards, filters, chart view, incident action screen if used | no curated screenshot pack tracked | curated screenshot set, captions, redacted public copies |
| Prepared-environment bundles | `NIDS_TestLab/results/phase4-*`, `NIDS_TestLab/results/phase5-*`, `NIDS_TestLab/reports/prepared_env_validation_index.md` | keep source bundles in place; export redacted summaries to `docs/assets/evidence/prepared-env/` | manifest, summary, runtime log, key metrics, operator notes, screenshot if useful | source bundles and index exist | redacted public summaries and screenshot selection |
| Offline lab scenario bundles | `NIDS_TestLab/results/phase3-*`, `NIDS_TestLab/reports/lab_execution_index.md` | keep source bundles in place; export key figures to `docs/assets/evidence/offline-lab/` | scenario summary, alert chronology, report output, chart or screenshot | source bundles and index exist | public-facing summary sheets |
| Performance charts | `reports/graphs/` | `docs/assets/charts/` | PNG exports for flow volume, severity over time, source/destination distributions, heatmaps, network graph | generated charts exist | selected chart set with captions and curation notes |
| False-positive analysis | `docs/false_positive_analysis.md`, `NIDS_TestLab/results/phase4-live-benign-soak-*`, `NIDS_TestLab/results/phase5-tuning/phase5-benign-soak-*` | `docs/assets/evidence/tuning/` | before/after alert comparison, tuning rationale, exact profile used, analyst verdict | analysis note exists | public-ready comparison sheet and visual diff |
| Deployment readiness docs | `docs/current_status.md`, `docs/testing_validation_master.md`, `docs/deployment_readiness_checklist.md`, `docs/platform_support_matrix.md` | keep in `docs/` | concise readiness summary, blockers, review dates, release boundary language | docs exist | owner/review-date fields still incomplete |
| Test and coverage artifacts | `artifacts/test-results/`, `artifacts/coverage/` | keep in `artifacts/`; publish summaries in `docs/assets/evidence/testing/` | JUnit summary, coverage summary, CI evidence pointers | artifacts exist | summarized public evidence sheet |
| Artifact-correlation evidence | `NIDS_TestLab/results/phase3-artifact-network-correlation-*` | `docs/assets/evidence/artifact-correlation/` | artifact rows, quarantine evidence, corresponding network alert summary | bundle exists | public-ready diagram or annotated summary |

## Naming Conventions

Use consistent names so evidence is easy to sort, cite, and link.

### Bundle and summary names

- Scenario bundle:
  - `phase5-benign-soak-tuned-20260312-163849`
- Public-facing summary:
  - `prep-env-005-benign-soak-tuned-summary-2026-03-12.md`
- Screenshot:
  - `dashboard-alert-feed-2026-03-12.png`
- Chart export:
  - `severity-over-time-phase3-mixed-traffic-2026-03-12.png`
- Evidence sheet:
  - `lab-scn-005-artifact-correlation-evidence-2026-03-12.md`

### Required fields in filenames

- scenario or evidence family
- short descriptive label
- date
- optional timestamp when there are multiple same-day captures

### Avoid

- spaces
- ambiguous names such as `final.png`
- public exports that expose local usernames, internal IPs, or non-redacted host paths unless intentionally retained for private evidence only

## Capture Checklist By Category

### Architecture diagrams

- export PNG or SVG from the current Mermaid sources
- add a short caption that matches the current repo architecture
- include a generation date

### Dashboard screenshots

- capture one clean overview
- capture one alert-focused screen
- capture one filter or drill-down example
- redact sensitive hostnames or tokens if screenshots become public

### Prepared-environment evidence

- manifest
- summary markdown
- runtime or operator notes
- packet, flow, alert, and loss metrics
- one screenshot only if it clarifies the story

### Offline lab evidence

- scenario description
- expected outcome
- actual outcome
- key counts
- one chart or timeline

### False-positive tuning evidence

- baseline behavior
- tuning change
- rerun outcome
- remaining caution statement

## Still Missing

- full `6` to `12` hour soak evidence for `PREP-ENV-007`
- a dedicated suppression-specific prepared-environment bundle
- a curated dashboard screenshot pack
- redacted public evidence exports for portfolio and publication use
- explicit owner and review-date fields for residual deployment risks

## Recommended Next Step

Build a small public evidence pack first:

1. one architecture diagram export
2. three dashboard screenshots
3. one offline scenario evidence sheet
4. one prepared-environment evidence sheet
5. one before/after false-positive tuning comparison
