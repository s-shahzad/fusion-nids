# NIDS paper — fill-in checklist

Skeleton: `paper/nids-paper.tex` (compiles now). Every `[FILL: ...]` must be
resolved from a REAL repo value or original prose before submission. No invented
numbers. Ordered by effort.

## Numbers you can pull in minutes (from the repo)
- [x] **Coverage %** — DONE: 75.83% line coverage (floor 72%), from Linux CI Extended Validation run 28607694888 (2026-07-02). NOTE: local Windows coverage deadlocks on native import (xgboost) under instrumentation — always measure coverage via CI dispatch, not locally.
- [x] **Prepared-env table** (Table `tab:prepenv`) — DONE from `prepared_env_validation_index.json` (2026-03-14, 36 runs, all 13 pass): PREP-ENV-003 (8127 recv/23 proc/8100 drop/99.67% loss), 005 (1404 flows/0 alerts, FP 2→0), 006 restart, 007 **completed 6h soak 87533 flows/0 alerts/400MiB RSS/107% CPU** (NOT partial anymore — old docs were stale), 008/009/010 operator, ~13.2s reload.
- [x] **Offline/prepared-env scenario counts** (§Datasets) — DONE: 13 prep-env scenarios, all passing, 36 recorded runs.
- [ ] **Ensemble weighting** (§Methodology) — one precise sentence from `src/NIDS/ml/supervised_ensemble.py` on how the 4 models combine.
- [ ] **Dataset name** (§Datasets) — the label taxonomy (dos/normal/probe/r2l/u2r) is NSL-KDD / KDD-Cup style. Confirm exact source + version and cite it. Feature set from `src/NIDS/ml/featureset.py`.
- [ ] **Blind-window seconds** (§Limitations) — restart latency (~13s in old docs; confirm current).
- [ ] **Platform scope** (§Limitations) — honest OS/interface validation scope.

## Real writing (the actual work — no shortcuts)
- [x] **Related Work** (§2) — DONE: 4 families written + 6 real verified citations added (Tavallaee NSL-KDD CISDA'09, Sharafaldin CIC-IDS2017 ICISSP'18, Zhou ensemble-IDS Computer Networks'20, Engelen CICIDS-troubleshooting WTMC'21, plus NIST/MITRE/CISA) AND self-citation to the GCAIoT'25 paper with an explicit 3-way distinction (5-path not 1, multi-class not binary, validation-method contribution). VERIFY each citation's exact venue/year before submission — they're from web search, not a citation manager.
- [ ] **Architecture figure** — export `thesis/diagrams/system_architecture.mmd` to `paper/figures/architecture.pdf` (mermaid-cli: `mmdc -i x.mmd -o x.pdf`) and `\includegraphics` it.
- [ ] **Dataset provenance (CRITICAL)** — the features are NOT the 41 classic KDD attributes; only the label taxonomy is KDD-style. State exactly how the labelled flows were produced (own capture vs re-mapped corpus) and cite. Do not let a reviewer assume "NSL-KDD" when the feature space is custom.

## Already filled from ground-truth (verify, don't redo)
- Tests: 245 collected / 229 pass / 16 deselected (current, matches CI).
- Held-out ML table: dos/normal/probe/r2l real values from `reports/ml_metrics.json`; u2r correctly marked absent from the split; weighted 0.996 F1, 0.9954 acc.
- Coverage floor 72% (`.coveragerc`).

## Honesty guardrails (do not violate)
- Lead with the held-out split (99.5%), NOT the 99.78% full-set number.
- Keep the per-class weakness (probe 0.72, u2r absent) visible — it is the paper's credibility.
- "Controlled pre-deployment candidate", never "production-ready".
- Different dataset from the GCAIoT paper (that was CIC-IDS binary; this is 5-class) — so the two papers are distinct, not self-overlap. Keep it that way.

## Venue (decide before drafting Related Work depth)
Best fits for a systems+validation angle: RAID, ACSAC, or a security workshop
(WOOT, CSET — CSET is *literally* about cyber-experimentation/validation and is
the single best fit for this paper's angle). Confirm the open CFP + deadline.
