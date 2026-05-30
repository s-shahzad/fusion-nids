# False Positive Analysis

Last updated: March 13, 2026

## Scope

This record tracks the benign-adjudication history for the tuned live profile used in the prepared environment.

The important tuning steps are now:

- Phase 5: `ml.unsupervised_min_active_components=2`
- Phase 9 candidate profile:
  - `ml.unsupervised_component_threshold=0.999`
  - `ml.unsupervised_confirmation_hits=2`
  - `ml.unsupervised_rearm_score_ratio=0.85`
  - `ml.unsupervised_episode_timeout_sec=30`

The Phase 9 change is intentionally narrow. It raises the two-component agreement bar slightly and prevents one anomaly episode from reopening new alerts every time the duplicate-suppression window expires.

## Pre-Tuning Comparison

The baseline live profile produced a real false-positive issue before tuning:

- Comparison run: `NIDS_TestLab/results/phase4-live-benign-soak-20260312-143826/`
- Scenario ID: `PREP-ENV-005` on the baseline live profile
- Flows: `414`
- Alerts: `2`
- Alert type: `Hybrid Unsupervised Anomaly Score`
- Verdict: `partial`

This baseline comparison is retained as the reference point for the later tuning decisions.

## Benign Adjudication Matrix

| Sample ID | Scenario ID | Objective | Flow count | Alert count | Adjudication result | Generalization / overfit assessment | Actual outcome | Evidence path | Verdict |
|---|---|---|---:|---:|---|---|---|---|---|
| `BENIGN-LIVE-001` | `PREP-ENV-005` | Re-run the original benign polling sample on the tuned live profile. | `1404` | `0` | `cleared_after_tuning` | `clears_exercised_sample_only` | The original exercised sample stayed clear on the tuned profile. | `NIDS_TestLab/results/phase5-tuning/phase5-benign-soak-tuned-20260312-200047/` | `pass` |
| `BENIGN-LIVE-002` | `PREP-ENV-011` | Validate tuned unsupervised behavior against a broader SaaS/API polling mix. | `1452` | `0` | `cleared_after_tuning` | `supports_generalization` | The broader benign SaaS polling sample cleared on the earlier tuned profile. | `NIDS_TestLab/results/phase6-benign/phase6-benign-saas-polling-20260312-200422/` | `pass` |
| `BENIGN-LIVE-003` | `PREP-ENV-012` | Validate tuned unsupervised behavior against a burstier browsing and collaboration mix. | `1216` | `1` | `still_false_positive_risk` | `possible_overfit` | The earlier tuned profile reproduced one `Hybrid Unsupervised Anomaly Score` alert. | `NIDS_TestLab/results/phase6-benign/phase6-benign-browsing-collaboration-20260312-200827/` | `partial` |
| `BENIGN-LIVE-002-RERUN` | `PREP-ENV-011` | Re-check broader benign SaaS/API polling after the Phase 9 candidate changes. | `1622` | `0` | `cleared_after_phase9_tuning` | `supports_generalization` | The broader benign SaaS polling sample remained clear on the updated profile. | `NIDS_TestLab/results/phase6-benign/phase6-benign-saas-polling-20260313-161149/` | `pass` |
| `BENIGN-LIVE-003-RERUN` | `PREP-ENV-012` | Re-check the earlier burstier benign false-positive sample after the Phase 9 candidate changes. | `1814` | `0` | `cleared_after_phase9_tuning` | `improved_but_full_soak_still_pending` | The previously failing browsing and collaboration sample cleared on rerun with the updated profile. | `NIDS_TestLab/results/phase6-benign/phase6-benign-browsing-collaboration-20260313-160630/` | `pass` |

## Historical Residual Alert Detail

The earlier `PREP-ENV-012` residual benign alert remains important as a historical reference:

- Rule: `Hybrid Unsupervised Anomaly Score`
- Engine: `ml`
- Severity: `high`
- Timestamp: `2026-03-12T20:08:48.482017+00:00`
- Summary: `Hybrid unsupervised anomaly score=1.00 (autoencoder=1.00, isolation_forest=1.00)`
- Fusion result: `fusion_label=benign`, `fusion_score=0.2377023291646393`

That alert no longer reproduced on the Phase 9 rerun, but it should still be treated as evidence that the tuned profile can drift into false positives when long-run benign behavior changes shape.

## Current Interpretation

The Phase 9 candidate meaningfully improves the benign false-positive picture:

- `PREP-ENV-011` stayed clean on rerun, so the broader benign SaaS/API sample did not regress.
- `PREP-ENV-012` cleared on rerun, so the prior residual limitation is no longer the current latest-status outcome.
- The remaining unresolved false-positive concern is no longer the short benign collaboration sample by itself; it is whether the long-duration soak will still surface repeated unsupervised ICMP episodes on the updated profile.

## Recommendation

- Treat `PREP-ENV-012` as improved, not fully retired.
- Do not overclaim that the unsupervised false-positive problem is solved until the updated profile completes a new full `PREP-ENV-007` soak.
- If the next soak still produces repeated benign unsupervised ICMP alerts, continue tuning by general decision-shaping rules only, not by sample-specific exceptions.
