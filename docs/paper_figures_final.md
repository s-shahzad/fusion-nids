# Final Figures Plan

## Figure 1 — System Architecture

Caption: High-level architecture of the hybrid intrusion detection workspace, showing input sources, ingest, normalization, feature extraction, detection engines, storage, outputs, and the surrounding validation framework.

## Figure 2 — Detection Pipeline

Caption: End-to-end detection pipeline from normalized event creation through signature scoring, anomaly detection, supervised ML, optional unsupervised ML, and fusion-based alert adjudication.

## Figure 3 — Validation Workflow

Caption: Evidence-driven validation workflow linking software tests, offline scenarios, prepared-environment execution, benign adjudication, suppression checks, and readiness review.

## Figure 4 — Prepared Environment Lab Setup

Caption: Prepared-environment lab topology showing the Windows orchestration host, Ubuntu sensor VM, Ubuntu target VM, live capture path, and evidence-bundle collection locations.

## Figure 5 — False-Positive Tuning Results

Caption: Benign adjudication comparison showing the phase 4 baseline false positives, the tuned passes for `PREP-ENV-005` and `PREP-ENV-011`, and the bounded residual limitation observed in `PREP-ENV-012`.

## Figure 6 — Long-Duration Soak Stability

Caption: Long-duration soak evidence view showing runtime stability metrics, memory growth, CPU trend, storage growth, alert volume, and restart behavior for `PREP-ENV-007` after the running soak completes.
