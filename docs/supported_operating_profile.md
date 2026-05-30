# Supported Operating Profile

## Purpose

This document defines what parts of the repository are inside the core project claim boundary and what parts are present but should not be used to expand the project story beyond validated evidence.

## Validated And Supported

These surfaces are inside the core project claim boundary:

- offline replay through `python -m nids run-local`
- `NIDS_TestLab/config/offline_replay_profile.yml`
- replay evidence stored in fresh output directories
- replay-review metrics artifacts:
  - `metrics.json`
  - `metrics_summary.md`
- fusion trace artifacts:
  - `fusion_trace.json`
  - `fusion_summary.md`
- offline lab scenarios through `scripts/run_lab_scenario.py`
- AI robustness scenarios and matrix artifacts
- taxonomy artifacts for scenario classification
- read-only and local-only API inspection around stored run artifacts
- protected `POST /run-local` API path with API key and rate limiting

## Experimental

These surfaces exist and may be useful internally, but they are not part of the strongest validated project claim set:

- dashboard and realtime visualization surfaces
- cloud/single-node deployment assets
- container packaging and deployment helpers
- prepared-environment and VM-assisted validation helpers
- campaign/exfiltration detector families that are present but not central to the validated offline replay story
- local LLM-assist and Ollama-backed explanation surfaces

These should be described as implemented or exploratory, not as fully validated core outcomes.

## Present But Out Of Scope For Core Project Claims

These surfaces should not be used to expand the core project claim boundary:

- live capture as a core operating mode
- external scanning
- internet-facing deployment claims
- production SOC positioning
- real-time detection claims
- broad real-world validation claims
- event-aligned academic benchmark claims such as precision/recall/F1 on a formal benchmark corpus

## Boundary Rules

- Use offline replay as the validation backbone.
- Use synthetic or authorized replay material only.
- Use a fresh output directory per run.
- Treat replay-review metrics as bounded review aids, not as formal benchmark metrics.
- Treat deployment assets as implementation assets unless they have matching validation evidence.

## Default Recommendation

For interviews, portfolio use, and technical review, the cleanest and most defensible profile is:

- offline replay only
- synthetic or authorized inputs only
- hybrid detector preserved as implemented
- scenario bundles and comparison artifacts as evidence
- metrics and fusion trace used as review layers
- API presented as a controlled local wrapper, not as a production platform
