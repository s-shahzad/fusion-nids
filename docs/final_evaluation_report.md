# Final Evaluation Report

## Scope

This document is the canonical late-phase evaluation summary for the Universal Hybrid Network Intrusion Detection System. It covers the current offline replay validation backbone, the replay-review metrics layer, fusion trace artifacts, AI robustness scenarios, taxonomy outputs, and the bounded API wrapper. It does not expand the system boundary beyond defensive-only, offline-first, synthetic or authorized data workflows.

## Validated Operating Profile

The supported and validated core profile is:

- offline replay through `python -m nids run-local`
- synthetic or authorized replay PCAP input only
- fresh output directory per run
- local artifact generation under repo-controlled paths
- optional replay-review metrics when ground truth is supplied
- optional control-layer access through the local FastAPI wrapper

The detailed boundary is documented in [supported_operating_profile.md](C:/Users/shaik/NIDS_Workspace/docs/supported_operating_profile.md).

## Tuned Baseline

The canonical tuned baseline remains the documented replay validation state for `serious_synthetic_20260310.pcap`:

- flows: `509`
- alerts: `10`
- alert ratio: `~1.96%`
- key tuned settings:
  - `ml.unsupervised_confirmation_hits = 2`
  - `fusion.min_agreement_count = 3`

This baseline is preserved as the project reference point. It should be read together with the fresh-output replay rule and the SQLite append caveat already documented in [README.md](C:/Users/shaik/NIDS_Workspace/README.md).

## Comparative Baseline Study

A reproducible comparison run is now available at:

- [comparison_baseline.json](C:/Users/shaik/NIDS_Workspace/docs/generated/comparison_baseline.json)
- [comparison_baseline.md](C:/Users/shaik/NIDS_Workspace/docs/generated/comparison_baseline.md)

That study runs the same replay input through:

- `signature_only`
- `anomaly_only`
- `ml_only`
- `hybrid_tuned`

Important note:

- the comparison study is replay-review evidence, not a replacement for the tuned baseline narrative by itself
- the earlier `8`-alert mismatch has been reconciled in [hybrid_tuned_reconciliation.md](C:/Users/shaik/NIDS_Workspace/docs/generated/hybrid_tuned_reconciliation.md)
- the current clean comparison rerun now reproduces the canonical `10-alert` tuned baseline

## Metrics Definitions And Limits

The replay metrics layer computes:

- TP
- FP
- FN
- precision
- recall
- F1

These metrics are currently category/label-based replay-review metrics, not event-aligned scientific benchmark metrics. The methodology and limits are documented in [metrics_methodology.md](C:/Users/shaik/NIDS_Workspace/docs/metrics_methodology.md).

## Fusion Trace Meaning

Fusion trace artifacts explain what the current fusion engine actually did during replay runs. They do not re-score alerts or redesign fusion. The artifacts are:

- `fusion_trace.json`
- `fusion_summary.md`

They should be used to answer:

- which engines contributed
- what the agreement count was
- whether ML confirmation contributed
- why escalation or non-escalation occurred

## Robustness Scenario Findings

AI robustness scenarios and the robustness matrix now provide bounded replay evidence for:

- low-rate scan behavior
- burst-then-idle behavior
- benign mimicry
- partial-signal cases
- alert-volume pressure

Reviewer-facing artifacts include:

- `robustness_summary.md`
- `robustness_matrix.json`
- `robustness_matrix.md`

These artifacts improve traceability and comparison, but they remain synthetic robustness evaluations rather than claims of real-world adversarial resilience.

## Taxonomy Meaning

The taxonomy layer classifies scenarios through a static internal mapping. It is a reporting aid, not external threat-intel enrichment. Scenario bundles may include:

- `taxonomy_map.json`
- `taxonomy_summary.md`

The taxonomy fields are designed to make scenario intent and detection path easier to review:

- attack family
- behavior category
- weakness tested
- primary detection path
- expected engines
- expected alert pattern
- severity
- optional tags

## Validation Breadth

Validation breadth has been formalized in [validation_breadth.md](C:/Users/shaik/NIDS_Workspace/docs/validation_breadth.md). The project now clearly separates:

- the main serious synthetic baseline replay
- focused single-family replay inputs such as DNS burst and HTTP login brute force
- standard offline lab scenarios
- AI robustness replay scenarios

This closes part of the prior breadth gap, but it does not turn the project into a broad multi-dataset benchmark.

## Performance Evidence

Bounded replay performance evidence is summarized in:

- [performance_profile.md](C:/Users/shaik/NIDS_Workspace/docs/performance_profile.md)
- [performance_profile.json](C:/Users/shaik/NIDS_Workspace/docs/generated/performance_profile.json)

This evidence is intentionally limited to tested replay conditions. It does not claim scalability beyond the observed runs.

## Failure Handling

Failure behavior is formalized in [failure_mode_matrix.md](C:/Users/shaik/NIDS_Workspace/docs/failure_mode_matrix.md). That matrix covers:

- replay input issues
- parser/runtime failure surfaces
- artifact generation failures
- metrics and fusion-trace failure behavior
- API wrapper error handling
- partial bundle generation cases

## Validated Vs Experimental Vs Out Of Scope

This split is formalized in [supported_operating_profile.md](C:/Users/shaik/NIDS_Workspace/docs/supported_operating_profile.md):

- validated and supported: offline replay, replay metrics, fusion trace, scenario bundles, robustness matrix, taxonomy layer, bounded API wrapper
- experimental: wider deployment paths, some cloud and dashboard surfaces, prepared-environment/live-related assets outside the offline-first claim set
- out of scope for core claims: live capture operation, external-facing deployment claims, broad real-world benchmarking, event-aligned academic metrics, production SOC positioning

## Known Limitations

- replay metrics are still coarse and label-based
- dataset breadth is improved but still narrow relative to a strong benchmark study
- deployment assets exist, but deployment proof remains weaker than offline replay proof
- the repository surface is broader than the core project claim boundary

## Current Conclusion

The project is strongest as an engineered offline hybrid replay-detection system with explicit evidence artifacts, bounded replay evaluation, fusion transparency, and structured scenario review. It is not yet a broad benchmark study and should not be positioned as production-proven. The current documentation set is intended to make that boundary explicit and defensible.
