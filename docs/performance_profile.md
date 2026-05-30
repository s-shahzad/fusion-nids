# Performance Profile

## Purpose

This document records bounded performance evidence for the offline replay path. It is intentionally narrow and should not be interpreted as a production scalability claim.

## Tested Conditions

Primary comparison replay:

- PCAP: `NIDS_TestLab/pcaps/serious_synthetic_20260310.pcap`
- flows observed per mode: `509`
- comparison artifacts:
  - `docs/generated/comparison_baseline.json`
  - `docs/generated/comparison_baseline.md`
- alert-count reconciliation artifact:
  - `docs/generated/hybrid_tuned_reconciliation.md`

Smoke-level runtime evidence:

- `tests/test_performance_pipeline.py`

Long-duration operational evidence:

- `docs/testing_validation_master.md`
- `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`

## Offline Replay Comparison Runtimes

Representative bounded replay timings:

| Mode | Runtime (s) | Flow/s |
|---|---:|---:|
| `signature_only` | 23.907 | 21.291 |
| `anomaly_only` | 28.974 | 17.567 |
| `ml_only` | 57776.235 | 0.009 |
| `hybrid_tuned` | 126.040 | 4.038 |

Alert-count interpretation for the tuned replay should come from the reconciliation artifact and the comparison baseline artifact, not from this performance summary.

## Additional Bounded Evidence

From the existing smoke suite in `tests/test_performance_pipeline.py`:

- offline replay throughput smoke target: `200` events with throughput `>= 10 events/sec`
- per-event runtime smoke target: average latency `< 100 ms`
- storage write pressure smoke target: `500` writes under `15 sec`
- bounded memory smoke target: peak traced memory `< 40 MiB` for the test case

From the documented long-duration prepared-environment soak evidence:

- duration: `21600.0s`
- flows: `87533`
- alerts: `0`
- peak RSS: `409444 KiB`
- peak CPU: `107.0%`
- reload latency: `13.335s`

## What This Supports

- the offline replay path is stable enough for controlled replay studies
- bounded replay throughput and latency evidence exists
- there is at least one long-duration evidence point for resource observation

## What This Does Not Support

- production scalability claims
- horizontal scaling claims
- high-concurrency API claims
- internet-facing service capacity claims

## Current Interpretation

The current evidence is appropriate for controlled replay evaluation and engineering review. It is not broad enough to claim formal scalability beyond the tested replay and soak conditions.
