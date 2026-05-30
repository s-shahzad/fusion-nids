# Metrics Methodology

## Purpose

The replay metrics layer is designed for controlled offline replay review. It is intentionally simple and deterministic.

## Current Metric Set

When ground truth is provided, the replay workflow computes:

- TP
- FP
- FN
- precision
- recall
- F1

## Matching Method

Current matching is:

- case-insensitive
- substring-based
- applied against observed alert `rule_name`, `summary`, and `engine`
- first-match oriented so each observed alert can satisfy at most one expected detection entry

Ground truth currently uses label/category-style expectations such as:

- `Port Scan Threshold`
- `DoS Rate Threshold`
- `HTTP Suspicious Keyword`
- `Hybrid Fusion Decision`

## What These Metrics Mean

These metrics are best interpreted as replay-review metrics:

- they measure whether the replay produced expected alert categories
- they support detector-path comparison and scenario review
- they help compare multiple controlled runs against the same replay input

## What These Metrics Do Not Mean

These metrics do not yet provide:

- per-event truth alignment
- per-flow benchmark labeling
- temporal correlation quality
- benchmark-grade precision/recall/F1 suitable for academic or production claims

## Known Limits

- substring matching can over-match broad or generic alert text
- category matching can collapse multiple distinct events into one expected label
- counts remain approximate when one replay contains multiple related detections under one category
- different detection paths may map to the same replay-review label

## Richer Ground Truth Examples

Current richer replay-review examples are now stored at:

- `docs/generated/ground_truth/serious_synthetic_replay_review.json`
- `docs/generated/ground_truth/dns_burst_replay_review.json`
- `docs/generated/ground_truth/http_login_bruteforce_replay_review.json`

These are still replay-review aids, not event-aligned truth corpora.

## Reviewer Guidance

Use replay metrics to answer:

- did the expected detection families appear
- how did comparison modes trade off TP, FP, and FN
- how did scenario outputs change across controlled reruns

Do not use replay metrics alone to answer:

- how accurate the system is on a broad dataset
- how the system would perform in production
- whether the system has benchmark-grade precision or recall
