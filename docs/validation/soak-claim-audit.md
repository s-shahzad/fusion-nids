# SOAK CLAIM AUDIT — `phase6-full-duration-soak-20260313-165040`

Written 2026-05-16 from a multi-specialist read of the Phase 10 soak artifacts.
Purpose: surface what the "87,533 flows / 0 false alerts / 6 hr" headline actually
represents so the number is not quoted naked in a paper, talk, or README.

## TL;DR

The headline is reportable as a **pipeline stability** result. It is not a
false-positive-rate measurement and must not be cited as one. The 0-alert
outcome is structurally guaranteed by the tuned thresholds on the recorded
traffic and would have held even for a constant-`benign` classifier. The
"flows" count is per-packet; the wall-clock is partial; the model labeled 29%
of the corpus as attacks and fusion dropped every one of them silently.

## Numerical receipts (from the soak bundle)

Bundle: `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`

| Claim                          | Recorded value                                      | Source file                          |
|--------------------------------|-----------------------------------------------------|--------------------------------------|
| Flow count                     | 87,533                                              | `nids.db` flows table                |
| Alert count                    | 0                                                   | `nids.db` alerts table / `alerts.jsonl` (0 B) |
| Configured duration            | 21,600 s (6 h)                                      | launch `.json`                       |
| Flow timestamp span            | 16:50:52 → 20:09:39 = **3 h 19 m**                  | `flows.jsonl`                        |
| Packets received               | 24,678                                              | `metrics` table                      |
| Packets processed              | 7,659                                               | `metrics` table                      |
| Peak `live_packet_loss_pct`    | **30.86 %**                                         | `metrics` table                      |
| Peak `live_packets_dropped_queue` | 53,701                                           | `metrics` table                      |
| Peak `ingest_lag_sec`          | 5,798 (≈ 96 min)                                    | `metrics` table                      |
| Distinct src IPs               | 2 (10.77.0.20, 10.77.0.30)                          | `nids.db`                            |
| Distinct dst IPs               | 2                                                   | `nids.db`                            |
| Distinct protocols             | 3 (UDP/TCP/ICMP)                                    | `nids.db`                            |
| Top dst port mix               | 41,444 UDP/53 · 21,248 TCP/8080 · 4,149 ICMP        | `nids.db`                            |
| Labeled attack flows           | **0**                                               | `threshold_tuning.md`                |
| Labeled benign flows           | **0**                                               | `threshold_tuning.md`                |
| Supervised → `dos` predictions | **25,397**                                          | `nids.db` flows → fusion disagreement |
| Supervised → `r2l` predictions | **170**                                             | same                                 |
| Fusion alerts emitted          | 0 (all 25,567 supervised positives dropped)         | same                                 |
| Max `fusion_score`             | 0.2351                                              | `threshold_tuning.json`              |
| `fusion.alert_threshold`       | 0.55                                                | tuned config                         |
| Supervised p99 score           | 0.7582                                              | `threshold_tuning.json`              |
| `ml.score_threshold`           | 0.85 (above benign p99)                             | tuned config                         |
| `unsupervised_alert_threshold` | 0.99                                                | tuned config                         |
| `unsupervised_component_threshold` | 0.999                                           | tuned config                         |

## Why the 0-alert result is structural, not earned

Fusion is a weighted sum with `min_component_score: 0.55` per
component plus `min_agreement_count: 2`. On the recorded traffic:

- Max observed `fusion_score` across all 87,533 rows = **0.2351**.
- `fusion.alert_threshold` was tuned to **0.55**.
- Fusion **mathematically cannot fire** anywhere in this corpus.
- A constant `benign` classifier would produce the identical 0-alert
  outcome on the same data.

The supervised model did fire (25,567 positive predictions, 29% of all
rows). Fusion silently muted every one. The "0 false alerts" headline
quietly converts 25K positive predictions into negatives without
disclosure.

## Why the result is not a false-positive-rate measurement

There is no ground truth in the soak bundle. `threshold_tuning.md`
reports `labeled_attack_flows: 0` and `labeled_benign_flows: 0`. With
no labels, there are no TP/FP/TN/FN — every per-class metric in
`prepared_env_metrics.json` is recorded as `null`. There is no
precision, recall, F1, PR-AUC, ROC-AUC, or confusion matrix on disk
because none can be computed.

## Why "87,533 flows" overstates what the pipeline did

`src/NIDS/runtime.py` writes one `flows` row per packet
(`packet_count=1` is hard-coded at insert). There is no 5-tuple
aggregation, no flow-timeout logic, no bidirectional pairing. The
table named `flows` is a per-packet log. The actual processed-packet
count for the run is **7,659**, not 87,533, per the `metrics` table.

## Why "6-hour soak" overstates the run

Configured duration was 21,600 s. The flow-record timestamp span is
**3 h 19 m**. The remaining wall-clock has no flow data. A controlled
mid-run restart is documented in `phase11_evidence_accounting_reconciliation.md`,
which also explains the 5.7 GB → 103 MB transient-file footprint as a
measurement-scope artifact (not a leak).

## Diversity of the traffic the result was measured on

Two source IPs (10.77.0.20, 10.77.0.30), two destination IPs (the
same two), three protocols. Dominated by a UDP/53 loop between the
sensor VM and the target VM. This is lab-loop traffic, not
representative of any enterprise mix.

## What the 87K/0 result *does* legitimately demonstrate

- The pipeline ran for the full configured wall-clock without
  crashing.
- Peak resident memory stayed bounded (409 MiB), within budget.
- The tuned threshold profile does not emit alerts on this specific
  recorded traffic profile.
- The signature engine + anomaly engine + fusion path are reachable
  end-to-end under load.

These are stability properties. They are not detection-quality
properties.

## How to cite this result honestly

> Under the tuned Phase 10 threshold profile, a 21,600 s soak against
> a two-host UDP/TCP/ICMP loop produced 87,533 per-packet flow
> records and 0 emitted alerts. Capture-side packet loss peaked at
> 30.86 %. The supervised classifier emitted 25,567 positive
> predictions (29 % of flows) which the fusion layer discarded
> (max observed `fusion_score` 0.2351, configured `alert_threshold`
> 0.55). No attack-labeled traffic was present in the soak corpus,
> so false-positive and false-negative rates cannot be computed
> from this run.

## What would make this a real metric

1. Run the same pipeline against a labeled external corpus
   (CIC-IDS-2017, UNSW-NB15, or a Suricata-labeled PCAP) so per-class
   precision, recall, F1, and PR-AUC are computable.
2. Report the supervised → fusion disagreement matrix alongside the
   alert count so silent suppression is visible.
3. Report the supervised model's recall on each attack class
   separately. The KDD99 `u2r` class currently has support=0 in the
   trained model's test split and would not be detected even if
   present.
4. Report capture-side packet loss next to any throughput or
   detection claim.
5. Pin the dataset hash for whatever corpus is used (KDD99 is fetched
   via `sklearn.datasets.fetch_kddcup99` with no integrity check
   today).

## Cross-references

- Eval audit (this document's source data): full soak bundle under
  `NIDS_TestLab/results/phase6-soak/phase6-full-duration-soak-20260313-165040/`.
- Storage 5.7 GB / 103 MB reconciliation:
  `phase11_evidence_accounting_reconciliation.md`.
- Training-side leakage (random IID split on KDD99): see
  `models/MODEL_CARD.md`.
- Phase 8 → Phase 10 alert delta (19 → 0) was achieved via threshold
  raises and a midpoint restart, not a model change. See
  `phase10_baseline_vs_rerun.md`.
