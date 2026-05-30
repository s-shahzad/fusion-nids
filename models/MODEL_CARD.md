# MODEL_CARD — `model.pkl`

Written 2026-05-16. Documents the current `models/model.pkl` artifact
(41 MB, last modified 2026-03-10) so anyone re-running training,
publishing metrics, or wiring the model into a downstream system has
the constraints in front of them.

## Identity

- **Path:** `models/model.pkl`
- **Last modified on disk:** 2026-03-10
- **Format:** joblib pickle of a `dict` payload with keys including
  `feature_columns`, `label_encoder`, member estimators (RF,
  ExtraTrees, HGB, optionally XGBoost), and per-member metrics.
- **Loader:** `src/NIDS/detect/ml_supervised.py` (reads
  `feature_columns` and re-applies the encoder).
- **No SHA-256 / version field** is stored alongside the file.
  Re-train output silently overwrites in place.

## Training data

- **Source:** KDD Cup 99, 10 % subset, fetched via
  `sklearn.datasets.fetch_kddcup99(percent10=True, shuffle=True,
  random_state=42)` in `bootstrap_training_db.py`.
- **Integrity check:** none. sklearn pulls the file from its CDN at
  fetch time; if the upstream changes, training silently shifts.
- **Effective row count after the `label_counts >= 2` filter:**
  ~25,000 (split 75/25 in `train.py`).
- **Known dataset hazards:** KDD Cup 99 contains heavily duplicated
  flows from the same attack campaigns. The project's own
  `nids_research_gaps.md` cites Tavallaee et al. (IEEE CISDA 2009)
  documenting this. The bias is acknowledged in docs and **not
  corrected in code**.

## Feature schema

15 columns, defined in `src/NIDS/ml/featureset.py:FEATURE_COLUMNS`.
Include 5-tuple-derived rates, byte/packet counts, TCP-flag
indicators, and three L7 boolean indicators (`has_dns_qname`,
`has_http_host`, `has_tls_sni`).

**KNOWN TRAIN/SERVE SKEW (high-severity bug):** The three
`has_*` indicators are computed from L7 fields at inference
(`src/NIDS/pipeline/features.py:79-81`) but are hard-coded to `0.0`
during training (`src/NIDS/ml/feature_builder.py:41-43`) because the
`flows` SQLite table never persisted `dns_qname` / `http_host` /
`tls_sni`. The model was therefore trained as if every flow had zero
L7 signal. At serve time these features fire on ~5–20 % of flows.
The model has effectively learned to ignore them. Fixing this
requires extending `FLOW_COLUMNS` in `storage/sqlite_store.py`,
persisting the three fields in `runtime.py`'s flow insert,
re-bootstrapping the training DB, and retraining.

## Training procedure

- **Splitter:** `sklearn.model_selection.train_test_split(X, y,
  test_size=0.25, random_state=42, stratify=stratify)` —
  `src/NIDS/ml/train.py:88`.
- **Splitter problem:** random IID shuffle on time-structured /
  duplicated data. Near-duplicate flows can land in both train and
  test, inflating accuracy. **Use a temporal split (sort by KDD's
  synthetic timestamp and slice the last 25 %) or a connection-group
  split (hash on a (src_ip, dst_ip, dst_port) tuple) instead.**
- **Ensemble:** weighted soft-vote of RF (n_estimators=250) +
  ExtraTrees + HistGradientBoosting + (XGBoost if installed). Member
  weights are set per-member from F1 on the held-out test split
  (`supervised_ensemble.py:252-253`) — mild test-set contamination
  into the weighting; predictions are not directly affected, but
  reported ensemble metrics are slightly optimistic.
- **Class imbalance:** `class_weight="balanced"` on tree members;
  sample weights passed to HGB and XGB.

## Evaluation

- **Source of metrics:** `reports/ml_metrics.json` (held-out test
  split) and `reports/ml_evaluation.json` (currently runs against the
  full dataset including the train split — see "Bug" below).
- **Headline numbers from `ml_metrics.json`:** weighted F1 0.9956,
  per-class:
  - `normal` F1 ~0.99 (well-supported)
  - `dos` F1 ~0.99 (well-supported)
  - `probe` F1 0.833
  - `r2l` F1 0.933
  - **`u2r` F1 0/0 (support = 0 in the test split, model cannot
    detect this class)**
- **The aggregate "99.56 % weighted F1" hides the `u2r` zero-recall
  result** because `u2r` carries near-zero weight in the weighted
  average. Any per-class table in a paper must list `u2r` explicitly.
- **Calibration:** none. Outputs are raw ensemble probabilities. The
  serving threshold `score_threshold=0.6`
  (`src/NIDS/detect/ml.py:30`) was not derived from a precision /
  FPR / recall curve. `reports/threshold_tuning.json` is currently
  populated with `"method": "no_score_data"` and zero values.

## Bug — `evaluate.py` is not an independent eval

`src/NIDS/ml/evaluate.py:25-26` calls `load_labeled_flows(db_path)`
with **no split filter**, so `ml_evaluation.json`'s
`"accuracy": 0.99784` is a score on all 25,000 rows including the
training partition. Use `ml_metrics.json` (which is the held-out
split) for the only honest accuracy number this model has produced.

## Unsupervised path

`src/NIDS/detect/ml_unsupervised.py` (IsolationForest + a shallow
MLP autoencoder) is calibrated on training-set percentiles for the
normalisation bounds (OK), but the autoencoder's reconstruction
threshold (95th percentile of error) is set from the same buffer
used to fit the autoencoder (`ml_unsupervised.py:182-184`). The
threshold should be set on a held-out partition of benign warmup
traffic.

## Intended use

Research / lab. The model is part of a hybrid IDS evaluated against
synthetic and lab scenarios; it has not been evaluated against any
externally labeled corpus (CIC-IDS, UNSW-NB15, MAWI, etc.). The
soak result (see `NIDS_Docs/SOAK_CLAIM_AUDIT.md`) is a stability
metric, not a detection-quality metric.

## Prohibited / unsupported use

- Do not deploy as the sole control on production traffic without an
  external eval first.
- Do not cite a single aggregate accuracy / F1 / "0 FP" number
  without the per-class breakdown and the dataset description.
- Do not rely on the `has_dns_qname` / `has_http_host` /
  `has_tls_sni` features until the train/serve skew is fixed; the
  model effectively ignores them.

## Reproducibility checklist (what's needed for an external reviewer)

- [ ] Pin the KDD99 archive SHA-256 in `bootstrap_training_db.py`.
- [ ] Replace the random IID split with a temporal or
      connection-group split.
- [ ] Restore L7 columns to `FLOW_COLUMNS` and retrain.
- [ ] Re-write `evaluate.py` to score only the held-out partition,
      or store the split-index manifest alongside `model.pkl`.
- [ ] Derive `score_threshold` from a precision/recall sweep on a
      validation split, not a hand-picked constant.
- [ ] Calibrate the autoencoder threshold on held-out benign
      traffic.
- [ ] Provide a one-shot `make train` (or equivalent) that chains
      `bootstrap_training_db -> train -> evaluate -> threshold-tune`
      reproducibly.
- [ ] Run the trained model against an external labeled corpus and
      attach per-class precision, recall, F1, PR-AUC, and a
      confusion matrix.

## Cross-references

- `NIDS_Docs/SOAK_CLAIM_AUDIT.md` — what the 87K/0-FP soak does and
  does not show.
- `src/NIDS/ml/featureset.py` — feature column source of truth.
- `src/NIDS/ml/feature_builder.py` — training-side feature build
  (where the L7 zero-pinning lives).
- `src/NIDS/pipeline/features.py` — serving-side feature build.
- `reports/ml_metrics.json` — the only honest accuracy number.
- `reports/threshold_tuning.json` — currently empty.
