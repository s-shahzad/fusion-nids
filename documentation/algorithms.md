# Algorithms Documentation

Generated: 2026-03-11 23:08 UTC

## Active Runtime Stack

- Signature rules for deterministic known-pattern detection
- Statistical anomaly detection using thresholds, EWMA-style logic, z-score signals, and DNS burst logic
- Supervised ensemble classification using random_forest, extra_trees, hist_gradient_boosting, xgboost
- Optional unsupervised scoring using Isolation Forest and a shallow autoencoder
- Fusion-based final decision logic

The current production path is hybrid by design. Historical SVM and Decision Tree experiments remain part of the project history but are not the active runtime path.
