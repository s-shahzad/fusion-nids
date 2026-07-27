# Detection Engine Architecture

## Component Description

The detection layer is intentionally hybrid. Universal NIDS does not rely on a single method. It combines rule-driven detection, statistical anomaly heuristics, supervised classification, optional unsupervised scoring, and a fusion layer that reasons across detector agreement.

## ASCII Detector Diagram

```text
Normalized Event + Features
          |
          +--> SignatureEngine
          |
          +--> AnomalyEngine
          |
          +--> MLEngineRouter
          |      |-- SupervisedMLEngine
          |      `-- UnsupervisedMLEngine
          |
          `--> FusionEngine
                   |
                   v
           Final alert candidates
                   |
                   v
          Duplicate + policy suppression
```

## Module Relationships

- `src/NIDS/detect/signature.py` handles rule-based matching.
- `src/NIDS/detect/anomaly.py` handles threshold, cooldown, and EWMA/z-score logic.
- `src/NIDS/detect/ml.py` coordinates supervised and unsupervised model evaluation.
- `src/NIDS/detect/ml_supervised.py` loads and scores the persisted ensemble model.
- `src/NIDS/detect/ml_unsupervised.py` performs hybrid anomaly scoring and episodic alert gating.
- `src/NIDS/detect/fusion.py` combines detector outputs into a single weighted decision.
- `src/NIDS/detect/suppression.py` and runtime suppression checks bound alert repetition.

## Data Flow Explanation

### Signature Detection

The signature engine loads YAML rules and matches on:

- protocol
- IP addresses
- ports
- dataset source
- DNS query names
- HTTP host, method, and URI
- TLS SNI
- payload text fragments

This path provides deterministic, explainable detections.

### Statistical / Anomaly Detection

`AnomalyEngine` evaluates runtime feature windows and emits structured alerts for:

- DoS rate threshold
- port scan threshold
- DNS burst / DGA-like activity
- SSH brute force
- RDP brute force
- HTTP login brute force
- EWMA z-score spike behavior

The current implementation includes destination-scoped DoS episode latching and rearm logic to prevent repeated burst reopening.

### Supervised ML

The supervised path uses a persisted ensemble payload and predicts:

- label / attack type
- score
- algorithm names
- model count

The runtime only emits a supervised alert when the predicted class is non-benign and the confidence threshold is met.

### Unsupervised ML

The optional unsupervised engine combines:

- `IsolationForest`
- a shallow autoencoder built with `MLPRegressor`

It supports:

- warmup buffering
- persisted baseline snapshots
- component-level scoring
- minimum active component logic
- confirmation hits before alerting
- episode timeout and rearm logic

### Fusion

The fusion layer merges signature, anomaly, supervised, and unsupervised scores using configurable weights and thresholds. It emits:

- `fusion_score`
- `fusion_label`
- `fusion_agreement_count`
- `fusion_components`
- `fusion_active_components`

## Key Files / Modules

- `src/NIDS/detect/signature.py`
- `src/NIDS/detect/anomaly.py`
- `src/NIDS/detect/ml.py`
- `src/NIDS/detect/ml_supervised.py`
- `src/NIDS/detect/ml_unsupervised.py`
- `src/NIDS/detect/fusion.py`
- `src/NIDS/detect/suppression.py`

## Operational Purpose

This structure gives the platform several desirable properties:

- deterministic coverage for known behaviors
- heuristic coverage for rate and threshold anomalies
- model-based classification for learned attack families
- optional unsupervised coverage for previously unseen behaviors
- explicit agreement-based fusion rather than opaque single-engine output

## Future Extension Points

- richer per-detector explainability fields in stored alert metadata
- adaptive fusion weights derived from validation evidence
- stronger cross-alert episode reasoning beyond per-engine latching
- tighter incident-priority projection from fusion confidence and rule family
