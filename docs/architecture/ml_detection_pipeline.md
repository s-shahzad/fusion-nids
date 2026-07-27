# ML Detection Pipeline

## Component Description

Universal NIDS integrates supervised and unsupervised ML into the runtime rather than treating models as separate offline-only tooling. The repository also includes explicit training and evaluation commands for the supervised model lifecycle.

## ASCII ML Pipeline Diagram

```text
Labeled Flows in SQLite
        |
        v
 dataset_loader -> feature_builder -> supervised_ensemble
        |                                  |
        |                                  v
        |                           model payload (.pkl)
        |                                  |
        +-----------------------------+    |
                                      v    v
                               Runtime MLEngineRouter
                                   |           |
                                   |           +--> SupervisedMLEngine
                                   |
                                   +--> UnsupervisedMLEngine
                                              |
                                              v
                                  alert candidates + prediction metadata
```

## Module Relationships

- `src/nids/ml/dataset_loader.py` reads labeled flows from SQLite for model-building workflows.
- `src/nids/ml/feature_builder.py` builds training frames from persisted flow rows.
- `src/nids/ml/featureset.py` defines the runtime/training feature vector order.
- `src/nids/ml/supervised_ensemble.py` builds and scores the ensemble payload.
- `src/nids/ml/train.py` trains and persists the supervised model.
- `src/nids/ml/evaluate.py` evaluates trained models against labeled flows.
- `src/nids/detect/ml.py` is the runtime router that invokes supervised and unsupervised inference.
- `src/nids/detect/ml_supervised.py` and `src/nids/detect/ml_unsupervised.py` perform runtime scoring.

## Data Flow Explanation

### Supervised Model Lifecycle

1. Labeled flow records are loaded from SQLite.
2. Training features are constructed using the shared feature-building utilities.
3. The ensemble payload is built and evaluated.
4. Metrics are written to JSON and Markdown.
5. The model payload is saved with metadata and later loaded by the runtime.

### Runtime Supervised Inference

1. The runtime builds a feature vector from the current event and derived features.
2. `SupervisedMLEngine` loads the ensemble payload from `models/model.pkl` or configured override.
3. A score and predicted label are returned.
4. If the result is non-benign and above threshold, a supervised alert is emitted.

### Runtime Unsupervised Inference

1. Early runtime events feed a warmup buffer.
2. Once enough samples accumulate, the unsupervised models fit against the buffered data.
3. For each new event, component scores are generated.
4. Active components, confirmation hits, and episode gating decide whether a visible alert is emitted.
5. The baseline snapshot can be persisted for continuity across runs.

### Router Behavior

`MLEngineRouter` adds operational controls:

- optional unsupervised enablement
- live inference throttling by flow key
- forced scoring on already suspicious events
- merged prediction metadata passed downstream to fusion and storage

## Key Files / Modules

- `src/nids/ml/train.py`
- `src/nids/ml/evaluate.py`
- `src/nids/ml/featureset.py`
- `src/nids/ml/feature_builder.py`
- `src/nids/ml/supervised_ensemble.py`
- `src/nids/detect/ml.py`
- `src/nids/detect/ml_supervised.py`
- `src/nids/detect/ml_unsupervised.py`

## Operational Purpose

The ML architecture is designed to make model logic operationally usable rather than isolated in notebooks. Runtime scoring, threshold reporting, and persisted training metrics all live inside the repository so that validation evidence stays coupled to the deployed logic.

## Future Extension Points

- explicit model registry metadata and signed model manifests
- stronger feature provenance between stored flow records and training frames
- richer unsupervised drift diagnostics based on persisted snapshots
- multi-model comparison reporting without changing the runtime contract
