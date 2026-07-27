# Universal NIDS System Architecture Overview

## Component Description

Universal NIDS is a layered hybrid intrusion detection platform built around one normalized event pipeline and multiple detection engines. The repository supports live packet capture, offline PCAP replay, Suricata and Zeek JSON ingest, and static artifact analysis without changing the core downstream evidence model.

The current implementation keeps these architectural layers intact:

- Input sources
- Ingest and normalization
- Feature extraction and short-window aggregation
- Detection engines
- Fusion and suppression
- Evidence storage and reporting
- Visualization and operator workflows
- Validation and prepared-environment execution

## ASCII Architecture Diagram

```text
Input Sources
  |-- Live NIC capture (Scapy / tcpdump FIFO)
  |-- Offline PCAP replay
  |-- Suricata eve.json ingest
  |-- Zeek JSON ingest
  |-- Artifact/file intake
          |
          v
Normalization Pipeline
  |-- packet parsing
  |-- adapter event normalization
  |-- flow/event shaping
          |
          v
Feature Extraction
  |-- packet/transport features
  |-- short-window counters
  |-- protocol presence flags
          |
          v
Detection Layer
  |-- SignatureEngine
  |-- AnomalyEngine
  |-- MLEngineRouter
       |-- SupervisedMLEngine
       |-- UnsupervisedMLEngine
  |-- FusionEngine
          |
          v
Suppression / Incident Controls
  |-- duplicate suppression
  |-- policy suppression
  |-- incident lifecycle state
          |
          v
Evidence Storage
  |-- SQLiteStore
  |-- JSONLStore
  |-- ArtifactStore
          |
          v
Outputs
  |-- dashboard APIs + WebSocket updates
  |-- incident / SLA / threshold reports
  |-- artifact reports
  |-- prepared-environment evidence bundles
```

## Module Relationships

- `src/nids/cli.py` is the main operator entry point and dispatches runtime, reporting, dashboard, visualization, training, and artifact commands.
- `src/nids/config.py` merges runtime defaults with YAML overrides and CLI arguments into `RuntimeConfig`.
- `src/nids/runtime.py` is the core coordinator for live and replay traffic processing.
- `src/nids/ingest/` provides live capture and replay adapters that all feed normalized event dictionaries into the runtime queue.
- `src/nids/pipeline/` turns normalized events into feature-rich records.
- `src/nids/detect/` contains signature, anomaly, ML, fusion, and duplicate suppression logic.
- `src/nids/storage/` persists alerts, flows, metrics, incidents, and suppression rules.
- `src/nids/visuals/` serves interactive and export-oriented analytics from SQLite.
- `src/nids/artifacts/` provides a parallel static-analysis subsystem for file-based evidence.
- `scripts/prepared_env_validation.py` and the lab assets under `lab/` orchestrate real validation evidence capture.

## Data Flow Explanation

1. Traffic or artifacts enter through a specific source adapter.
2. Packets or adapter records are normalized into a common event schema.
3. Runtime feature extraction derives per-event and short-window features.
4. Signature, anomaly, supervised ML, and optional unsupervised ML evaluate the same normalized event.
5. Fusion combines detector outputs into a higher-level decision record.
6. Duplicate and policy suppression gates operator-visible alert volume.
7. Flows, alerts, metrics, incidents, and suppressions are persisted to SQLite and JSONL.
8. Dashboards, reports, and prepared-environment bundles read from the persisted evidence layer.

## Key Files / Modules

- `src/nids/cli.py`
- `src/nids/config.py`
- `src/nids/runtime.py`
- `src/nids/ingest/live.py`
- `src/nids/ingest/offline.py`
- `src/nids/pipeline/parser.py`
- `src/nids/pipeline/features.py`
- `src/nids/detect/anomaly.py`
- `src/nids/detect/signature.py`
- `src/nids/detect/ml.py`
- `src/nids/detect/ml_supervised.py`
- `src/nids/detect/ml_unsupervised.py`
- `src/nids/detect/fusion.py`
- `src/nids/storage/sqlite_store.py`
- `src/nids/storage/jsonl_store.py`
- `src/nids/storage/incident_store.py`
- `src/nids/visuals/dashboard.py`
- `src/nids/artifacts/analyzer.py`
- `scripts/prepared_env_validation.py`

## Operational Purpose

The system is designed to support research-grade detection experimentation and evidence-driven validation without fragmenting the operational data model. One runtime path supports both short engineering loops and structured pre-deployment evidence collection.

## Future Extension Points

- Additional ingest adapters that emit the same normalized event schema
- More expressive fusion policies and explainability fields
- Hot-reload maintenance workflows without replacing the existing runtime model
- Additional protected-storage or evidence-governance controls on top of the current SQLite and JSONL outputs
- Stronger cross-correlation between network alerts, incidents, and artifact findings
