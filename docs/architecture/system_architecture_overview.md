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

- `src/NIDS/cli.py` is the main operator entry point and dispatches runtime, reporting, dashboard, visualization, training, and artifact commands.
- `src/NIDS/config.py` merges runtime defaults with YAML overrides and CLI arguments into `RuntimeConfig`.
- `src/NIDS/runtime.py` is the core coordinator for live and replay traffic processing.
- `src/NIDS/ingest/` provides live capture and replay adapters that all feed normalized event dictionaries into the runtime queue.
- `src/NIDS/pipeline/` turns normalized events into feature-rich records.
- `src/NIDS/detect/` contains signature, anomaly, ML, fusion, and duplicate suppression logic.
- `src/NIDS/storage/` persists alerts, flows, metrics, incidents, and suppression rules.
- `src/NIDS/visuals/` serves interactive and export-oriented analytics from SQLite.
- `src/NIDS/artifacts/` provides a parallel static-analysis subsystem for file-based evidence.
- `scripts/prepared_env_validation.py` and the lab assets under `NIDS_TestLab/` orchestrate real validation evidence capture.

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

- `src/NIDS/cli.py`
- `src/NIDS/config.py`
- `src/NIDS/runtime.py`
- `src/NIDS/ingest/live.py`
- `src/NIDS/ingest/offline.py`
- `src/NIDS/pipeline/parser.py`
- `src/NIDS/pipeline/features.py`
- `src/NIDS/detect/anomaly.py`
- `src/NIDS/detect/signature.py`
- `src/NIDS/detect/ml.py`
- `src/NIDS/detect/ml_supervised.py`
- `src/NIDS/detect/ml_unsupervised.py`
- `src/NIDS/detect/fusion.py`
- `src/NIDS/storage/sqlite_store.py`
- `src/NIDS/storage/jsonl_store.py`
- `src/NIDS/storage/incident_store.py`
- `src/NIDS/visuals/dashboard.py`
- `src/NIDS/artifacts/analyzer.py`
- `scripts/prepared_env_validation.py`

## Operational Purpose

The system is designed to support research-grade detection experimentation and evidence-driven validation without fragmenting the operational data model. One runtime path supports both short engineering loops and structured pre-deployment evidence collection.

## Future Extension Points

- Additional ingest adapters that emit the same normalized event schema
- More expressive fusion policies and explainability fields
- Hot-reload maintenance workflows without replacing the existing runtime model
- Additional protected-storage or evidence-governance controls on top of the current SQLite and JSONL outputs
- Stronger cross-correlation between network alerts, incidents, and artifact findings
