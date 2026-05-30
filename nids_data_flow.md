# Universal NIDS Data Flow

## Component Description

Universal NIDS uses a shared data path for live traffic, offline replay, and adapter-fed JSON events. Artifact analysis is separate at ingest time, but it converges on the same evidence-storage philosophy: normalized records, traceable outputs, and reportable evidence bundles.

## ASCII Data Flow Diagram

```text
Live Packets / PCAP / Suricata / Zeek
                |
                v
      Normalized Event Dictionary
                |
                v
      Feature Extraction + Windows
                |
                v
      Detector Evaluation
    /      |        |        \
Signature  Stats   Sup ML   Unsup ML
    \      |        |        /
             Fusion
                |
                v
   Suppression + Incident Projection
                |
                v
   SQLite + JSONL + Dashboard / Reports
```

## Module Relationships

- `src/NIDS/ingest/live.py` captures packets from a real NIC and enqueues normalized events.
- `src/NIDS/ingest/offline.py` replays PCAPs and normalizes Suricata and Zeek JSON records into the same event shape.
- `src/NIDS/pipeline/parser.py` extracts protocol-aware fields from packets.
- `src/NIDS/pipeline/features.py` derives runtime features and rolling-window counters.
- `src/NIDS/runtime.py` passes each event through detectors, fusion, suppression, and storage.
- `src/NIDS/storage/` and `src/NIDS/visuals/` consume persisted evidence rather than direct packet streams.

## Data Flow Explanation

### 1. Input Acquisition

- Live capture supports Scapy-based sniffing and a `tcpdump` FIFO path.
- Offline replay streams PCAPs with optional labels.
- Suricata and Zeek ingest read JSON lines and normalize them into the same downstream schema.

### 2. Event Normalization

`src/NIDS/pipeline/parser.py` emits event records containing:

- timestamp
- source and destination IP
- source and destination ports
- protocol
- packet length
- TCP flags
- payload preview / protocol-specific fields
- DNS, HTTP, and TLS metadata when available
- dataset and label fields when present

### 3. Feature Construction

`FeatureExtractor` combines direct event fields with short-lived counters such as:

- destination packet rate
- unique destination ports per source window
- unique destination hosts per source window
- DNS/HTTP/TLS field presence flags
- payload-length and transport flags

### 4. Detector Inputs

The runtime feeds the same event and features into:

- `SignatureEngine`
- `AnomalyEngine`
- `MLEngineRouter`

This keeps detector comparisons aligned on identical source context.

### 5. Fusion and Suppression

- `FusionEngine` converts detector agreement into a final fusion score and optional fusion alert.
- `AlertSuppressor` reduces duplicate visibility.
- `SQLiteStore.match_active_suppression()` applies policy suppression before operator-facing persistence.

### 6. Persistence and Consumption

- Flows, alerts, and metrics are written to SQLite and JSONL.
- Incidents and suppression state are stored in SQLite.
- Dashboard APIs and report generators read from the SQLite evidence layer.
- Prepared-environment scenarios copy runtime artifacts into timestamped evidence bundles.

## Key Files / Modules

- `src/NIDS/ingest/live.py`
- `src/NIDS/ingest/offline.py`
- `src/NIDS/pipeline/parser.py`
- `src/NIDS/pipeline/features.py`
- `src/NIDS/runtime.py`
- `src/NIDS/storage/sqlite_store.py`
- `src/NIDS/storage/jsonl_store.py`

## Operational Purpose

The operational goal of this data path is consistency. Live capture, replay, and adapter-based ingest all produce comparable records, which makes validation, reporting, and threshold analysis reproducible across execution modes.

## Future Extension Points

- Additional log or telemetry adapters that map into the same normalized event schema
- Stronger event lineage markers between raw source and fused alert
- Stream-level provenance tags for multi-sensor or multi-region deployments
- Optional schema export for external analytics tooling without changing the runtime path
