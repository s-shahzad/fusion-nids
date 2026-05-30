# Runtime Execution Flow

## Component Description

`src/NIDS/runtime.py` is the central orchestrator for packet and adapter event processing. It is responsible for queueing, feature extraction, detector invocation, storage, suppression handling, metric emission, and optional maintenance scheduling.

## ASCII Runtime Flow Diagram

```text
Ingress Adapters
   |
   v
async queue
   |
   v
NIDSRuntime._process_event
   |
   +--> FeatureExtractor
   +--> AnomalyEngine
   +--> SignatureEngine
   +--> MLEngineRouter
   +--> FusionEngine
   |
   +--> persist flow
   +--> build alert records
   +--> policy suppression
   +--> duplicate suppression
   +--> persist alerts
   +--> optional notifications
   |
   v
periodic metrics + optional maintenance
```

## Module Relationships

- `src/NIDS/cli.py` calls `run_runtime(...)`.
- `src/NIDS/config.py` builds the runtime configuration used by the runtime.
- `src/NIDS/ingest/live.py` and `src/NIDS/ingest/offline.py` feed the runtime queue.
- `src/NIDS/runtime.py` owns detector and storage object lifecycles.
- `src/NIDS/utils/notifications.py` supplies optional webhook notifications.
- `src/NIDS/storage/sqlite_store.py` and `src/NIDS/storage/jsonl_store.py` are the main evidence sinks.

## Data Flow Explanation

### Startup

At startup, the runtime instantiates:

- queue and telemetry state
- `FeatureExtractor`
- `SignatureEngine`
- `AnomalyEngine`
- `MLEngineRouter`
- `FusionEngine`
- `AlertSuppressor`
- `SQLiteStore`
- `JSONLStore`
- optional notifier

### Event Processing

For each normalized event, the runtime performs this sequence:

1. extract features
2. run anomaly detection
3. run signature detection
4. run ML routing and scoring
5. run fusion
6. persist the flow record
7. construct alert payloads from all emitting detectors
8. apply active policy suppression rules from SQLite
9. apply duplicate suppression
10. persist accepted alerts
11. emit optional notifications

### Metric and Maintenance Paths

The runtime also records:

- throughput and queue metrics
- live-capture loss counters and burst rates
- heartbeat-style metrics for dashboard consumption

If enabled, scheduled maintenance can run retention cleanup and optional `VACUUM`.

## Key Files / Modules

- `src/NIDS/runtime.py`
- `src/NIDS/config.py`
- `src/NIDS/ingest/live.py`
- `src/NIDS/ingest/offline.py`
- `src/NIDS/pipeline/features.py`
- `src/NIDS/detect/`
- `src/NIDS/storage/`
- `src/NIDS/utils/notifications.py`

## Operational Purpose

The runtime keeps the operational contract simple: one event in, one deterministic processing order, one evidence model out. That makes it possible to compare live capture, replay, and prepared-environment results without changing the detection pipeline structure.

## Future Extension Points

- hot-reload orchestration layered on top of the current runtime lifecycle
- stronger backpressure policies or queue shaping without replacing the queue-based model
- richer event-tracing hooks for fine-grained detector timing
- protected notification channels and stronger evidence-governance hooks
