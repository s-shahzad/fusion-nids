# Dashboard and Visualization Architecture

## Component Description

The visualization layer turns persisted evidence into interactive operator views and exportable analytics. It is deliberately downstream of SQLite so that dashboards and charts operate on stable stored evidence rather than direct packet streams.

## ASCII Visualization Diagram

```text
SQLite Evidence
  |-- alerts
  |-- flows
  |-- metrics
  |-- incidents
  `-- suppression_rules
          |
          v
    visuals/queries.py
          |
          +--> charts.py -> Plotly figures
          |
          +--> dashboard.py
          |      |-- FastAPI endpoints
          |      |-- WebSocket realtime feed
          |      |-- incident APIs
          |      `-- suppression / ack APIs
          |
          `--> export.py
                 `-- offline chart bundles
```

## Module Relationships

- `src/NIDS/visuals/queries.py` builds Pandas-based analytics frames from SQLite.
- `src/NIDS/visuals/charts.py` converts analytics frames into Plotly figures.
- `src/NIDS/visuals/dashboard.py` exposes FastAPI endpoints, realtime payloads, incident APIs, and a browser dashboard.
- `src/NIDS/visuals/export.py` generates offline chart bundles from the same analytics path.
- `src/NIDS/storage/sqlite_store.py` and `src/NIDS/storage/incident_store.py` provide the underlying state.
- `src/NIDS/utils/notifications.py` is optionally used for incident-update notifications.

## Data Flow Explanation

### Analytics Query Layer

`build_analytics(...)` loads alerts and flows from SQLite, applies optional lookback and filter controls, and derives:

- alerts per minute
- packets per second
- top sources
- top ports
- severity over time
- engine share
- source/port heatmaps
- packet-length distributions
- burst-size distributions
- host activity scatter data
- Sankey link data
- network graph edges

### Dashboard Layer

The FastAPI application adds:

- health and readiness endpoints
- realtime JSON endpoints
- realtime WebSocket streaming
- alert acknowledgement APIs
- suppression creation and revoke APIs
- incident listing, bulk update, assign, and status APIs

The dashboard reads from SQLite and incident state instead of maintaining its own parallel event store.

### Export Layer

The CLI `visualize` command uses the same query and chart modules to produce offline export bundles.

## Key Files / Modules

- `src/NIDS/visuals/queries.py`
- `src/NIDS/visuals/charts.py`
- `src/NIDS/visuals/dashboard.py`
- `src/NIDS/visuals/export.py`
- `src/NIDS/storage/sqlite_store.py`
- `src/NIDS/storage/incident_store.py`

## Operational Purpose

This layer provides both analyst-facing situational awareness and evidence-packaging support. Because it is backed by persisted evidence, it remains usable for post-run review, report generation, and prepared-environment closeout.

## Future Extension Points

- richer incident-to-alert drill-down views
- stronger provenance displays for fusion and suppression decisions
- more export formats for publication and release evidence
- multi-sensor dashboard partitioning without changing the current storage model
