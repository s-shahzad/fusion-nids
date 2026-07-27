# Artifact Analysis Pipeline

## Component Description

Universal NIDS includes a static artifact-analysis subsystem alongside the packet-centric intrusion-detection path. This subsystem is designed for file intake, lightweight triage, duplicate detection, quarantine routing, and evidence preservation without executing the incoming artifacts.

## ASCII Artifact Pipeline Diagram

```text
Incoming File / Directory
          |
          v
     intake.py
          |
          v
    analyzer.py
  |-- hashes
  |-- MIME detection
  |-- parser dispatch
  |-- lite heuristics / YARA-like checks
          |
          v
 Risk Decision
  |-- low/medium -> processed/
  `-- high       -> quarantine/
          |
          v
 ArtifactStore
  |-- SQLite artifacts table
  `-- artifacts.jsonl
          |
          v
 artifact-report / bundle evidence
```

## Module Relationships

- `src/NIDS/artifacts/intake.py` manages one-shot scans and watch mode.
- `src/NIDS/artifacts/analyzer.py` performs normalized static analysis.
- `src/NIDS/artifacts/storage.py` persists records and handles duplicate lookups by SHA-256.
- `src/NIDS/artifacts/report.py` generates markdown summaries from stored artifact evidence.
- `src/NIDS/artifacts/parsers/` contains file-type-specific parsers for PDF, DOCX, XLSX, ZIP, HTML, JSON, CSV, Python, and executable-oriented handling.
- `src/NIDS/cli.py` exposes `artifact-scan`, `artifact-watch`, and `artifact-report`.

## Data Flow Explanation

1. The intake path discovers files from an incoming directory or explicit file path.
2. The analyzer computes hashes and MIME information.
3. A type-specific parser extracts metadata and bounded text where supported.
4. Lightweight heuristic scoring evaluates suspicious strings, high-entropy segments, and YARA-lite pattern groups.
5. The record is assigned a risk level and routed to either `processed` or `quarantine`.
6. The final artifact record is written to SQLite and JSONL.
7. A markdown summary can be generated later from the stored results.

## Key Files / Modules

- `src/NIDS/artifacts/intake.py`
- `src/NIDS/artifacts/analyzer.py`
- `src/NIDS/artifacts/storage.py`
- `src/NIDS/artifacts/report.py`
- `src/NIDS/artifacts/parsers/csv_parser.py`
- `src/NIDS/artifacts/parsers/docx_parser.py`
- `src/NIDS/artifacts/parsers/exe_parser.py`
- `src/NIDS/artifacts/parsers/html_parser.py`
- `src/NIDS/artifacts/parsers/json_parser.py`
- `src/NIDS/artifacts/parsers/pdf_parser.py`
- `src/NIDS/artifacts/parsers/py_parser.py`
- `src/NIDS/artifacts/parsers/xlsx_parser.py`
- `src/NIDS/artifacts/parsers/zip_parser.py`

## Operational Purpose

The artifact subsystem extends the platform beyond pure network telemetry. It allows a lab scenario or operator workflow to preserve suspicious files, quarantine high-risk content, and correlate artifact triage with network evidence without requiring an external malware-analysis platform.

## Future Extension Points

- stronger parser provenance and extraction-limit metadata
- cryptographic manifesting for quarantined artifact bundles
- richer cross-linking between network alerts and artifact hashes
- pluggable higher-fidelity static-analysis engines that preserve the current storage contract
