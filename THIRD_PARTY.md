# Third-Party Software Review Draft

Date: March 14, 2026

## Purpose

This file is a conservative third-party review draft for Universal NIDS. It is
not yet the final compliance record. It covers the clean active platform
boundary after the Phase 13 provenance-lockdown pass and separately calls out
archived / excluded content that remains pending review.

## Active Boundary Note

As of Phase 13, provenance-pending legacy source trees and the legacy Flask
dashboard surface were moved under:

- `_archive/provenance_review_pending/phase13_20260314/`

Those archived items are not part of the clean active runtime boundary and are
not intended for release packaging until provenance review is completed.

## Sources Used

- `requirements.txt`
- `Dockerfile`
- local `.venv` package metadata via `importlib.metadata`
- repository import and usage references under `src/NIDS/`, `scripts/`, and `tests/`

## Review Status Legend

- `recorded`: data captured from repo files or local package metadata
- `review_needed`: inventory exists but licensing or release posture still needs review
- `high_review_needed`: explicit legal or redistribution review required

## High-Priority Review Item

### Scapy

- package/component: `scapy`
- local version seen: `2.7.0`
- local license field: `GPL-2.0-only`
- local classifier: `License :: OSI Approved :: GNU General Public License v2 (GPLv2)`
- repo usage evidence:
  - `src/NIDS/ingest/live.py`
  - `src/NIDS/ingest/offline.py`
  - `src/NIDS/pipeline/parser.py`
  - `scripts/run_lab_scenario.py`
  - test fixtures under `tests/`
- review status: `high_review_needed`
- note: this item must be reviewed explicitly before any public redistribution or
  future commercial packaging story is treated as finalized

## Active Python Dependencies

| Package / component | Version if known | License if known | Source of truth | Usage area in repo | Review status | Notes / risk |
|---|---:|---|---|---|---|---|
| scapy | 2.7.0 | GPL-2.0-only | `requirements.txt`; local `.venv` metadata; repo imports | live capture, offline PCAP parsing, packet parser, lab scenario generation | high_review_needed | Strongest known redistribution review item. |
| PyYAML | 6.0.3 | MIT | `requirements.txt`; local `.venv` metadata | runtime and validation config loading | recorded | No issue identified from local metadata. |
| paramiko | 4.0.0 | LGPL-2.1 | `requirements.txt`; local `.venv` metadata; repo imports | prepared-environment and live-VM validation support | review_needed | Active validation-tooling dependency. |
| rich | 14.3.3 | MIT | `requirements.txt`; local `.venv` metadata | declared dependency; direct usage still to be confirmed | review_needed | Keep until repo-level usage review is finalized. |
| fastapi | 0.135.1 | MIT | `requirements.txt`; local `.venv` metadata; repo imports | dashboard API and HTTP endpoints | recorded | License expression available locally as MIT. |
| uvicorn | 0.42.0 | BSD-3-Clause | `requirements.txt`; local `.venv` metadata; repo imports | dashboard serving path | recorded | License expression available locally as BSD-3-Clause. |
| joblib | 1.5.3 | BSD-3-Clause | `requirements.txt`; local `.venv` metadata; repo imports | ML model load/save, unsupervised snapshots | recorded | License expression available locally as BSD-3-Clause. |
| numpy | 2.4.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | `requirements.txt`; local `.venv` metadata; repo imports | ML, charts, training, feature support | review_needed | Composite license expression should be carried carefully into a maintained SBOM. |
| pytest | 9.0.2 | MIT | `requirements.txt`; local `.venv` metadata; repo imports | test framework | recorded | Test-only role should still be marked in maintained inventory. |
| pytest-cov | 7.0.0 | MIT classifier observed | `requirements.txt`; local `.venv` metadata | coverage tooling | review_needed | Treat as test-only dependency. |
| plotly | 6.6.0 | MIT License | `requirements.txt`; local `.venv` metadata; repo imports | charts, dashboard visuals | recorded | Used in `src/NIDS/visuals/charts.py`. |
| pandas | 3.0.1 | BSD 3-Clause License | `requirements.txt`; local `.venv` metadata; repo imports | analytics queries, ML/training helpers | recorded | Used in `src/NIDS/visuals/queries.py` and ML utilities. |
| kaleido | 1.2.0 | MIT text observed locally | `requirements.txt`; local `.venv` metadata | chart export support | review_needed | Direct runtime import path should be confirmed in maintained inventory. |
| pypdf | 6.9.1 | BSD-3-Clause | `requirements.txt`; local `.venv` metadata; repo imports | PDF artifact parsing | recorded | Used in `src/NIDS/artifacts/parsers/pdf_parser.py`. |
| python-docx | 1.2.0 | MIT | `requirements.txt`; local `.venv` metadata; repo imports | DOCX parsing and report/document generation | recorded | Used in artifact parsing and validation/report generation scripts. |
| openpyxl | 3.1.5 | MIT | `requirements.txt`; local `.venv` metadata; repo imports | XLSX artifact parsing | recorded | Used in `src/NIDS/artifacts/parsers/xlsx_parser.py`. |
| beautifulsoup4 | 4.14.3 | MIT License | `requirements.txt`; local `.venv` metadata; repo imports | HTML parsing | recorded | Used in `src/NIDS/artifacts/parsers/html_parser.py`. |
| lxml | 6.0.2 | BSD-3-Clause | `requirements.txt`; local `.venv` metadata; repo imports | HTML parsing backend | recorded | Used via BeautifulSoup parser selection. |
| pefile | 2024.8.26 | MIT | `requirements.txt`; local `.venv` metadata; repo imports | PE / executable artifact parsing | recorded | Used in `src/NIDS/artifacts/parsers/exe_parser.py`. |
| scikit-learn | 1.8.0 | BSD-3-Clause | `requirements.txt`; local `.venv` metadata; repo imports | supervised ML, unsupervised ML, training, evaluation | recorded | Core ML dependency. |
| python-magic | 0.4.27 | MIT | `requirements.txt`; local `.venv` metadata; repo imports | MIME detection for artifact analysis | recorded | Used in `src/NIDS/artifacts/analyzer.py`. |
| xgboost | 3.2.0 | Apache-2.0 | `requirements.txt`; local `.venv` metadata; repo imports | supervised ensemble option | recorded | Optional model path appears to exist in the current architecture. |

## System And Container Components

| Component | Version if known | License if known | Source of truth | Usage area in repo | Review status | Notes / risk |
|---|---:|---|---|---|---|---|
| `python:3.11-slim` | to be confirmed from image digest | to be confirmed | `Dockerfile` | container base image | review_needed | Base image should be captured in a maintained SBOM or image bill of materials. |
| `libpcap0.8` | distro package version to be confirmed | to be confirmed | `Dockerfile` | live capture support | review_needed | System dependency for packet-capture path. |
| `tcpdump` | distro package version to be confirmed | to be confirmed | `Dockerfile` | live capture backend support | review_needed | System utility dependency used by the live-capture path. |

## Archived / Excluded Components

These imports were observed only in archived provenance-pending content and are
not part of the clean active runtime boundary after Phase 13:

| Package / component | Version if known | License if known | Archived usage area | Review status | Notes / risk |
|---|---:|---|---|---|---|
| flask | to be confirmed | to be confirmed | `_archive/provenance_review_pending/phase13_20260314/nids_server.py`; archived CAPSTON app code | review_needed | Keep excluded from release packaging until provenance and scope are reviewed. |
| requests | to be confirmed | to be confirmed | archived CAPSTON helper scripts | review_needed | Keep excluded from release packaging until provenance and scope are reviewed. |

## Current Limits

This draft does not yet answer:

- which dependencies belong inside the final public release boundary
- whether any dependency should be excluded from a future commercial path
- the final legal interpretation of `scapy` in the intended distribution model
- the final notice handling needed for container/base-image redistribution

## Next Step

1. convert this draft into a maintained compliance record
2. verify unresolved system/container component details from authoritative sources
3. decide the intended public packaging boundary before finalizing redistribution language
