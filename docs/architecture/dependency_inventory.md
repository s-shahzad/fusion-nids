# Dependency Inventory Draft

Date: March 14, 2026

## Purpose

This file is a conservative dependency inventory draft for Universal NIDS. It is
intended to support later SBOM generation and third-party review. It does not
replace a formal SBOM.

## Active Boundary Note

Phase 13 moved provenance-pending legacy trees and the legacy Flask dashboard
surface under `_archive/provenance_review_pending/phase13_20260314/`. Those
archived files are excluded from the clean active platform boundary.

## Sources Used

- declared dependencies in `requirements.txt`
- `Dockerfile`
- local `.venv` package metadata visible during the Phase 13 pass
- repository import references under `src/NIDS/`, `scripts/`, and `tests/`

## Current Notes

- versions below are local observed versions where available
- licenses are listed only when directly visible from local package metadata
- unresolved license fields are marked `to be confirmed`
- `scapy` requires explicit future review

## Active Python Dependencies

| Declared dependency | Requirement declaration | Local version seen | License seen locally | Primary repo usage evidence | Notes |
|---|---|---:|---|---|---|
| scapy | `scapy>=2.5.0` | 2.7.0 | GPL-2.0-only | `src/NIDS/ingest/live.py`; `src/NIDS/ingest/offline.py`; `src/NIDS/pipeline/parser.py`; `scripts/run_lab_scenario.py` | Explicit legal review item. |
| PyYAML | `PyYAML>=6.0.1` | 6.0.3 | MIT | runtime config and validation config loading | Used for YAML config parsing. |
| paramiko | `paramiko>=4.0.0` | 4.0.0 | LGPL-2.1 | `scripts/live_vm_attack_validation.py` | Active validation-tooling dependency. |
| rich | `rich>=13.7.1` | 14.3.3 | MIT | declared dependency; direct usage to be confirmed | Keep as unresolved usage mapping until maintained inventory is finalized. |
| fastapi | `fastapi>=0.115.0` | 0.135.1 | MIT | `src/NIDS/visuals/dashboard.py`; dashboard tests | Dashboard API dependency. |
| uvicorn[standard] | `uvicorn[standard]>=0.42.0` | 0.42.0 | BSD-3-Clause | `src/NIDS/visuals/dashboard.py`; dashboard operational tests | Dashboard serving dependency. |
| joblib | `joblib>=1.4.2` | 1.5.3 | BSD-3-Clause | `src/NIDS/ml/train.py`; `src/NIDS/detect/ml_supervised.py`; `src/NIDS/detect/ml_unsupervised.py` | Model and snapshot serialization. |
| numpy | `numpy>=1.26.4` | 2.4.3 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | ML and chart modules | Composite license expression should be preserved in a maintained SBOM. |
| pytest | `pytest>=8.3.2` | 9.0.2 | MIT | `tests/` | Test-only dependency. |
| pytest-cov | `pytest-cov>=6.0.0` | 7.0.0 | MIT classifier observed | coverage runs | Test-only dependency. |
| plotly | `plotly>=5.24.1` | 6.6.0 | MIT License | `src/NIDS/visuals/charts.py` | Visualization and reporting support. |
| pandas | `pandas>=2.2.2` | 3.0.1 | BSD 3-Clause License | `src/NIDS/visuals/queries.py`; ML/data scripts | Analytics and historical data processing. |
| kaleido | `kaleido>=0.2.1` | 1.2.0 | MIT text observed locally | chart export support | Direct import path should be confirmed later. |
| pypdf | `pypdf>=6.9.1` | 6.9.1 | BSD-3-Clause | `src/NIDS/artifacts/parsers/pdf_parser.py` | Artifact PDF parsing. |
| python-docx | `python-docx>=1.1.2` | 1.2.0 | MIT | `src/NIDS/artifacts/parsers/docx_parser.py`; `src/NIDS/thesis.py`; `scripts/ubuntu_os_defense_validation.py` | DOCX parsing and generation. |
| openpyxl | `openpyxl>=3.1.5` | 3.1.5 | MIT | `src/NIDS/artifacts/parsers/xlsx_parser.py` | XLSX artifact parsing. |
| beautifulsoup4 | `beautifulsoup4>=4.12.3` | 4.14.3 | MIT License | `src/NIDS/artifacts/parsers/html_parser.py` | HTML parsing. |
| lxml | `lxml>=5.3.0` | 6.0.2 | BSD-3-Clause | `src/NIDS/artifacts/parsers/html_parser.py` via `BeautifulSoup(..., "lxml")` | Parser backend dependency. |
| pefile | `pefile>=2024.8.26` | 2024.8.26 | MIT | `src/NIDS/artifacts/parsers/exe_parser.py` | PE analysis support. |
| scikit-learn | `scikit-learn>=1.5.2` | 1.8.0 | BSD-3-Clause | supervised and unsupervised ML modules | Core ML dependency. |
| python-magic | `python-magic>=0.4.27` | 0.4.27 | MIT | `src/NIDS/artifacts/analyzer.py` | MIME detection support. |
| xgboost | `xgboost>=3.2.0` | 3.2.0 | Apache-2.0 | `src/NIDS/ml/supervised_ensemble.py`; optional model paths | Optional supervised ensemble component. |

## System / Container Dependencies

| Component | Declaration source | Version seen | License seen locally | Primary usage evidence | Notes |
|---|---|---:|---|---|---|
| `python:3.11-slim` | `Dockerfile` base image | to be confirmed | to be confirmed | container build base | Should be captured in the release inventory/SBOM. |
| `libpcap0.8` | `Dockerfile` apt install | to be confirmed | to be confirmed | live capture support | System-level packet-capture dependency. |
| `tcpdump` | `Dockerfile` apt install | to be confirmed | to be confirmed | live capture backend support | System utility dependency. |

## Archived / Excluded Dependency Surface

The following imports were observed only in archived provenance-pending content
after Phase 13 and are not part of the clean active platform boundary:

| Dependency | Archived usage evidence | Notes |
|---|---|---|
| `flask` | `_archive/provenance_review_pending/phase13_20260314/nids_server.py`; archived CAPSTON app code | Excluded from the clean active platform boundary. |
| `requests` | archived CAPSTON helper scripts | Excluded from the clean active platform boundary. |

## Unresolved Items

- optional versus required distribution scope has not been finalized
- no machine-readable SBOM has been generated yet
- `scapy` remains the strongest open redistribution review item
- system/container component notice handling still needs formal inventory

## Recommended Follow-Up

1. decide whether this markdown inventory is sufficient for the next milestone
2. if not, generate a machine-readable SBOM draft
3. align `THIRD_PARTY.md`, `NOTICE`, and the final project license decision with the same source data
