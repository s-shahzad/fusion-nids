# Provenance

Date: March 14, 2026

## Purpose

This file defines the clean active-platform boundary for Universal NIDS and
separates it from archived or provenance-pending content.

## Clean Active Platform Boundary

The following directories and files are considered part of the clean active
platform boundary:

- `nids/`
- `src/NIDS/`
- `scripts/`
  - only the current maintained validation, reporting, and orchestration scripts
- `config/`
- `rules/`
- `models/`
- `tests/`
- `Dockerfile`
- `.dockerignore`
- `requirements.txt`
- release and legal/compliance documents that describe the active platform

## Archived / Excluded / Pending Review Boundary

The following content is not part of the clean active platform boundary and is
excluded from release packaging pending provenance review:

- `_archive/provenance_review_pending/phase13_20260314/src/src/`
- `_archive/provenance_review_pending/phase13_20260314/src/CAPSTON/`
- `_archive/provenance_review_pending/phase13_20260314/src/merged_unique/`
- `_archive/provenance_review_pending/phase13_20260314/src/ev_related_data/`
- `_archive/provenance_review_pending/phase13_20260314/src/NIDS/src/`
- `_archive/provenance_review_pending/phase13_20260314/nids_server.py`
- `_archive/provenance_review_pending/phase13_20260314/nids_page.html`
- `_archive/provenance_review_pending/phase13_20260314/nids_page.js`
- `_archive/provenance_review_pending/phase13_20260314/nids_page.css`

These items remain in the repository only for historical retention and later
provenance review. They are not part of the maintained runtime path.

## Current Statement

- Core runtime algorithms in the active platform are independently implemented
  for this project.
- Third-party dependencies are used under their own licenses and remain subject
  to review and notice obligations.
- No proprietary IDS product source code is intentionally included in the clean
  active platform boundary.
- Compatibility references to Suricata and Zeek are descriptive adapter/support
  references, not product-brand adoption.

## Working Rule

Any code with unclear origin, imported local history, or repository-external
merge provenance must stay outside the clean active boundary until it is
reviewed and explicitly accepted.
