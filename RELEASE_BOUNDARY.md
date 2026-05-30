# Release Boundary

Date: March 14, 2026

## Purpose

This file defines what belongs to the active research platform, what remains
internal-only, and what is archived or excluded from redistribution.

## Active Research Platform

These areas belong to the maintained active research platform:

- `nids/`
- `src/NIDS/`
- `scripts/`
  - current maintained orchestration, reporting, and validation scripts
- `config/`
- `rules/`
- `models/`
- `tests/`
- `Dockerfile`
- `.dockerignore`
- `requirements.txt`
- active legal/compliance/provenance docs

## Internal-Only Or Controlled-Use Content

These areas are part of project operations or validation history, but they are
not assumed to be public-release content by default:

- `NIDS_TestLab/`
- `data/`
- `artifacts/`
- `reports/`
- `output/`
- retained evidence bundles, manifests, and validation indexes

## Archived And Excluded

These items are excluded from the clean active platform boundary and should stay
out of release bundles until provenance review is complete:

- `_archive/provenance_review_pending/phase13_20260314/`

This includes archived legacy source trees and the old Flask dashboard surface.

## Optional Modules

Optional modules that remain part of the active platform may ship only if their
dependencies and legal posture are reviewed. This currently includes:

- campaign behavior detection
- exfiltration behavior detection
- threat-intelligence enrichment

Their optional status does not exempt them from provenance and dependency review.

## Not Safe For Public Redistribution Yet

Do not treat the following as release-ready until further review:

- archived provenance-pending source trees
- local-origin or personal-origin source snapshots
- unsanitized validation evidence and generated artifacts
- any bundle that includes unresolved `scapy` redistribution assumptions

## Packaging Rule

Build and release only from the clean active platform boundary. Do not publish
the whole repository as a single unrestricted bundle.
