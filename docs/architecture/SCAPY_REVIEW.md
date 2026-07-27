# Scapy Review

Date: March 14, 2026

## Purpose

This file records where `scapy` is used in the active platform and why it
matters to the release/legal review.

## Where Scapy Is Used

Active platform usage:

- `src/NIDS/ingest/live.py`
- `src/NIDS/ingest/offline.py`
- `src/NIDS/pipeline/parser.py`
- `scripts/run_lab_scenario.py`
- packet/PCAP-related tests under `tests/`

## Operational Role

`scapy` is not just lab decoration in the current platform. It is used in core
packet ingest and normalization paths, including:

- live packet capture parsing
- offline PCAP replay parsing
- normalized event extraction for the runtime pipeline

That means the active project currently depends on `scapy` for core runtime
packet-processing support, not only helper tooling.

## Why It Matters

Local package metadata in the current environment reports:

- package: `scapy`
- version: `2.7.0`
- license field: `GPL-2.0-only`

At a high level, that means redistribution posture must be reviewed explicitly
before treating the active platform as ready for unrestricted public or
commercial packaging.

## Current Practical Position

- keep the current implementation stable
- do not overstate legal conclusions
- treat `scapy` as an open review item
- do not assume it is automatically acceptable for every future distribution model

## Possible Future Treatments

1. Keep `scapy` under a reviewed distribution model.
2. Isolate Scapy-dependent behavior more clearly to limited runtime/tooling boundaries.
3. Replace the Scapy-dependent packet path later with a permissive alternative if the project needs a different release posture.

## Current Recommendation

Do not replace `scapy` in Phase 13. Keep the current runtime stable, document
the dependency clearly, and make it a Phase 14+ release-strategy decision.
