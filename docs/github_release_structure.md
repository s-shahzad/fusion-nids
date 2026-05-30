# GitHub Release Structure

This document proposes a future public-facing release layout that keeps the project understandable for reviewers while separating public material from internal or environment-specific content.

## Suggested Public Layout

```text
README.md
docs/
  architecture.md
  quickstart.md
  validation_framework.md
examples/
scenarios/
models/
rules/
```

## Public Content

### `README.md`

- project overview
- current verdict and bounded readiness statement
- supported inputs and outputs
- installation summary
- links to architecture and validation docs

### `docs/architecture.md`

- system overview
- architecture diagram
- pipeline layers
- storage and reporting model

### `docs/quickstart.md`

- minimal setup steps
- safe offline usage path
- sample commands for replay, reporting, and artifact handling
- clear notice that prepared-environment validation requires extra setup

### `docs/validation_framework.md`

- testing strategy
- offline scenario framework
- prepared-environment methodology
- benign adjudication and suppression validation approach
- current readiness boundaries

### `examples/`

- small safe example PCAP references or commands
- example report outputs
- sanitized example configuration snippets

### `scenarios/`

- redacted or publication-safe offline scenario definitions
- scenario descriptions and intended validation outcomes

### `models/`

- public only if redistribution and provenance are acceptable
- otherwise provide model metadata, hashes, or instructions to regenerate

### `rules/`

- public rules that do not expose sensitive environment assumptions
- changelog or rule rationale where useful

## Internal or Restricted Content

Keep these internal unless they are redacted first:

- live lab credentials, IPs, passwords, or environment secrets
- unredacted prepared-environment evidence bundles
- launch records or logs that expose internal host details
- internal-only scenarios tied to specific VM topology assumptions
- model artifacts with licensing or dataset-provenance restrictions
- operational notes that would overstate readiness if read without context

## Release Positioning

The public release should present the workspace as:

- a research-oriented hybrid intrusion detection project
- evidence-backed and reviewable
- suitable for professor feedback, paper drafting, and controlled technical discussion

The public release should not present the workspace as:

- production-ready
- zero-downtime capable
- fully generalized across all benign traffic envelopes
