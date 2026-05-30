# GitHub Release Plan

## Goal

Prepare the repository for a public-facing release that is credible, useful, and aligned with the current project state. The release should support publication, portfolio use, and open-source visibility without overstating readiness.

## What Should Be Public Now

- core source code under `src/NIDS/`
- safe utility scripts that help explain the workflow
- current documentation set under `docs/`
- thesis diagram sources under `thesis/diagrams/`
- selected generated charts under `reports/graphs/`
- redacted screenshots and curated demo assets
- public-safe validation summaries:
  - current status
  - testing and validation master record
  - false-positive analysis
  - project one-pager
  - showcase story
  - paper planning docs

## What Should Remain Private For Now

- unreviewed or unredacted evidence bundles that contain local host details, operator notes, or absolute machine-specific paths
- sensitive or non-public PCAPs
- any environment-specific secrets, tokens, or private configuration files
- raw prepared-environment logs that expose internal network layout or usernames
- draft materials that could be mistaken for a product promise, customer commitment, or legal/security guarantee
- any commercial proposal materials until the support boundary is clearer

## Public Release Boundary

The repository can be positioned publicly as:

- research-first
- open-source-first
- evidence-backed
- suitable for controlled pre-deployment review

It should not yet be positioned publicly as:

- production-ready
- enterprise-supported
- zero-false-positive
- zero-downtime-maintained
- commercial SaaS-ready

## README Section Plan

### 1. Project Summary

- one-paragraph explanation of Universal NIDS
- include the current tagline

### 2. Why This Project Exists

- explain the gap between model demos and evidence-backed validation

### 3. Current Capabilities

- live capture
- offline replay
- optional adapters
- hybrid detection
- retention and reporting
- artifact static analysis

### 4. Architecture Snapshot

- one architecture diagram or simple pipeline

### 5. Validation Snapshot

- `152` collected tests
- `144 passed, 8 deselected`
- `79.16%` coverage
- `5` latest offline scenario passes
- `10` latest prepared-environment passes across `17` manifests

### 6. What This Repo Is Not

- not yet a production-ready security product
- not yet validated for zero-downtime maintenance
- not yet supported by a completed full-duration soak

### 7. Quick Start

- simplest offline run path
- simplest report path
- simplest dashboard path

### 8. Demo And Evidence

- one prepared-environment example
- one tuning example
- one artifact-correlation example
- link to public-safe screenshots or charts

### 9. Documentation Map

- one-pager
- showcase story
- paper outline
- validation master record
- deployment readiness
- evidence inventory

### 10. Roadmap

- full-duration soak
- broader benign adjudication
- suppression-specific live evidence
- maintenance workflow decision

## Examples / Demo Assets List

Release-ready examples to curate:

- one offline replay example with expected outputs
- one prepared-environment evidence summary for `PREP-ENV-003`
- one false-positive tuning summary for `PREP-ENV-005`
- one artifact-correlation summary for `LAB-SCN-005`
- one architecture diagram export
- three dashboard screenshots:
  - overview
  - alert feed
  - chart/filter view
- two or three chart exports from `reports/graphs/`
- one short demo walkthrough video or GIF if it can be recorded cleanly

## Open-Source Release Checklist

### Repo Hygiene

- confirm `.gitignore` excludes secrets, temporary output, and non-public artifacts
- confirm no credentials or tokens are embedded in docs or examples
- confirm public docs use consistent naming and readiness language

### Documentation

- tighten `README.md` around the current release posture
- link to the strongest docs in `docs/`
- add one public-safe architecture figure
- add one public-safe validation snapshot

### Evidence Curation

- choose which bundles are safe to reference publicly
- redact screenshots and logs if needed
- export a small public evidence pack
- avoid publishing raw data that creates privacy or disclosure risk

### Demo Assets

- choose a single prepared-environment story
- choose a single tuning story
- choose a single artifact-correlation story
- verify captions and screenshots match the current repo state

### Release Boundary Language

- keep "controlled pre-deployment candidate"
- keep "research-first"
- avoid enterprise or product guarantees

## Recommended Initial GitHub Release Shape

- public repository with a stronger README
- curated docs package
- one architecture figure
- one validation snapshot
- one short demo path
- one small public evidence pack

This is enough for a credible first open-source release without forcing a commercial or production story before the evidence supports it.
