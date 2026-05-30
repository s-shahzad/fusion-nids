# Validation Breadth

## Purpose

This document formalizes the replay families currently used to broaden evaluation beyond a single narrow baseline.

## Family 1: Main Serious Synthetic Replay

- PCAP: `NIDS_TestLab/pcaps/serious_synthetic_20260310.pcap`
- Role: canonical tuned baseline and comparative baseline input
- Behavior mix:
  - scan activity
  - DoS-style behavior
  - suspicious pattern behavior
  - fusion-relevant overlap
- Ground truth example:
  - `docs/generated/ground_truth/serious_synthetic_replay_review.json`
- Realism limit:
  - replay-review oriented and synthetic rather than a broad benchmark corpus

## Family 2: Focused DNS Burst Replay

- PCAP: `NIDS_TestLab/pcaps/dns_burst_20260310.pcap`
- Role: anomaly-focused replay family
- Primary behavior:
  - DNS burst / DGA-like activity
- Expected detections:
  - `DNS Burst / DGA-like Activity`
- Ground truth example:
  - `docs/generated/ground_truth/dns_burst_replay_review.json`
- Realism limit:
  - single-family replay, useful for threshold and path validation rather than broad realism

## Family 3: Focused HTTP Login Brute Force Replay

- PCAP: `NIDS_TestLab/pcaps/http_login_bruteforce_20260310.pcap`
- Role: application-layer threshold replay family
- Primary behavior:
  - repeated login attempts against a synthetic endpoint
- Expected detections:
  - `HTTP Login Brute Force Threshold`
- Ground truth example:
  - `docs/generated/ground_truth/http_login_bruteforce_replay_review.json`
- Realism limit:
  - focused detector-path validation rather than realistic web application behavior diversity

## Family 4: Standard Offline Lab Scenarios

- Source: `NIDS_TestLab/scenarios/*.yml`
- Role: self-contained scenario bundles for mixed and correlation-style replay
- Coverage includes:
  - port scan replay
  - brute-force replay
  - flood and burst replay
  - mixed benign and malicious replay
  - artifact and network correlation replay
- Realism limit:
  - generated lab scenarios emphasize repeatability and reviewability over traffic diversity

## Family 5: AI Robustness Replay Scenarios

- Source: `src/NIDS/adversary/ai_scenarios.py`
- Role: bounded evasion-style and robustness-oriented replay review
- Coverage includes:
  - `slow_scan`
  - `burst_then_idle`
  - `mimic_normal`
  - `partial_signal`
  - `alert_flood`
- Realism limit:
  - synthetic stress and evasion motifs, not real adversarial traffic evaluation

## What This Closes

This breadth expansion closes part of the earlier validation-breadth gap by making the project rely on more than one replay family:

- one mixed serious replay baseline
- two focused single-family replay inputs
- standard lab replay bundles
- AI robustness scenario bundles

## What It Does Not Close

- it does not create a broad public benchmark study
- it does not establish real-world traffic realism
- it does not replace event-aligned evaluation
- it does not justify production-detection claims
