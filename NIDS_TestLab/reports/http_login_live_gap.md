# HTTP Login Live Resolution

Generated: 2026-03-10 22:22 UTC

## Summary

- Offline replay for `HTTP Login Brute Force Threshold` is working.
- Live VM lab validation is now working.
- The detector logic was not the blocker.
- The fix was the live capture path on the sensor VM.

## Evidence

- Offline replay pass:
  - [serious_test_report.md](C:/Users/shaik/NIDS_Workspace/NIDS_TestLab/results/http-login-bruteforce-smoke/serious_test_report.md)
- Resolved live VM pass:
  - [serious_test_report.md](C:/Users/shaik/NIDS_Workspace/NIDS_TestLab/results/live-http-login-bruteforce-port80-20260310-224500/serious_test_report.md)

## What Was Fixed

- The live ingest path was changed from the old Scapy-only path to a backend-aware capture path that can use `tcpdump` for payload fidelity in the VM lab.
- The VM-only profile keeps `http_login_threshold: 2` in `20s` because VirtualBox capture still drops some requests under short bursts.
- The stable validation path is the existing service on sensor port `80`, not the temporary high-port helper.
- The resolved live run produced:
  - `22` total flows
  - `1` alert
  - rule `HTTP Login Brute Force Threshold`
  - detail `Source 10.77.0.20 posted to login endpoint 2 times against 10.77.0.30 in 20s`

## Current Impact

- Replay/PCAP web-login abuse testing is covered.
- Live HTTP login abuse validation is trustworthy on the VM sensor using the current lab profile and the port `80` validation path.
- Web exploit and web/C2 testing can now move forward on the same live capture backend.

## Remaining Constraint

1. The VM threshold is intentionally lower than the repo default because the lab is still lossy under burst traffic.
2. Revisit the threshold after denser replay or higher-fidelity live capture in a less lossy environment.
