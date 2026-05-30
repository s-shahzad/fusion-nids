# NIDS Attack Test Ledger

Generated: 2026-03-11 20:35 UTC

This ledger is the thesis-oriented reference log for attack testing performed in `NIDS_TestLab`. Each entry records what was tested, where it was tested, the observed result, the key fix or enabling change, and the evidence folder to cite later.

The OS-level follow-on scope is tracked separately in [os_defense_test_plan.md](C:/NIDS_Workspace/NIDS_TestLab/reports/os_defense_test_plan.md).
The literature-backed implementation notes are tracked in [nids_research_gaps.md](C:/NIDS_Workspace/NIDS_TestLab/reports/nids_research_gaps.md).

## Completed Network Detections

| Attack Case | Environment | Result | Key Fix / Enabler | Evidence |
|---|---|---|---|---|
| HTTP suspicious keyword / web-shell style request | offline replay, live VM lab | pass | HTTP payload signature path validated in the live lab | [serious-offline-20260310-162331](C:/NIDS_Workspace/output/serious-offline-20260310-162331), [serious-live-20260310-163914-r5](C:/NIDS_Workspace/NIDS_TestLab/results/serious-live-20260310-163914-r5) |
| DNS burst / DGA-like activity | offline replay, live VM lab | pass | DNS parser fix and VM-lab threshold tuning | [dns-burst-smoke-v2](C:/NIDS_Workspace/NIDS_TestLab/results/dns-burst-smoke-v2), [live-dns-burst-20260310-213700](C:/NIDS_Workspace/NIDS_TestLab/results/live-dns-burst-20260310-213700) |
| SSH brute force | offline replay, live VM lab | pass | added SSH brute-force anomaly logic and VM-lab thresholds | [ssh-bruteforce-smoke-v2](C:/NIDS_Workspace/NIDS_TestLab/results/ssh-bruteforce-smoke-v2), [live-ssh-bruteforce-20260310-214200](C:/NIDS_Workspace/NIDS_TestLab/results/live-ssh-bruteforce-20260310-214200) |
| RDP brute force | offline replay, live VM lab | pass | added RDP brute-force anomaly logic and VM-lab thresholds | [rdp-bruteforce-smoke](C:/NIDS_Workspace/NIDS_TestLab/results/rdp-bruteforce-smoke), [live-rdp-bruteforce-20260310-214900](C:/NIDS_Workspace/NIDS_TestLab/results/live-rdp-bruteforce-20260310-214900) |
| HTTP login brute force | offline replay, live VM lab | pass | switched the sensor to the tcpdump-backed ingest path and validated against the stable port `80` service | [http-login-bruteforce-smoke](C:/NIDS_Workspace/NIDS_TestLab/results/http-login-bruteforce-smoke), [live-http-login-bruteforce-port80-20260310-224500](C:/NIDS_Workspace/NIDS_TestLab/results/live-http-login-bruteforce-port80-20260310-224500) |
| Port scan signature and anomaly threshold | offline replay, live VM lab | pass | initiator-only TCP SYN scan counting and VM-lab threshold tuning | [offline-profile-smoke](C:/NIDS_Workspace/NIDS_TestLab/results/offline-profile-smoke), [live-port-scan-directionality-20260310-235000](C:/NIDS_Workspace/NIDS_TestLab/results/live-port-scan-directionality-20260310-235000) |
| DoS / packet-rate threshold | offline replay, live VM lab | pass | sustained DNS/UDP flood validation on the VM profile | [serious-offline-20260310-162331](C:/NIDS_Workspace/output/serious-offline-20260310-162331), [live-dos-dns-flood-20260310-232000](C:/NIDS_Workspace/NIDS_TestLab/results/live-dos-dns-flood-20260310-232000) |
| Hybrid fusion decision | offline replay, live VM lab | partial pass | fusion engine works, but live thresholds remain conservative | [serious-offline-20260310-162331](C:/NIDS_Workspace/output/serious-offline-20260310-162331), [serious-live-20260310-163914-r5](C:/NIDS_Workspace/NIDS_TestLab/results/serious-live-20260310-163914-r5) |

## Completed Static Malware-Family Triage

| Family | Result | Observation | Evidence |
|---|---|---|---|
| Seed artifact batch | partial pass | synthetic baseline validation of static triage workflow | [artifact-scan-seed-20260310-235900](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-seed-20260310-235900) |
| Phishing docs / scripts | pass | `6` scanned, `4` quarantined as high | [artifact-scan-phishing-seed-20260310-230000](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-phishing-seed-20260310-230000) |
| PE droppers / loaders | pass | `7` scanned, `4` high, `.msi` and `.bin` heuristics improved | [artifact-scan-pe-loader-seed-20260310-234000](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-pe-loader-seed-20260310-234000) |
| Credential stealer | pass | `6` scanned, `2` high, `3` medium, `1` low | [artifact-scan-credential-stealer-seed-20260310-234500](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-credential-stealer-seed-20260310-234500) |
| RAT / backdoor | pass | `6` scanned, `4` high-risk quarantines | [artifact-scan-rat-backdoor-seed-20260311-000500](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-rat-backdoor-seed-20260311-000500) |
| Ransomware | pass | `7` scanned, `5` high-risk quarantines | [artifact-scan-ransomware-seed-20260311-001500](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-ransomware-seed-20260311-001500) |

## Completed OS Defense Cases

| Case | Environment | Result | Key Fix / Enabler | Evidence |
|---|---|---|---|---|
| Ubuntu cron persistence + suspicious HTTP beacon | live VM lab | pass after one rerun | first run produced `0` flows with the opaque `wget` transport; the validated rerun switched to a deterministic raw Bash `/dev/tcp` HTTP beacon, widened the HTTP suspicious-keyword rule for Linux loader tokens, and captured target crontab artifacts alongside the sensor output | [ubuntu-os-cron-http-beacon-20260311-160500](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-cron-http-beacon-20260311-160500), [ubuntu-os-cron-http-beacon-20260311-161200](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-cron-http-beacon-20260311-161200) |
| Ubuntu systemd persistence + DNS beacon | live VM lab | pass after multiple reruns | the service deployment path was already correct; the decisive fix was removing the extra UDP sink from the OS-defense runner so the service-driven DNS beacon reached the live sensor path normally, yielding `36` flows and `1` `DNS Burst / DGA-like Activity` alert while keeping the failed iterations for traceability | [ubuntu-os-systemd-dns-beacon-20260311-164900](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-164900), [ubuntu-os-systemd-dns-beacon-20260311-165700](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-165700), [ubuntu-os-systemd-dns-beacon-20260311-170500](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-170500), [ubuntu-os-systemd-dns-beacon-20260311-162948](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-162948) |
| Ubuntu defense-tamper simulation + service-stop intent | live VM lab | pass | a dedicated Linux tamper signature and the new Ubuntu OS-defense case runner preserved both attack-side host artifacts and defense-side sensor artifacts; the target advertised `sudo systemctl stop` and `sudo ufw disable` over HTTP, safely stopped a temporary guard service, and the sensor fired `Linux Defense Tamper Command` | [ubuntu-os-defense-tamper-20260311-attack-defense](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-defense-tamper-20260311-attack-defense) |

## Concurrent Multi-Attack Validation

These runs matter because the thesis claim is not only that the NIDS detects isolated attacks, but that it can distinguish overlapping attacks in the same time window.

| Run | Composition | Result | Key Finding | Evidence |
|---|---|---|---|---|
| Mixed live overlap with HTTP path | DNS burst, DNS flood, scan, SSH, RDP, HTTP login, HTTP suspicious keyword | blocked / infrastructure regression | run completed with `0` flows and `0` alerts; this is a runtime/helper-path problem, not a detector result | [live-multi-attack-20260311-141800](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-20260311-141800) |
| Mixed live overlap without HTTP path | DNS burst, DNS flood, scan, SSH, RDP | partial pass | `81` flows, `2` alerts; only `Suspicious Port Scan` survived under overlap | [live-multi-attack-no-http-20260311-142600](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-no-http-20260311-142600) |
| Balanced live overlap | DNS burst, scan, SSH, RDP | partial pass | `26` flows, `1` alert; again only `Suspicious Port Scan` survived | [live-multi-attack-balanced-20260311-142900](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-balanced-20260311-142900) |
| Mixed live overlap after helper-path repair | DNS burst, DNS flood, scan, SSH, RDP, HTTP login | partial pass | `340` flows, `1` alert; DoS survived under overlap after the dedicated UDP sink and repaired HTTP helper path | [live-multi-attack-fixed-20260311-144100](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-fixed-20260311-144100) |
| Mixed live overlap, DNS-focused | DNS burst, scan, SSH, RDP, HTTP login | partial pass | `70` flows, `1` alert; DNS burst survived under overlap with the lighter composition | [live-multi-attack-overlap-20260311-145000](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-overlap-20260311-145000) |
| Mixed live overlap, best current same-window proof | DNS burst, scan, HTTP login | partial pass | `49` flows, `3` alerts; `DNS Burst / DGA-like Activity`, `Suspicious Port Scan`, and `Hybrid Fusion Decision` fired in the same run | [live-multi-attack-dns-http-scan-20260311-145300](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-dns-http-scan-20260311-145300) |
| Isolated HTTP login on `8080` after helper-path repair | HTTP login brute force | pass | `19` flows, `1` alert; `HTTP Login Brute Force Threshold` now survives on the repaired `8080` helper path | [live-http-8080-regression-20260311-144500](C:/NIDS_Workspace/NIDS_TestLab/results/live-http-8080-regression-20260311-144500) |
| Isolated HTTP suspicious keyword on `8080` | HTTP suspicious keyword | miss | only a single SYN was captured; this web-signature path is still unstable on the repaired helper path | [live-http-keyword-8080-regression-20260311-150200](C:/NIDS_Workspace/NIDS_TestLab/results/live-http-keyword-8080-regression-20260311-150200) |
| Tuned overlap: DNS burst + HTTP login | DNS burst, HTTP login | partial pass | `59` flows, `1` alert; DNS survives, but only one HTTP POST was preserved under overlap | [live-overlap-dns-http-tuned-20260311-150900](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-http-tuned-20260311-150900) |
| Tuned overlap: DNS burst + SSH | DNS burst, SSH | partial pass | `39` flows, `3` alerts; DNS survives and the port-22 path still yields `Suspicious Port Scan` plus fusion, but not the SSH brute-force threshold | [live-overlap-dns-ssh-tuned-20260311-151100](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-ssh-tuned-20260311-151100) |
| Tuned overlap: DNS burst + RDP | DNS burst, RDP | partial pass | `72` flows, `2` alerts; DNS survives and the port-3389 signature survives, but not the RDP brute-force threshold | [live-overlap-dns-rdp-tuned-20260311-151300](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-rdp-tuned-20260311-151300) |
| Tuned overlap: DNS burst + RDP, heavier attempt budget | DNS burst, RDP | partial pass | `37` flows, `2` alerts; extra RDP attempts did not push the threshold over the line under overlap | [live-overlap-dns-rdp-heavy-20260311-151600](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-rdp-heavy-20260311-151600) |
| Overlap profile: DNS burst + RDP | DNS burst, RDP | pass | `42` flows, `4` alerts; `DNS Burst / DGA-like Activity`, `RDP Brute Force Threshold`, `Suspicious Port Scan`, and `Hybrid Fusion Decision` fired in one run | [live-overlap-profile-dns-rdp-20260311-152700](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-rdp-20260311-152700) |
| Overlap profile: DNS burst + HTTP login | DNS burst, HTTP login | partial pass | `50` flows, `1` alert; DNS survives, but the overlap profile still did not preserve enough HTTP POSTs for the login threshold | [live-overlap-profile-dns-http-20260311-153000](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-http-20260311-153000) |
| Overlap profile: DNS burst + HTTP login, ordered launch | DNS burst, HTTP login | pass | `121` flows, `2` alerts; `DNS Burst / DGA-like Activity` and `HTTP Login Brute Force Threshold` fired together after ordered launch tuning | [live-overlap-profile-dns-http-ordered-20260311-154000](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-http-ordered-20260311-154000) |
| Overlap profile: DNS burst + SSH | DNS burst, SSH | partial pass | `37` flows, `3` alerts; DNS survives and the port-22 signature/fusion path survives, but not the SSH brute-force threshold | [live-overlap-profile-dns-ssh-20260311-153200](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-ssh-20260311-153200) |

## Findings To Cite

1. Single-attack validation is materially ahead of concurrent-attack validation.
   The current stack detects the tested single cases reliably in replay and in the isolated live lab.

2. Static artifact triage is strong enough for family-level screening, but it is still synthetic-first.
   Real sample intake is still needed before any strong claim about malware-family coverage.

3. Concurrent live overlap is still the main research gap, but it is no longer a blank spot.
   The repaired live validator now has evidence for same-window detection, including a DNS-plus-HTTP-login pass after ordered launch tuning and a DNS-plus-RDP-threshold pass on the dedicated overlap profile.

4. The overlap misses are now specific enough to target.
   The web-helper path is repaired and HTTP login now survives one ordered overlap run on `8080`, but it is not yet stable across all mixed runs. SSH under overlap still degrades to the port-22 signature/fusion path. RDP is the strongest overlap-profile brute-force case so far.

5. The next-level claim should be framed carefully.
   The evidence supports "broad hybrid coverage with validated single-case detection and partially validated concurrent overlap," not yet "all threats detected simultaneously."

6. The OS-defense phase now has three validated Ubuntu cases with both attack and defense evidence preserved.
   Cron-based persistence plus scripted HTTP beacon traffic, systemd-based persistence plus DNS beacon traffic, and defense-tamper plus safe service-stop intent are all now documented on the target and detected by the sensor in the same evidence package.

7. The prior `systemd + DNS beacon` miss is still useful research evidence even though it is now resolved.
   The failed folders remain cited, and the final passing rerun demonstrates a concrete validation workflow: reproduce, isolate the transport-side difference, fix the runner, and retain the failed history instead of rewriting it.

## Remaining Attack Families

- SQL injection / web exploit
- Beaconing / C2
- Exfiltration
- Lateral movement
- Low-and-slow stealth scan
- Worm / self-propagation
- Real RAT/backdoor samples
- Real ransomware samples
- Real credential-stealer samples
- Load/stress testing after the above coverage stabilizes

## Remaining OS Defense Cases
- Ubuntu staged archive exfil over HTTP or DNS
- Windows safe-only posture validation on the host
- Windows full attack-and-defense validation after a dedicated VM is added
- macOS target validation after a dedicated VM is added

## Next Research Actions

1. Preserve the repaired concurrent transport path.
   The dedicated UDP sink, repaired HTTP helper, and `8080` web-path regression should remain part of future live overlap testing.

2. Keep the dedicated overlap profile for thesis-grade concurrent validation.
   The profile is [live_vm_overlap_profile.yml](C:/NIDS_Workspace/NIDS_TestLab/config/live_vm_overlap_profile.yml), and the validator can switch to it with `--config-relpath`.

3. Tune concurrent overlap pacing and live sensor throughput so HTTP login and SSH survive the same mixed window as DNS and scan activity.
   The pacing knobs are in [live_vm_attack_validation.py](C:/NIDS_Workspace/scripts/live_vm_attack_validation.py): `--dns-delay-sec`, `--ssh-attempt-delay-sec`, `--rdp-attempt-delay-sec`, `--http-login-attempt-delay-sec`, and `--http-keyword-request-delay-sec`.

4. Add beaconing and exfiltration cases before behavioral malware execution, using the now-validated `systemd + DNS beacon` case as the Linux baseline.

5. Move from synthetic malware-family triage to selected real samples in the isolated behavioral VM only.

6. Keep every new run under `NIDS_TestLab\results\` and cite that folder in both the coverage matrix and this ledger.

7. Use the literature-backed gap note before making strong research claims.
   The current implementation/limitations summary is [nids_research_gaps.md](C:/NIDS_Workspace/NIDS_TestLab/reports/nids_research_gaps.md).

