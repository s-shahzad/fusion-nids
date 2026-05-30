# NIDS Attack Coverage Matrix

Generated: 2026-03-11 23:56 UTC

## Environments

- `Offline Replay`: deterministic PCAP replay from `NIDS_TestLab\pcaps`
- `Live VM Lab`: `nids-kali-attacker` or `nids-ubuntu-target` -> `nids-ubuntu-sensor`
- `Static Artifact Triage`: static-only file analysis through `artifact-scan`
- `Behavioral Malware VM`: isolated execution in target VM with sensor capture
- `Load/Stress`: sustained packet/API/dashboard load

## Current Coverage

| Attack Type | Offline Replay | Live VM Lab | Static Artifact | Current Status | Evidence | Action Required |
|---|---|---|---|---|---|---|
| HTTP suspicious keyword / web-shell style request | PASS | PASS | N/A | covered; parser-driven HTTP signature matching now no longer depends on a fixed destination-port list | `serious-offline-20260310-162331`, `serious-live-20260310-163914-r5` | keep moving protocol-aware detections away from fixed-port assumptions and add more HTTP exploit payloads |
| HTTP login brute force / credential spray | PASS | PASS | N/A | covered after tcpdump-backed live ingest and VM profile tuning | `http-login-bruteforce-smoke`, `live-http-login-bruteforce-port80-20260310-224500` | keep the VM-only threshold at `2` complete login POSTs in `20s`; revisit after higher-fidelity live capture or denser replay |
| DNS burst / DGA-like activity | PASS | PASS | N/A | covered in replay and tuned VM profile | `dns-burst-smoke-v2`, `live-dns-burst-20260310-213700` | add DNS lexical features and periodicity checks before C2 malware testing |
| SSH brute force / password spray | PASS | PASS | N/A | covered in replay and tuned VM profile | `ssh-bruteforce-smoke-v2`, `live-ssh-bruteforce-20260310-214200` | add auth-failure and username spray features later; keep VM-lab threshold separate from repo default |
| RDP brute force / connection spray | PASS | PASS | N/A | covered in replay and tuned VM profile | `rdp-bruteforce-smoke`, `live-rdp-bruteforce-20260310-214900` | add Windows logon-failure context and credential-spray heuristics later |
| Port scan signature on `22/23/3389` | PASS | PASS | N/A | covered | `serious-offline-20260310-162331`, `serious-live-20260310-163914-r5` | add more scan signature ports and common admin services |
| Port scan anomaly threshold | PASS | PASS | N/A | covered after initiator-only SYN scan counting and VM profile tuning | `offline-profile-smoke`, `live-port-scan-directionality-20260310-235000` | add UDP scan and low-and-slow scan variants later; keep the VM-only threshold separate from the repo default |
| DoS / packet-rate threshold | PASS | PASS | N/A | covered after sustained DNS/UDP flood validation on the live VM profile | `serious-offline-20260310-162331`, `live-dos-dns-flood-20260310-232000` | add HTTP flood and non-DNS UDP flood variants later so DoS coverage is not tied to the DNS service path |
| Supervised ensemble classification | PARTIAL | PARTIAL | N/A | not production-ready alone | contributes to fusion scores, but no strong standalone supervised alert evidence from current lab cases | collect labeled lab traffic and retrain on scan, burst, DNS, brute-force, and beacon cases |
| Unsupervised anomaly detection | NOISY | NOT READY | N/A | partial | offline replay produced many unsupervised alerts; live VM evidence is not yet useful | recalibrate on live flow-level data, shorten warmup only for lab profile, and evaluate false-positive rate before malware runs |
| Fusion decision | PASS | PASS (limited) | N/A | partial | offline replay produced `25` fusion alerts; live VM produced `1` fusion alert on scan traffic | retune fusion thresholds after more labeled live cases |
| Concurrent mixed attack overlap | N/A | PARTIAL | N/A | concurrent live validator is implemented and now proves multi-alert overlap, including DNS + HTTP login and DNS + RDP threshold survival on the dedicated overlap profile, but coverage is still uneven by attack family | `live-overlap-profile-dns-http-ordered-20260311-154000`, `live-overlap-profile-dns-rdp-20260311-152700`, `live-multi-attack-dns-http-scan-20260311-145300`, `live-multi-attack-fixed-20260311-144100`, `live-overlap-profile-dns-http-20260311-153000`, `live-overlap-profile-dns-ssh-20260311-153200`, `live-overlap-dns-http-tuned-20260311-150900`, `live-multi-attack-no-http-20260311-142600`, `live-multi-attack-balanced-20260311-142900`, `live-multi-attack-20260311-141800` | keep the dedicated overlap profile, preserve the DNS+HTTP and DNS+RDP overlap runs, and next tune true SSH brute-force detection plus web-signature overlap so they survive the same mixed window |
| Ubuntu cron persistence + suspicious HTTP beacon | N/A | PASS | N/A | first OS-defense case is covered after switching the target beacon to a deterministic raw `/dev/tcp` HTTP request and widening the HTTP suspicious-keyword rule for Linux loader tokens; host crontab evidence is captured alongside the sensor artifacts | `ubuntu-os-cron-http-beacon-20260311-161200`, `ubuntu-os-cron-http-beacon-20260311-160500` | keep it as the HTTP-beacon baseline and extend the same attack/defense evidence pattern to staged exfiltration cases |
| Ubuntu systemd persistence + DNS beacon | N/A | PASS | N/A | covered after removing the extra UDP sink from the OS-defense runner so the service-driven DNS beacon reached the live sensor path normally; failed iterations are preserved for thesis traceability | `ubuntu-os-systemd-dns-beacon-20260311-164900`, `ubuntu-os-systemd-dns-beacon-20260311-165700`, `ubuntu-os-systemd-dns-beacon-20260311-170500`, `ubuntu-os-systemd-dns-beacon-20260311-162948` | use the validated case as the baseline for upcoming beaconing/C2 and staged exfiltration work, and add slower periodic-beacon tests later |
| Ubuntu defense-tamper simulation + service-stop intent | N/A | PASS | N/A | covered with explicit attack-side tamper artifacts and defense-side sensor evidence in one case folder; the target advertised `sudo systemctl stop` and `sudo ufw disable` over HTTP, stopped a temporary guard service safely, and the sensor fired a dedicated Linux tamper signature | `ubuntu-os-defense-tamper-20260311-attack-defense` | extend the same attack/defense dual-evidence format to staged exfiltration and later Windows posture validation |
| Ubuntu staged archive exfiltration over HTTP | N/A | PASS | N/A | covered with staged archive artifacts, defense-side sensor evidence, VM hardening snapshots, and explicit attack-strength documentation; the target packaged `3` files into a `tar.gz` archive and sent `4` HTTP POST exfil attempts while the sensor fired a dedicated exfiltration signature | `ubuntu-os-staged-http-exfil-20260311-attack-defense-r4` | use this as the HTTP exfil baseline, add a DNS-exfil variant later, and carry the same hardening-plus-attack-strength reporting into Windows safe-only posture validation |
| Static malicious file triage | N/A | N/A | PARTIAL | synthetic seed, phishing, PE-loader, credential-stealer, RAT/backdoor, and ransomware passes exercised; real malware samples still pending | `artifact-scan-seed-20260310-235900`, `artifact-scan-phishing-seed-20260310-230000`, `artifact-scan-pe-loader-seed-20260310-234000`, `artifact-scan-credential-stealer-seed-20260310-234500`, `artifact-scan-rat-backdoor-seed-20260311-000500`, `artifact-scan-ransomware-seed-20260311-001500` | move selected real RAT/backdoor and ransomware samples into isolated behavioral VM validation; keep execution in the lab only |

## Attacks Completed So Far

1. `HTTP Suspicious Keyword`
   Environment: offline replay and live VM lab
   Result: detected

2. `Suspicious Port Scan` signature
   Environment: offline replay and live VM lab
   Result: detected

3. `Port Scan Threshold`
   Environment: offline replay and live VM lab
   Result: detected after counting only initiator-side TCP SYN attempts and lowering the VM-lab threshold to `24` ports in `12s`

4. `DoS Rate Threshold`
   Environment: offline replay and live VM lab
   Result: detected live after validating with a sustained DNS/UDP flood against port `53`

5. `Hybrid Fusion Decision`
   Environment: offline replay and live VM lab
   Result: detected, but current live fusion is still conservative

6. `DNS Burst / DGA-like Activity`
   Environment: offline replay and live VM lab
   Result: detected after DNS parser fix and VM-lab threshold tuning

7. `SSH Brute Force Threshold`
   Environment: offline replay and live VM lab
   Result: detected after adding SSH brute-force anomaly logic and VM-lab threshold tuning

8. `RDP Brute Force Threshold`
   Environment: offline replay and live VM lab
   Result: detected after adding RDP brute-force anomaly logic and VM-lab threshold tuning

9. `HTTP Login Brute Force Threshold`
   Environment: offline replay and live VM lab
   Result: detected after switching the live VM sensor to the tcpdump-backed ingest path and validating against the stable port `80` service

10. `RAT / Backdoor` static triage
   Environment: static artifact triage
   Result: detected in the synthetic family pass with `4` high-risk quarantines out of `6` artifacts

11. `Ransomware` static triage
   Environment: static artifact triage
   Result: detected in the synthetic family pass with `5` high-risk quarantines out of `7` artifacts

12. `Concurrent mixed attack overlap`
   Environment: live VM lab
   Result: partial; simultaneous live runs are reproducible and now produce multi-alert evidence, with the strongest current proofs being `DNS Burst / DGA-like Activity` + `HTTP Login Brute Force Threshold`, `DNS Burst / DGA-like Activity` + `RDP Brute Force Threshold`, and `DNS Burst / DGA-like Activity` + `Suspicious Port Scan` + `Hybrid Fusion Decision`

13. `Ubuntu cron persistence + suspicious HTTP beacon`
   Environment: live VM lab
   Result: detected after replacing the first opaque `wget` transport attempt with a deterministic raw Bash `/dev/tcp` HTTP beacon and capturing the target crontab artifacts alongside the sensor evidence

14. `Ubuntu systemd persistence + DNS beacon`
   Environment: live VM lab
   Result: detected after removing the extra UDP sink from the OS-defense runner; the final rerun produced `36` flows and `1` `DNS Burst / DGA-like Activity` alert while preserving the earlier failed evidence folders for thesis traceability

15. `Ubuntu defense-tamper simulation + service-stop intent`
   Environment: live VM lab
   Result: detected with `41` flows and `1` `Linux Defense Tamper Command` alert while preserving both attack-side host artifacts and defense-side sensor artifacts in the same result folder

16. `Ubuntu staged archive exfiltration over HTTP`
   Environment: live VM lab
   Result: detected with `40` flows and `1` `Linux Archive Exfiltration` alert while preserving the staged archive, transfer log, VM hardening snapshots, and defense-side sensor evidence in the same result folder

## Upcoming Attack Campaign

| Attack Family | Concrete Cases | Environment | Expected Detector(s) | Current Status | If Missed, Fix |
|---|---|---|---|---|---|
| SQL injection / web exploit | SQLi strings, path traversal, command injection | offline replay, live VM lab | signature, supervised, fusion | pending | expand HTTP payload signatures and web exploit training data |
| Lateral movement | SMB, PsExec, WinRM, RDP pivoting | live VM lab | signature, anomaly, supervised, fusion | pending | add service-aware rules and host-to-host movement features |
| Beaconing / C2 | fixed-interval HTTP/DNS/TLS callbacks | offline replay, live VM lab, behavioral malware VM | anomaly, unsupervised, fusion | pending | add periodicity features, destination rarity, and beacon signatures |
| Exfiltration | large outbound HTTP, DNS exfil, archive staging | offline replay, live VM lab, behavioral malware VM | anomaly, supervised, fusion | pending | add byte-volume, transfer-duration, and DNS payload features |
| SYN/UDP/HTTP flood | sustained high-rate bursts | live VM lab, load/stress | anomaly, fusion | in progress | validate `live_vm_profile.yml`; if still missed, aggregate live packets before ML |
| Low-and-slow stealth scan | slow port scan across long window | offline replay, live VM lab | anomaly, unsupervised | pending | add longer scan windows and connection history counters |
| Phishing docs / scripts | macro docs, HTA, JS, VBS, PowerShell | static artifact triage first, then behavioral malware VM if needed | artifact scan, signature | synthetic static pass complete; real samples pending | keep expanding static rules, then move only selected real samples into isolated behavioral testing |
| PE droppers / loaders | packed EXE, downloader, staged loader | static artifact triage first, then behavioral malware VM | artifact scan, network detectors during execution | synthetic static pass complete; real samples pending | keep improving MSI/bin heuristics and record network IOCs during execution for selected real samples |
| RAT / backdoor | reverse shell, HTTP C2, DNS C2 | static artifact triage first, then behavioral malware VM | artifact scan, signature, anomaly, unsupervised, fusion | synthetic static pass complete; real samples pending | add C2-specific traffic tests, persistence signatures, and labeled training data before behavioral runs |
| Ransomware | file encryption + beacon + exfil prep | static artifact triage first, then behavioral malware VM | artifact scan, anomaly, fusion | synthetic static pass complete; real samples pending | capture file + network indicators and add rules for shadow-copy deletion, staging, and exfil traffic before behavioral runs |
| Credential stealer | browser/data exfil, webhook posts | static artifact triage first, then behavioral malware VM | artifact scan, anomaly, supervised, fusion | synthetic static pass complete; real samples pending | add exfil destination/rate features and suspicious POST signatures before behavioral runs |
| Worm / self-propagation | host discovery, scan, exploit spread | live VM lab, behavioral malware VM | signature, anomaly, fusion | pending | strengthen scan detection and host-spread graph features |
| Ubuntu persistence and defense cases | cron, systemd, downloader shell, service-stop, firewall-disable, staged exfil | live VM lab | signature, anomaly, fusion, operator note | in progress | keep using the dedicated Ubuntu OS-defense runner, use the validated cron, systemd, defense-tamper, and staged-exfil cases as baselines, and preserve both attack-side host artifacts and defense-side sensor alerts in the result folder |

## Action Queue Before Malware Execution

1. Replace the synthetic family passes with real sample intake by family.
   Path: `NIDS_TestLab\artifacts\incoming`
   Command: `RUN_ARTIFACT_STATIC_SCAN.ps1`

2. Take the next real malware families into static triage.
   Recommended: selected `RAT / backdoor` and `ransomware` samples first, then confirm `credential stealer` with real samples.

3. Only after static triage, move selected samples into isolated behavioral VM testing.
   Goal: observe network behavior without ever executing samples on the host.

4. After the malware-family passes, return to the remaining network gaps.
   Priority: `SQL injection / web exploit`, `Beaconing / C2`, `Exfiltration`, `Lateral movement`, `Low-and-slow stealth scan`, `Worm / self-propagation`.

5. Treat concurrent multi-attack validation as a first-class regression.
   Goal: make the live VM lab detect multiple overlapping attacks in the same run, not only single-case validations.

6. Use the resolved `systemd + DNS beacon` case as the baseline for the next OS-defense and C2 cases.
   Goal: preserve the failed evidence folders, but move the active fix queue to defense-tamper, staged exfiltration, and slower periodic beacon variants.

## Evidence Folders

- Offline synthetic replay: [serious-offline-20260310-162331](C:/NIDS_Workspace/output/serious-offline-20260310-162331)
- Offline packaged smoke run: [offline-profile-smoke](C:/NIDS_Workspace/NIDS_TestLab/results/offline-profile-smoke)
- First improved live lab run: [serious-live-20260310-163914-r5](C:/NIDS_Workspace/NIDS_TestLab/results/serious-live-20260310-163914-r5)
- DNS burst replay fix: [dns-burst-smoke-v2](C:/NIDS_Workspace/NIDS_TestLab/results/dns-burst-smoke-v2)
- SSH brute-force replay fix: [ssh-bruteforce-smoke-v2](C:/NIDS_Workspace/NIDS_TestLab/results/ssh-bruteforce-smoke-v2)
- RDP brute-force replay fix: [rdp-bruteforce-smoke](C:/NIDS_Workspace/NIDS_TestLab/results/rdp-bruteforce-smoke)
- HTTP login brute-force replay fix: [http-login-bruteforce-smoke](C:/NIDS_Workspace/NIDS_TestLab/results/http-login-bruteforce-smoke)
- Live DNS burst validation: [live-dns-burst-20260310-213700](C:/NIDS_Workspace/NIDS_TestLab/results/live-dns-burst-20260310-213700)
- Live DoS DNS/UDP flood validation: [live-dos-dns-flood-20260310-232000](C:/NIDS_Workspace/NIDS_TestLab/results/live-dos-dns-flood-20260310-232000)
- Live port-scan directionality validation: [live-port-scan-directionality-20260310-235000](C:/NIDS_Workspace/NIDS_TestLab/results/live-port-scan-directionality-20260310-235000)
- Live SSH brute-force validation: [live-ssh-bruteforce-20260310-214200](C:/NIDS_Workspace/NIDS_TestLab/results/live-ssh-bruteforce-20260310-214200)
- Live RDP brute-force validation: [live-rdp-bruteforce-20260310-214900](C:/NIDS_Workspace/NIDS_TestLab/results/live-rdp-bruteforce-20260310-214900)
- Live HTTP login brute-force validation: [live-http-login-bruteforce-port80-20260310-224500](C:/NIDS_Workspace/NIDS_TestLab/results/live-http-login-bruteforce-port80-20260310-224500)
- Static triage synthetic seed pass: [artifact-scan-seed-20260310-235900](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-seed-20260310-235900)
- Static triage phishing family pass: [artifact-scan-phishing-seed-20260310-230000](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-phishing-seed-20260310-230000)
- Static triage PE/dropper family pass: [artifact-scan-pe-loader-seed-20260310-234000](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-pe-loader-seed-20260310-234000)
- Static triage credential-stealer family pass: [artifact-scan-credential-stealer-seed-20260310-234500](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-credential-stealer-seed-20260310-234500)
- Static triage RAT/backdoor family pass: [artifact-scan-rat-backdoor-seed-20260311-000500](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-rat-backdoor-seed-20260311-000500)
- Static triage ransomware family pass: [artifact-scan-ransomware-seed-20260311-001500](C:/NIDS_Workspace/NIDS_TestLab/results/artifact-scan-ransomware-seed-20260311-001500)
- Concurrent mixed attack validation with HTTP path: [live-multi-attack-20260311-141800](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-20260311-141800)
- Concurrent mixed attack validation without HTTP path: [live-multi-attack-no-http-20260311-142600](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-no-http-20260311-142600)
- Concurrent mixed attack validation, balanced overlap: [live-multi-attack-balanced-20260311-142900](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-balanced-20260311-142900)
- Concurrent mixed attack validation, repaired HTTP/UDP helper paths: [live-multi-attack-fixed-20260311-144100](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-fixed-20260311-144100)
- Concurrent mixed attack validation, DNS overlap: [live-multi-attack-overlap-20260311-145000](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-overlap-20260311-145000)
- Concurrent mixed attack validation, best same-window evidence: [live-multi-attack-dns-http-scan-20260311-145300](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-dns-http-scan-20260311-145300)
- HTTP login regression on `8080`: [live-http-8080-regression-20260311-144500](C:/NIDS_Workspace/NIDS_TestLab/results/live-http-8080-regression-20260311-144500)
- Concurrent overlap, DNS + HTTP login tuned pacing: [live-overlap-dns-http-tuned-20260311-150900](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-http-tuned-20260311-150900)
- Concurrent overlap, DNS + SSH tuned pacing: [live-overlap-dns-ssh-tuned-20260311-151100](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-ssh-tuned-20260311-151100)
- Concurrent overlap, DNS + RDP tuned pacing: [live-overlap-dns-rdp-tuned-20260311-151300](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-rdp-tuned-20260311-151300)
- Concurrent overlap, DNS + RDP heavy pacing: [live-overlap-dns-rdp-heavy-20260311-151600](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-dns-rdp-heavy-20260311-151600)
- Concurrent overlap profile, DNS + RDP: [live-overlap-profile-dns-rdp-20260311-152700](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-rdp-20260311-152700)
- Concurrent overlap profile, DNS + HTTP login: [live-overlap-profile-dns-http-20260311-153000](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-http-20260311-153000)
- Concurrent overlap profile, DNS + HTTP login ordered launch: [live-overlap-profile-dns-http-ordered-20260311-154000](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-http-ordered-20260311-154000)
- Concurrent overlap profile, DNS + SSH: [live-overlap-profile-dns-ssh-20260311-153200](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-ssh-20260311-153200)
- Ubuntu systemd persistence + DNS beacon, final passing rerun: [ubuntu-os-systemd-dns-beacon-20260311-162948](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-162948)
- Ubuntu defense-tamper simulation + service-stop intent: [ubuntu-os-defense-tamper-20260311-attack-defense](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-defense-tamper-20260311-attack-defense)
- Ubuntu staged archive exfiltration over HTTP: [ubuntu-os-staged-http-exfil-20260311-attack-defense-r4](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-staged-http-exfil-20260311-attack-defense-r4)

