# NIDS Test Lab

This folder is the local staging area for isolated NIDS testing on this PC.

## What It Contains

- `pcaps/`: put replay PCAP files here
- `config/`: dedicated lab-only runtime profiles
- `isos/`: place VM installer ISOs here
- `vm_exports/`: exported VM images and backups
- `output/`: runtime DB and JSONL output
- `reports/`: threshold and analysis reports
- `logs/`: optional operator logs
- `BUILD_REALISTIC_LAB.ps1`: realistic attacker/target/sensor lab bootstrap
- `INSTALL_GUESTS.ps1`: unattended Ubuntu guest install launcher
- `CREATE_FIRST_VM.ps1`: first VirtualBox VM bootstrap
- `RUN_OFFLINE_TEST.ps1`: local replay launcher
- `RUN_UBUNTU_OS_DEFENSE_TEST.ps1`: Ubuntu host-defense validation launcher for persistence/tamper/exfil cases
- `RUN_ARTIFACT_STATIC_SCAN.ps1`: static-only artifact scan launcher for later malware sample triage
- `STAGE_STATIC_TRIAGE_FIXTURES.ps1`: safe synthetic artifact generator for first-pass static triage validation
- `STAGE_PHISHING_TRIAGE_FIXTURES.ps1`: safe phishing-doc/script fixture generator for family-level static triage validation
- `STAGE_PE_LOADER_TRIAGE_FIXTURES.ps1`: safe PE/dropper fixture generator for family-level static triage validation
- `STAGE_CREDENTIAL_STEALER_TRIAGE_FIXTURES.ps1`: safe credential-stealer fixture generator for family-level static triage validation
- `STAGE_RAT_BACKDOOR_TRIAGE_FIXTURES.ps1`: safe RAT/backdoor fixture generator for family-level static triage validation
- `STAGE_RANSOMWARE_TRIAGE_FIXTURES.ps1`: safe ransomware fixture generator for family-level static triage validation
- `LAB_ACCESS.md`: final SSH, IP, and guest access notes
- `reports\attack_coverage_matrix.md`: tracked attack coverage, misses, and fix queue
- `reports\attack_test_ledger.md`: evidence-backed research log for completed, partial, and pending attack tests
- `reports\os_defense_test_plan.md`: OS-level defense validation scope and recording rules
- `reports\nids_research_gaps.md`: representative primary-paper notes, cited implementation gaps, and next research-backed fixes

## Isolation Goal

The preferred setup is a **three-VM VirtualBox lab**:

- `nids-kali-attacker`
- `nids-ubuntu-target`
- `nids-ubuntu-sensor`

All three use the same **Internal Network** such as `nidslab`.

This keeps the Windows host off the guest network while still letting the VMs talk to each other. By default the builder keeps **all lab VMs internal-only**. If you later want package updates, you can opt into a temporary second `NAT` adapter for the Ubuntu VMs.

## Setup

Open **PowerShell as Administrator** and run:

```powershell
C:\NIDS_Workspace\scripts\setup_virtualbox_lab.ps1 -InstallVirtualBox
```

Then build the realistic lab:

```powershell
.\BUILD_REALISTIC_LAB.ps1 -AttachIso -UbuntuIsoPath C:\NIDS_Workspace\NIDS_TestLab\isos\ubuntu-24.04.4-live-server-amd64.iso
```

If you want the script to fetch the official Ubuntu Server ISO first:

```powershell
.\BUILD_REALISTIC_LAB.ps1 -DownloadUbuntuIso
```

If you intentionally want temporary NAT update adapters on the Ubuntu VMs:

```powershell
.\BUILD_REALISTIC_LAB.ps1 -AttachIso -EnableNatUpdateAdapters
```

The realistic topology is:

- `nids-kali-attacker`: cloned from the existing `kali` VM, internal network only
- `nids-ubuntu-target`: Ubuntu target VM, internal network only by default
- `nids-ubuntu-sensor`: Ubuntu sensor VM, internal network with promiscuous capture, internal-only by default

Host exposure stays low because:

- no `Host-Only` adapter is configured
- no `Bridged` adapter is configured
- clipboard is disabled
- drag and drop is disabled
- VRDE is disabled

## Run Offline Replay

After setup, copy PCAPs into `pcaps\` and run:

```powershell
.\RUN_OFFLINE_TEST.ps1
```

If you have labels:

```powershell
.\RUN_OFFLINE_TEST.ps1 -LabelsPath C:\NIDS_Workspace\NIDS_TestLab\pcaps\labels.csv
```

The offline launcher now:

- uses `config\offline_replay_profile.yml`
- writes each run to `results\offline-<timestamp>\`
- generates `serious_test_report.md`
- generates `threshold_tuning.md`

If you want a specific PCAP file instead of the whole folder:

```powershell
.\RUN_OFFLINE_TEST.ps1 -PcapPath C:\NIDS_Workspace\NIDS_TestLab\pcaps\serious_synthetic_20260310.pcap
```

## Live VM Sensor Profile

For the Ubuntu sensor VM, use `config\live_vm_profile.yml`. This is tuned for the VirtualBox lab and is intentionally separate from the repo defaults.

Inside `nids-ubuntu-sensor`:

```bash
cd /opt/nids_workspace
sudo .venv/bin/python -m nids run \
  --interface enp0s3 \
  --rules rules/rules.yml \
  --config NIDS_TestLab/config/live_vm_profile.yml \
  --output-dir NIDS_TestLab/results/live-$(date +%Y%m%d-%H%M%S) \
  --sensor-id nids-ubuntu-sensor \
  --model models/model.pkl \
  --unsupervised
```

This profile:

- lowers the VM-lab DoS threshold to `90 pkt/s`
- lowers scan detection to `24` ports in `12s` for VirtualBox lab validation
- lowers SSH brute-force threshold to `3` attempts in `12s` for VirtualBox lab validation
- lowers RDP brute-force threshold to `3` attempts in `12s` for VirtualBox lab validation
- lowers HTTP login brute-force threshold to `2` complete login POSTs in `20s` for VirtualBox lab validation
- lowers DNS unique-name threshold to `24` to account for VM capture loss during burst tests
- throttles live ML to one cached score per `(src,dst,proto)` each `0.5s`
- lowers supervised live score threshold to `0.67`
- reduces unsupervised warmup to `60` flows for shorter lab runs

From the Windows host, you can run the reusable live validator for clean per-case evidence:

```powershell
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-dns-burst-manual --dns-count 80 --ssh-attempts 0
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-dos-dns-flood-manual --dns-count 0 --dns-flood-rate-per-sec 180 --dns-flood-duration-sec 5 --ssh-attempts 0
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-port-scan-manual --dns-count 0 --scan-start-port 5000 --scan-port-count 120 --scan-delay-sec 0.08 --ssh-attempts 0
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-ssh-bruteforce-manual --dns-count 0 --ssh-attempts 20
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-rdp-bruteforce-manual --dns-count 0 --ssh-attempts 0 --rdp-attempts 20
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-http-login-manual --dns-count 0 --ssh-attempts 0 --rdp-attempts 0 --http-login-attempts 10
```

That helper syncs the current parser/anomaly/profile files to the sensor VM, runs the requested live case, and pulls the resulting DB/report artifacts back into `NIDS_TestLab\results\`.

For overlapping multi-attack validation in the same time window, use the same helper with `--concurrent`. A practical example is:

```powershell
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --run-name live-multi-attack-manual --dns-count 160 --scan-start-port 20 --scan-port-count 40 --scan-delay-sec 0.1 --http-login-attempts 8 --http-login-port 8080 --concurrent --concurrent-start-spacing-sec 2.5 --warmup-sec 6 --settle-sec 20
```

Each live validator run now also writes:

- `attack_validation_summary.json`
- `attack_validation_summary.md`

Those summaries show which attack families were expected in the run and which rules actually fired.

Current note: the repaired concurrent path can now produce same-window evidence in the live lab. The strongest current mixed proofs are [live-overlap-profile-dns-http-ordered-20260311-154000](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-http-ordered-20260311-154000), where `DNS Burst / DGA-like Activity` and `HTTP Login Brute Force Threshold` both fired in one run, and [live-multi-attack-dns-http-scan-20260311-145300](C:/NIDS_Workspace/NIDS_TestLab/results/live-multi-attack-dns-http-scan-20260311-145300), where `DNS Burst / DGA-like Activity`, `Suspicious Port Scan`, and `Hybrid Fusion Decision` fired in one run.

For thesis-grade overlap validation, there is also a dedicated profile at [live_vm_overlap_profile.yml](C:/NIDS_Workspace/NIDS_TestLab/config/live_vm_overlap_profile.yml). It widens the brute-force/login windows and disables the live unsupervised path to reduce runtime pressure during mixed runs. Use it with:

```powershell
..\.venv\Scripts\python.exe ..\scripts\live_vm_attack_validation.py --config-relpath NIDS_TestLab/config/live_vm_overlap_profile.yml --run-name live-overlap-manual --dns-count 160 --dns-delay-sec 0.09 --rdp-attempts 18 --rdp-attempt-delay-sec 0.8 --concurrent --concurrent-start-spacing-sec 4.0 --warmup-sec 6 --settle-sec 25
```

The strongest current overlap-profile proofs are [live-overlap-profile-dns-rdp-20260311-152700](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-rdp-20260311-152700), where `DNS Burst / DGA-like Activity`, `RDP Brute Force Threshold`, `Suspicious Port Scan`, and `Hybrid Fusion Decision` fired in one run, and [live-overlap-profile-dns-http-ordered-20260311-154000](C:/NIDS_Workspace/NIDS_TestLab/results/live-overlap-profile-dns-http-ordered-20260311-154000), where `DNS Burst / DGA-like Activity` and `HTTP Login Brute Force Threshold` fired together after ordered launch tuning.

Current note: HTTP login brute-force validation now passes live in the VM lab when the sensor uses the tcpdump-backed capture path and the stable port `80` service. The resolved note is in [http_login_live_gap.md](C:/NIDS_Workspace/NIDS_TestLab/reports/http_login_live_gap.md).

For live DoS validation, prefer the sustained DNS/UDP flood path on port `53`. In this lab that path is materially more reliable than blasting a closed high UDP port, and it still exercises the same `DoS Rate Threshold` detector.

For live port-scan validation, the VM profile now uses `24` ports in `12s`, while the main repo defaults stay stricter. That lab-specific value is intentional because VirtualBox capture drops just enough SYNs that the old `25`-port threshold would miss clean dedicated sweeps.

## Later Malware Testing

For later malware work, use **static-only** artifact scanning first. Do not execute samples in the host or normal target VM.

Stage files under:

- `artifacts\incoming`

Then run:

```powershell
.\RUN_ARTIFACT_STATIC_SCAN.ps1
```

If you want a safe first-pass validation set before using real samples, stage the synthetic fixtures first:

```powershell
.\STAGE_STATIC_TRIAGE_FIXTURES.ps1
.\RUN_ARTIFACT_STATIC_SCAN.ps1 -IncomingPath C:\NIDS_Workspace\NIDS_TestLab\artifacts\incoming\<seed-folder> -Recursive
```

If you want the phishing-doc/script family specifically:

```powershell
.\STAGE_PHISHING_TRIAGE_FIXTURES.ps1
.\RUN_ARTIFACT_STATIC_SCAN.ps1 -IncomingPath C:\NIDS_Workspace\NIDS_TestLab\artifacts\incoming\<phishing-folder> -Recursive
```

If you want the PE/dropper family specifically:

```powershell
.\STAGE_PE_LOADER_TRIAGE_FIXTURES.ps1
.\RUN_ARTIFACT_STATIC_SCAN.ps1 -IncomingPath C:\NIDS_Workspace\NIDS_TestLab\artifacts\incoming\<pe-loader-folder> -Recursive
```

If you want the credential-stealer family specifically:

```powershell
.\STAGE_CREDENTIAL_STEALER_TRIAGE_FIXTURES.ps1
.\RUN_ARTIFACT_STATIC_SCAN.ps1 -IncomingPath C:\NIDS_Workspace\NIDS_TestLab\artifacts\incoming\<credential-folder> -Recursive
```

If you want the RAT/backdoor family specifically:

```powershell
.\STAGE_RAT_BACKDOOR_TRIAGE_FIXTURES.ps1
.\RUN_ARTIFACT_STATIC_SCAN.ps1 -IncomingPath C:\NIDS_Workspace\NIDS_TestLab\artifacts\incoming\<rat-folder> -Recursive
```

If you want the ransomware family specifically:

```powershell
.\STAGE_RANSOMWARE_TRIAGE_FIXTURES.ps1
.\RUN_ARTIFACT_STATIC_SCAN.ps1 -IncomingPath C:\NIDS_Workspace\NIDS_TestLab\artifacts\incoming\<ransomware-folder> -Recursive
```

That will:

- analyze files statically only
- move low-risk items to `artifacts\processed`
- move high-risk items to `artifacts\quarantine`
- write a result DB/report under `results\artifact-scan-<timestamp>\`

## Ubuntu OS Defense Validation

For host-defense validation inside the isolated lab, start with the Ubuntu target VM. The first reusable runner is:

```powershell
.\RUN_UBUNTU_OS_DEFENSE_TEST.ps1
```

That launcher calls [ubuntu_os_defense_validation.py](C:/NIDS_Workspace/scripts/ubuntu_os_defense_validation.py), supports `cron-http`, `systemd-dns`, and `defense-tamper` cases, and packages the attack-side target artifacts and the defense-side sensor artifacts into a single evidence folder under `results\`.

Examples:

```powershell
.\RUN_UBUNTU_OS_DEFENSE_TEST.ps1 -Case cron-http
.\RUN_UBUNTU_OS_DEFENSE_TEST.ps1 -Case systemd-dns
.\RUN_UBUNTU_OS_DEFENSE_TEST.ps1 -Case defense-tamper
```

The runner now uses the dedicated [os_defense_profile.yml](C:/NIDS_Workspace/NIDS_TestLab/config/os_defense_profile.yml) and writes a thesis-style `phd_case_report.docx` into each run folder.

The first completed OS-defense result is [ubuntu-os-cron-http-beacon-20260311-161200](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-cron-http-beacon-20260311-161200). That run captured `5` flows and `1` `HTTP Suspicious Keyword` alert while preserving:

- `cron_http_beacon.sh`
- `crontab_installed.txt`
- `crontab_after_cleanup.txt`
- `cron_http_beacon.log`
- `operator_note.md`

The validated `systemd + DNS beacon` result is [ubuntu-os-systemd-dns-beacon-20260311-162948](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-162948). That rerun captured `36` flows and `1` `DNS Burst / DGA-like Activity` alert after removing the extra UDP sink from the OS-defense runner.

The validated defense-tamper result is [ubuntu-os-defense-tamper-20260311-attack-defense](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-defense-tamper-20260311-attack-defense). That run captured `41` flows and `1` `Linux Defense Tamper Command` alert while preserving both the attack-side host artifacts and the defense-side sensor artifacts in the same case folder.

Use the OS scope and recording rules in [os_defense_test_plan.md](C:/NIDS_Workspace/NIDS_TestLab/reports/os_defense_test_plan.md) before adding the next Ubuntu staged-exfiltration or lower-rate beacon cases.

Earlier `systemd` fix iterations remain part of the thesis record and should not be deleted:
- [ubuntu-os-systemd-dns-beacon-20260311-164900](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-164900)
- [ubuntu-os-systemd-dns-beacon-20260311-165700](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-165700)
- [ubuntu-os-systemd-dns-beacon-20260311-170500](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-170500)

## Notes

- VirtualBox is the preferred lab path for this machine.
- The authoritative summary after each build is [realistic_lab_summary.json](C:/NIDS_Workspace/NIDS_TestLab/realistic_lab_summary.json).
- The thesis-friendly attack history is tracked in [attack_test_ledger.md](C:/NIDS_Workspace/NIDS_TestLab/reports/attack_test_ledger.md).
- The OS-level validation scope is tracked in [os_defense_test_plan.md](C:/NIDS_Workspace/NIDS_TestLab/reports/os_defense_test_plan.md).
- The cited research-gap note is tracked in [nids_research_gaps.md](C:/NIDS_Workspace/NIDS_TestLab/reports/nids_research_gaps.md).
- Keep the original `kali` VM untouched; the lab uses a clone.

