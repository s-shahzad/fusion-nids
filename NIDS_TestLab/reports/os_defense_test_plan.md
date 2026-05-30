# OS Defense Test Plan

Generated: 2026-03-11 22:55 UTC

This plan extends `NIDS_TestLab` from network-only validation into host and operating-system defense validation. The goal is to test not only whether the NIDS detects hostile traffic, but also whether the defended OS and its surrounding controls hold up under realistic attack pressure inside the isolated lab.

## Scope

The practical operating-system scope for the current lab is:

- `Ubuntu / Linux`: fully testable now in the isolated VMs
- `Kali / Linux attacker`: used as the attack source and offensive tool host
- `Windows`: safe-only defense validation on the host or a future Windows lab VM
- `macOS`: future target only if a dedicated macOS VM is added later

This is not a license to test outside the isolated lab. All active attack simulation should stay inside `NIDS_TestLab`.

## Evidence Rule

Every OS-level test should produce:

1. a result folder under `NIDS_TestLab\results\`
2. the runtime `nids.db`
3. `alerts.jsonl`
4. `flows.jsonl`
5. `serious_test_report.md`
6. `attack_validation_summary.md` if the live validator is used
7. a short operator note describing the OS control that was tested and the observed result

## Current Lab Reality

- `Ubuntu target`: active test target
- `Ubuntu sensor`: active defended NIDS sensor
- `Kali attacker`: active offensive source
- `Windows host`: do not execute malware; use only safe hardening and telemetry validation unless a dedicated Windows VM is added
- `macOS`: not currently present in the lab

Completed OS-defense cases so far:

- `Ubuntu cron persistence + suspicious HTTP beacon`: pass in [ubuntu-os-cron-http-beacon-20260311-161200](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-cron-http-beacon-20260311-161200)
- `Ubuntu systemd persistence + DNS beacon`: pass in [ubuntu-os-systemd-dns-beacon-20260311-162948](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-systemd-dns-beacon-20260311-162948)
- `Ubuntu defense-tamper simulation + service-stop intent`: pass in [ubuntu-os-defense-tamper-20260311-attack-defense](C:/NIDS_Workspace/NIDS_TestLab/results/ubuntu-os-defense-tamper-20260311-attack-defense)

## OS Test Matrix

| OS Family | Test Theme | Concrete Cases | Current Lab Status | Expected Control / Detection |
|---|---|---|---|---|
| Ubuntu / Linux | Authentication abuse | SSH brute force, sudo misuse, reused credentials | ready now | SSH brute-force detection, auth log visibility, host lockout policy |
| Ubuntu / Linux | Persistence | cron job drop, systemd service drop, rc-local style persistence | ready now | file/process visibility, service audit, anomaly or signature coverage |
| Ubuntu / Linux | Scripted execution | bash one-liners, `curl`/`wget` downloaders, pipe-to-shell patterns | ready now | suspicious payload detection, HTTP/DNS beacon visibility |
| Ubuntu / Linux | Defense tamper | service stop attempts, firewall disable attempts, log deletion simulation | ready now | host hardening validation, anomaly detection, operator evidence |
| Ubuntu / Linux | Data staging and exfil | tar/zip staging, outbound HTTP/DNS transfer simulation | ready now | exfiltration detection, archive staging visibility |
| Ubuntu / Linux | Resource abuse | CPU or packet pressure against defended services | ready now | DoS detection, sensor stability, alert latency |
| Windows | Authentication abuse | RDP brute force, WinRM/SMB auth attempts | safe-only now, full later with Windows VM | RDP detection, logon-failure telemetry, service exposure review |
| Windows | Living-off-the-land | PowerShell, `cmd.exe`, `rundll32`, `certutil`, `mshta`, scheduled tasks | safe-only now, full later with Windows VM | HTTP suspicious keyword, process-aware host evidence, persistence audit |
| Windows | Persistence | scheduled tasks, startup entries, service creation | safe-only now, full later with Windows VM | persistence visibility and detection notes |
| Windows | Defense tamper | firewall disable attempts, logging disable simulation, Defender tamper simulation | safe-only now, full later with Windows VM | OS defense posture and recovery checks |
| Windows | Data staging and exfil | archive staging, webhook posts, browser data simulation | safe-only now, full later with Windows VM | exfiltration visibility and artifact triage coverage |
| macOS | Persistence | launch agents / launch daemons | future | host persistence coverage once macOS VM exists |
| macOS | Scripted execution | `osascript`, shell downloaders, curl-based staging | future | command and web-path visibility once macOS VM exists |
| macOS | Data access / exfil | archive staging, outbound HTTP/DNS transfer | future | exfil detection and host artifact evidence once macOS VM exists |

## Strong-Environment Rules

To count as a strong environment:

- keep all active attack traffic inside the isolated VM network
- snapshot the target VM before and after each destructive phase
- keep the sensor VM separate from the target VM
- preserve `NIDS_TestLab\results\` evidence for every run
- log the exact profile, command, and target OS in the ledger
- never use the everyday Windows host as the malware execution target

## Immediate OS Phase

Start with Linux because the lab is already built for it:

1. `Ubuntu target`: persistence simulation
   Cases: cron, systemd service, downloader shell script

2. `Ubuntu target`: defense tamper simulation
   Cases: firewall disable attempt, service stop attempt, log deletion simulation

3. `Ubuntu target`: staged data exfil
   Cases: zip/tar staging plus outbound HTTP/DNS transfer simulation

4. `Windows`: safe-only posture validation
   Cases: startup persistence review, scheduled-task inventory, firewall rule review, service exposure review

5. `Windows VM later`: real Windows attack-and-defense validation once a dedicated VM exists

## Recording Format

For each OS test case, record:

- `os_family`
- `target_vm`
- `attack_theme`
- `attack_case`
- `defense_control`
- `nids_expected_rules`
- `observed_alerts`
- `status`
- `evidence_folder`
- `fix_if_missed`

## Next Recommended OS Cases

1. `Ubuntu`: staged archive exfil over HTTP
2. `Ubuntu`: lower-rate periodic DNS beacon variant
3. `Windows safe-only`: startup / service / scheduled-task posture inventory
4. `Windows safe-only`: firewall and exposed-service posture inventory
5. `Windows safe-only`: service-hardening and log-retention posture inventory
