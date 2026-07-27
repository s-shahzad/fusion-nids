# Lab Access

- Username: set via `LAB_VM_USER`
- Password: set via `LAB_VM_PASS`
- Target VM: `nids-ubuntu-target`
- Sensor VM: `nids-ubuntu-sensor`
- Attacker VM: `nids-kali-attacker`
- Target SSH: `127.0.0.1:2224`
- Sensor SSH: `127.0.0.1:2223`
- Sensor NIDS path: `/opt/nids_workspace`

Local lab note:

- copy `.env.example` to `.env` and set `LAB_VM_USER` and `LAB_VM_PASS` locally before running the prepared-environment or attack-validation scripts

Recommended internal IP plan after OS install:

- `nids-kali-attacker`: `10.77.0.10/24`
- `nids-ubuntu-target`: `10.77.0.20/24`
- `nids-ubuntu-sensor`: `10.77.0.30/24`
