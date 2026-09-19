# WireGuard and NIDS: isolated baseline lab

## Scope

This is a real conventional WireGuard tunnel between two temporary Linux network
namespaces connected by a veth pair. It does not change host routes, install a
host VPN, expose a public listener, or contact an external VPN endpoint. Both
namespaces lack default routes. The inner addresses are 10.203.0.1/30 and
10.203.0.2/30; the isolated underlay uses documentation addresses 192.0.2.1/30
and 192.0.2.2/30. No real customer or laptop traffic is captured.

Ephemeral private keys are generated into a private Linux temporary directory,
with mode 0600 files. Keys are not included in reports or command output.
Namespaces and capture processes owned by this run are removed on normal exit
and ordinary exceptions. SIGTERM, SIGKILL, or machine failure can prevent cleanup: inspect
`ip netns list` for the exact `fn-c-<run-id>` / `fn-g-<run-id>` resources, and remove
only resources confirmed to belong to that interrupted run.

## Run on Linux

Requires root in a disposable Linux environment with WireGuard kernel support,
iproute2, wireguard-tools, tcpdump, ping, and Python 3. Root is needed for network
namespaces and capture; do not expose this script as a remote API.

```bash
sudo python3 scripts/wireguard_lab.py --output "$PWD/runtime_data/wireguard-run-01"
python scripts/verify_wireguard_capture.py runtime_data/wireguard-run-01
```

Use a new output directory each time. The verifier uses the normal project
Python environment (Scapy and project dependencies); it does not need root.
It prints its result without writing inside the root-owned capture directory.
Use `--report <new-user-writable-file.json>` to retain a report separately.
On Windows, run the first command in WSL against the checkout's `/mnt/c/...`
path, then run the verifier with the Windows project Python environment.

Only `runtime_data/` holds captures and raw evidence; it is ignored by Git.
Do not publish packet files or private operational data automatically.

## Verified 2026-09-19

Executed on WSL2 Ubuntu, Linux 6.18.33.2-microsoft-standard-WSL2,
wireguard-tools v1.0.20250521. The local environment was prepared with Ubuntu
packages wireguard-tools, tcpdump, python3-scapy, and python3-yaml and their
dependencies. Verification used the existing Windows Python 3.11 project venv.

| Check | Observed result |
|---|---|
| Initial tunnel | Ping succeeds; authenticated handshake timestamp present |
| Peer removed at gateway | Tunnel ping fails while underlay ping still succeeds |
| Peer reauthorized; client session reset | Tunnel ping succeeds again |
| Inner interface capture | 2 parsed TCP events; 1 dedicated demo signature alert |
| Outer interface capture | 2 UDP tunnel packets; 0 inner-port signature alerts |
| Cleanup | No lab namespaces remain after execution |

Repeated successfully in two fresh output directories. Five focused tests passed
using `python -m pytest -q tests/test_wireguard_lab.py tests/test_vpn_demo_evidence.py`.
They cover owned-resource cleanup on early failure, rejection of a wrong outer
endpoint, read-only verification of capture artifacts, and demo detector controls.
Python compilation passed. Independent review identified a root-owned output
directory issue; verification now prints by default and accepts a separate report
destination, rather than requiring write access to the capture directory.

The connection probe targets a closed lab TCP port and produces SYN/RST traffic.
It does not exploit a service. Detection uses the real Fusion parser and
SignatureEngine, with `demo/vpn/demo-rule.yml`. This is a capture-visibility and
signature integration check, not a test of all detection engines or a benchmark.

The outer capture filter selects WireGuard UDP traffic; this checks the selected
packet structure and negative signature control, not a comprehensive leak audit
or independent proof of cryptographic strength. No claim of DNS/IPv6 leak
protection, multi-customer isolation, uptime, throughput, or PQC resistance follows.

## Product progression

- [x] Real isolated tunnel, handshake, revoke, and reauthorize behavior.
- [x] Actual inner/outer capture passed through parser and signature checks.
- [ ] Continuous runtime health and capture failure reporting in the real dashboard.
- [ ] Separate customer gateway isolation and authorization tests.
- [ ] DNS/IPv6 routing, gateway restart, load, and recovery measurements.
- [ ] Select and review a PQC key-establishment candidate, then compare baselines.
- [ ] Client support, retention, deployment, and support practices for a paid pilot.

Reference for namespace integration:
https://www.wireguard.com/netns/
