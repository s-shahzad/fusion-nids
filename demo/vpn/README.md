# Managed VPN concept demo

Local product prototype. No VPN connection, authentication, traffic capture,
customer account, billing, or firewall enforcement is implemented here.
Device approval/revocation and gateway states are browser-only simulations.
Reloading resets the session. Do not enter customer information or keys.

## Run

From the repository root, with the project dependencies installed:

```powershell
python scripts/build_vpn_demo.py
python -m http.server 8765 --bind 127.0.0.1 --directory demo/vpn
```

Open http://127.0.0.1:8765. Serve only this directory, never the repository root.
The server is for a local demonstration, not deployment.

## Walkthrough

1. Add a fictional device; its status starts Pending. Approve it.
2. Replay the detection fixture. The build step ran the real SignatureEngine
   against synthetic normalized events. The UI displays that saved result;
   it is not running detection in your browser or measuring live performance.
3. Set capture to Failed or Stale. A running VPN must not imply working NIDS.
4. Revoke a device. It remains revoked when monitoring changes state.
5. Export a demo report, which explicitly identifies simulated data.

The detection fixture uses a dedicated demo rule and a benign negative control.
It validates rule matching, not the four-engine pipeline or threat accuracy.
No packets are transmitted. The tunnel drawing shows intended architecture.
HTTPS payloads remain encrypted even after VPN tunnel termination.

## Acceptance checklist

- [x] Build fixture and prove positive plus negative detector cases.
- [x] Browser: approval, revocation, capture states, replay, reset, export.
- [x] Browser: user labels render as text, keyboard focus, narrow screen.
- [x] Independent review: no remaining actionable findings after validating malformed fixtures.

Validation on 2026-09-19: 10 focused Python tests passed (demo evidence,
signature engine, live worker lifecycle). `python scripts/verify_vpn_demo.py`
passed with Chromium at 1440px and 390px, including unavailable/malformed
evidence handling. Browser checks require the optional Playwright package and
its Chromium installation. These are local checks, not physical-device tests.

## Next engineering milestone

The first real isolated tunnel baseline has now been exercised; see
[WireGuard lab evidence](../../docs/validation/wireguard-isolated-lab.md).
The browser demo remains simulated and is not connected to that lab.

Extend the isolated baseline into a dedicated customer gateway, then validate
DNS/IPv6 routing, customer isolation, and failover behavior. Customer access controls,
device-held private keys, data retention, and operational support need their
own implementation and tests before a paid pilot. No production claims or
pricing commitments are made by this demo.
