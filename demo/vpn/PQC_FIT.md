# Role in a PQC business

This prototype is a demonstration and a starting point for a measurement lab.
It has no VPN implementation or post-quantum cryptography implementation.

## Customer outcome

An initial offering could assess a customer's remote-access deployment, test a
selected post-quantum migration option, and deliver evidence of compatibility,
performance, and operational behavior. A managed service is a later offering,
conditional on a working tunnel, isolation, support, and validated operations.
This is a business hypothesis, not evidence of demand or existing customers.

## Separate responsibilities

- VPN: authenticate peers and protect transport.
- PQC migration: select and validate key establishment and its lifecycle.
- NIDS: observe permitted inner-interface traffic and report suspicious behavior.
- Service operations: onboarding, revocation, monitoring, retention, recovery.

NIDS alerts do not establish quantum resistance. WireGuard's documented baseline
key exchange uses Curve25519; its optional preshared-key input is a separate
mechanism. Adding an IDS does not change either. A PQC integration needs review
of the actual protocol, implementation, peer authentication, key distribution,
rotation, downgrade/failure behavior, and client compatibility. Do not invent
cryptography or label the current prototype quantum-safe.

Source, checked 2026-09-19:
https://www.wireguard.com/protocol/

## Next lab evidence

Record exact versions and configuration for each candidate. Compare baseline
and candidate under the same hosts, routes, offered load, and capture settings:

1. Connection establishment and reconnection time, including distributions.
2. Throughput, latency, packet loss, CPU and memory, with NIDS on and off.
3. Peer revocation, key rotation, gateway restart, and failed key establishment.
4. DNS/IPv6 routing and customer isolation, with explicit expected outcomes.
5. Which encrypted/inner traffic is visible and which detections were exercised.

Keep synthetic demonstration output separate from real measurement artifacts.
The signature fixture proves a positive and negative rule-matching case only;
it does not establish attack detection accuracy, real-time performance, or PQC
readiness. An assessment report must state coverage and unresolved limitations.
