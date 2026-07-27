# Security Policy

## Reporting a Vulnerability

**Preferred: [open a private security advisory](https://github.com/s-shahzad/fusion-nids/security/advisories/new).**
Private vulnerability reporting is enabled on this repository, so a report can
reach the maintainer through GitHub without ever being public.

Alternatively, email **shaikazhadshahzad@gmail.com**.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

Expect a response within 7 days. **Please do not open a public GitHub issue for
security vulnerabilities.**

## Scope

This policy covers:
- The core detection engine (`src/nids/`)
- The REST API (`src/nids/api/`)
- Lab and validation scripts (`scripts/`, `lab/`)

## Current security posture

Stated accurately so reports can be scoped against what actually exists.

**Authentication fails closed for non-loopback callers.** Loopback
(`127.0.0.1`, `::1`, `localhost`) is always permitted without a token — a
deliberate development-ergonomics choice, and a real trust assumption. Any other
caller must present a token, and enabling `NIDS_ALLOW_REMOTE_API` or
`NIDS_ALLOW_MUTATING_ROUTES` **without** configuring the matching token returns
503 rather than serving unauthenticated requests.

**Protected endpoints are authenticated.** `/run-local`, the per-run routes,
exports, and all `/llm/*` routes require `UNIVERSAL_NIDS_API_KEY` through
`get_universal_nids_api_key`, which returns 503 when no key is configured.
Several also carry rate limits.

**Unauthenticated by design:** `/health`, `/version`, `/baseline`, `/routes`,
`/status`, `/dashboard`, `/runs`. If you believe one of these discloses
something it should not, that is worth reporting.

**Model artefacts are integrity-checked.** All three `joblib.load` sites verify
a configured SHA-256 before unpickling, because unpickling executes arbitrary
code. Digests come from `NIDS_SUPERVISED_MODEL_SHA256`,
`NIDS_UNSUPERVISED_SNAPSHOT_SHA256`, or a `<file>.sha256` sidecar. **With no
digest configured the load proceeds with a logged warning** — a known weaker
default kept for compatibility. Configuring digests is recommended.

**Report output is confined.** Incident reports resolve under a fixed `reports/`
root; paths escaping it are rejected.

**Lab SSH verifies host keys.** `RejectPolicy` with a `known_hosts` file
(`NIDS_LAB_KNOWN_HOSTS`, else the user default). There is no auto-add fallback.

**Credentials are never hardcoded.** Lab scripts read VM credentials from
`LAB_VM_USER` / `LAB_VM_PASS`.

## Known limitations, already understood

Documented rather than reported:

- The dashboard and API are intended for local or controlled-network use. This
  is a controlled pre-deployment candidate, not a hardened production service.
- Unverified model loads are permitted when no digest is configured.
- Two authentication systems coexist with different configuration sources and
  header names. Both fail closed; unification is tracked as open work.
- No claim is made about resistance to adversarial evasion, traffic mimicry, or
  adversarial ML against the detection ensemble. This has not been tested.

See the [Threat Model](https://github.com/s-shahzad/fusion-nids/wiki/Threat-Model)
for what is in and out of scope, and
[Known Limitations](https://github.com/s-shahzad/fusion-nids/wiki/Known-Limitations)
for what the published results do and do not show.
