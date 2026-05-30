# Privacy Modes

The privacy layer is additive and does not change detector, fusion, ML, or replay decisions.

## Modes

- `off`
  - no privacy filtering
- `review`
  - intended for analyst or API review
  - can mask IPs and sanitize file paths
- `strict`
  - stronger masking for payload-like text and user identifiers

## Current Scope

Privacy filtering currently applies to:

- run inspection alerts
- portfolio export alert samples
- generated report text when privacy config is supplied

It does not redesign SQLite storage or alter the replay ground truth workflow.

## Optional Export Encryption

When enabled, selected export JSON artifacts can also be written as encrypted `.enc` files.

- key source is externalized through `NIDS_PRIVACY_KEY`
- no secret is stored in the repository
- encryption is intended for local artifact handling, not full key-management orchestration
