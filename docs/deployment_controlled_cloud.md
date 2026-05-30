# Controlled Cloud Deployment

## Deployment Position

Cloud deployment is allowed only as a controlled defensive environment. The validated detection pipeline remains unchanged and should be deployed behind strict ingress and secret controls.

## Guardrails

- Private network or allowlisted ingress only
- Token-protected API
- Read-only routes exposed by default
- Mutating routes disabled unless change-controlled
- Separate cloud config file from local config
- Volume-backed persistence for `output/`, `reports/`, `state/`, and `models/`

## Recommended Pattern

1. Use `deployment/docker-compose.production.yml`.
2. Provide environment through secret-managed variables, not hardcoded files.
3. Bind API to an internal address behind a reverse proxy or internal load balancer.
4. Keep the dashboard and API access restricted to approved admin networks.
5. Preserve SQLite for initial cloud pilot or place PostgreSQL behind the storage abstraction when ready.

## Minimum Controls

- API token required
- Trusted hosts configured
- Central log shipping allowed only from defensive infrastructure
- Backup and rollback paths tested before promotion
