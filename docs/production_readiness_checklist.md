# NIDS Production Readiness Checklist

Last updated: 2026-03-07

## Goal

Close final rollout risk by validating security controls, load behavior, and live-operations readiness before production handoff.

## 1) Security Validation (Required)

Run dashboard security smoke checks while dashboard is started with `--token` and `--action-token`.

```bash
python scripts/dashboard_security_smoke.py \
  --host 127.0.0.1 \
  --port 8000 \
  --view-token <VIEW_TOKEN> \
  --action-token <ACTION_TOKEN>
```

Pass criteria:

- `/api/realtime` without token returns `401`.
- `/api/realtime` with view token returns `200`.
- write action with wrong action token returns `401`.
- write action with forbidden role returns `403`.
- write action with valid action token + role returns `200`.

## 2) Load Validation (Required)

Run latency/error probe against dashboard realtime endpoint.

```bash
python scripts/dashboard_load_probe.py \
  --host 127.0.0.1 \
  --port 8000 \
  --path /api/realtime \
  --token <VIEW_TOKEN> \
  --requests 200 \
  --warmup 20 \
  --p95-max-ms 750 \
  --max-error-rate 0.01
```

Pass criteria:

- `p95 <= 750ms`
- error rate `<= 1%`
- no sustained 5xx responses

## 3) Live Integration Validation (Required)

1. Start runtime and dashboard stack.
2. Confirm `/healthz` and `/readyz` are healthy.
3. Verify new alert creation and incident queue updates.
4. Execute one assign/status workflow from dashboard.
5. Generate SLA summary:

```bash
python -m nids sla-report --from-db output/nids.db --out-json reports/weekly_sla_summary.json --out-md reports/weekly_sla_summary.md --lookback-days 7
```

Pass criteria:

- alerts, incidents, and audit actions are persisted.
- SLA report files are generated and non-empty.
- no notifier delivery crash in runtime logs.

## 4) Notification Reliability Validation (Required)

Validate dead-letter controls and rotation:

- `NIDS_NOTIFY_DEAD_LETTER`
- `NIDS_NOTIFY_DEAD_LETTER_MAX_BYTES`
- `NIDS_NOTIFY_DEAD_LETTER_BACKUP_COUNT`

Pass criteria:

- failed notification events are recorded.
- rotation files are created once size threshold is exceeded.
- backup count cap is enforced.

## 5) External TLS Endpoint Validation (Required for Internet-Exposed Deployments)

Audit production/staging HTTPS endpoint certificate and protocol settings.

```bash
python scripts/tls_endpoint_audit.py \
  --url https://<NIDS_DASHBOARD_HOST> \
  --min-days-valid 14
```

Pass criteria:

- successful certificate verification chain.
- TLS version is `TLSv1.2` or newer.
- certificate validity remaining is at least 14 days.

## 6) CI Security Gates (Required)

Workflow `.github/workflows/security.yml` must pass on the release commit.

Required jobs:

- dependency vulnerability audit (`pip-audit`)
- static security analysis (`bandit`)
- secret scanning (`gitleaks`)
- dashboard runtime security smoke (`dashboard_security_smoke.py` + `dashboard_load_probe.py`)

Optional manual gate for external deployments:

- `workflow_dispatch` input `https_url` to run TLS endpoint audit in CI.

## 7) Release Gate

Production release is approved only when all checks above pass and are attached to release evidence.
