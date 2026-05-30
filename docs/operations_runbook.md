# NIDS Operations Runbook

## Incident Management Flow

1. Detect: runtime writes alerts to `output/nids.db`.
2. Triage: open dashboard Incident Queue and assign owner.
3. Contain: move status to `investigating` or `contained` and capture reason.
4. Resolve: set status to `resolved` and include closure note.
5. Review: validate SLA metrics and overdue trend.

## Dashboard Operations

Start dashboard:

```bash
python -m nids dashboard --from-db output/nids.db --host 127.0.0.1 --port 8000
```

Optional write-token separation:

```bash
python -m nids dashboard --from-db output/nids.db --token view-token --action-token action-token
```

Health checks:

- `GET /healthz` for liveness + notifier state.
- `GET /readyz` for dependency readiness + table checks.

## Weekly SLA Reporting

Generate weekly SLA KPI outputs:

```bash
python -m nids sla-report --from-db output/nids.db --out-json reports/weekly_sla_summary.json --out-md reports/weekly_sla_summary.md --lookback-days 7
```

Review these fields first:

- `totals.response_breaches`
- `totals.resolution_breaches`
- `rates.response_breach_rate`
- `rates.resolution_breach_rate`
- `overdue_trend`

## Notification Reliability Controls

Runtime and dashboard both support notifier hardening:

- retry/backoff: `--notify-max-retries`, `--notify-backoff-sec`, `--notify-max-backoff-sec`
- rate limit: `--notify-min-interval-sec`
- dead-letter path: `--notify-dead-letter`
- dead-letter rotation: `--notify-dead-letter-max-bytes`, `--notify-dead-letter-backup-count`

Environment equivalents:

- `NIDS_NOTIFY_DEAD_LETTER`
- `NIDS_NOTIFY_DEAD_LETTER_MAX_BYTES`
- `NIDS_NOTIFY_DEAD_LETTER_BACKUP_COUNT`

## Dead-Letter Handling

1. Check latest dead-letter event:

```bash
# PowerShell
Get-Content output/notification_failures.jsonl -Tail 1
```

2. Confirm rotation files exist (if enabled):

```bash
# PowerShell
Get-ChildItem output/notification_failures.jsonl*
```

3. If failures persist, verify webhook reachability and token/URL validity.

## Security + Load Validation Scripts

Security smoke check:

CI enforcement is defined in `.github/workflows/security.yml` (pip-audit, bandit, gitleaks, and runtime dashboard smoke checks).

```bash
python scripts/dashboard_security_smoke.py --host 127.0.0.1 --port 8000 --view-token <VIEW_TOKEN> --action-token <ACTION_TOKEN>
```

Load probe:

```bash
python scripts/dashboard_load_probe.py --host 127.0.0.1 --port 8000 --path /api/realtime --token <VIEW_TOKEN> --requests 200 --warmup 20 --p95-max-ms 750 --max-error-rate 0.01
```

## TLS Endpoint Audit (External Deployments)

Use for staging/production HTTPS endpoints:

```bash
python scripts/tls_endpoint_audit.py --url https://<NIDS_DASHBOARD_HOST> --min-days-valid 14
```

Manual CI option:

- Run `.github/workflows/security.yml` with `workflow_dispatch` and provide `https_url`.

Use `docs/production_readiness_checklist.md` as the release gate.
