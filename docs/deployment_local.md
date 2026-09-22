# Local Deployment

## Purpose

Run the platform in an offline-first local environment with SQLite as the system of record.

## Recommended Environment

- Windows workstation, local VM, or Linux host
- SQLite at `output/nids.db`
- API bound to loopback only
- Ollama and any future AI add-ons bound to loopback only

## Steps

1. Copy environment example values from `config/environments/local.yml.example`.
2. Set environment variables:
   - `NIDS_ENV=local`
   - `NIDS_OUTPUT_DIR=output`
   - `NIDS_SQLITE_PATH=output/nids.db`
   - `NIDS_API_TOKEN=<read-secret>` (required even on loopback)
   - `NIDS_ALLOW_REMOTE_API=false`
   - `NIDS_ALLOW_MUTATING_ROUTES=false`
3. Start the validated runtime with existing CLI commands.
4. Start the production API:

```powershell
$env:PYTHONPATH = 'src'
python .\scripts\run_production_api.py
```

5. Validate:
   - `GET /health/live`
   - `GET /health/ready` with `X-API-Token: <read-secret>`
   - `GET /v1/alerts/recent` with `X-API-Token: <read-secret>`

## Safety Defaults

- Loopback bind only
- Read-focused routes enabled by default
- Mutating routes disabled unless explicitly allowed
- SQLite remains primary until PostgreSQL parity exists

For privileged operations configure a separate `NIDS_ACTION_TOKEN`, enable
`NIDS_ALLOW_MUTATING_ROUTES`, and send both read and action credentials. See
[authentication migration](api_authentication.md). Restart after configuration changes.
