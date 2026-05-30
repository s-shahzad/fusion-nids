# Rollback Plan

## Rollback Objective

Return to the previously validated runtime without changing detector logic or losing runtime outputs.

## Rollback Strategy

1. Stop the production API wrapper only.
2. Keep existing runtime outputs:
   - `output/nids.db`
   - `output/alerts.jsonl`
   - `output/flows.jsonl`
   - `output/metrics.jsonl`
3. Revert to the original runtime and dashboard launch commands from `README.md`.
4. If deployment config caused the issue:
   - restore prior environment variables
   - remove production-only API launch
   - keep SQLite as the active store

## Fast Rollback Checks

- `python -m nids dashboard --from-db output/nids.db`
- `python -m nids report --from-db output/nids.db --out reports/summary.md`
- `python -m nids run-local --pcap-dir pcaps --rules rules/rules.yml`

## Rollback Trigger Conditions

- Production API fails readiness
- Storage abstraction fails to read from SQLite
- Route restrictions misbehave
- Deployment config blocks existing operational workflows
