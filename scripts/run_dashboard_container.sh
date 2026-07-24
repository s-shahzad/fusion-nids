#!/usr/bin/env sh
set -eu

# Bind to loopback by default; only expose on all interfaces once an auth
# token has been configured, so an unauthenticated dashboard can never be
# reachable from outside the container.
if [ -n "${DASHBOARD_TOKEN:-}" ] || [ -n "${DASHBOARD_ACTION_TOKEN:-}" ]; then
  DASHBOARD_HOST="0.0.0.0"
else
  DASHBOARD_HOST="127.0.0.1"
fi

set -- --from-db "${NIDS_DB_PATH:-output/nids.db}" --host "$DASHBOARD_HOST" --port 8000

if [ -n "${DASHBOARD_TOKEN:-}" ]; then
  set -- "$@" --token "${DASHBOARD_TOKEN}"
fi

if [ -n "${DASHBOARD_ACTION_TOKEN:-}" ]; then
  set -- "$@" --action-token "${DASHBOARD_ACTION_TOKEN}"
fi

if [ -n "${NIDS_SLACK_WEBHOOK:-}" ]; then
  set -- "$@" --notify-webhook "${NIDS_SLACK_WEBHOOK}"
fi

if [ -n "${NIDS_NOTIFY_TIMEOUT_SEC:-}" ]; then
  set -- "$@" --notify-timeout-sec "${NIDS_NOTIFY_TIMEOUT_SEC}"
fi

if [ -n "${NIDS_NOTIFY_MAX_RETRIES:-}" ]; then
  set -- "$@" --notify-max-retries "${NIDS_NOTIFY_MAX_RETRIES}"
fi

if [ -n "${NIDS_NOTIFY_BACKOFF_SEC:-}" ]; then
  set -- "$@" --notify-backoff-sec "${NIDS_NOTIFY_BACKOFF_SEC}"
fi

if [ -n "${NIDS_NOTIFY_MAX_BACKOFF_SEC:-}" ]; then
  set -- "$@" --notify-max-backoff-sec "${NIDS_NOTIFY_MAX_BACKOFF_SEC}"
fi

if [ -n "${NIDS_NOTIFY_MIN_INTERVAL_SEC:-}" ]; then
  set -- "$@" --notify-min-interval-sec "${NIDS_NOTIFY_MIN_INTERVAL_SEC}"
fi

if [ -n "${NIDS_NOTIFY_DEAD_LETTER:-}" ]; then
  set -- "$@" --notify-dead-letter "${NIDS_NOTIFY_DEAD_LETTER}"
fi

if [ -n "${NIDS_NOTIFY_DEAD_LETTER_MAX_BYTES:-}" ]; then
  set -- "$@" --notify-dead-letter-max-bytes "${NIDS_NOTIFY_DEAD_LETTER_MAX_BYTES}"
fi

if [ -n "${NIDS_NOTIFY_DEAD_LETTER_BACKUP_COUNT:-}" ]; then
  set -- "$@" --notify-dead-letter-backup-count "${NIDS_NOTIFY_DEAD_LETTER_BACKUP_COUNT}"
fi

echo "dashboard command: python -m nids dashboard $*"
exec python -m nids dashboard "$@"
