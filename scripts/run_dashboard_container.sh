#!/usr/bin/env sh
set -eu

CMD="python -m nids dashboard --from-db ${NIDS_DB_PATH:-output/nids.db} --host 0.0.0.0 --port 8000"

if [ -n "${DASHBOARD_TOKEN:-}" ]; then
  CMD="$CMD --token ${DASHBOARD_TOKEN}"
fi

if [ -n "${DASHBOARD_ACTION_TOKEN:-}" ]; then
  CMD="$CMD --action-token ${DASHBOARD_ACTION_TOKEN}"
fi


if [ -n "${NIDS_SLACK_WEBHOOK:-}" ]; then
  CMD="$CMD --notify-webhook ${NIDS_SLACK_WEBHOOK}"
fi

if [ -n "${NIDS_NOTIFY_TIMEOUT_SEC:-}" ]; then
  CMD="$CMD --notify-timeout-sec ${NIDS_NOTIFY_TIMEOUT_SEC}"
fi

if [ -n "${NIDS_NOTIFY_MAX_RETRIES:-}" ]; then
  CMD="$CMD --notify-max-retries ${NIDS_NOTIFY_MAX_RETRIES}"
fi

if [ -n "${NIDS_NOTIFY_BACKOFF_SEC:-}" ]; then
  CMD="$CMD --notify-backoff-sec ${NIDS_NOTIFY_BACKOFF_SEC}"
fi

if [ -n "${NIDS_NOTIFY_MAX_BACKOFF_SEC:-}" ]; then
  CMD="$CMD --notify-max-backoff-sec ${NIDS_NOTIFY_MAX_BACKOFF_SEC}"
fi

if [ -n "${NIDS_NOTIFY_MIN_INTERVAL_SEC:-}" ]; then
  CMD="$CMD --notify-min-interval-sec ${NIDS_NOTIFY_MIN_INTERVAL_SEC}"
fi

if [ -n "${NIDS_NOTIFY_DEAD_LETTER:-}" ]; then
  CMD="$CMD --notify-dead-letter ${NIDS_NOTIFY_DEAD_LETTER}"
fi

if [ -n "${NIDS_NOTIFY_DEAD_LETTER_MAX_BYTES:-}" ]; then
  CMD="$CMD --notify-dead-letter-max-bytes ${NIDS_NOTIFY_DEAD_LETTER_MAX_BYTES}"
fi

if [ -n "${NIDS_NOTIFY_DEAD_LETTER_BACKUP_COUNT:-}" ]; then
  CMD="$CMD --notify-dead-letter-backup-count ${NIDS_NOTIFY_DEAD_LETTER_BACKUP_COUNT}"
fi

echo "dashboard command: $CMD"
exec sh -c "$CMD"

