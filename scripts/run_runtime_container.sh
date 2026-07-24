#!/usr/bin/env sh
set -eu

set -- run --rules "${NIDS_RULES_PATH:-rules/rules.yml}" --output-dir "${NIDS_OUTPUT_DIR:-output}" --config "${NIDS_CONFIG_PATH:-config/nids.yml}" --sensor-id "${NIDS_SENSOR_ID:-sensor-local}"

if [ -n "${NIDS_PCAP_DIR:-}" ]; then
  set -- "$@" --pcap-dir "${NIDS_PCAP_DIR}"
fi

if [ -n "${NIDS_INTERFACE:-}" ]; then
  set -- "$@" --interface "${NIDS_INTERFACE}"
fi

if [ -n "${NIDS_LABELS_PATH:-}" ]; then
  set -- "$@" --labels "${NIDS_LABELS_PATH}"
fi

if [ "${NIDS_UNSUPERVISED:-0}" = "1" ]; then
  set -- "$@" --unsupervised
fi

if [ -n "${NIDS_MODEL_PATH:-}" ]; then
  set -- "$@" --model "${NIDS_MODEL_PATH}"
fi

if [ -n "${NIDS_SLACK_WEBHOOK:-}" ]; then
  set -- "$@" --notify-webhook "${NIDS_SLACK_WEBHOOK}"
fi

if [ -n "${NIDS_NOTIFY_MIN_SEVERITY:-}" ]; then
  set -- "$@" --notify-min-severity "${NIDS_NOTIFY_MIN_SEVERITY}"
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

echo "runtime command: python -m nids $*"
exec python -m nids "$@"
