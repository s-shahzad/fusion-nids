#!/usr/bin/env sh
set -eu

CMD="python -m nids run --rules ${NIDS_RULES_PATH:-rules/rules.yml} --output-dir ${NIDS_OUTPUT_DIR:-output} --config ${NIDS_CONFIG_PATH:-config/nids.yml} --sensor-id ${NIDS_SENSOR_ID:-sensor-local}"

if [ -n "${NIDS_PCAP_DIR:-}" ]; then
  CMD="$CMD --pcap-dir ${NIDS_PCAP_DIR}"
fi

if [ -n "${NIDS_INTERFACE:-}" ]; then
  CMD="$CMD --interface ${NIDS_INTERFACE}"
fi

if [ -n "${NIDS_LABELS_PATH:-}" ]; then
  CMD="$CMD --labels ${NIDS_LABELS_PATH}"
fi

if [ "${NIDS_UNSUPERVISED:-0}" = "1" ]; then
  CMD="$CMD --unsupervised"
fi

if [ -n "${NIDS_MODEL_PATH:-}" ]; then
  CMD="$CMD --model ${NIDS_MODEL_PATH}"
fi

if [ -n "${NIDS_SLACK_WEBHOOK:-}" ]; then
  CMD="$CMD --notify-webhook ${NIDS_SLACK_WEBHOOK}"
fi

if [ -n "${NIDS_NOTIFY_MIN_SEVERITY:-}" ]; then
  CMD="$CMD --notify-min-severity ${NIDS_NOTIFY_MIN_SEVERITY}"
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

echo "runtime command: $CMD"
exec sh -c "$CMD"

