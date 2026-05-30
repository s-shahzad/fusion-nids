#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${1:-eth0}"
PCAP_DIR="${2:-pcaps}"
RULES_PATH="${3:-rules/rules.yml}"

python -m nids run \
  --interface "${INTERFACE}" \
  --pcap-dir "${PCAP_DIR}" \
  --rules "${RULES_PATH}"
