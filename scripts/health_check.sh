#!/usr/bin/env sh
set -eu

HOST="${1:-127.0.0.1}"
PORT="${2:-8000}"
TOKEN="${3:-}"

QUERY=""
if [ -n "$TOKEN" ]; then
  QUERY="?token=$TOKEN"
fi

BASE="http://${HOST}:${PORT}"

echo "Checking ${BASE}/healthz${QUERY}"
curl -fsS "${BASE}/healthz${QUERY}" >/tmp/nids_healthz.json
cat /tmp/nids_healthz.json

echo ""
echo "Checking ${BASE}/readyz${QUERY}"
curl -fsS "${BASE}/readyz${QUERY}" >/tmp/nids_readyz.json
cat /tmp/nids_readyz.json

echo ""
