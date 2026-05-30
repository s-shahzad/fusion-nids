#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_prepare_bundle.sh [options]

Options:
  --repo-dir <path>        Local repository root. Default: current repo root.
  --out-dir <path>         Directory for generated bundle files.
  --bundle-name <name>     Override generated tar.gz file name.
  --verify-only            Verify required deployment inputs and exit.
  --help                   Show this help text.
EOF
}

REPO_DIR="$(oracle_repo_root)"
OUT_DIR="$REPO_DIR/release/deployment-bundles"
BUNDLE_NAME=""
VERIFY_ONLY="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir)
      REPO_DIR="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --bundle-name)
      BUNDLE_NAME="$2"
      shift 2
      ;;
    --verify-only)
      VERIFY_ONLY="1"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      oracle_die "Unknown argument: $1"
      ;;
  esac
done

oracle_require_cmd tar
oracle_require_dir "$REPO_DIR"
oracle_assert_deployment_inputs "$REPO_DIR"

if [[ "$VERIFY_ONLY" == "1" ]]; then
  oracle_log "verified_repo_dir=$REPO_DIR"
  oracle_log "verified_inputs=ok"
  exit 0
fi

mkdir -p "$OUT_DIR"

STAMP="$(oracle_timestamp_utc)"
if [[ -z "$BUNDLE_NAME" ]]; then
  BUNDLE_NAME="universal-nids-oracle-${STAMP}.tar.gz"
fi
BUNDLE_PATH="$OUT_DIR/$BUNDLE_NAME"
MANIFEST_PATH="${BUNDLE_PATH%.tar.gz}.manifest.txt"

mapfile -t DEPLOY_ITEMS < <(oracle_deployment_items)
oracle_run tar -C "$REPO_DIR" -czf "$BUNDLE_PATH" "${DEPLOY_ITEMS[@]}"

BUNDLE_SHA256="$(oracle_hash_file "$BUNDLE_PATH")"
{
  printf 'generated_at_utc=%s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf 'repo_dir=%s\n' "$REPO_DIR"
  printf 'bundle_path=%s\n' "$BUNDLE_PATH"
  printf 'bundle_sha256=%s\n' "$BUNDLE_SHA256"
  printf 'included_paths=\n'
  printf '%s\n' "${DEPLOY_ITEMS[@]}"
} >"$MANIFEST_PATH"

oracle_log "bundle_path=$BUNDLE_PATH"
oracle_log "manifest_path=$MANIFEST_PATH"
oracle_log "bundle_sha256=$BUNDLE_SHA256"
