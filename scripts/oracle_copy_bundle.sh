#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_copy_bundle.sh --host <ip> --user <user> --key-path <path> --bundle-path <path> [options]

Options:
  --env-file <path>            Project-local Oracle env file. Default: deployment/oracle_vm.env when present.
  --ssh-port <port>            SSH port. Default: 22.
  --project-dir <path>         Remote project directory. Default: /opt/universal-nids.
  --remote-upload-dir <path>   Remote temporary upload directory. Default: /tmp/universal-nids-upload.
  --upload-only                Upload bundle without extracting it into the project directory.
  --help                       Show this help text.
EOF
}

UPLOAD_ONLY="0"
BUNDLE_PATH=""
REMOTE_HOST=""
REMOTE_USER=""
SSH_KEY_PATH=""
SSH_PORT="$ORACLE_DEFAULT_SSH_PORT"
REMOTE_PROJECT_DIR="$ORACLE_DEFAULT_REMOTE_PROJECT_DIR"
REMOTE_UPLOAD_DIR="$ORACLE_DEFAULT_REMOTE_UPLOAD_DIR"
ENV_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      REMOTE_HOST="$2"
      shift 2
      ;;
    --user)
      REMOTE_USER="$2"
      shift 2
      ;;
    --key-path)
      SSH_KEY_PATH="$2"
      shift 2
      ;;
    --bundle-path)
      BUNDLE_PATH="$2"
      shift 2
      ;;
    --env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="$2"
      shift 2
      ;;
    --project-dir)
      REMOTE_PROJECT_DIR="$2"
      shift 2
      ;;
    --remote-upload-dir)
      REMOTE_UPLOAD_DIR="$2"
      shift 2
      ;;
    --upload-only)
      UPLOAD_ONLY="1"
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

oracle_require_value "$BUNDLE_PATH" "--bundle-path"
oracle_require_file "$BUNDLE_PATH"
MANIFEST_PATH="${BUNDLE_PATH%.tar.gz}.manifest.txt"

if [[ -z "$ENV_FILE" ]]; then
  DEFAULT_ENV_FILE="$(oracle_default_project_env_file)"
  if [[ -f "$DEFAULT_ENV_FILE" ]]; then
    ENV_FILE="$DEFAULT_ENV_FILE"
  fi
fi
oracle_load_project_env "$ENV_FILE"

oracle_require_cmd ssh
oracle_require_cmd scp
oracle_initialize_ssh

REMOTE_BUNDLE_PATH="$REMOTE_UPLOAD_DIR/$(basename "$BUNDLE_PATH")"
REMOTE_MANIFEST_PATH="$REMOTE_UPLOAD_DIR/$(basename "$MANIFEST_PATH")"

oracle_run_remote_script '
set -euo pipefail
upload_dir="$1"
project_dir="$2"
remote_user="$3"
sudo -n true >/dev/null 2>&1
install -d -m 755 "$upload_dir"
sudo install -d -m 755 "$project_dir"
sudo chown -R "$remote_user:$remote_user" "$project_dir"
' "$REMOTE_UPLOAD_DIR" "$REMOTE_PROJECT_DIR" "$REMOTE_USER"

oracle_run_scp "$BUNDLE_PATH" "$REMOTE_TARGET:$REMOTE_BUNDLE_PATH"
if [[ -f "$MANIFEST_PATH" ]]; then
  oracle_run_scp "$MANIFEST_PATH" "$REMOTE_TARGET:$REMOTE_MANIFEST_PATH"
fi

if [[ "$UPLOAD_ONLY" == "1" ]]; then
  oracle_log "remote_bundle_path=$REMOTE_BUNDLE_PATH"
  exit 0
fi

oracle_run_remote_script '
set -euo pipefail
bundle_path="$1"
project_dir="$2"
remote_user="$3"
sudo -n true >/dev/null 2>&1
sudo tar -xzf "$bundle_path" -C "$project_dir"
sudo chown -R "$remote_user:$remote_user" "$project_dir"
test -f "$project_dir/docker-compose.cloud-single-node.yml"
test -f "$project_dir/.env.example"
printf "remote_project_dir=%s\n" "$project_dir"
printf "remote_bundle_path=%s\n" "$bundle_path"
' "$REMOTE_BUNDLE_PATH" "$REMOTE_PROJECT_DIR" "$REMOTE_USER"
