#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_remote_collect.sh --host <ip> --user <user> --key-path <path> [options]

Options:
  --env-file <path>       Project-local Oracle env file. Default: deployment/oracle_vm.env when present.
  --ssh-port <port>       SSH port. Default: 22.
  --project-dir <path>    Remote project directory. Default: /opt/universal-nids.
  --out-dir <path>        Local collection root. Default: archives/oracle_vm_collections.
  --tail <lines>          Tail line count for captured compose logs. Default: 100.
  --include-output        Also collect runtime/output in addition to logs, reports, and manifests.
  --archive               Create a timestamped tar.gz archive of the collected files.
  --help                  Show this help text.
EOF
}

REMOTE_HOST=""
REMOTE_USER=""
SSH_KEY_PATH=""
SSH_PORT="$ORACLE_DEFAULT_SSH_PORT"
REMOTE_PROJECT_DIR="$ORACLE_DEFAULT_REMOTE_PROJECT_DIR"
LOCAL_OUT_DIR=""
TAIL_LINES="100"
INCLUDE_OUTPUT="0"
ARCHIVE_COLLECTION="0"
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
    --out-dir)
      LOCAL_OUT_DIR="$2"
      shift 2
      ;;
    --tail)
      TAIL_LINES="$2"
      shift 2
      ;;
    --include-output)
      INCLUDE_OUTPUT="1"
      shift
      ;;
    --archive)
      ARCHIVE_COLLECTION="1"
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

oracle_require_cmd ssh
oracle_require_cmd rsync
if [[ -z "$ENV_FILE" ]]; then
  DEFAULT_ENV_FILE="$(oracle_default_project_env_file)"
  if [[ -f "$DEFAULT_ENV_FILE" ]]; then
    ENV_FILE="$DEFAULT_ENV_FILE"
  fi
fi
oracle_load_project_env "$ENV_FILE"
LOCAL_OUT_DIR="${LOCAL_OUT_DIR:-${ORACLE_VM_COLLECTION_DIR:-$(oracle_repo_root)/archives/oracle_vm_collections}}"
oracle_initialize_ssh

STAMP="$(oracle_timestamp_utc)"
DEST_DIR="$LOCAL_OUT_DIR/$STAMP"
mkdir -p "$DEST_DIR"

oracle_print_command "${SSH_BASE[@]}" bash -lc "\"if sudo docker compose version >/dev/null 2>&1; then sudo docker compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' ps -a; else sudo docker-compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' ps -a; fi\""
"${SSH_BASE[@]}" bash -lc "if sudo docker compose version >/dev/null 2>&1; then sudo docker compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' ps -a; else sudo docker-compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' ps -a; fi" >"$DEST_DIR/docker-compose-ps.txt" 2>&1 || true

oracle_print_command "${SSH_BASE[@]}" bash -lc "\"if sudo docker compose version >/dev/null 2>&1; then sudo docker compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' logs --tail '$TAIL_LINES' nids-runtime; else sudo docker-compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' logs --tail '$TAIL_LINES' nids-runtime; fi\""
"${SSH_BASE[@]}" bash -lc "if sudo docker compose version >/dev/null 2>&1; then sudo docker compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' logs --tail '$TAIL_LINES' nids-runtime; else sudo docker-compose --project-directory '$REMOTE_PROJECT_DIR' --env-file '$REMOTE_PROJECT_DIR/.env' -f '$REMOTE_PROJECT_DIR/docker-compose.cloud-single-node.yml' logs --tail '$TAIL_LINES' nids-runtime; fi" >"$DEST_DIR/docker-compose-runtime-tail.txt" 2>&1 || true

mkdir -p "$DEST_DIR/runtime" "$DEST_DIR/manifests"
oracle_run_rsync -az -e "$RSYNC_RSH" "$REMOTE_TARGET:$REMOTE_PROJECT_DIR/cloud_data/runtime/logs/" "$DEST_DIR/runtime/logs/"
oracle_run_rsync -az -e "$RSYNC_RSH" "$REMOTE_TARGET:$REMOTE_PROJECT_DIR/cloud_data/runtime/reports/" "$DEST_DIR/runtime/reports/"
oracle_run_rsync -az -e "$RSYNC_RSH" "$REMOTE_TARGET:$REMOTE_PROJECT_DIR/cloud_data/manifests/" "$DEST_DIR/manifests/"

if [[ "$INCLUDE_OUTPUT" == "1" ]]; then
  oracle_run_rsync -az -e "$RSYNC_RSH" "$REMOTE_TARGET:$REMOTE_PROJECT_DIR/cloud_data/runtime/output/" "$DEST_DIR/runtime/output/"
fi

if [[ "$ARCHIVE_COLLECTION" == "1" ]]; then
  ARCHIVE_PATH="$LOCAL_OUT_DIR/${STAMP}.tar.gz"
  oracle_run tar -C "$LOCAL_OUT_DIR" -czf "$ARCHIVE_PATH" "$STAMP"
  oracle_log "archive_path=$ARCHIVE_PATH"
fi

oracle_log "collection_dir=$DEST_DIR"
