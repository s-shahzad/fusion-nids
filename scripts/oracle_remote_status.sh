#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_remote_status.sh --host <ip> --user <user> --key-path <path> [options]

Options:
  --env-file <path>      Project-local Oracle env file. Default: deployment/oracle_vm.env when present.
  --ssh-port <port>      SSH port. Default: 22.
  --project-dir <path>   Remote project directory. Default: /opt/universal-nids.
  --service <name>       Service to tail. Default: nids-runtime.
  --tail <lines>         Log tail line count. Default: 50.
  --follow               Follow docker compose logs after the status summary.
  --help                 Show this help text.
EOF
}

REMOTE_HOST=""
REMOTE_USER=""
SSH_KEY_PATH=""
SSH_PORT="$ORACLE_DEFAULT_SSH_PORT"
REMOTE_PROJECT_DIR="$ORACLE_DEFAULT_REMOTE_PROJECT_DIR"
SERVICE_NAME="nids-runtime"
TAIL_LINES="50"
FOLLOW_LOGS="0"
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
    --service)
      SERVICE_NAME="$2"
      shift 2
      ;;
    --tail)
      TAIL_LINES="$2"
      shift 2
      ;;
    --follow)
      FOLLOW_LOGS="1"
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
if [[ -z "$ENV_FILE" ]]; then
  DEFAULT_ENV_FILE="$(oracle_default_project_env_file)"
  if [[ -f "$DEFAULT_ENV_FILE" ]]; then
    ENV_FILE="$DEFAULT_ENV_FILE"
  fi
fi
oracle_load_project_env "$ENV_FILE"
oracle_initialize_ssh

oracle_run_remote_script '
set -euo pipefail
project_dir="$1"
service_name="$2"
tail_lines="$3"
follow_logs="$4"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
cloud_root="$project_dir/cloud_data"
if sudo docker compose version >/dev/null 2>&1; then
  compose_base=(sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
else
  compose_base=(sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
fi

printf "project_dir=%s\n" "$project_dir"
printf "cloud_root=%s\n" "$cloud_root"
df -h "$project_dir" "$cloud_root" || true
"${compose_base[@]}" ps -a || true

if [[ -d "$cloud_root/runtime/logs" ]]; then
  printf "\nlatest_runtime_logs\n"
  ls -1t "$cloud_root/runtime/logs" | head -n 5 || true
fi

if [[ -d "$cloud_root/manifests" ]]; then
  printf "\nlatest_manifests\n"
  ls -1t "$cloud_root/manifests" | head -n 5 || true
fi

printf "\ncompose_logs_%s\n" "$service_name"
if [[ "$follow_logs" == "1" ]]; then
  "${compose_base[@]}" logs -f --tail "$tail_lines" "$service_name"
else
  "${compose_base[@]}" logs --tail "$tail_lines" "$service_name" || true
fi
' "$REMOTE_PROJECT_DIR" "$SERVICE_NAME" "$TAIL_LINES" "$FOLLOW_LOGS"
