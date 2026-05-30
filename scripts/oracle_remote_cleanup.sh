#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_remote_cleanup.sh --host <ip> --user <user> --key-path <path> [options]

Options:
  --env-file <path>             Project-local Oracle env file. Default: deployment/oracle_vm.env when present.
  --ssh-port <port>             SSH port. Default: 22.
  --project-dir <path>          Remote project directory. Default: /opt/universal-nids.
  --older-than-hours <hours>    Candidate age threshold. Default: 24.
  --apply                       Remove replay staging and optional temp candidates.
  --stop                        Stop project containers after cleanup.
  --clean-artifact-intake       Also target runtime/artifacts/incoming.
  --clean-upload-cache          Also target tmp/oracle-uploaded-bundles.
  --help                        Show this help text.
EOF
}

REMOTE_HOST=""
REMOTE_USER=""
SSH_KEY_PATH=""
SSH_PORT="$ORACLE_DEFAULT_SSH_PORT"
REMOTE_PROJECT_DIR="$ORACLE_DEFAULT_REMOTE_PROJECT_DIR"
OLDER_THAN_HOURS="24"
APPLY_CHANGES="0"
STOP_CONTAINERS="0"
CLEAN_ARTIFACT_INTAKE="0"
CLEAN_UPLOAD_CACHE="0"
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
    --older-than-hours)
      OLDER_THAN_HOURS="$2"
      shift 2
      ;;
    --apply)
      APPLY_CHANGES="1"
      shift
      ;;
    --stop)
      STOP_CONTAINERS="1"
      shift
      ;;
    --clean-artifact-intake)
      CLEAN_ARTIFACT_INTAKE="1"
      shift
      ;;
    --clean-upload-cache)
      CLEAN_UPLOAD_CACHE="1"
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
older_than_hours="$2"
apply_changes="$3"
stop_containers="$4"
clean_artifact_intake="$5"
clean_upload_cache="$6"
cloud_root="$project_dir/cloud_data"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
minutes="$(( older_than_hours * 60 ))"

cleanup_args=(python3 scripts/cloud_validation_workflow.py cleanup-temp --root "$cloud_root" --older-than-hours "$older_than_hours")
if [[ "$apply_changes" == "1" ]]; then
  cleanup_args+=(--apply)
fi
(cd "$project_dir" && "${cleanup_args[@]}")

clean_find_path() {
  target_path="$1"
  label="$2"
  if [[ ! -d "$target_path" ]]; then
    return 0
  fi
  printf "\n%s_candidates\n" "$label"
  find "$target_path" -mindepth 1 -maxdepth 1 -mmin +"$minutes" -print || true
  if [[ "$apply_changes" == "1" ]]; then
    find "$target_path" -mindepth 1 -maxdepth 1 -mmin +"$minutes" -exec rm -rf {} +
  fi
}

if [[ "$clean_artifact_intake" == "1" ]]; then
  clean_find_path "$cloud_root/runtime/artifacts/incoming" "artifact_intake"
fi

if [[ "$clean_upload_cache" == "1" ]]; then
  clean_find_path "$project_dir/tmp/oracle-uploaded-bundles" "upload_cache"
fi

if [[ "$stop_containers" == "1" ]]; then
  if sudo docker compose version >/dev/null 2>&1; then
    sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file" down
  else
    sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file" down
  fi
fi
' "$REMOTE_PROJECT_DIR" "$OLDER_THAN_HOURS" "$APPLY_CHANGES" "$STOP_CONTAINERS" "$CLEAN_ARTIFACT_INTAKE" "$CLEAN_UPLOAD_CACHE"
