#!/usr/bin/env bash
set -euo pipefail

ORACLE_DEFAULT_REMOTE_PROJECT_DIR="/opt/universal-nids"
ORACLE_DEFAULT_REMOTE_UPLOAD_DIR="/tmp/universal-nids-upload"
ORACLE_DEFAULT_SSH_PORT="22"

oracle_die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

oracle_log() {
  printf '%s\n' "$*"
}

oracle_print_command() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
}

oracle_run() {
  oracle_print_command "$@"
  "$@"
}

oracle_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || oracle_die "Required command not found: $1"
}

oracle_require_value() {
  local value="$1"
  local label="$2"
  [[ -n "$value" ]] || oracle_die "Missing required argument: $label"
}

oracle_require_file() {
  local path="$1"
  [[ -f "$path" ]] || oracle_die "Required file not found: $path"
}

oracle_require_dir() {
  local path="$1"
  [[ -d "$path" ]] || oracle_die "Required directory not found: $path"
}

oracle_repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.." && pwd
}

oracle_default_project_env_file() {
  printf '%s/deployment/oracle_vm.env\n' "$(oracle_repo_root)"
}

oracle_timestamp_utc() {
  date -u +"%Y%m%d-%H%M%S"
}

oracle_expand_home_path() {
  local raw_path="$1"
  case "$raw_path" in
    "~")
      printf '%s\n' "$HOME"
      ;;
    "~/"*)
      printf '%s/%s\n' "$HOME" "${raw_path#~/}"
      ;;
    *)
      printf '%s\n' "$raw_path"
      ;;
  esac
}

oracle_hash_command() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf 'sha256sum\n'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf 'shasum\n'
    return 0
  fi
  return 1
}

oracle_hash_file() {
  local file_path="$1"
  local hash_cmd
  hash_cmd="$(oracle_hash_command)" || oracle_die "sha256sum or shasum is required for bundle hashing"
  if [[ "$hash_cmd" == "sha256sum" ]]; then
    "$hash_cmd" "$file_path" | awk '{print $1}'
    return 0
  fi
  "$hash_cmd" -a 256 "$file_path" | awk '{print $1}'
}

oracle_deployment_items() {
  cat <<'EOF'
.dockerignore
.env.example
Dockerfile
LEGAL_SAFE_DEVELOPMENT.md
LICENSE
NOTICE
PROVENANCE.md
README.md
RELEASE_BOUNDARY.md
SCAPY_REVIEW.md
THIRD_PARTY.md
config
docker-compose.cloud-single-node.yml
deployment/oracle_vm.env.example
docs/cloud_single_node_profile.md
docs/cloud_storage_boundary.md
docs/cloud_validation_workflow.md
docs/current_status.md
docs/next_actions.md
docs/oracle_vm_cleanup_runbook.md
docs/oracle_vm_deployment_steps.md
docs/oracle_vm_first_boot.md
docs/oracle_vm_nids_runbook.md
models
nids
requirements.txt
rules
scripts
src
state/project_status.json
EOF
}

oracle_assert_deployment_inputs() {
  local repo_dir="$1"
  local relative_path=""
  while IFS= read -r relative_path; do
    [[ -n "$relative_path" ]] || continue
    if [[ ! -e "$repo_dir/$relative_path" ]]; then
      oracle_die "Deployment input missing from repository: $relative_path"
    fi
  done < <(oracle_deployment_items)
}

oracle_load_project_env() {
  local env_file="$1"
  [[ -n "$env_file" ]] || return 0
  [[ -f "$env_file" ]] || oracle_die "Oracle project env file not found: $env_file"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
}

oracle_apply_project_defaults() {
  REMOTE_HOST="${REMOTE_HOST:-${ORACLE_VM_HOST:-}}"
  REMOTE_USER="${REMOTE_USER:-${ORACLE_VM_USER:-}}"
  SSH_KEY_PATH="${SSH_KEY_PATH:-${ORACLE_VM_SSH_KEY_PATH:-}}"
  SSH_PORT="${SSH_PORT:-${ORACLE_VM_SSH_PORT:-$ORACLE_DEFAULT_SSH_PORT}}"
  REMOTE_PROJECT_DIR="${REMOTE_PROJECT_DIR:-${ORACLE_VM_PROJECT_DIR:-$ORACLE_DEFAULT_REMOTE_PROJECT_DIR}}"
  REMOTE_UPLOAD_DIR="${REMOTE_UPLOAD_DIR:-${ORACLE_VM_REMOTE_UPLOAD_DIR:-$ORACLE_DEFAULT_REMOTE_UPLOAD_DIR}}"
}

oracle_initialize_ssh() {
  oracle_apply_project_defaults
  oracle_require_value "${REMOTE_HOST:-}" "--host"
  oracle_require_value "${REMOTE_USER:-}" "--user"
  oracle_require_value "${SSH_KEY_PATH:-}" "--key-path"
  SSH_KEY_PATH="$(oracle_expand_home_path "$SSH_KEY_PATH")"
  oracle_require_file "$SSH_KEY_PATH"

  SSH_PORT="${SSH_PORT:-$ORACLE_DEFAULT_SSH_PORT}"
  REMOTE_PROJECT_DIR="${REMOTE_PROJECT_DIR:-$ORACLE_DEFAULT_REMOTE_PROJECT_DIR}"
  REMOTE_UPLOAD_DIR="${REMOTE_UPLOAD_DIR:-$ORACLE_DEFAULT_REMOTE_UPLOAD_DIR}"
  REMOTE_TARGET="${REMOTE_USER}@${REMOTE_HOST}"

  SSH_BASE=(ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -i "$SSH_KEY_PATH")
  SCP_BASE=(scp -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -i "$SSH_KEY_PATH")
  RSYNC_SSH_BASE=(ssh -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -i "$SSH_KEY_PATH")
  if [[ -n "$SSH_PORT" ]]; then
    SSH_BASE+=(-p "$SSH_PORT")
    SCP_BASE+=(-P "$SSH_PORT")
    RSYNC_SSH_BASE+=(-p "$SSH_PORT")
  fi
  SSH_BASE+=("$REMOTE_TARGET")

  local quoted_rsh=""
  printf -v quoted_rsh '%q ' "${RSYNC_SSH_BASE[@]}"
  RSYNC_RSH="${quoted_rsh% }"
}

oracle_run_ssh() {
  oracle_print_command "${SSH_BASE[@]}" "$@"
  "${SSH_BASE[@]}" "$@"
}

oracle_run_remote_script() {
  local script_body="$1"
  shift
  oracle_print_command "${SSH_BASE[@]}" bash -s -- "$@"
  printf '%s\n' "$script_body" | "${SSH_BASE[@]}" bash -s -- "$@"
}

oracle_run_scp() {
  oracle_print_command "${SCP_BASE[@]}" "$@"
  "${SCP_BASE[@]}" "$@"
}

oracle_run_rsync() {
  local rsync_args=("$@")
  oracle_print_command rsync "${rsync_args[@]}"
  rsync "${rsync_args[@]}"
}

oracle_remote_cloud_data_dir() {
  local remote_project_dir="$1"
  printf '%s/cloud_data\n' "$remote_project_dir"
}

oracle_remote_tmp_bundle_dir() {
  local remote_project_dir="$1"
  printf '%s/tmp/oracle-uploaded-bundles\n' "$remote_project_dir"
}
