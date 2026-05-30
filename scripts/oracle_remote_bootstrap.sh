#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_remote_bootstrap.sh --host <ip> --user <user> --key-path <path> [options]

Options:
  --env-file <path>      Project-local Oracle env file. Default: deployment/oracle_vm.env when present.
  --ssh-port <port>      SSH port. Default: 22.
  --project-dir <path>   Remote project directory. Default: /opt/universal-nids.
  --help                 Show this help text.
EOF
}

REMOTE_HOST=""
REMOTE_USER=""
SSH_KEY_PATH=""
SSH_PORT="$ORACLE_DEFAULT_SSH_PORT"
REMOTE_PROJECT_DIR="$ORACLE_DEFAULT_REMOTE_PROJECT_DIR"
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
REMOTE_CLOUD_DATA_DIR="$(oracle_remote_cloud_data_dir "$REMOTE_PROJECT_DIR")"

oracle_run_remote_script '
set -euo pipefail
remote_user="$1"
project_dir="$2"
cloud_root="$3"

sudo -n true >/dev/null 2>&1 || {
  echo "Passwordless sudo is required for bootstrap." >&2
  exit 1
}

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update

base_packages=(ca-certificates curl git python3 rsync tar)
missing_packages=()
for package_name in "${base_packages[@]}"; do
  if ! dpkg -s "$package_name" >/dev/null 2>&1; then
    missing_packages+=("$package_name")
  fi
done
if [[ ${#missing_packages[@]} -gt 0 ]]; then
  sudo apt-get install -y "${missing_packages[@]}"
fi

if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get install -y docker.io
fi

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  for compose_package in docker-compose-v2 docker-compose-plugin docker-compose; do
    if apt-cache show "$compose_package" >/dev/null 2>&1; then
      sudo apt-get install -y "$compose_package"
      break
    fi
  done
fi

sudo systemctl enable --now docker

layout_paths=(
  "$project_dir"
  "$cloud_root/runtime/output"
  "$cloud_root/runtime/logs"
  "$cloud_root/runtime/reports"
  "$cloud_root/runtime/artifacts/incoming"
  "$cloud_root/runtime/artifacts/processed"
  "$cloud_root/runtime/artifacts/quarantine"
  "$cloud_root/lab_generated/bundles"
  "$cloud_root/lab_generated/archive"
  "$cloud_root/replay/staging"
  "$cloud_root/archive/output_bundles"
  "$cloud_root/manifests"
  "$project_dir/tmp/oracle-uploaded-bundles"
)
for path_item in "${layout_paths[@]}"; do
  sudo install -d -m 755 "$path_item"
done
sudo chown -R "$remote_user:$remote_user" "$project_dir"

sudo docker version >/dev/null 2>&1 || {
  echo "Docker is installed but not responding." >&2
  exit 1
}

if docker compose version >/dev/null 2>&1; then
  compose_version="$(docker compose version --short)"
elif command -v docker-compose >/dev/null 2>&1; then
  compose_version="$(docker-compose version --short)"
else
  echo "Docker Compose is not available after bootstrap." >&2
  exit 1
fi

printf "docker_ok=true\n"
printf "compose_version=%s\n" "$compose_version"
printf "remote_project_dir=%s\n" "$project_dir"
printf "remote_cloud_data_dir=%s\n" "$cloud_root"
' "$REMOTE_USER" "$REMOTE_PROJECT_DIR" "$REMOTE_CLOUD_DATA_DIR"
