#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./oracle_common.sh
. "$SCRIPT_DIR/oracle_common.sh"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/oracle_remote_run.sh --host <ip> --user <user> --key-path <path> [options]

Sync options:
  --sync-method <rsync|bundle|git|none>   Default: rsync.
  --local-repo <path>                     Local repository root for rsync mode.
  --bundle-path <path>                    Local deployment bundle for bundle mode.
  --repo-url <url>                        Remote clone URL for git mode.
  --repo-ref <ref>                        Optional branch, tag, or commit for git mode.

Run options:
  --run-mode <replay|live>                Default: replay.
  --local-lab-bundle <path>               Local lab_generated bundle directory for replay mode.
  --remote-lab-bundle <path>              Remote lab_generated bundle directory for replay mode.
  --run-stamp <stamp>                     Optional deterministic run stamp.
  --sensor-id <id>                        Sensor identifier prefix. Default: oracle-cloud.
  --interface <name>                      Live interface for run-mode live.
  --enable-dashboard                      Start the loopback-only dashboard service after live start.

Connection options:
  --env-file <path>                       Project-local Oracle env file. Default: deployment/oracle_vm.env when present.
  --ssh-port <port>                       SSH port. Default: 22.
  --project-dir <path>                    Remote project directory. Default: /opt/universal-nids.
  --help                                  Show this help text.
EOF
}

REMOTE_HOST=""
REMOTE_USER=""
SSH_KEY_PATH=""
SSH_PORT="$ORACLE_DEFAULT_SSH_PORT"
REMOTE_PROJECT_DIR="$ORACLE_DEFAULT_REMOTE_PROJECT_DIR"
LOCAL_REPO=""
SYNC_METHOD=""
RUN_MODE=""
BUNDLE_PATH=""
REPO_URL=""
REPO_REF=""
LOCAL_LAB_BUNDLE=""
REMOTE_LAB_BUNDLE=""
RUN_STAMP=""
SENSOR_ID=""
LIVE_INTERFACE=""
ENABLE_DASHBOARD="0"
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
    --local-repo)
      LOCAL_REPO="$2"
      shift 2
      ;;
    --sync-method)
      SYNC_METHOD="$2"
      shift 2
      ;;
    --bundle-path)
      BUNDLE_PATH="$2"
      shift 2
      ;;
    --repo-url)
      REPO_URL="$2"
      shift 2
      ;;
    --repo-ref)
      REPO_REF="$2"
      shift 2
      ;;
    --run-mode)
      RUN_MODE="$2"
      shift 2
      ;;
    --local-lab-bundle)
      LOCAL_LAB_BUNDLE="$2"
      shift 2
      ;;
    --remote-lab-bundle)
      REMOTE_LAB_BUNDLE="$2"
      shift 2
      ;;
    --run-stamp)
      RUN_STAMP="$2"
      shift 2
      ;;
    --sensor-id)
      SENSOR_ID="$2"
      shift 2
      ;;
    --interface)
      LIVE_INTERFACE="$2"
      shift 2
      ;;
    --enable-dashboard)
      ENABLE_DASHBOARD="1"
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
LOCAL_REPO="${LOCAL_REPO:-${ORACLE_VM_LOCAL_REPO:-$(oracle_repo_root)}}"
SYNC_METHOD="${SYNC_METHOD:-${ORACLE_VM_SYNC_METHOD:-rsync}}"
RUN_MODE="${RUN_MODE:-${ORACLE_VM_RUN_MODE:-replay}}"
SENSOR_ID="${SENSOR_ID:-${ORACLE_VM_SENSOR_ID:-oracle-cloud}}"
LOCAL_LAB_BUNDLE="${LOCAL_LAB_BUNDLE:-${ORACLE_VM_LOCAL_LAB_BUNDLE:-}}"
oracle_initialize_ssh
REMOTE_CLOUD_DATA_DIR="$(oracle_remote_cloud_data_dir "$REMOTE_PROJECT_DIR")"

case "$SYNC_METHOD" in
  rsync)
    oracle_require_dir "$LOCAL_REPO"
    oracle_assert_deployment_inputs "$LOCAL_REPO"
    oracle_run_remote_script '
set -euo pipefail
project_dir="$1"
remote_user="$2"
sudo -n true >/dev/null 2>&1
sudo install -d -m 755 "$project_dir"
sudo chown -R "$remote_user:$remote_user" "$project_dir"
' "$REMOTE_PROJECT_DIR" "$REMOTE_USER"

    mapfile -t DEPLOY_ITEMS < <(oracle_deployment_items)
    RSYNC_ARGS=(-az --partial --progress -e "$RSYNC_RSH")
    for item in "${DEPLOY_ITEMS[@]}"; do
      RSYNC_ARGS+=("$LOCAL_REPO/$item")
    done
    RSYNC_ARGS+=("$REMOTE_TARGET:$REMOTE_PROJECT_DIR/")
    oracle_run_rsync "${RSYNC_ARGS[@]}"
    ;;
  bundle)
    oracle_require_cmd scp
    oracle_require_value "$BUNDLE_PATH" "--bundle-path"
    oracle_require_file "$BUNDLE_PATH"
    MANIFEST_PATH="${BUNDLE_PATH%.tar.gz}.manifest.txt"
    REMOTE_BUNDLE_PATH="$REMOTE_UPLOAD_DIR/$(basename "$BUNDLE_PATH")"
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
      oracle_run_scp "$MANIFEST_PATH" "$REMOTE_TARGET:$REMOTE_UPLOAD_DIR/$(basename "$MANIFEST_PATH")"
    fi
    oracle_run_remote_script '
set -euo pipefail
bundle_path="$1"
project_dir="$2"
remote_user="$3"
sudo -n true >/dev/null 2>&1
sudo tar -xzf "$bundle_path" -C "$project_dir"
sudo chown -R "$remote_user:$remote_user" "$project_dir"
' "$REMOTE_BUNDLE_PATH" "$REMOTE_PROJECT_DIR" "$REMOTE_USER"
    ;;
  git)
    oracle_require_value "$REPO_URL" "--repo-url"
    oracle_run_remote_script '
set -euo pipefail
repo_url="$1"
project_dir="$2"
repo_ref="$3"
sudo -n true >/dev/null 2>&1
sudo install -d -m 755 "$project_dir"
sudo chown "$USER:$USER" "$project_dir"
if [[ -d "$project_dir/.git" ]]; then
  git -C "$project_dir" fetch --all --tags
else
  git clone "$repo_url" "$project_dir"
fi
if [[ -n "$repo_ref" ]]; then
  git -C "$project_dir" checkout "$repo_ref"
  git -C "$project_dir" pull --ff-only origin "$repo_ref" || true
else
  git -C "$project_dir" pull --ff-only || true
fi
' "$REPO_URL" "$REMOTE_PROJECT_DIR" "$REPO_REF"
    ;;
  none)
    :
    ;;
  *)
    oracle_die "Unsupported --sync-method value: $SYNC_METHOD"
    ;;
esac

oracle_run_remote_script '
set -euo pipefail
project_dir="$1"
cloud_root="$2"
live_interface="$3"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
example_file="$project_dir/.env.example"

test -f "$compose_file"
test -f "$example_file"
test -f "$project_dir/Dockerfile"
test -f "$project_dir/config/nids_cloud_single_node.yml"
test -f "$project_dir/scripts/cloud_validation_workflow.py"
test -d "$project_dir/src"

if [[ ! -f "$env_file" ]]; then
  cp "$example_file" "$env_file"
fi

upsert_env() {
  key="$1"
  value="$2"
  file="$3"
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf "%s=%s\n" "$key" "$value" >>"$file"
  fi
}

upsert_env "NIDS_CONFIG_PATH" "config/nids_cloud_single_node.yml" "$env_file"
upsert_env "NIDS_CLOUD_RUNTIME_OUTPUT_DIR" "$cloud_root/runtime/output" "$env_file"
upsert_env "NIDS_CLOUD_RUNTIME_LOG_DIR" "$cloud_root/runtime/logs" "$env_file"
upsert_env "NIDS_CLOUD_RUNTIME_REPORTS_DIR" "$cloud_root/runtime/reports" "$env_file"
upsert_env "NIDS_CLOUD_RUNTIME_ARTIFACTS_DIR" "$cloud_root/runtime/artifacts" "$env_file"
upsert_env "NIDS_CLOUD_LAB_BUNDLES_DIR" "$cloud_root/lab_generated/bundles" "$env_file"
upsert_env "NIDS_CLOUD_REPLAY_DIR" "$cloud_root/replay/staging" "$env_file"
if [[ -n "$live_interface" ]]; then
  upsert_env "NIDS_INTERFACE" "$live_interface" "$env_file"
fi

layout_paths=(
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
  install -d -m 755 "$path_item"
done

sudo docker version >/dev/null 2>&1
if sudo docker compose version >/dev/null 2>&1; then
  sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file" config >/dev/null
else
  sudo docker-compose --project-directory "$project_dir" -f "$compose_file" config >/dev/null
fi
' "$REMOTE_PROJECT_DIR" "$REMOTE_CLOUD_DATA_DIR" "$LIVE_INTERFACE"

if [[ "$RUN_MODE" == "live" ]]; then
  oracle_require_value "$LIVE_INTERFACE" "--interface"
  oracle_run_remote_script '
set -euo pipefail
project_dir="$1"
enable_dashboard="$2"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"
if sudo docker compose version >/dev/null 2>&1; then
  compose_base=(sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
else
  compose_base=(sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
fi
"${compose_base[@]}" build nids-runtime
"${compose_base[@]}" up -d nids-runtime
if [[ "$enable_dashboard" == "1" ]]; then
  "${compose_base[@]}" --profile dashboard up -d nids-dashboard
fi
"${compose_base[@]}" ps
printf "runtime_output_dir=%s\n" "$project_dir/cloud_data/runtime/output"
printf "runtime_logs_dir=%s\n" "$project_dir/cloud_data/runtime/logs"
printf "runtime_reports_dir=%s\n" "$project_dir/cloud_data/runtime/reports"
' "$REMOTE_PROJECT_DIR" "$ENABLE_DASHBOARD"
  exit 0
fi

if [[ "$RUN_MODE" != "replay" ]]; then
  oracle_die "Unsupported --run-mode value: $RUN_MODE"
fi

if [[ -n "$LOCAL_LAB_BUNDLE" ]]; then
  oracle_require_dir "$LOCAL_LAB_BUNDLE"
  BUNDLE_SOURCE_NAME="$(basename "$LOCAL_LAB_BUNDLE")"
  REMOTE_TEMP_BUNDLE_ROOT="$(oracle_remote_tmp_bundle_dir "$REMOTE_PROJECT_DIR")"
  if [[ -z "$RUN_STAMP" ]]; then
    RUN_STAMP="$(oracle_timestamp_utc)"
  fi
  REMOTE_LAB_BUNDLE="$REMOTE_TEMP_BUNDLE_ROOT/${BUNDLE_SOURCE_NAME}-${RUN_STAMP}"
  oracle_run_remote_script '
set -euo pipefail
bundle_dir="$1"
install -d -m 755 "$bundle_dir"
' "$REMOTE_LAB_BUNDLE"
  oracle_run_rsync -az --partial --progress -e "$RSYNC_RSH" "$LOCAL_LAB_BUNDLE/" "$REMOTE_TARGET:$REMOTE_LAB_BUNDLE/"
fi

oracle_require_value "$REMOTE_LAB_BUNDLE" "--local-lab-bundle or --remote-lab-bundle"
if [[ -z "$RUN_STAMP" ]]; then
  RUN_STAMP="$(oracle_timestamp_utc)"
fi

oracle_run_remote_script '
set -euo pipefail
project_dir="$1"
cloud_root="$2"
bundle_dir="$3"
run_stamp="$4"
sensor_id="$5"
compose_file="$project_dir/docker-compose.cloud-single-node.yml"
env_file="$project_dir/.env"

if sudo docker compose version >/dev/null 2>&1; then
  compose_base=(sudo docker compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
else
  compose_base=(sudo docker-compose --project-directory "$project_dir" --env-file "$env_file" -f "$compose_file")
fi
"${compose_base[@]}" build nids-runtime

plan_json="$(cd "$project_dir" && python3 scripts/cloud_validation_workflow.py stage-bundle --root "$cloud_root" --bundle-dir "$bundle_dir" --sensor-id "$sensor_id" --run-stamp "$run_stamp")"
printf "%s" "$plan_json" >"$cloud_root/manifests/oracle_latest_plan.json"

mapfile -t plan_fields < <(printf "%s" "$plan_json" | python3 -c '"'"'import json, sys; payload=json.load(sys.stdin); print(payload["staged_bundle_dir"]); print(payload["pcap_path"]); print(payload["labels_path"]); print(payload["runtime_output_dir"]); print(payload["reports_dir"]); print(payload["plan_path"])'"'"')
staged_bundle_dir="${plan_fields[0]}"
pcap_path="${plan_fields[1]}"
labels_path="${plan_fields[2]}"
runtime_output_dir="${plan_fields[3]}"
reports_dir="${plan_fields[4]}"
plan_path="${plan_fields[5]}"
run_name="$(basename "$runtime_output_dir")"
combined_log_path="$cloud_root/runtime/logs/${run_name}.docker-run.log"

set -o pipefail
"${compose_base[@]}" run --rm \
  -e "NIDS_PCAP_DIR=/data/replay/staging/$(basename "$staged_bundle_dir")/$(basename "$pcap_path")" \
  -e "NIDS_LABELS_PATH=/data/replay/staging/$(basename "$staged_bundle_dir")/$(basename "$labels_path")" \
  -e "NIDS_OUTPUT_DIR=/data/runtime/output/$run_name" \
  -e "NIDS_SENSOR_ID=${sensor_id}-${run_stamp}" \
  nids-runtime 2>&1 | tee "$combined_log_path"

"${compose_base[@]}" run --rm nids-runtime \
  python -m nids report \
  --from-db "/data/runtime/output/$run_name/nids.db" \
  --out "/data/runtime/reports/$run_name/summary.md"

"${compose_base[@]}" run --rm nids-runtime \
  python -m nids visualize \
  --from-db "/data/runtime/output/$run_name/nids.db" \
  --out "/data/runtime/reports/$run_name/graphs"

"${compose_base[@]}" ps -a || true
printf "run_name=%s\n" "$run_name"
printf "plan_path=%s\n" "$plan_path"
printf "runtime_output_dir=%s\n" "$runtime_output_dir"
printf "runtime_reports_dir=%s\n" "$reports_dir"
printf "runtime_log_path=%s\n" "$combined_log_path"
' "$REMOTE_PROJECT_DIR" "$REMOTE_CLOUD_DATA_DIR" "$REMOTE_LAB_BUNDLE" "$RUN_STAMP" "$SENSOR_ID"
