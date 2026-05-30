#!/usr/bin/env sh
set -eu

REPO_URL="${REPO_URL:-}"
TARGET_DIR="${TARGET_DIR:-$HOME/universal-nids}"
REPO_REF="${REPO_REF:-}"
COMPOSE_FILE="docker-compose.cloud-single-node.yml"
ENV_FILE=".env"
EXAMPLE_FILE=".env.example"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

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

require_cmd git
require_cmd docker

if [ ! -d "$TARGET_DIR" ]; then
  if [ -z "$REPO_URL" ]; then
    echo "TARGET_DIR does not exist and REPO_URL is empty." >&2
    echo "Set REPO_URL to your Universal NIDS repository URL." >&2
    exit 1
  fi
  git clone "$REPO_URL" "$TARGET_DIR"
fi

cd "$TARGET_DIR"

if [ -n "$REPO_REF" ]; then
  git fetch --all --tags
  git checkout "$REPO_REF"
fi

if [ ! -f "$EXAMPLE_FILE" ]; then
  echo "Expected $EXAMPLE_FILE in repository root." >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "Created $ENV_FILE from $EXAMPLE_FILE"
fi

upsert_env "NIDS_CONFIG_PATH" "config/nids_cloud_single_node.yml" "$ENV_FILE"
upsert_env "NIDS_CLOUD_RUNTIME_OUTPUT_DIR" "./cloud_data/runtime/output" "$ENV_FILE"
upsert_env "NIDS_CLOUD_RUNTIME_LOG_DIR" "./cloud_data/runtime/logs" "$ENV_FILE"
upsert_env "NIDS_CLOUD_RUNTIME_REPORTS_DIR" "./cloud_data/runtime/reports" "$ENV_FILE"
upsert_env "NIDS_CLOUD_RUNTIME_ARTIFACTS_DIR" "./cloud_data/runtime/artifacts" "$ENV_FILE"
upsert_env "NIDS_CLOUD_LAB_BUNDLES_DIR" "./cloud_data/lab_generated/bundles" "$ENV_FILE"
upsert_env "NIDS_CLOUD_REPLAY_DIR" "./cloud_data/replay/staging" "$ENV_FILE"

mkdir -p \
  cloud_data/runtime/output \
  cloud_data/runtime/logs \
  cloud_data/runtime/reports \
  cloud_data/runtime/artifacts/incoming \
  cloud_data/runtime/artifacts/processed \
  cloud_data/runtime/artifacts/quarantine \
  cloud_data/lab_generated/bundles \
  cloud_data/lab_generated/archive \
  cloud_data/replay/staging \
  cloud_data/archive/output_bundles \
  cloud_data/manifests

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" build nids-runtime
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d nids-runtime

running_services="$(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps --status running --services)"
if printf "%s\n" "$running_services" | grep -qx "nids-runtime"; then
  echo "Universal NIDS runtime container is running."
else
  echo "Runtime container did not report as running." >&2
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --tail 100 nids-runtime || true
  exit 1
fi

echo ""
echo "Cloud deployment bootstrap complete."
echo "Repo root: $TARGET_DIR"
echo "Compose file: $COMPOSE_FILE"
echo "Runtime config: config/nids_cloud_single_node.yml"
echo ""
echo "Next steps:"
echo "1. Stage one replay bundle with scripts/cloud_validation_workflow.py"
echo "2. Keep the dashboard disabled unless operator review is needed"
echo "3. Review cloud_security_baseline.md before opening any additional access"
