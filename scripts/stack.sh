#!/usr/bin/env sh
set -eu

ACTION="${1:-start}"
BUILD="${2:-}"

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/.env"
EXAMPLE_FILE="$ROOT/.env.example"
COMPOSE_FILE="$ROOT/docker-compose.yml"

if [ ! -f "$ENV_FILE" ]; then
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "Created .env from .env.example"
fi

case "$ACTION" in
  start)
    if [ "$BUILD" = "--build" ]; then
      docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build
    else
      docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d
    fi
    ;;
  stop)
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down
    ;;
  restart)
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down
    if [ "$BUILD" = "--build" ]; then
      docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build
    else
      docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d
    fi
    ;;
  logs)
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs -f --tail 200
    ;;
  *)
    echo "Usage: scripts/stack.sh [start|stop|restart|logs] [--build]"
    exit 1
    ;;
esac
