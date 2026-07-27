#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

if ! docker info >/dev/null 2>&1; then
  echo "Docker Desktop is not running. Start Docker Desktop, then run this script again."
  exit 1
fi

docker compose -f compose.local.yml up -d --build

echo "Waiting for the MVA PostgreSQL API..."
for attempt in $(seq 1 60); do
  if curl --fail --silent http://127.0.0.1:8787/health >/dev/null; then
    echo "MVA local stack is ready."
    echo "UI:  http://127.0.0.1:8820/"
    echo "API: http://127.0.0.1:8787/health"
    exit 0
  fi
  sleep 2
done

echo "The local stack did not become ready. Run: docker compose -f compose.local.yml logs"
exit 1
