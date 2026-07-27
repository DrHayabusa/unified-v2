#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_DIR="$ROOT_DIR/.local"
PG_DATA="$LOCAL_DIR/postgres-data"
PG_LOG="$LOCAL_DIR/postgres.log"
API_LOG="$LOCAL_DIR/api.log"
UI_LOG="$LOCAL_DIR/ui.log"
PG_PORT="${MVA_POSTGRES_PORT:-55432}"
API_PORT="${MVA_API_PORT:-8787}"
UI_PORT="${MVA_UI_PORT:-8820}"
POSTGRES_APP_VERSION="2.9.5"
POSTGRES_MAJOR="17"
POSTGRES_DMG="$LOCAL_DIR/Postgres-${POSTGRES_APP_VERSION}-${POSTGRES_MAJOR}.dmg"
POSTGRES_VOLUME="/Volumes/Postgres-${POSTGRES_APP_VERSION}-${POSTGRES_MAJOR}"
POSTGRES_URL="https://github.com/PostgresApp/PostgresApp/releases/download/v${POSTGRES_APP_VERSION}/Postgres-${POSTGRES_APP_VERSION}-${POSTGRES_MAJOR}.dmg"

mkdir -p "$LOCAL_DIR"

if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT_DIR/.env"
  set +a
fi

LITELLM_URL="${LITELLM_URL:-http://127.0.0.1:4000}"
: "${LITELLM_API_KEY:?Set LITELLM_API_KEY in .env}"
: "${LITELLM_MODEL:?Set LITELLM_MODEL in .env}"
LITELLM_CONNECT_TIMEOUT_MS="${LITELLM_CONNECT_TIMEOUT_MS:-10000}"
LITELLM_READ_TIMEOUT_MS="${LITELLM_READ_TIMEOUT_MS:-600000}"

api_contract_ready() {
  curl --fail --silent "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 \
    && curl --fail --silent "http://127.0.0.1:${API_PORT}/api/v1/auth/setup-status" >/dev/null 2>&1
}

stop_owned_api_if_incompatible() {
  local pid_file="$LOCAL_DIR/api.pid"
  [[ -f "$pid_file" ]] || return 1

  local pid
  pid="$(cat "$pid_file")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1 || return 1

  if ! lsof -nP -a -p "$pid" -iTCP:"$API_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    return 1
  fi

  echo "Restarting the project-owned API because its authentication contract is stale..."
  kill "$pid"
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  rm -f "$pid_file"
}

find_postgres_bin() {
  local candidates=(
    "/Applications/Postgres.app/Contents/Versions/${POSTGRES_MAJOR}/bin"
    "${POSTGRES_VOLUME}/Postgres.app/Contents/Versions/${POSTGRES_MAJOR}/bin"
    "/opt/homebrew/opt/postgresql@${POSTGRES_MAJOR}/bin"
  )
  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate/postgres" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

PG_BIN="$(find_postgres_bin || true)"
if [[ -z "$PG_BIN" ]]; then
  if [[ ! -f "$POSTGRES_DMG" ]]; then
    echo "Downloading the official PostgreSQL 17 runtime..."
    curl --fail --location --progress-bar --output "$POSTGRES_DMG" "$POSTGRES_URL"
  fi
  if [[ ! -d "$POSTGRES_VOLUME" ]]; then
    hdiutil attach -nobrowse -readonly "$POSTGRES_DMG" >/dev/null
  fi
  PG_BIN="$(find_postgres_bin || true)"
fi

if [[ -z "$PG_BIN" ]]; then
  echo "PostgreSQL 17 binaries could not be located."
  exit 1
fi

if [[ ! -f "$PG_DATA/PG_VERSION" ]]; then
  echo "Initializing the project-local PostgreSQL database..."
  "$PG_BIN/initdb" -D "$PG_DATA" --username=mva --auth=trust --encoding=UTF8 --locale=C
fi

if ! "$PG_BIN/pg_isready" -h 127.0.0.1 -p "$PG_PORT" -U mva >/dev/null 2>&1; then
  "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_LOG" -o "-p $PG_PORT -h 127.0.0.1" start
fi

if ! "$PG_BIN/psql" -h 127.0.0.1 -p "$PG_PORT" -U mva -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'mva'" | grep -q 1; then
  "$PG_BIN/createdb" -h 127.0.0.1 -p "$PG_PORT" -U mva mva
fi

if [[ ! -d "$ROOT_DIR/server/node_modules" ]]; then
  npm install --prefix "$ROOT_DIR/server"
fi
if [[ ! -d "$ROOT_DIR/react-ui/node_modules" ]]; then
  npm install --prefix "$ROOT_DIR/react-ui"
fi

if ! api_contract_ready; then
  if lsof -nP -iTCP:"$API_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    if ! stop_owned_api_if_incompatible; then
      echo "Port $API_PORT is occupied by a service that is not the current MVA API."
      echo "Stop that service or set MVA_API_PORT to an available port."
      exit 1
    fi
  fi
  (
    cd "$ROOT_DIR/server"
    nohup env \
      DATABASE_URL="postgresql://mva@127.0.0.1:${PG_PORT}/mva" \
      HOST=127.0.0.1 \
      PORT="$API_PORT" \
      CORS_ORIGINS="http://127.0.0.1:${UI_PORT},http://localhost:${UI_PORT}" \
      LITELLM_URL="$LITELLM_URL" \
      LITELLM_API_KEY="$LITELLM_API_KEY" \
      LITELLM_MODEL="$LITELLM_MODEL" \
      LITELLM_CONNECT_TIMEOUT_MS="$LITELLM_CONNECT_TIMEOUT_MS" \
      LITELLM_READ_TIMEOUT_MS="$LITELLM_READ_TIMEOUT_MS" \
      node src/server.js >"$API_LOG" 2>&1 &
    echo $! >"$LOCAL_DIR/api.pid"
  )
fi

echo "Waiting for the local API..."
for attempt in $(seq 1 30); do
  if api_contract_ready; then
    break
  fi
  if [[ "$attempt" -eq 30 ]]; then
    echo "The API did not start. Review $API_LOG"
    exit 1
  fi
  sleep 1
done

env \
  VITE_MVA_DATABASE_API_URL="http://127.0.0.1:${API_PORT}" \
  npm run build --prefix "$ROOT_DIR/react-ui" -- --mode production

if ! curl --fail --silent "http://127.0.0.1:${UI_PORT}/" >/dev/null 2>&1; then
  if lsof -nP -iTCP:"$UI_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $UI_PORT is occupied by another process."
    exit 1
  fi
  (
    cd "$ROOT_DIR/react-ui"
    nohup ./node_modules/.bin/vite preview --host 127.0.0.1 --port "$UI_PORT" >"$UI_LOG" 2>&1 &
    echo $! >"$LOCAL_DIR/ui.pid"
  )
fi

echo "Waiting for the local UI..."
for attempt in $(seq 1 30); do
  if curl --fail --silent "http://127.0.0.1:${UI_PORT}/" >/dev/null; then
    echo "MVA with PostgreSQL is ready."
    echo "UI:  http://127.0.0.1:${UI_PORT}/"
    echo "API: http://127.0.0.1:${API_PORT}/health"
    echo "LLM: ${LITELLM_MODEL} via ${LITELLM_URL} (server-side only)"
    exit 0
  fi
  if [[ "$attempt" -eq 30 ]]; then
    echo "The UI did not start. Review $UI_LOG"
    exit 1
  fi
  sleep 1
done
