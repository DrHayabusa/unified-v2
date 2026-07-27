#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_DIR="$ROOT_DIR/.local"
PG_DATA="$LOCAL_DIR/postgres-data"
POSTGRES_MAJOR="17"

stop_pid_file() {
  local pid_file="$1"
  local label="$2"
  if [[ ! -f "$pid_file" ]]; then
    return
  fi
  local pid
  pid="$(cat "$pid_file")"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid"
    echo "Stopped $label."
  fi
  rm -f "$pid_file"
}

stop_pid_file "$LOCAL_DIR/ui.pid" "MVA UI"
stop_pid_file "$LOCAL_DIR/api.pid" "MVA API"

PG_CTL=""
for candidate in \
  "/Applications/Postgres.app/Contents/Versions/${POSTGRES_MAJOR}/bin/pg_ctl" \
  "/Volumes/Postgres-2.9.5-17/Postgres.app/Contents/Versions/${POSTGRES_MAJOR}/bin/pg_ctl" \
  "/opt/homebrew/opt/postgresql@${POSTGRES_MAJOR}/bin/pg_ctl"; do
  if [[ -x "$candidate" ]]; then
    PG_CTL="$candidate"
    break
  fi
done

if [[ -n "$PG_CTL" && -f "$PG_DATA/PG_VERSION" ]] && "$PG_CTL" -D "$PG_DATA" status >/dev/null 2>&1; then
  "$PG_CTL" -D "$PG_DATA" stop -m fast
fi
