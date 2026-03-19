#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/postgres.yaml"
BACKEND_ENV_EXAMPLE="${ROOT_DIR}/backend/.env.example"
BACKEND_ENV_FILE="${ROOT_DIR}/backend/.env"
FRONTEND_ENV_EXAMPLE="${ROOT_DIR}/frontend/.env.example"
FRONTEND_ENV_FILE="${ROOT_DIR}/frontend/.env.local"
VENV_DIR="${ROOT_DIR}/.venv"
RUN_DIR="${ROOT_DIR}/.dev"
RUNTIME_FILE="${RUN_DIR}/runtime.env"
BACKEND_LOG_FILE="${RUN_DIR}/backend.log"
FRONTEND_LOG_FILE="${RUN_DIR}/frontend.log"

MODE="start"
DETACH=0
STARTED_POSTGRES=0
BACKEND_PID=""
FRONTEND_PID=""
BACKEND_PORT=""
FRONTEND_PORT=""


parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --detach)
        DETACH=1
        ;;
      --stop)
        MODE="stop"
        ;;
      --logs)
        MODE="logs"
        ;;
      --status)
        MODE="status"
        ;;
      *)
        printf 'Unknown argument: %s\n' "$1" >&2
        exit 1
        ;;
    esac
    shift
  done
}


require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  fi
}


ensure_file_from_example() {
  local example_file="$1"
  local target_file="$2"

  if [[ -f "$target_file" ]]; then
    return
  fi

  cp "$example_file" "$target_file"
  printf 'Created %s from %s\n' "$target_file" "$example_file"
}


load_env_file() {
  local env_file="$1"

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi

    local key="${line%%=*}"
    local value="${line#*=}"
    value="${value%$'\r'}"
    export "${key}=${value}"
  done < "$env_file"
}


load_runtime_state() {
  if [[ ! -f "$RUNTIME_FILE" ]]; then
    return 1
  fi

  load_env_file "$RUNTIME_FILE"
  BACKEND_PID="${BACKEND_PID:-}"
  FRONTEND_PID="${FRONTEND_PID:-}"
  BACKEND_PORT="${BACKEND_PORT:-}"
  FRONTEND_PORT="${FRONTEND_PORT:-}"
  STARTED_POSTGRES="${STARTED_POSTGRES:-0}"
  return 0
}


write_runtime_state() {
  mkdir -p "$RUN_DIR"

  cat > "$RUNTIME_FILE" <<EOF
BACKEND_PID=${BACKEND_PID}
FRONTEND_PID=${FRONTEND_PID}
BACKEND_PORT=${BACKEND_PORT}
FRONTEND_PORT=${FRONTEND_PORT}
STARTED_POSTGRES=${STARTED_POSTGRES}
EOF
}


clear_runtime_state() {
  rm -f "$RUNTIME_FILE"
}


pid_is_running() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}


pick_free_port() {
  local start_port="$1"

  python3 - "$start_port" <<'PY'
import socket
import sys

start_port = int(sys.argv[1])

for candidate in range(start_port, start_port + 50):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if sock.connect_ex(("127.0.0.1", candidate)) != 0:
            print(candidate)
            raise SystemExit(0)

raise SystemExit(1)
PY
}


wait_for_http() {
  local url="$1"
  local attempts="$2"

  python3 - "$url" "$attempts" <<'PY'
import sys
import time
import urllib.request

url = sys.argv[1]
attempts = int(sys.argv[2])

for _ in range(attempts):
    try:
        with urllib.request.urlopen(url, timeout=2):
            raise SystemExit(0)
    except Exception:
        time.sleep(1)

raise SystemExit(1)
PY
}


ensure_backend_runtime() {
  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    printf 'Creating Python virtual environment...\n'
    python3 -m venv "${VENV_DIR}"
  fi

  if ! "${VENV_DIR}/bin/python" -c "import fastapi, sqlalchemy, psycopg" >/dev/null 2>&1; then
    printf 'Installing backend dependencies...\n'
    "${VENV_DIR}/bin/pip" install -e "${ROOT_DIR}/backend[dev]"
  fi
}


ensure_frontend_runtime() {
  if [[ ! -d "${ROOT_DIR}/frontend/node_modules" ]]; then
    printf 'Installing frontend dependencies...\n'
    (
      cd "${ROOT_DIR}/frontend"
      npm install
    )
  fi
}


start_postgres() {
  if docker compose -f "$COMPOSE_FILE" ps --services --status running | grep -qx 'postgres'; then
    printf 'Postgres is already running.\n'
  else
    printf 'Starting Postgres...\n'
    docker compose -f "$COMPOSE_FILE" up -d
    STARTED_POSTGRES=1
  fi

  until docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U auditor -d auditor >/dev/null 2>&1; do
    sleep 1
  done
}


prepare_log_files() {
  mkdir -p "$RUN_DIR"
  : > "$BACKEND_LOG_FILE"
  : > "$FRONTEND_LOG_FILE"
}


start_backend() {
  local cors_origins

  cors_origins="http://localhost:${FRONTEND_PORT},http://127.0.0.1:${FRONTEND_PORT}"

  if [[ "$DETACH" -eq 1 ]]; then
    (
      cd "$ROOT_DIR"
      load_env_file "$BACKEND_ENV_FILE"
      export AUDITOR_CORS_ORIGINS="$cors_origins"
      exec "${VENV_DIR}/bin/uvicorn" api.app.main:app --app-dir backend --host 127.0.0.1 --port "$BACKEND_PORT" --reload
    ) >> "$BACKEND_LOG_FILE" 2>&1 &
  else
    (
      cd "$ROOT_DIR"
      load_env_file "$BACKEND_ENV_FILE"
      export AUDITOR_CORS_ORIGINS="$cors_origins"
      exec "${VENV_DIR}/bin/uvicorn" api.app.main:app --app-dir backend --host 127.0.0.1 --port "$BACKEND_PORT" --reload
    ) > >(tee -a "$BACKEND_LOG_FILE" | sed -u 's/^/[backend] /') 2>&1 &
  fi

  BACKEND_PID=$!

  if ! wait_for_http "http://127.0.0.1:${BACKEND_PORT}/api/v1/health" 60; then
    printf 'Backend did not become ready on port %s.\n' "$BACKEND_PORT" >&2
    exit 1
  fi
}


start_frontend() {
  local api_base_url

  api_base_url="http://127.0.0.1:${BACKEND_PORT}/api/v1"

  if [[ "$DETACH" -eq 1 ]]; then
    (
      cd "${ROOT_DIR}/frontend"
      load_env_file "$FRONTEND_ENV_FILE"
      export API_BASE_URL="$api_base_url"
      export NEXT_PUBLIC_API_BASE_URL="$api_base_url"
      exec npm run dev -- --hostname 127.0.0.1 --port "$FRONTEND_PORT"
    ) >> "$FRONTEND_LOG_FILE" 2>&1 &
  else
    (
      cd "${ROOT_DIR}/frontend"
      load_env_file "$FRONTEND_ENV_FILE"
      export API_BASE_URL="$api_base_url"
      export NEXT_PUBLIC_API_BASE_URL="$api_base_url"
      exec npm run dev -- --hostname 127.0.0.1 --port "$FRONTEND_PORT"
    ) > >(tee -a "$FRONTEND_LOG_FILE" | sed -u 's/^/[frontend] /') 2>&1 &
  fi

  FRONTEND_PID=$!

  if ! wait_for_http "http://127.0.0.1:${FRONTEND_PORT}" 90; then
    printf 'Frontend did not become ready on port %s.\n' "$FRONTEND_PORT" >&2
    exit 1
  fi
}


print_summary() {
  printf '%s\n' ''
  printf '%s\n' 'Development environment is running.'
  printf '%s\n' "- frontend: http://127.0.0.1:${FRONTEND_PORT}"
  printf '%s\n' "- framework view: http://127.0.0.1:${FRONTEND_PORT}/framework"
  printf '%s\n' "- sample workflow: http://127.0.0.1:${FRONTEND_PORT}/workflows/bootstrap-scan"
  printf '%s\n' "- backend api: http://127.0.0.1:${BACKEND_PORT}/api/v1"
  printf '%s\n' "- backend docs: http://127.0.0.1:${BACKEND_PORT}/api/v1/docs"
  printf '%s\n' "- backend log: ${BACKEND_LOG_FILE}"
  printf '%s\n' "- frontend log: ${FRONTEND_LOG_FILE}"
  printf '%s\n' ''

  if [[ "$DETACH" -eq 1 ]]; then
    printf '%s\n' 'Use ./scripts/dev.sh --logs to follow logs and ./scripts/dev.sh --stop to stop services.'
  else
    printf '%s\n' 'Press Ctrl+C to stop the frontend and backend.'
  fi

  if [[ "$STARTED_POSTGRES" -eq 1 && "${DEV_KEEP_POSTGRES:-0}" != "1" ]]; then
    printf '%s\n' 'Postgres will also stop when this script exits.'
  elif [[ "$STARTED_POSTGRES" -eq 1 ]]; then
    printf '%s\n' 'Postgres will stay running because DEV_KEEP_POSTGRES=1.'
  else
    printf '%s\n' 'Postgres was already running before this script started.'
  fi

  printf '%s\n' ''
}


stop_pid() {
  local pid="$1"

  if ! pid_is_running "$pid"; then
    return
  fi

  kill "$pid" >/dev/null 2>&1 || true

  for _ in $(seq 1 20); do
    if ! pid_is_running "$pid"; then
      return
    fi
    sleep 0.5
  done

  kill -9 "$pid" >/dev/null 2>&1 || true
}


stop_stack() {
  if ! load_runtime_state; then
    printf '%s\n' 'No saved development runtime state was found.'
    return
  fi

  stop_pid "$BACKEND_PID"
  stop_pid "$FRONTEND_PID"

  if [[ "$STARTED_POSTGRES" -eq 1 && "${DEV_KEEP_POSTGRES:-0}" != "1" ]]; then
    docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
  fi

  clear_runtime_state
  printf '%s\n' 'Stopped saved development services.'
}


show_logs() {
  if [[ ! -f "$BACKEND_LOG_FILE" && ! -f "$FRONTEND_LOG_FILE" ]]; then
    printf '%s\n' 'No development log files were found.' >&2
    exit 1
  fi

  tail -n 40 -f "$BACKEND_LOG_FILE" "$FRONTEND_LOG_FILE"
}


show_status() {
  if ! load_runtime_state; then
    printf '%s\n' 'Development environment is not running.'
    return
  fi

  printf '%s\n' 'Development runtime state:'
  printf '%s\n' "- backend pid: ${BACKEND_PID}"
  printf '%s\n' "- frontend pid: ${FRONTEND_PID}"
  printf '%s\n' "- backend port: ${BACKEND_PORT}"
  printf '%s\n' "- frontend port: ${FRONTEND_PORT}"
  printf '%s\n' "- postgres started by script: ${STARTED_POSTGRES}"
}


ensure_not_running() {
  if ! load_runtime_state; then
    return
  fi

  if pid_is_running "$BACKEND_PID" || pid_is_running "$FRONTEND_PID"; then
    printf '%s\n' 'Development services are already running. Use ./scripts/dev.sh --stop first.' >&2
    exit 1
  fi

  clear_runtime_state
}


cleanup() {
  local exit_code=$?

  trap - EXIT INT TERM

  stop_pid "$BACKEND_PID"
  stop_pid "$FRONTEND_PID"

  if [[ "$STARTED_POSTGRES" -eq 1 && "${DEV_KEEP_POSTGRES:-0}" != "1" ]]; then
    docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
  fi

  clear_runtime_state
  exit "$exit_code"
}


start_stack() {
  require_command python3
  require_command npm
  require_command docker
  require_command sed
  require_command tee

  ensure_not_running
  ensure_file_from_example "$BACKEND_ENV_EXAMPLE" "$BACKEND_ENV_FILE"
  ensure_file_from_example "$FRONTEND_ENV_EXAMPLE" "$FRONTEND_ENV_FILE"

  ensure_backend_runtime
  ensure_frontend_runtime
  prepare_log_files

  BACKEND_PORT="${BACKEND_PORT:-$(pick_free_port 8000)}"
  FRONTEND_PORT="${FRONTEND_PORT:-$(pick_free_port 3000)}"

  trap cleanup EXIT INT TERM

  start_postgres
  start_backend
  start_frontend
  write_runtime_state
  print_summary

  if [[ "$DETACH" -eq 1 ]]; then
    trap - EXIT INT TERM
    exit 0
  fi

  wait -n "$BACKEND_PID" "$FRONTEND_PID"
}


main() {
  parse_args "$@"

  case "$MODE" in
    start)
      start_stack
      ;;
    stop)
      stop_stack
      ;;
    logs)
      show_logs
      ;;
    status)
      show_status
      ;;
  esac
}


main "$@"
