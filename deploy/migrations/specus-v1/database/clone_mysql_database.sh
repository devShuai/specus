#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DATABASE=""
DESTINATION_DATABASE="specus"
HOST=""
PORT=""
USER_NAME=""
LOGIN_PATH=""
SOCKET=""
APPLY=false

usage() {
  cat <<'EOF'
Usage:
  clone_mysql_database.sh --source NAME [options]

Options:
  --source NAME            Existing database to clone.
  --destination NAME       New database name (default: specus).
  --host HOST              MySQL host.
  --port PORT              MySQL TCP port.
  --user USER              MySQL user.
  --login-path NAME        mysql_config_editor login path.
  --socket PATH            MySQL Unix socket.
  --apply                  Create and migrate the destination database.
  -h, --help               Show this help.

Authentication uses normal MySQL client mechanisms such as ~/.my.cnf,
--login-path, or MYSQL_PWD. Passwords are never accepted as command arguments.
The source database is retained for rollback.
EOF
}

while (($# > 0)); do
  case "$1" in
    --source)
      SOURCE_DATABASE="${2:?missing source database}"
      shift 2
      ;;
    --destination)
      DESTINATION_DATABASE="${2:?missing destination database}"
      shift 2
      ;;
    --host)
      HOST="${2:?missing host}"
      shift 2
      ;;
    --port)
      PORT="${2:?missing port}"
      shift 2
      ;;
    --user)
      USER_NAME="${2:?missing user}"
      shift 2
      ;;
    --login-path)
      LOGIN_PATH="${2:?missing login path}"
      shift 2
      ;;
    --socket)
      SOCKET="${2:?missing socket}"
      shift 2
      ;;
    --apply)
      APPLY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${SOURCE_DATABASE}" ]]; then
  echo "--source is required." >&2
  exit 2
fi
for identifier in "${SOURCE_DATABASE}" "${DESTINATION_DATABASE}"; do
  if [[ ! "${identifier}" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "Unsafe database identifier: ${identifier}" >&2
    exit 2
  fi
done
if ! command -v mysql >/dev/null 2>&1 || ! command -v mysqldump >/dev/null 2>&1; then
  echo "mysql and mysqldump are required." >&2
  exit 1
fi

MYSQL_ARGS=()
if [[ -n "${LOGIN_PATH}" ]]; then MYSQL_ARGS+=("--login-path=${LOGIN_PATH}"); fi
if [[ -n "${HOST}" ]]; then MYSQL_ARGS+=("--host=${HOST}"); fi
if [[ -n "${PORT}" ]]; then MYSQL_ARGS+=("--port=${PORT}"); fi
if [[ -n "${USER_NAME}" ]]; then MYSQL_ARGS+=("--user=${USER_NAME}"); fi
if [[ -n "${SOCKET}" ]]; then MYSQL_ARGS+=("--socket=${SOCKET}"); fi

source_count="$(
  mysql "${MYSQL_ARGS[@]}" --batch --skip-column-names \
    --execute="SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${SOURCE_DATABASE}'"
)"
destination_count="$(
  mysql "${MYSQL_ARGS[@]}" --batch --skip-column-names \
    --execute="SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='${DESTINATION_DATABASE}'"
)"
if [[ "${source_count}" != "1" ]]; then
  echo "Source database does not exist: ${SOURCE_DATABASE}" >&2
  exit 1
fi
if [[ "${destination_count}" != "0" ]]; then
  echo "Destination database already exists: ${DESTINATION_DATABASE}" >&2
  exit 1
fi

read -r source_charset source_collation < <(
  mysql "${MYSQL_ARGS[@]}" --batch --skip-column-names \
    --execute="SELECT default_character_set_name, default_collation_name FROM information_schema.schemata WHERE schema_name='${SOURCE_DATABASE}'"
)
if [[ ! "${source_charset}" =~ ^[A-Za-z0-9_]+$ \
   || ! "${source_collation}" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "Unsafe source database character-set metadata." >&2
  exit 1
fi

if ! "${APPLY}"; then
  echo "PLAN: create ${DESTINATION_DATABASE} with ${source_charset}/${source_collation}"
  echo "PLAN: clone ${SOURCE_DATABASE} to ${DESTINATION_DATABASE}"
  echo "PLAN: apply mysql.sql inside ${DESTINATION_DATABASE}"
  echo "Plan only; rerun with --apply."
  exit 0
fi

mysql "${MYSQL_ARGS[@]}" --execute="$(
  printf 'CREATE DATABASE `%s` CHARACTER SET %s COLLATE %s' \
    "${DESTINATION_DATABASE}" "${source_charset}" "${source_collation}"
)"

mysqldump "${MYSQL_ARGS[@]}" \
  --single-transaction \
  --routines \
  --events \
  --triggers \
  --hex-blob \
  "${SOURCE_DATABASE}" \
  | mysql "${MYSQL_ARGS[@]}" "${DESTINATION_DATABASE}"

mysql "${MYSQL_ARGS[@]}" "${DESTINATION_DATABASE}" < "${SCRIPT_DIR}/mysql.sql"

old_schema_objects="$(
  mysql "${MYSQL_ARGS[@]}" --batch --skip-column-names \
    --execute="SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DESTINATION_DATABASE}' AND LOWER(table_name) LIKE '%tunnel%'"
)"
if [[ "${old_schema_objects}" != "0" ]]; then
  echo "Migration verification failed: legacy table names remain." >&2
  exit 1
fi

echo "database=${DESTINATION_DATABASE}"
echo "rollback_database=${SOURCE_DATABASE}"
