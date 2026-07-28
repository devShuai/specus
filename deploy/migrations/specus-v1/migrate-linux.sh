#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
APPLY=false
REWRITE_DOMAIN=false
IMPLEMENTATION=""
ARTIFACT=""
CONFIG_PATHS=()
SQLITE_DATABASES=()

usage() {
  cat <<'EOF'
Usage:
  migrate-linux.sh [options]

Options:
  --implementation java|go|csharp
                              Migrate the matching systemd service and runtime layout.
  --artifact PATH             New Java JAR, Go binary, or .NET publish directory.
                              Required with --apply and --implementation.
  --config PATH               Migrate one config file; repeat as needed.
  --sqlite PATH               Migrate one SQLite database; repeat as needed.
  --rewrite-domain            Replace the legacy public hostname with
                              specus.devshuai.com.
  --apply                     Execute. Without this flag the script only plans.
  -h, --help                  Show this help.

PostgreSQL and MySQL are migrated separately with database/postgresql.sql and
database/mysql.sql so credentials never need to be passed through this script.
EOF
}

while (($# > 0)); do
  case "$1" in
    --implementation)
      IMPLEMENTATION="${2:?missing implementation}"
      shift 2
      ;;
    --config)
      CONFIG_PATHS+=("${2:?missing config path}")
      shift 2
      ;;
    --artifact)
      ARTIFACT="${2:?missing artifact path}"
      shift 2
      ;;
    --sqlite)
      SQLITE_DATABASES+=("${2:?missing SQLite path}")
      shift 2
      ;;
    --rewrite-domain)
      REWRITE_DOMAIN=true
      shift
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

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for configuration and SQLite migration." >&2
  exit 1
fi

OLD_SERVICE=""
NEW_SERVICE=""
UNIT_SOURCE=""
OLD_ETC=""
NEW_ETC=""
OLD_OPT=""
NEW_OPT=""
OLD_VAR=""
NEW_VAR=""
OLD_LOG=""
NEW_LOG=""
ARTIFACT_KIND=""
ARTIFACT_DESTINATION=""

case "${IMPLEMENTATION}" in
  "")
    ;;
  java)
    OLD_SERVICE="tunnel-server"
    NEW_SERVICE="specus-server"
    UNIT_SOURCE="${REPO_ROOT}/deploy/java-server/systemd/specus-server.service"
    OLD_ETC="/etc/tunnel-server"
    NEW_ETC="/etc/specus-server"
    OLD_OPT="/opt/tunnel-server"
    NEW_OPT="/opt/specus-server"
    OLD_VAR="/var/lib/tunnel-server"
    NEW_VAR="/var/lib/specus-server"
    OLD_LOG="/var/log/tunnel-server"
    NEW_LOG="/var/log/specus-server"
    ARTIFACT_KIND="file"
    ARTIFACT_DESTINATION="${NEW_OPT}/specus-server.jar"
    ;;
  go)
    OLD_SERVICE="tunnel-server-go"
    NEW_SERVICE="specus-server-go"
    UNIT_SOURCE="${REPO_ROOT}/deploy/go-server/systemd/specus-server-go.service"
    OLD_ETC="/etc/tunnel-server-go"
    NEW_ETC="/etc/specus-server-go"
    OLD_OPT="/opt/tunnel-server-go"
    NEW_OPT="/opt/specus-server-go"
    OLD_VAR="/var/lib/tunnel-server-go"
    NEW_VAR="/var/lib/specus-server-go"
    OLD_LOG="/var/log/tunnel-server-go"
    NEW_LOG="/var/log/specus-server-go"
    ARTIFACT_KIND="executable"
    ARTIFACT_DESTINATION="${NEW_OPT}/specus-server"
    ;;
  csharp)
    OLD_SERVICE="tunnel-server-csharp"
    NEW_SERVICE="specus-server-csharp"
    UNIT_SOURCE="${REPO_ROOT}/deploy/csharp-server/systemd/specus-server-csharp.service"
    OLD_ETC="/etc/tunnel-server-csharp"
    NEW_ETC="/etc/specus-server-csharp"
    OLD_OPT="/opt/tunnel-server-csharp"
    NEW_OPT="/opt/specus-server-csharp"
    OLD_VAR="/var/lib/tunnel-server-csharp"
    NEW_VAR="/var/lib/specus-server-csharp"
    OLD_LOG="/var/log/tunnel-server-csharp"
    NEW_LOG="/var/log/specus-server-csharp"
    ARTIFACT_KIND="directory"
    ARTIFACT_DESTINATION="${NEW_OPT}/Specus.Server.dll"
    ;;
  *)
    echo "Unsupported implementation: ${IMPLEMENTATION}" >&2
    exit 2
    ;;
esac

if [[ -n "${ARTIFACT}" && -z "${IMPLEMENTATION}" ]]; then
  echo "--artifact requires --implementation." >&2
  exit 2
fi

if "${APPLY}" && [[ -n "${IMPLEMENTATION}" && -z "${ARTIFACT}" ]]; then
  echo "--artifact is required when applying a systemd implementation migration." >&2
  exit 2
fi

if [[ -n "${ARTIFACT}" ]]; then
  if [[ "${ARTIFACT_KIND}" = "directory" && ! -d "${ARTIFACT}" ]]; then
    echo ".NET publish directory not found: ${ARTIFACT}" >&2
    exit 1
  elif [[ "${ARTIFACT_KIND}" != "directory" && ! -f "${ARTIFACT}" ]]; then
    echo "Release artifact not found: ${ARTIFACT}" >&2
    exit 1
  fi
fi

print_command() {
  printf 'PLAN:'
  printf ' %q' "$@"
  printf '\n'
}

run() {
  if "${APPLY}"; then
    "$@"
  else
    print_command "$@"
  fi
}

move_layout() {
  local source="$1"
  local destination="$2"
  if [[ ! -e "${source}" ]]; then
    return
  fi
  if [[ -e "${destination}" ]]; then
    echo "Cannot move ${source}: ${destination} already exists." >&2
    exit 1
  fi
  run mv -- "${source}" "${destination}"
}

if [[ -n "${IMPLEMENTATION}" ]]; then
  if [[ ! -f "${UNIT_SOURCE}" ]]; then
    echo "New systemd unit not found: ${UNIT_SOURCE}" >&2
    exit 1
  fi
  for pair in \
    "${OLD_ETC}|${NEW_ETC}" \
    "${OLD_VAR}|${NEW_VAR}" \
    "${OLD_LOG}|${NEW_LOG}"; do
    source_path="${pair%%|*}"
    destination_path="${pair#*|}"
    if [[ -e "${source_path}" && -e "${destination_path}" ]]; then
      echo "Layout conflict: both ${source_path} and ${destination_path} exist." >&2
      exit 1
    fi
  done
  if [[ -e "${NEW_OPT}" ]]; then
    echo "Runtime conflict: ${NEW_OPT} already exists." >&2
    exit 1
  fi

  default_env="${OLD_ETC}/tunnel-server.env"
  if [[ -f "${default_env}" && ${#CONFIG_PATHS[@]} -eq 0 ]]; then
    CONFIG_PATHS+=("${default_env}")
  fi
  if [[ ${#SQLITE_DATABASES[@]} -eq 0 ]]; then
    for candidate in \
      "${OLD_VAR}/shuai-tunnel.db" \
      "${OLD_VAR}/shuai-specus.db" \
      "${OLD_VAR}/tunnel-server.db"; do
      if [[ -f "${candidate}" ]]; then
        SQLITE_DATABASES+=("${candidate}")
      fi
    done
  fi
fi

if "${APPLY}" && [[ -n "${IMPLEMENTATION}" && "${EUID}" -ne 0 ]]; then
  echo "--apply with --implementation must run as root." >&2
  exit 1
fi

if [[ -n "${IMPLEMENTATION}" ]]; then
  if systemctl is-active --quiet "${OLD_SERVICE}" 2>/dev/null; then
    run systemctl stop "${OLD_SERVICE}"
  fi
  if systemctl is-active --quiet "${NEW_SERVICE}" 2>/dev/null; then
    run systemctl stop "${NEW_SERVICE}"
  fi
fi

if ((${#CONFIG_PATHS[@]} > 0)); then
  env_args=("${SCRIPT_DIR}/migrate_env.py" "${CONFIG_PATHS[@]}" "--rename-files")
  if "${REWRITE_DOMAIN}"; then
    env_args+=("--rewrite-domain")
  fi
  if "${APPLY}"; then
    env_args+=("--apply")
  fi
  python3 "${env_args[@]}"
fi

for database in "${SQLITE_DATABASES[@]}"; do
  sqlite_args=("${SCRIPT_DIR}/database/migrate_sqlite.py" "${database}")
  if "${APPLY}"; then
    sqlite_args+=("--apply")
  fi
  python3 "${sqlite_args[@]}"
done

if [[ -n "${IMPLEMENTATION}" ]]; then
  move_layout "${OLD_ETC}" "${NEW_ETC}"
  move_layout "${OLD_VAR}" "${NEW_VAR}"
  move_layout "${OLD_LOG}" "${NEW_LOG}"

  if ! getent group specus >/dev/null 2>&1; then
    run groupadd --system specus
  fi
  if ! id -u specus >/dev/null 2>&1; then
    run useradd --system --gid specus --home-dir "${NEW_VAR}" \
      --shell /usr/sbin/nologin specus
  fi
  for directory in "${NEW_ETC}" "${NEW_VAR}" "${NEW_LOG}"; do
    if [[ -d "${directory}" ]]; then
      run chown -R specus:specus "${directory}"
    fi
  done

  run install -d -m 0755 -o root -g root "${NEW_OPT}"
  if [[ -n "${ARTIFACT}" ]]; then
    case "${ARTIFACT_KIND}" in
      file)
        run install -m 0644 "${ARTIFACT}" "${ARTIFACT_DESTINATION}"
        ;;
      executable)
        run install -m 0755 "${ARTIFACT}" "${ARTIFACT_DESTINATION}"
        ;;
      directory)
        run cp -a -- "${ARTIFACT}/." "${NEW_OPT}/"
        run chown -R root:root "${NEW_OPT}"
        ;;
    esac
  else
    echo "PLAN: supply --artifact before applying this migration"
  fi

  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_dir="/var/backups/specus-migration/${stamp}"
  old_unit="/etc/systemd/system/${OLD_SERVICE}.service"
  if [[ -f "${old_unit}" ]]; then
    run install -d -m 0700 "${backup_dir}"
    run cp -a "${old_unit}" "${backup_dir}/"
  fi
  run install -m 0644 "${UNIT_SOURCE}" \
    "/etc/systemd/system/${NEW_SERVICE}.service"
  if [[ -f "${old_unit}" ]]; then
    run systemctl disable "${OLD_SERVICE}"
    run rm -f -- "${old_unit}"
  fi
  run systemctl daemon-reload
  run systemctl enable "${NEW_SERVICE}"
  if "${APPLY}" && [[ ! -f "${ARTIFACT_DESTINATION}" ]]; then
    echo "Installed entry point is missing: ${ARTIFACT_DESTINATION}" >&2
    exit 1
  fi
  run systemctl start "${NEW_SERVICE}"
  if "${APPLY}"; then
    systemctl --no-pager --full status "${NEW_SERVICE}"
  fi
fi

if ! "${APPLY}"; then
  echo "Plan completed. Re-run with --apply during a service maintenance window."
fi
