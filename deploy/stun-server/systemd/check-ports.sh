#!/usr/bin/env bash
set -euo pipefail

ENV_SRC="${1:-}"
ALLOW_SERVICE=""
if [[ "${2:-}" == "--allow-service" ]]; then
  ALLOW_SERVICE="${3:-}"
fi

if [[ $EUID -ne 0 ]]; then
  echo "[ERR] 请使用 root 或 sudo 运行端口检查" >&2
  exit 1
fi
if [[ -z "$ENV_SRC" || ! -f "$ENV_SRC" ]]; then
  echo "用法: $0 /path/to/stun-server.env [--allow-service service-name]" >&2
  exit 1
fi
if ! command -v ss >/dev/null 2>&1; then
  echo "[ERR] 未找到 ss，无法执行部署前端口检查" >&2
  exit 1
fi

validate_env_file() {
  local env_path="$1"
  local line line_number=0
  local assignment_pattern='^[A-Z][A-Z0-9_]*=([A-Za-z0-9._:/+@=-]*|"[A-Za-z0-9 ._:/+=-]*")$'
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ ! "$line" =~ $assignment_pattern ]]; then
      echo "[ERR] $env_path:$line_number 包含不安全或不受支持的配置语法" >&2
      return 1
    fi
  done < "$env_path"
}

validate_port() {
  local name="$1"
  local value="$2"
  local allow_zero="${3:-false}"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value > 65535 )); then
    echo "[ERR] $name 不是有效端口: $value" >&2
    return 1
  fi
  if [[ "$allow_zero" != "true" && "$value" == "0" ]]; then
    echo "[ERR] $name 不能为 0" >&2
    return 1
  fi
}

listener_owned_by_service() {
  local listeners="$1"
  local allowed_pid="$2"
  local line token pid saw_pid
  [[ "$allowed_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    saw_pid="false"
    while IFS= read -r token; do
      [[ -z "$token" ]] && continue
      saw_pid="true"
      pid="${token#pid=}"
      [[ "$pid" == "$allowed_pid" ]] || return 1
    done < <(grep -oE 'pid=[0-9]+' <<<"$line" || true)
    [[ "$saw_pid" == "true" ]] || return 1
  done <<<"$listeners"
  return 0
}

check_port() {
  local protocol="$1"
  local port="$2"
  local allowed_pid="$3"
  local listeners
  if [[ "$protocol" == "udp" ]]; then
    listeners="$(ss -H -lunp "sport = :$port" 2>/dev/null || true)"
  else
    listeners="$(ss -H -ltnp "sport = :$port" 2>/dev/null || true)"
  fi
  [[ -n "$listeners" ]] || return 0
  if listener_owned_by_service "$listeners" "$allowed_pid"; then
    return 0
  fi
  echo "[ERR] $protocol/$port 已被其他进程占用:" >&2
  printf '%s\n' "$listeners" >&2
  return 1
}

validate_env_file "$ENV_SRC"
set -a
# shellcheck disable=SC1090
source "$ENV_SRC"
set +a

primary_port="${STUN_PRIMARY_PORT:-3478}"
alternate_port="${STUN_ALTERNATE_PORT:-3479}"
metrics_port="${STUN_METRICS_PORT:-9108}"
validate_port STUN_PRIMARY_PORT "$primary_port"
validate_port STUN_ALTERNATE_PORT "$alternate_port" true
validate_port STUN_METRICS_PORT "$metrics_port" true

allowed_pid=0
if [[ -n "$ALLOW_SERVICE" ]]; then
  allowed_pid="$(systemctl show "$ALLOW_SERVICE" --property=MainPID --value 2>/dev/null || true)"
  [[ "$allowed_pid" =~ ^[1-9][0-9]*$ ]] || allowed_pid=0
fi

declare -A checked_udp=()
for port in "$primary_port" "$alternate_port"; do
  [[ "$port" == "0" || -n "${checked_udp[$port]:-}" ]] && continue
  checked_udp[$port]=1
  check_port udp "$port" "$allowed_pid"
done
case "${STUN_DISTRIBUTED_ENABLED:-false}" in
  1|true|TRUE|yes|YES|on|ON)
    control_port="${STUN_DISTRIBUTED_CONTROL_PORT:-3480}"
    validate_port STUN_DISTRIBUTED_CONTROL_PORT "$control_port"
    if [[ -z "${checked_udp[$control_port]:-}" ]]; then
      check_port udp "$control_port" "$allowed_pid"
    fi
    ;;
esac
if [[ "$metrics_port" != "0" ]]; then
  check_port tcp "$metrics_port" "$allowed_pid"
fi

echo "[OK] STUN 配置端口可用"
