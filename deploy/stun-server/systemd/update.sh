#!/usr/bin/env bash
set -euo pipefail

JAR_SRC="${1:-}"
ENV_SRC="${2:-}"
SERVICE="stun-server"
INSTALL_DIR="/opt/shuai-stun-server"
JAR_DEST="$INSTALL_DIR/stun-server.jar"
CONFIG_DIR="/etc/shuai-stun-server"
ENV_DEST="$CONFIG_DIR/stun-server.env"
UNIT_DEST="/etc/systemd/system/stun-server.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_KEEP="${STUN_BACKUP_KEEP:-5}"
ACTIVE_TIMEOUT_SEC="${STUN_ACTIVE_TIMEOUT_SEC:-20}"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
fail() { printf '[%s] [ERR] %s\n' "$(date '+%F %T')" "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
  fail "请使用 root 或 sudo 运行"
  exit 1
fi
if [[ -z "$JAR_SRC" || ! -f "$JAR_SRC" ]]; then
  fail "用法: $0 /path/to/stun-server.jar [/path/to/stun-server.env]"
  exit 1
fi
if [[ ! -f "$JAR_DEST" ]]; then
  fail "$JAR_DEST 不存在，请先运行 install.sh"
  exit 1
fi
if [[ ! "$BACKUP_KEEP" =~ ^[1-9][0-9]*$ ]]; then
  fail "STUN_BACKUP_KEEP 必须是正整数"
  exit 1
fi
if [[ ! "$ACTIVE_TIMEOUT_SEC" =~ ^[1-9][0-9]*$ ]]; then
  fail "STUN_ACTIVE_TIMEOUT_SEC 必须是正整数"
  exit 1
fi
if [[ -z "$ENV_SRC" ]]; then
  ENV_SRC="$ENV_DEST"
fi
if [[ ! -f "$ENV_SRC" ]]; then
  fail "配置文件不存在: $ENV_SRC"
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
      fail "$env_path:$line_number 包含不安全或不受支持的配置语法"
      return 1
    fi
  done < "$env_path"
}

check_config() {
  local jar_path="$1"
  local env_path="$2"
  validate_env_file "$env_path"
  (
    set -a
    # shellcheck disable=SC1090
    source "$env_path"
    set +a
    # shellcheck disable=SC2086
    java ${JAVA_OPTS:-} -jar "$jar_path" --check-config
  )
}

check_metrics() {
  local env_path="$1"
  local metrics_address metrics_port metrics_host
  metrics_address="$(
    set -a
    # shellcheck disable=SC1090
    source "$env_path"
    set +a
    printf '%s' "${STUN_METRICS_BIND_ADDRESS:-127.0.0.1}"
  )"
  metrics_port="$(
    set -a
    # shellcheck disable=SC1090
    source "$env_path"
    set +a
    printf '%s' "${STUN_METRICS_PORT:-9108}"
  )"
  [[ "$metrics_port" == "0" ]] && return 0
  if ! command -v curl >/dev/null 2>&1; then
    log "未找到 curl，跳过 Prometheus 指标检查"
    return 0
  fi
  metrics_host="$metrics_address"
  [[ "$metrics_address" == *:* ]] && metrics_host="[$metrics_address]"
  grep -q '^stun_uptime_seconds ' < <(
    curl --noproxy '*' -fsS --max-time 3 \
      "http://${metrics_host}:${metrics_port}/metrics" 2>/dev/null
  )
}

wait_until_healthy() {
  local env_path="$1"
  local deadline=$((SECONDS + ACTIVE_TIMEOUT_SEC))
  while (( SECONDS < deadline )); do
    if systemctl is-active --quiet "$SERVICE" && check_metrics "$env_path"; then
      sleep 1
      if systemctl is-active --quiet "$SERVICE" && check_metrics "$env_path"; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

java -jar "$JAR_SRC" --help >/dev/null
check_config "$JAR_SRC" "$ENV_SRC"
WAS_ACTIVE="false"
if systemctl is-active --quiet "$SERVICE"; then
  WAS_ACTIVE="true"
fi

UPDATE_ENV="true"
if [[ "$(readlink -f "$ENV_SRC")" == "$(readlink -f "$ENV_DEST")" ]]; then
  UPDATE_ENV="false"
fi

TS="$(date +%Y%m%d-%H%M%S)-$$"
BACKUP_ROOT="$INSTALL_DIR/backups"
BACKUP_DIR="$BACKUP_ROOT/$TS"
install -d -m 0750 -o root -g stun "$BACKUP_DIR"
install -m 0644 -o root -g root "$JAR_DEST" "$BACKUP_DIR/stun-server.jar"
install -m 0640 -o root -g stun "$ENV_DEST" "$BACKUP_DIR/stun-server.env"
HAD_UNIT="false"
if [[ -f "$UNIT_DEST" ]]; then
  HAD_UNIT="true"
  install -m 0644 -o root -g root "$UNIT_DEST" "$BACKUP_DIR/stun-server.service"
fi
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' \
  | sort -nr \
  | tail -n +$((BACKUP_KEEP + 1)) \
  | cut -d' ' -f2- \
  | xargs -r rm -rf --

rollback() {
  fail "更新失败，回滚到 $BACKUP_DIR"
  systemctl stop "$SERVICE" || true
  install -m 0644 -o root -g root \
          "$BACKUP_DIR/stun-server.jar" "$JAR_DEST"
  install -m 0640 -o root -g stun \
          "$BACKUP_DIR/stun-server.env" "$ENV_DEST"
  if [[ -f "$BACKUP_DIR/stun-server.service" ]]; then
    install -m 0644 -o root -g root \
            "$BACKUP_DIR/stun-server.service" "$UNIT_DEST"
  elif [[ "$HAD_UNIT" == "false" ]]; then
    rm -f -- "$UNIT_DEST"
  fi
  systemctl daemon-reload
  if [[ "$WAS_ACTIVE" == "true" ]]; then
    if ! systemctl start "$SERVICE" || ! wait_until_healthy "$ENV_DEST"; then
      systemctl stop "$SERVICE" || true
      fail "旧版本也无法恢复健康，请立即检查 journalctl -u $SERVICE"
    fi
  else
    log "部署前服务未运行，已恢复文件并保持停止状态"
  fi
  exit 2
}

systemctl stop "$SERVICE" || true
if ! bash "$SCRIPT_DIR/check-ports.sh" "$ENV_SRC"; then
  rollback
fi
install -m 0644 -o root -g root "$JAR_SRC" "$JAR_DEST" || rollback
if [[ "$UPDATE_ENV" == "true" ]]; then
  install -m 0640 -o root -g stun "$ENV_SRC" "$ENV_DEST" || rollback
fi
install -m 0644 -o root -g root \
        "$SCRIPT_DIR/stun-server.service" "$UNIT_DEST" || rollback
install -m 0640 -o root -g stun \
        "$SCRIPT_DIR/stun-server.env.example" \
        "$CONFIG_DIR/stun-server.env.example" || rollback
systemctl daemon-reload || rollback
systemctl start "$SERVICE" || rollback

if wait_until_healthy "$ENV_DEST"; then
  log "更新成功；配置、JAR 和 unit 的备份位于 $BACKUP_DIR"
  exit 0
fi

rollback
