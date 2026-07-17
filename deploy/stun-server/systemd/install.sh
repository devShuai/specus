#!/usr/bin/env bash
set -euo pipefail

JAR_SRC="${1:-}"
ENV_SRC="${2:-}"
APP_USER="stun"
APP_GROUP="stun"
INSTALL_DIR="/opt/shuai-stun-server"
CONFIG_DIR="/etc/shuai-stun-server"
DATA_DIR="/var/lib/shuai-stun-server"
SERVICE="stun-server"
ENV_FILE="$CONFIG_DIR/stun-server.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTIVE_TIMEOUT_SEC="${STUN_ACTIVE_TIMEOUT_SEC:-20}"

if [[ $EUID -ne 0 ]]; then
  echo "[ERR] 请使用 root 或 sudo 运行" >&2
  exit 1
fi
if [[ -z "$JAR_SRC" || ! -f "$JAR_SRC" ]]; then
  echo "用法: $0 /path/to/stun-server.jar [/path/to/stun-server.env]" >&2
  exit 1
fi
if [[ -n "$ENV_SRC" && ! -f "$ENV_SRC" ]]; then
  echo "[ERR] 配置文件不存在: $ENV_SRC" >&2
  exit 1
fi
if ! command -v java >/dev/null 2>&1; then
  echo "[ERR] 未找到 Java 21+" >&2
  exit 1
fi
if [[ ! "$ACTIVE_TIMEOUT_SEC" =~ ^[1-9][0-9]*$ ]]; then
  echo "[ERR] STUN_ACTIVE_TIMEOUT_SEC 必须是正整数" >&2
  exit 1
fi

JAVA_MAJOR="$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | awk -F. '{print $1}')"
if [[ "${JAVA_MAJOR:-0}" -lt 21 ]]; then
  echo "[ERR] 需要 Java 21+，当前版本 ${JAVA_MAJOR:-unknown}" >&2
  exit 1
fi

java -jar "$JAR_SRC" --help >/dev/null

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

check_config() {
  local jar_path="$1"
  local env_path="$2"
  validate_env_file "$env_path"
  (
    set -a
    # The deployment env is root-owned input and is also consumed by systemd.
    # shellcheck disable=SC1090
    source "$env_path"
    set +a
    # JAVA_OPTS is intentionally split into JVM arguments.
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
    echo "[WARN] 未找到 curl，跳过 Prometheus 指标检查"
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

if [[ -n "$ENV_SRC" ]]; then
  check_config "$JAR_SRC" "$ENV_SRC"
  bash "$SCRIPT_DIR/check-ports.sh" "$ENV_SRC" --allow-service "$SERVICE"
fi

if ! getent group "$APP_GROUP" >/dev/null; then
  groupadd --system "$APP_GROUP"
fi
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --gid "$APP_GROUP" --home-dir "$DATA_DIR" \
          --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 0755 -o root -g root "$INSTALL_DIR"
install -d -m 0750 -o root -g "$APP_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$DATA_DIR"
install -m 0644 -o root -g root "$JAR_SRC" "$INSTALL_DIR/stun-server.jar"
install -m 0644 -o root -g root "$SCRIPT_DIR/stun-server.service" \
        /etc/systemd/system/stun-server.service
install -m 0640 -o root -g "$APP_GROUP" \
        "$SCRIPT_DIR/stun-server.env.example" "$CONFIG_DIR/stun-server.env.example"

if [[ -n "$ENV_SRC" ]]; then
  install -m 0640 -o root -g "$APP_GROUP" "$ENV_SRC" "$ENV_FILE"
  echo "[OK] 已安装节点配置 $ENV_FILE"
elif [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 -o root -g "$APP_GROUP" \
          "$SCRIPT_DIR/stun-server.env.example" "$ENV_FILE"
  echo "[OK] 已创建 $ENV_FILE，请先填写真实 IP"
else
  echo "[--] 保留已有 $ENV_FILE"
fi

systemctl daemon-reload
systemctl enable stun-server.service >/dev/null

if [[ -n "$ENV_SRC" ]]; then
  systemctl restart "$SERVICE"
  if ! wait_until_healthy "$ENV_FILE"; then
    echo "[ERR] STUN 服务安装后未通过健康检查" >&2
    systemctl --no-pager --full status "$SERVICE" || true
    journalctl -u "$SERVICE" -n 80 --no-pager || true
    systemctl stop "$SERVICE" || true
    systemctl reset-failed "$SERVICE" || true
    exit 2
  fi
  echo "[OK] 独立 STUN server 已安装并启动"
  exit 0
fi

cat <<EOF
[OK] 独立 STUN server 已安装，但尚未启动。

1. 编辑节点配置：
   sudo vim $ENV_FILE
2. 选择单机四端点或 Java 双节点模式，并按配置放行 P1/P2 公网 UDP 端口。
   双节点模式还需仅在两台服务器内网之间放行 3480/udp。
3. 启动：
   sudo systemctl start stun-server
   sudo systemctl status stun-server
   sudo journalctl -u stun-server -f
EOF
