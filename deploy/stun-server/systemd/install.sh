#!/usr/bin/env bash
set -euo pipefail

JAR_SRC="${1:-}"
APP_USER="stun"
APP_GROUP="stun"
INSTALL_DIR="/opt/shuai-stun-server"
CONFIG_DIR="/etc/shuai-stun-server"
DATA_DIR="/var/lib/shuai-stun-server"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "[ERR] 请使用 root 或 sudo 运行" >&2
  exit 1
fi
if [[ -z "$JAR_SRC" || ! -f "$JAR_SRC" ]]; then
  echo "用法: $0 /path/to/stun-server.jar" >&2
  exit 1
fi
if ! command -v java >/dev/null 2>&1; then
  echo "[ERR] 未找到 Java 21+" >&2
  exit 1
fi

JAVA_MAJOR="$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | awk -F. '{print $1}')"
if [[ "${JAVA_MAJOR:-0}" -lt 21 ]]; then
  echo "[ERR] 需要 Java 21+，当前版本 ${JAVA_MAJOR:-unknown}" >&2
  exit 1
fi

java -jar "$JAR_SRC" --help >/dev/null

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

ENV_FILE="$CONFIG_DIR/stun-server.env"
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 -o root -g "$APP_GROUP" \
          "$SCRIPT_DIR/stun-server.env.example" "$ENV_FILE"
  echo "[OK] 已创建 $ENV_FILE，请先填写真实 IP"
else
  echo "[--] 保留已有 $ENV_FILE"
fi

systemctl daemon-reload
systemctl enable stun-server.service >/dev/null

cat <<EOF
[OK] 独立 STUN server 已安装，但尚未启动。

1. 编辑四端点配置：
   sudo vim $ENV_FILE
2. 检查本机已配置两个 bind IP，并放行两个公网 IP 上的 3478/udp、3479/udp。
3. 启动：
   sudo systemctl start stun-server
   sudo systemctl status stun-server
   sudo journalctl -u stun-server -f
EOF
