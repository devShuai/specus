#!/usr/bin/env bash
set -euo pipefail

# Go server first-time install
# Usage: sudo bash install.sh <path-to-binary>

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"

BINARY="${1:-${REPO_ROOT}/implementations/go/server/specus-server}"
SERVICE_NAME="specus-server-go"
INSTALL_DIR="/opt/specus-server-go"
CONFIG_DIR="/etc/specus-server-go"
DATA_DIR="/var/lib/specus-server-go"
LOG_DIR="/var/log/specus-server-go"
LOG_FILE="$LOG_DIR/specus-server.log"
LOGROTATE_CONFIG="/etc/logrotate.d/specus-server-go"
USER="specus"
GROUP="specus"

if [[ $EUID -ne 0 ]]; then
  echo "请以 root 身份运行" >&2
  exit 1
fi

if [[ ! -f "$BINARY" ]]; then
  echo "二进制文件不存在: $BINARY" >&2
  echo "请先编译: cd implementations/go/server && go generate ./web && go build -o specus-server ./cmd/specus-server" >&2
  exit 1
fi
ELF_MAGIC="$(LC_ALL=C od -An -tx1 -N4 "$BINARY" | tr -d '[:space:]')"
if [[ "$ELF_MAGIC" != "7f454c46" ]]; then
  echo "部署文件不是 Linux ELF 二进制: $BINARY" >&2
  exit 1
fi

# Create system user
if ! id -u "$USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

# Create directories
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0750 "$CONFIG_DIR" -o root -g "$GROUP"
install -d -m 0750 "$DATA_DIR" -o "$USER" -g "$GROUP"
install -d -m 0750 "$LOG_DIR" -o "$USER" -g "$GROUP"
touch "$LOG_FILE"
chown "$USER:$GROUP" "$LOG_FILE"
chmod 0640 "$LOG_FILE"

# Install binary
install -m 0755 "$BINARY" "$INSTALL_DIR/specus-server"

# Install env template (never overwrite live env)
install -m 0644 -o root -g root \
  "$SCRIPT_DIR/specus-server.env.example" "$CONFIG_DIR/specus-server.env.example"
if [[ ! -f "$CONFIG_DIR/specus-server.env" ]]; then
  install -m 0640 -o root -g "$GROUP" \
    "$SCRIPT_DIR/specus-server.env.example" "$CONFIG_DIR/specus-server.env"
  echo "已创建 $CONFIG_DIR/specus-server.env — 请编辑后启动服务"
fi

# Install systemd unit
install -m 0644 -o root -g root \
  "$SCRIPT_DIR/specus-server-go.service" /etc/systemd/system/specus-server-go.service
install -m 0644 -o root -g root \
  "$SCRIPT_DIR/specus-server-go.logrotate" "$LOGROTATE_CONFIG"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "Go server 安装完成"
echo "  - 二进制: $INSTALL_DIR/specus-server"
echo "  - 配置:   $CONFIG_DIR/specus-server.env"
echo "  - 日志:   $LOG_DIR/specus-server.log"
echo "  - 启动:   sudo systemctl start $SERVICE_NAME"
