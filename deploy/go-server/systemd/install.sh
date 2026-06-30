#!/usr/bin/env bash
set -euo pipefail

# Go server first-time install
# Usage: sudo bash install.sh <path-to-binary>

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

BINARY="${1:-${REPO_ROOT}/implementations/go/server/shuai-tunnel-server}"
SERVICE_NAME="tunnel-server-go"
INSTALL_DIR="/opt/tunnel-server-go"
CONFIG_DIR="/etc/tunnel-server-go"
DATA_DIR="/var/lib/tunnel-server-go"
LOG_DIR="/var/log/tunnel-server-go"
USER="tunnel"
GROUP="tunnel"

if [[ $EUID -ne 0 ]]; then
  echo "请以 root 身份运行" >&2
  exit 1
fi

if [[ ! -f "$BINARY" ]]; then
  echo "二进制文件不存在: $BINARY" >&2
  echo "请先编译: cd implementations/go/server && go generate ./web && go build -o shuai-tunnel-server ./cmd/shuai-tunnel-server" >&2
  exit 1
fi

# Create system user
if ! id -u "$USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

# Create directories
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0750 "$CONFIG_DIR"
install -d -m 0750 "$DATA_DIR" -o "$USER" -g "$GROUP"
install -d -m 0750 "$LOG_DIR" -o "$USER" -g "$GROUP"

# Install binary
install -m 0755 "$BINARY" "$INSTALL_DIR/shuai-tunnel-server"

# Install env template (never overwrite live env)
cp "$SCRIPT_DIR/tunnel-server.env.example" "$CONFIG_DIR/tunnel-server.env.example"
if [[ ! -f "$CONFIG_DIR/tunnel-server.env" ]]; then
  cp "$SCRIPT_DIR/tunnel-server.env.example" "$CONFIG_DIR/tunnel-server.env"
  chmod 0640 "$CONFIG_DIR/tunnel-server.env"
  chown "$USER:$GROUP" "$CONFIG_DIR/tunnel-server.env"
  echo "已创建 $CONFIG_DIR/tunnel-server.env — 请编辑后启动服务"
fi

# Install systemd unit
cp "$SCRIPT_DIR/tunnel-server-go.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "Go server 安装完成"
echo "  - 二进制: $INSTALL_DIR/shuai-tunnel-server"
echo "  - 配置:   $CONFIG_DIR/tunnel-server.env"
echo "  - 启动:   sudo systemctl start $SERVICE_NAME"