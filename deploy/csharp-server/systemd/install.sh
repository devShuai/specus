#!/usr/bin/env bash
set -euo pipefail

# C# server first-time install
# Usage: sudo bash install.sh <path-to-publish-output-dir>

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

PUBLISH_DIR="${1:-${REPO_ROOT}/implementations/csharp/server/publish}"
SERVICE_NAME="specus-server-csharp"
INSTALL_DIR="/opt/specus-server-csharp"
CONFIG_DIR="/etc/specus-server-csharp"
DATA_DIR="/var/lib/specus-server-csharp"
LOG_DIR="/var/log/specus-server-csharp"
USER="specus"
GROUP="specus"

if [[ $EUID -ne 0 ]]; then
  echo "请以 root 身份运行" >&2
  exit 1
fi

if [[ ! -d "$PUBLISH_DIR" ]]; then
  echo "发布目录不存在: $PUBLISH_DIR" >&2
  echo "请先发布: dotnet publish ..." >&2
  exit 1
fi

if [[ ! -f "${PUBLISH_DIR}/Specus.Server.dll" ]]; then
  echo "发布目录中未找到 Specus.Server.dll" >&2
  exit 1
fi

# Create system user
if ! id -u "$USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

# Create directories
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0750 -o root -g "$GROUP" "$CONFIG_DIR"
install -d -m 0750 "$DATA_DIR" -o "$USER" -g "$GROUP"
install -d -m 0750 "$LOG_DIR" -o "$USER" -g "$GROUP"

# Install publish output (rsync to preserve structure)
rsync -a --delete "${PUBLISH_DIR}/" "${INSTALL_DIR}/"
chown -R root:root "$INSTALL_DIR"
chmod -R 0755 "$INSTALL_DIR"

# Ensure wwwroot is readable
if [[ -d "${INSTALL_DIR}/wwwroot" ]]; then
  find "${INSTALL_DIR}/wwwroot" -type f -exec chmod 0644 {} \;
fi

# Install env template (never overwrite live env)
cp "$SCRIPT_DIR/specus-server.env.example" "$CONFIG_DIR/specus-server.env.example"
if [[ ! -f "$CONFIG_DIR/specus-server.env" ]]; then
  cp "$SCRIPT_DIR/specus-server.env.example" "$CONFIG_DIR/specus-server.env"
  chmod 0640 "$CONFIG_DIR/specus-server.env"
  chown "root:$GROUP" "$CONFIG_DIR/specus-server.env"
  echo "已创建 $CONFIG_DIR/specus-server.env — 请编辑后启动服务"
  echo "如需密码登录，请先生成独立强口令和稳定 JWT 密钥，再启用 PASSWORD_LOGIN_ENABLED"
else
  echo "已存在 $CONFIG_DIR/specus-server.env，不覆盖；最新模板见 specus-server.env.example"
fi

# Install systemd unit
cp "$SCRIPT_DIR/specus-server-csharp.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo "C# server 安装完成"
echo "  - 安装目录: $INSTALL_DIR"
echo "  - 配置:     $CONFIG_DIR/specus-server.env"
echo "  - 状态:     已注册并设为开机自启，本次安装未启动服务"
echo "  - 启动:     sudo systemctl start $SERVICE_NAME"
