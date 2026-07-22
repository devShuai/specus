#!/usr/bin/env bash
# =============================================================================
# tunnel-server systemd 一键安装脚本
#
# 用法（root 或 sudo 执行）：
#   sudo ./install.sh /path/to/tunnel-server-1.0-SNAPSHOT.jar
#
# 流程：
#   1) 校验 Java 21+ 与 root 权限
#   2) 创建 tunnel 系统账号（无登录 shell、无家目录）
#   3) 准备目录：
#        /opt/tunnel-server          —— 存放 jar
#        /etc/tunnel-server          —— 存放环境变量文件
#        /var/lib/tunnel-server      —— 工作目录（fallback SQLite / 临时数据）
#        /var/log/tunnel-server      —— 应用滚动日志（同时保留 journald）
#   4) 拷贝 jar、systemd unit、env 模板
#   5) systemctl daemon-reload + enable
#
# 不会自动启动服务 —— 需要先编辑 /etc/tunnel-server/tunnel-server.env
# 填好 MySQL 连接信息、管理员密码、JWT 密钥和可选 ES 配置后再执行：
#   systemctl start tunnel-server
#   systemctl status tunnel-server
#   journalctl -u tunnel-server -f
# =============================================================================
set -euo pipefail

JAR_SRC="${1:-}"
APP_USER="tunnel"
APP_GROUP="tunnel"
INSTALL_DIR="/opt/tunnel-server"
CONFIG_DIR="/etc/tunnel-server"
DATA_DIR="/var/lib/tunnel-server"
LOG_DIR="/var/log/tunnel-server"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- 0. 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
  echo "[ERR] 请使用 root 或 sudo 运行" >&2
  exit 1
fi

if [[ -z "$JAR_SRC" ]]; then
  echo "用法: $0 /path/to/tunnel-server-x.y.z.jar" >&2
  exit 1
fi

if [[ ! -f "$JAR_SRC" ]]; then
  echo "[ERR] jar 文件不存在: $JAR_SRC" >&2
  exit 1
fi

if ! command -v java >/dev/null 2>&1; then
  echo "[ERR] 未找到 java，请先安装 JDK 21 (Temurin/OpenJDK 21+)" >&2
  exit 1
fi

JAVA_MAJOR="$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | awk -F. '{print $1}')"
if [[ "${JAVA_MAJOR:-0}" -lt 21 ]]; then
  echo "[ERR] 需要 Java 21+，当前版本 $JAVA_MAJOR" >&2
  exit 1
fi

# ---------- 1. 创建系统账号 ----------
if ! getent group "$APP_GROUP" >/dev/null; then
  groupadd --system "$APP_GROUP"
  echo "[OK] 创建用户组 $APP_GROUP"
fi
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --gid "$APP_GROUP" --home-dir "$DATA_DIR" \
          --shell /usr/sbin/nologin "$APP_USER"
  echo "[OK] 创建用户 $APP_USER"
fi

# ---------- 2. 准备目录 ----------
install -d -m 0755 -o root      -g root      "$INSTALL_DIR"
install -d -m 0750 -o root      -g "$APP_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$DATA_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$LOG_DIR"

# ---------- 3. 拷贝 jar ----------
install -m 0644 -o root -g root "$JAR_SRC" "$INSTALL_DIR/tunnel-server.jar"
echo "[OK] jar 已部署到 $INSTALL_DIR/tunnel-server.jar"

# ---------- 4. 拷贝 systemd unit ----------
install -m 0644 -o root -g root "$SCRIPT_DIR/tunnel-server.service" \
        /etc/systemd/system/tunnel-server.service
echo "[OK] systemd unit 已部署"

# ---------- 5. 拷贝环境变量模板（仅当目标不存在时） ----------
ENV_FILE="$CONFIG_DIR/tunnel-server.env"
ENV_EXAMPLE_FILE="$CONFIG_DIR/tunnel-server.env.example"
install -m 0640 -o root -g "$APP_GROUP" \
        "$SCRIPT_DIR/tunnel-server.env.example" "$ENV_EXAMPLE_FILE"
echo "[OK] 最新环境变量模板已部署到 $ENV_EXAMPLE_FILE"

if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 -o root -g "$APP_GROUP" \
          "$SCRIPT_DIR/tunnel-server.env.example" "$ENV_FILE"
  echo "[OK] 环境变量模板已部署到 $ENV_FILE"
  echo "     ⚠️  请编辑该文件，填好 MySQL 连接信息、管理员密码、JWT 密钥后再启动服务"
else
  echo "[--] 已存在 $ENV_FILE，不覆盖"
  echo "     可用 diff 对比新增变量：diff -u $ENV_FILE $ENV_EXAMPLE_FILE"
fi

# ---------- 6. 注册 systemd 服务 ----------
systemctl daemon-reload
systemctl enable tunnel-server.service >/dev/null
echo "[OK] tunnel-server.service 已启用（开机自启）"

cat <<EOF

============================================================
安装完成。下一步：

  1. 编辑环境变量：
       sudo vim $ENV_FILE
     至少修改：
       TUNNEL_DB_URL / TUNNEL_DB_USERNAME / TUNNEL_DB_PASSWORD
       TUNNEL_AUTH_PASSWORD
       TUNNEL_AUTH_JWT_SECRET   (openssl rand -base64 48)
     可选修改：
       TUNNEL_PUBLIC_ADDRESS
       TUNNEL_ELASTICSEARCH_URIS / TUNNEL_ELASTICSEARCH_USERNAME / TUNNEL_ELASTICSEARCH_PASSWORD
       TUNNEL_AUTH_TENANT_ID / TUNNEL_OIDC_TENANT_CLAIM

  2. 启动服务：
       sudo systemctl start tunnel-server
       sudo systemctl status tunnel-server
       sudo tail -F $LOG_DIR/tunnel-server.log
       sudo journalctl -u tunnel-server -f
============================================================
EOF
