#!/usr/bin/env bash
set -euo pipefail

# Go server rolling update
# Usage: sudo bash update.sh <path-to-new-binary>

SERVICE_NAME="tunnel-server-go"
INSTALL_DIR="/opt/tunnel-server-go"
BACKUP_DIR="${INSTALL_DIR}/backup"
HEALTH_URL="${TUNNEL_HEALTH_URL:-http://127.0.0.1:8088/health}"
MAX_RETRIES=30
RETRY_INTERVAL=2

BINARY="${1:-}"

log()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; }

if [[ $EUID -ne 0 ]]; then
  error "请以 root 身份运行"
  exit 1
fi

if [[ -z "$BINARY" || ! -f "$BINARY" ]]; then
  error "用法: sudo bash update.sh <path-to-new-binary>"
  exit 1
fi

if [[ ! -f "${INSTALL_DIR}/shuai-tunnel-server" ]]; then
  error "未安装的服务: ${INSTALL_DIR}/shuai-tunnel-server"
  exit 1
fi

if ! systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
  error "systemd 服务 $SERVICE_NAME 未注册"
  exit 1
fi

if [[ "$(realpath "$BINARY")" == "${INSTALL_DIR}/shuai-tunnel-server" ]]; then
  error "源文件和目标文件相同，无法更新"
  exit 1
fi

log "准备升级 Go server"
log "  当前二进制: ${INSTALL_DIR}/shuai-tunnel-server"
log "  新二进制: $BINARY"

# Backup current binary
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="${BACKUP_DIR}/shuai-tunnel-server.bak.$(date +%Y%m%d-%H%M%S)"
cp "${INSTALL_DIR}/shuai-tunnel-server" "$BACKUP_FILE"
log "已备份当前二进制 -> $BACKUP_FILE"

# Keep last 5 backups
ls -1t "${BACKUP_DIR}/"*.bak.* 2>/dev/null | tail -n +6 | xargs -r rm -f --

# Stop service
log "停止 ${SERVICE_NAME} ..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
sleep 1

# Replace binary
install -m 0755 "$BINARY" "${INSTALL_DIR}/shuai-tunnel-server"
log "已替换二进制"

# Start service
log "启动 ${SERVICE_NAME} ..."
systemctl start "$SERVICE_NAME"

# Wait for active
log "等待 systemd 报告 active（最多 60s）..."
for i in $(seq 1 30); do
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    break
  fi
  sleep 2
done

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
  error "服务未能在 60s 内启动"
  ROLLBACK=true
fi

# Wait for health
log "等待 HTTP 健康检查（最多 60s）..."
for i in $(seq 1 $MAX_RETRIES); do
  if curl -sf -o /dev/null "$HEALTH_URL" 2>/dev/null; then
    HEALTH_OK=true
    break
  fi
  sleep $RETRY_INTERVAL
done

if [[ "${HEALTH_OK:-false}" == "true" ]]; then
  log "升级成功 ✅"
  log "  当前二进制: ${INSTALL_DIR}/shuai-tunnel-server"
  log "  回滚备份:  $BACKUP_FILE"
  log "  查看日志:  journalctl -u ${SERVICE_NAME} -f"
  exit 0
fi

# Rollback
log "健康检查失败，执行回滚..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
cp "$BACKUP_FILE" "${INSTALL_DIR}/shuai-tunnel-server"
systemctl start "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
  log "回滚成功 ✅（使用备份 $BACKUP_FILE）"
  exit 2
else
  error "回滚失败 ❌ — 请手动干预"
  error "  备份位于: $BACKUP_FILE"
  exit 3
fi
