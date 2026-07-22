#!/usr/bin/env bash
# =============================================================================
# tunnel-server 滚动更新脚本
#
# 用法（root 或 sudo 执行）：
#   sudo ./update.sh /path/to/tunnel-server-x.y.z.jar
#
# 流程：
#   1) 校验前置条件（root / jar 存在 / 服务已通过 install.sh 安装过）
#   2) 同步最新 systemd unit 与 env.example（不覆盖真实 env）
#   3) 备份当前 jar 为 tunnel-server.jar.bak.<timestamp>，保留最近 5 份
#   4) systemctl stop tunnel-server（等优雅停机；超时后 SIGKILL）
#   5) 拷新 jar
#   6) systemctl start tunnel-server
#   7) 健康检查：
#        - 等服务 active（默认最多 60s，可用 TUNNEL_ACTIVE_TIMEOUT_SEC 覆盖）
#        - actuator /health 状态 UP（默认最多 120s，可用 TUNNEL_HEALTH_TIMEOUT_SEC 覆盖）
#   8) 任一步失败 → 回滚到上一份 bak 并重启
#
# 退出码：
#   0 = 升级成功；1 = 前置失败；2 = 升级失败但回滚成功；3 = 回滚也失败（需人工介入）
# =============================================================================
set -euo pipefail

JAR_SRC="${1:-}"
SERVICE="tunnel-server"
INSTALL_DIR="/opt/tunnel-server"
JAR_DEST="$INSTALL_DIR/tunnel-server.jar"
CONFIG_DIR="${TUNNEL_CONFIG_DIR:-/etc/tunnel-server}"
LOG_DIR="/var/log/tunnel-server"
ENV_FILE="$CONFIG_DIR/tunnel-server.env"
ENV_EXAMPLE_FILE="$CONFIG_DIR/tunnel-server.env.example"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_KEEP=5
ACTIVE_TIMEOUT_SEC="${TUNNEL_ACTIVE_TIMEOUT_SEC:-60}"
HEALTH_TIMEOUT_SEC="${TUNNEL_HEALTH_TIMEOUT_SEC:-120}"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
fail() { printf '[%s] [ERR] %s\n' "$(date '+%F %T')" "$*" >&2; }

read_env_value() {
  local key="$1"
  local fallback="$2"
  local value=""
  if [[ -f "$ENV_FILE" ]]; then
    value="$(awk -F= -v key="$key" '
      $0 !~ /^[[:space:]]*#/ && $1 == key {
        sub(/^[^=]*=/, "")
        print
        exit
      }
    ' "$ENV_FILE" 2>/dev/null || true)"
  fi
  value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//;s/^"//;s/"$//')"
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "$fallback"
  fi
}

HEALTH_PORT="${TUNNEL_HEALTH_PORT:-$(read_env_value SERVER_PORT 8088)}"
HEALTH_URL="${TUNNEL_HEALTH_URL:-http://127.0.0.1:${HEALTH_PORT}/actuator/health}"

# ---------- 0. 前置检查 ----------
if [[ $EUID -ne 0 ]]; then
  fail "请使用 root 或 sudo 运行"; exit 1
fi
if [[ -z "$JAR_SRC" ]]; then
  fail "用法: $0 /path/to/tunnel-server-x.y.z.jar"; exit 1
fi
if [[ ! -f "$JAR_SRC" ]]; then
  fail "jar 文件不存在: $JAR_SRC"; exit 1
fi
if [[ ! -f "$JAR_DEST" ]]; then
  fail "$JAR_DEST 不存在，请先用 install.sh 完成首次安装"; exit 1
fi
if ! systemctl list-unit-files "$SERVICE.service" >/dev/null 2>&1; then
  fail "$SERVICE.service 未注册到 systemd"; exit 1
fi

# 避免把同一个文件拷给自己
if [[ "$(readlink -f "$JAR_SRC")" == "$(readlink -f "$JAR_DEST")" ]]; then
  fail "源 jar 与目标 jar 是同一文件，无需更新"; exit 1
fi

sync_deploy_files() {
  local unit_src="$SCRIPT_DIR/tunnel-server.service"
  local env_example_src="$SCRIPT_DIR/tunnel-server.env.example"
  local env_group="root"

  if getent group tunnel >/dev/null; then
    env_group="tunnel"
  fi

  if [[ -f "$unit_src" ]]; then
    install -m 0644 -o root -g root "$unit_src" /etc/systemd/system/tunnel-server.service
    log "已同步 systemd unit -> /etc/systemd/system/tunnel-server.service"
  fi

  if [[ -f "$env_example_src" ]]; then
    install -d -m 0750 -o root -g "$env_group" "$CONFIG_DIR"
    install -m 0640 -o root -g "$env_group" "$env_example_src" "$ENV_EXAMPLE_FILE"
    log "已同步最新环境变量模板 -> $ENV_EXAMPLE_FILE"
    if [[ -f "$ENV_FILE" ]]; then
      log "真实环境变量文件 $ENV_FILE 不会被覆盖；如需合并新增变量，请手动 diff 模板"
    fi
  fi

  if id -u tunnel >/dev/null 2>&1 && getent group tunnel >/dev/null; then
    install -d -m 0750 -o tunnel -g tunnel "$LOG_DIR"
    log "已确认日志目录 -> $LOG_DIR"
  fi

  systemctl daemon-reload
}

sync_deploy_files

NEW_SIZE=$(stat -c %s "$JAR_SRC")
OLD_SIZE=$(stat -c %s "$JAR_DEST")
log "准备升级 $SERVICE"
log "  当前 jar: $JAR_DEST (${OLD_SIZE} bytes)"
log "  新   jar: $JAR_SRC (${NEW_SIZE} bytes)"

# ---------- 1. 备份 ----------
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="$INSTALL_DIR/tunnel-server.jar.bak.$TS"
install -m 0644 -o root -g root "$JAR_DEST" "$BACKUP"
log "已备份当前 jar -> $BACKUP"

# 保留最近 BACKUP_KEEP 份，老的删掉
ls -1t "$INSTALL_DIR"/tunnel-server.jar.bak.* 2>/dev/null \
  | tail -n +$((BACKUP_KEEP + 1)) \
  | xargs -r rm -f || true

# ---------- 2. 升级流程（带回滚） ----------
rollback() {
  fail "升级失败，开始回滚到 $BACKUP"
  systemctl stop "$SERVICE" || true
  if install -m 0644 -o root -g root "$BACKUP" "$JAR_DEST"; then
    if systemctl start "$SERVICE"; then
      log "回滚完成，旧版本已恢复运行"
      exit 2
    fi
  fi
  fail "回滚失败！请手动恢复：sudo install -m 0644 $BACKUP $JAR_DEST && sudo systemctl start $SERVICE"
  exit 3
}

wait_active() {
  local deadline=$((SECONDS + ACTIVE_TIMEOUT_SEC))
  while (( SECONDS < deadline )); do
    if systemctl is-active --quiet "$SERVICE"; then return 0; fi
    sleep 1
  done
  return 1
}

wait_healthy() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT_SEC))
  while (( SECONDS < deadline )); do
    local status
    status="$(curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([A-Z]*\)".*/\1/p')"
    if [[ "$status" == "UP" ]]; then return 0; fi
    sleep 2
  done
  return 1
}

log "停止 $SERVICE …"
systemctl stop "$SERVICE" || { fail "stop 失败"; rollback; }

log "替换 jar …"
if ! install -m 0644 -o root -g root "$JAR_SRC" "$JAR_DEST"; then
  fail "拷贝新 jar 失败"; rollback
fi

log "启动 $SERVICE …"
if ! systemctl start "$SERVICE"; then
  fail "start 失败"; rollback
fi

log "等待 systemd 报告 active（最多 ${ACTIVE_TIMEOUT_SEC}s）…"
if ! wait_active; then
  fail "$SERVICE 未能进入 active 状态"; rollback
fi

if command -v curl >/dev/null 2>&1; then
  log "等待 ${HEALTH_URL} 返回 UP（最多 ${HEALTH_TIMEOUT_SEC}s）…"
  if ! wait_healthy; then
    fail "$HEALTH_URL 始终不是 UP"; rollback
  fi
else
  log "未找到 curl，跳过 actuator 健康检查"
fi

log "升级成功 ✅"
log "  - 当前运行 jar: $(readlink -f "$JAR_DEST")"
log "  - 回滚备份:    $BACKUP"
log "  - 文件日志:    $LOG_DIR/tunnel-server.log"
log "  - systemd 日志: journalctl -u $SERVICE -f"
exit 0
