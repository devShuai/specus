#!/usr/bin/env bash
# =============================================================================
# tunnel-server 滚动更新脚本
#
# 用法（root 或 sudo 执行）：
#   sudo ./update.sh /path/to/tunnel-server-x.y.z.jar
#
# 流程：
#   1) 校验前置条件（root / jar 存在 / 服务已通过 install.sh 安装过）
#   2) 备份当前 jar 为 tunnel-server.jar.bak.<timestamp>，保留最近 5 份
#   3) systemctl stop tunnel-server（等优雅停机；超时后 SIGKILL）
#   4) 拷新 jar
#   5) systemctl start tunnel-server
#   6) 健康检查：
#        - 等服务 active（最多 60s）
#        - actuator /health 状态 UP（最多 60s）
#   7) 任一步失败 → 回滚到上一份 bak 并重启
#
# 退出码：
#   0 = 升级成功；1 = 前置失败；2 = 升级失败但回滚成功；3 = 回滚也失败（需人工介入）
# =============================================================================
set -euo pipefail

JAR_SRC="${1:-}"
SERVICE="tunnel-server"
INSTALL_DIR="/opt/tunnel-server"
JAR_DEST="$INSTALL_DIR/tunnel-server.jar"
BACKUP_KEEP=5
HEALTH_URL="${TUNNEL_HEALTH_URL:-http://127.0.0.1:8088/actuator/health}"
ACTIVE_TIMEOUT_SEC=60
HEALTH_TIMEOUT_SEC=60

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
fail() { printf '[%s] [ERR] %s\n' "$(date '+%F %T')" "$*" >&2; }

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
log "  - 查看日志:    journalctl -u $SERVICE -f"
exit 0
