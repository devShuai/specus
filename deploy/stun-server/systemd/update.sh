#!/usr/bin/env bash
set -euo pipefail

JAR_SRC="${1:-}"
SERVICE="stun-server"
INSTALL_DIR="/opt/shuai-stun-server"
JAR_DEST="$INSTALL_DIR/stun-server.jar"
CONFIG_DIR="/etc/shuai-stun-server"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_KEEP=5
ACTIVE_TIMEOUT_SEC="${STUN_ACTIVE_TIMEOUT_SEC:-20}"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
fail() { printf '[%s] [ERR] %s\n' "$(date '+%F %T')" "$*" >&2; }

if [[ $EUID -ne 0 ]]; then
  fail "请使用 root 或 sudo 运行"
  exit 1
fi
if [[ -z "$JAR_SRC" || ! -f "$JAR_SRC" ]]; then
  fail "用法: $0 /path/to/stun-server.jar"
  exit 1
fi
if [[ ! -f "$JAR_DEST" ]]; then
  fail "$JAR_DEST 不存在，请先运行 install.sh"
  exit 1
fi

java -jar "$JAR_SRC" --help >/dev/null
install -m 0644 -o root -g root "$SCRIPT_DIR/stun-server.service" \
        /etc/systemd/system/stun-server.service
install -m 0640 -o root -g stun "$SCRIPT_DIR/stun-server.env.example" \
        "$CONFIG_DIR/stun-server.env.example"
systemctl daemon-reload

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP="$INSTALL_DIR/stun-server.jar.bak.$TS"
install -m 0644 -o root -g root "$JAR_DEST" "$BACKUP"
ls -1t "$INSTALL_DIR"/stun-server.jar.bak.* 2>/dev/null \
  | tail -n +$((BACKUP_KEEP + 1)) \
  | xargs -r rm -f || true

rollback() {
  fail "更新失败，回滚到 $BACKUP"
  systemctl stop "$SERVICE" || true
  install -m 0644 -o root -g root "$BACKUP" "$JAR_DEST"
  systemctl start "$SERVICE"
  exit 2
}

systemctl stop "$SERVICE" || rollback
install -m 0644 -o root -g root "$JAR_SRC" "$JAR_DEST" || rollback
systemctl start "$SERVICE" || rollback

deadline=$((SECONDS + ACTIVE_TIMEOUT_SEC))
while (( SECONDS < deadline )); do
  if systemctl is-active --quiet "$SERVICE"; then
    sleep 1
    if systemctl is-active --quiet "$SERVICE"; then
      log "更新成功；查看日志: journalctl -u $SERVICE -f"
      exit 0
    fi
  fi
  sleep 1
done

rollback
