#!/usr/bin/env bash
set -euo pipefail

JAR_SRC="${1:-}"
ENV_SRC="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR_DEST="/opt/shuai-stun-server/stun-server.jar"
ENV_DEST="/etc/shuai-stun-server/stun-server.env"

if [[ $EUID -ne 0 ]]; then
  echo "[ERR] 请使用 root 或 sudo 运行" >&2
  exit 1
fi
if [[ -z "$JAR_SRC" || ! -f "$JAR_SRC" || -z "$ENV_SRC" || ! -f "$ENV_SRC" ]]; then
  echo "用法: $0 /path/to/stun-server.jar /path/to/stun-server.env" >&2
  exit 1
fi

if [[ -f "$JAR_DEST" && -f "$ENV_DEST" ]]; then
  exec bash "$SCRIPT_DIR/update.sh" "$JAR_SRC" "$ENV_SRC"
fi

exec bash "$SCRIPT_DIR/install.sh" "$JAR_SRC" "$ENV_SRC"
