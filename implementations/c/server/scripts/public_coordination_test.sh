#!/usr/bin/env bash
set -euo pipefail

TEST_BINARY="${1:?public coordination test binary is required}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-redis.XXXXXX")"
PORT="${SPECUS_TEST_REDIS_PORT:-16389}"

cleanup() {
  set +e
  if [[ -n "${REDIS_PID:-}" ]]; then kill "$REDIS_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

redis-server --bind 127.0.0.1 --port "$PORT" --protected-mode yes \
  --save '' --appendonly no --dir "$TMP_DIR" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!

for _ in $(seq 1 60); do
  if redis-cli -h 127.0.0.1 -p "$PORT" ping >/dev/null 2>&1; then break; fi
  sleep 0.05
done
redis-cli -h 127.0.0.1 -p "$PORT" ping >/dev/null

SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://127.0.0.1:$PORT/0" \
SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="specus:test:coordination" \
SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=100 \
"$TEST_BINARY"
