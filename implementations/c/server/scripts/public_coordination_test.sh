#!/usr/bin/env bash
set -euo pipefail

TEST_BINARY="${1:?public coordination test binary is required}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-redis.XXXXXX")"
source "$(dirname "${BASH_SOURCE[0]}")/test_fixture_resources.sh"

cleanup() {
  set +e
  if [[ -n "${REDIS_PID:-}" ]]; then kill "$REDIS_PID" 2>/dev/null || true; fi
  if [[ -n "${REDIS_PID:-}" ]]; then wait "$REDIS_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

PORT="$(specus_test_pick_ports "${SPECUS_TEST_REDIS_PORT:-}")"
PREFIX="specus:test:coordination:${TMP_DIR##*/}"

redis-server --bind 127.0.0.1 --port "$PORT" --protected-mode yes \
  --save '' --appendonly no --dir "$TMP_DIR" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!

specus_test_wait_redis "$REDIS_PID" "$PORT" "$TMP_DIR/redis.log"

SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://127.0.0.1:$PORT/0" \
SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="$PREFIX" \
SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=100 \
"$TEST_BINARY"
