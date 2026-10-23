#!/usr/bin/env bash
set -euo pipefail

TEST_BINARY="${1:?public coordination test binary is required}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-redis.XXXXXX")"
PORT="${SPECUS_TEST_REDIS_PORT:-16389}"

cleanup() {
  set +e
  if [[ -n "${REDIS_PID:-}" ]]; then kill "$REDIS_PID" 2>/dev/null || true; fi
  # The reconnect test restarts redis-server on the same port; stop whichever instance is left.
  redis-cli -h 127.0.0.1 -p "$PORT" shutdown nosave >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

redis-server --bind 127.0.0.1 --port "$PORT" --protected-mode yes \
  --unixsocket "$TMP_DIR/redis.sock" --unixsocketperm 700 \
  --save '' --appendonly no --dir "$TMP_DIR" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!

for _ in $(seq 1 60); do
  if redis-cli -h 127.0.0.1 -p "$PORT" ping >/dev/null 2>&1; then break; fi
  sleep 0.05
done
redis-cli -h 127.0.0.1 -p "$PORT" ping >/dev/null

SPECUS_TEST_REDIS_PORT="$PORT" \
SPECUS_TEST_REDIS_DIR="$TMP_DIR" \
SPECUS_TEST_REDIS_SOCKET="$TMP_DIR/redis.sock" \
SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://127.0.0.1:$PORT/0" \
SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="specus:test:coordination" \
SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=100 \
"$TEST_BINARY"

# An unescaped '#' in the password ends the authority there, so java.net.URI and Lettuce (and C)
# take ":hunter2" as the host: startup fails, the log names no part of it and says what to escape.
if ! SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
  SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://:hunter2#tail@127.0.0.1:$PORT/0" \
  "$TEST_BINARY" --probe refused 2>"$TMP_DIR/cut-password.log"; then
  echo "a password cut by '#' did not fail startup" >&2
  cat "$TMP_DIR/cut-password.log" >&2
  exit 1
fi
if grep -q hunter2 "$TMP_DIR/cut-password.log" || ! grep -q "percent-encode" "$TMP_DIR/cut-password.log"; then
  echo "the startup log shows part of the password, or does not say what to escape" >&2
  cat "$TMP_DIR/cut-password.log" >&2
  exit 1
fi
