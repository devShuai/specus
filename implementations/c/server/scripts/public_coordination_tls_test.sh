#!/usr/bin/env bash
# public_coordination_tests over rediss://, as Java's Lettuce connects with SPECUS_PUBLIC_TRANSFER_REDIS_URI
# set to rediss://: a throwaway CA and server certificate (DNS:localhost, IP:127.0.0.1), one
# redis-server with a plain port for the fixture's own commands and a TLS port for the coordination
# layer. The binary runs its whole suite over TLS (Pub/Sub, timeouts, reconnect after a restart,
# which brings the TLS port back) and the SslVerifyMode probes (FULL, CA, NONE; untrusted CA).
set -euo pipefail

TEST_BINARY="${1:?public coordination test binary is required}"
C_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-redis-tls.XXXXXX")"
PORT="${SPECUS_TEST_REDIS_TLS_FIXTURE_PORT:-16392}"
TLS_PORT="${SPECUS_TEST_REDIS_TLS_PORT:-16393}"

cleanup() {
  set +e
  if [[ -n "${REDIS_PID:-}" ]]; then kill "$REDIS_PID" 2>/dev/null || true; fi
  # The reconnect test restarts redis-server on the same ports; stop whichever instance is left.
  redis-cli -h 127.0.0.1 -p "$PORT" shutdown nosave >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# shellcheck source=tls_test_pki.sh
source "$C_DIR/scripts/tls_test_pki.sh"
make_test_pki "$TMP_DIR" localhost "IP:127.0.0.1"

# 127.0.0.2 reaches the same server under an address the certificate does not name. Neither Java
# nor C offers a client certificate, so the server must not require one.
redis-server --bind 127.0.0.1 127.0.0.2 --port "$PORT" --tls-port "$TLS_PORT" \
  --tls-cert-file "$TMP_DIR/server.pem" --tls-key-file "$TMP_DIR/server.key" \
  --tls-ca-cert-file "$TMP_DIR/ca.pem" --tls-auth-clients no --protected-mode yes \
  --save '' --appendonly no --dir "$TMP_DIR" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!

for _ in $(seq 1 60); do
  if redis-cli -h 127.0.0.1 -p "$PORT" ping >/dev/null 2>&1; then break; fi
  sleep 0.05
done
if ! redis-cli -h 127.0.0.1 -p "$PORT" ping >/dev/null 2>&1; then
  cat "$TMP_DIR/redis.log" >&2
  exit 1
fi

# SSL_CERT_FILE is OpenSSL's trust store override, the counterpart of javax.net.ssl.trustStore.
SSL_CERT_FILE="$TMP_DIR/ca.pem" \
SPECUS_TEST_REDIS_PORT="$PORT" \
SPECUS_TEST_REDIS_DIR="$TMP_DIR" \
SPECUS_TEST_REDIS_TLS_PORT="$TLS_PORT" \
SPECUS_TEST_REDIS_TLS_CERT="$TMP_DIR/server.pem" \
SPECUS_TEST_REDIS_TLS_KEY="$TMP_DIR/server.key" \
SPECUS_TEST_REDIS_TLS_CA="$TMP_DIR/ca.pem" \
SPECUS_TEST_REDIS_OTHER_CA="$TMP_DIR/other-ca.pem" \
SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
SPECUS_PUBLIC_TRANSFER_REDIS_URI="rediss://127.0.0.1:$TLS_PORT/0" \
SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="specus:test:coordination" \
SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=100 \
"$TEST_BINARY"
