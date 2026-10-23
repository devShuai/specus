#!/usr/bin/env bash
# Redis Sentinel for the C coordination layer, as Java's Lettuce follows it: a password-protected
# master and replica, one Sentinel monitoring them, and public_coordination_sentinel_tests driving a
# SENTINEL FAILOVER. With "tls" as the second argument every node and the Sentinel also listen on a
# TLS port, replicate over TLS, and the URI is rediss-sentinel:// with full certificate checks.
# Each node keeps a plain port for the fixture's own commands.
set -euo pipefail

TEST_BINARY="${1:?public coordination sentinel test binary is required}"
MODE="${2:-plain}"
C_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$MODE" == tls ]]; then BASE="${SPECUS_TEST_SENTINEL_BASE_PORT:-16410}"; else BASE="${SPECUS_TEST_SENTINEL_BASE_PORT:-16400}"; fi
MASTER_PORT=$BASE
REPLICA_PORT=$((BASE + 1))
SENTINEL_PORT=$((BASE + 2))
DEAD_PORT=$((BASE + 3)) # nothing listens here: the first Sentinel of the URI is unreachable
MASTER_TLS_PORT=$((BASE + 4))
REPLICA_TLS_PORT=$((BASE + 5))
SENTINEL_TLS_PORT=$((BASE + 6))
HUNG_PORT=$((BASE + 7))    # accepts and never answers (a hung Sentinel, or a proxy with a dead backend)
CLOSING_PORT=$((BASE + 8)) # accepts and closes at once
PASSWORD="sentinel-test-secret"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-redis-sentinel.XXXXXX")"
PIDS=()

cleanup() {
  set +e
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

dump_logs() {
  for log in "$TMP_DIR"/*.log; do echo "== $log" >&2; tail -40 "$log" >&2; done
}

wait_for() {
  local description="$1"
  shift
  for _ in $(seq 1 200); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.05
  done
  echo "timed out waiting for $description" >&2
  dump_logs
  exit 1
}

TLS_ARGS=()
SENTINEL_TLS_CONFIG=""
MASTER_ADDRESS_PORT=$MASTER_PORT
REPLICA_ADDRESS_PORT=$REPLICA_PORT
SENTINEL_ADDRESS_PORT=$SENTINEL_PORT
SCHEME="redis-sentinel"
if [[ "$MODE" == tls ]]; then
  # shellcheck source=tls_test_pki.sh
  source "$C_DIR/scripts/tls_test_pki.sh"
  make_test_pki "$TMP_DIR" localhost "IP:127.0.0.1"
  TLS_ARGS=(--tls-cert-file "$TMP_DIR/server.pem" --tls-key-file "$TMP_DIR/server.key"
            --tls-ca-cert-file "$TMP_DIR/ca.pem" --tls-auth-clients no --tls-replication yes)
  # tls-replication also makes the Sentinel reach the nodes over TLS, and a replica announce its
  # TLS port, so every address the Sentinel hands out is a TLS one.
  SENTINEL_TLS_CONFIG="tls-port $SENTINEL_TLS_PORT
tls-cert-file $TMP_DIR/server.pem
tls-key-file $TMP_DIR/server.key
tls-ca-cert-file $TMP_DIR/ca.pem
tls-auth-clients no
tls-replication yes"
  MASTER_ADDRESS_PORT=$MASTER_TLS_PORT
  REPLICA_ADDRESS_PORT=$REPLICA_TLS_PORT
  SENTINEL_ADDRESS_PORT=$SENTINEL_TLS_PORT
  SCHEME="rediss-sentinel"
  export SSL_CERT_FILE="$TMP_DIR/ca.pem"
fi

start_node() {
  local name="$1" port="$2" tls_port="$3"
  shift 3
  mkdir -p "$TMP_DIR/$name"
  local tls=()
  if [[ "$MODE" == tls ]]; then tls=(--tls-port "$tls_port" "${TLS_ARGS[@]}"); fi
  # repl-diskless-sync-delay 0: Redis would otherwise wait 5 s for more replicas before a full sync.
  redis-server --bind 127.0.0.1 --port "$port" "${tls[@]}" --requirepass "$PASSWORD" --masterauth "$PASSWORD" \
    --repl-diskless-sync-delay 0 --save '' --appendonly no --dir "$TMP_DIR/$name" "$@" \
    >"$TMP_DIR/$name.log" 2>&1 &
  PIDS+=("$!")
}

start_node master "$MASTER_PORT" "$MASTER_TLS_PORT"
wait_for "the master" redis-cli -p "$MASTER_PORT" -a "$PASSWORD" --no-auth-warning ping
start_node replica "$REPLICA_PORT" "$REPLICA_TLS_PORT" --replicaof 127.0.0.1 "$MASTER_ADDRESS_PORT"
replica_linked() {
  redis-cli -p "$REPLICA_PORT" -a "$PASSWORD" --no-auth-warning info replication | grep -q 'master_link_status:up'
}
wait_for "the replica to sync" replica_linked

# The Sentinel starts once the replica is attached, so its first INFO of the master already lists it.
mkdir -p "$TMP_DIR/sentinel"
cat >"$TMP_DIR/sentinel.conf" <<CONF
port $SENTINEL_PORT
bind 127.0.0.1
dir $TMP_DIR/sentinel
$SENTINEL_TLS_CONFIG
sentinel monitor mymaster 127.0.0.1 $MASTER_ADDRESS_PORT 1
sentinel auth-pass mymaster $PASSWORD
sentinel down-after-milliseconds mymaster 5000
sentinel failover-timeout mymaster 10000
CONF
redis-server "$TMP_DIR/sentinel.conf" --sentinel >"$TMP_DIR/sentinel.log" 2>&1 &
PIDS+=("$!")
wait_for "the Sentinel" redis-cli -p "$SENTINEL_PORT" ping
if redis-cli -p "$DEAD_PORT" ping >/dev/null 2>&1; then
  echo "port $DEAD_PORT is in use; set SPECUS_TEST_SENTINEL_BASE_PORT" >&2
  exit 1
fi

# Two Sentinels that accept the connection but are no use: Lettuce's handshake round trip fails on
# them, which counts as a connection failure, so it goes on to the next Sentinel; C must as well.
python3 - "$HUNG_PORT" "$CLOSING_PORT" >"$TMP_DIR/listeners.log" 2>&1 <<'PY' &
import socket
import sys
import threading

def listen(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(64)
    return server

hung = listen(int(sys.argv[1]))
closing = listen(int(sys.argv[2]))
held = []

def hold():
    while True:
        connection, _ = hung.accept()
        held.append(connection)  # never read, never answered

threading.Thread(target=hold, daemon=True).start()
while True:
    connection, _ = closing.accept()
    connection.close()
PY
PIDS+=("$!")
listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_for "the hung listener" listening "$HUNG_PORT"
wait_for "the closing listener" listening "$CLOSING_PORT"

QUERY="sentinelMasterId=mymaster&clientName=specus-c-sentinel"
SENTINELS="127.0.0.1:$DEAD_PORT,127.0.0.1:$HUNG_PORT,127.0.0.1:$CLOSING_PORT,127.0.0.1:$SENTINEL_ADDRESS_PORT"
if ! SPECUS_TEST_MASTER_PORT="$MASTER_PORT" \
  SPECUS_TEST_REPLICA_PORT="$REPLICA_PORT" \
  SPECUS_TEST_SENTINEL_PORT="$SENTINEL_PORT" \
  SPECUS_TEST_REPLICA_ADDRESS_PORT="$REPLICA_ADDRESS_PORT" \
  SPECUS_TEST_MASTER_ADDRESS_PORT="$MASTER_ADDRESS_PORT" \
  SPECUS_TEST_DATA_PASSWORD="$PASSWORD" \
  SPECUS_TEST_UNKNOWN_MASTER_URI="$SCHEME://:$PASSWORD@$SENTINELS/0?sentinelMasterId=nosuchmaster" \
  SPECUS_TEST_NO_SENTINEL_URI="$SCHEME://:$PASSWORD@127.0.0.1:$DEAD_PORT/0?$QUERY" \
  SPECUS_TEST_WRONG_PASSWORD_URI="$SCHEME://:wrong-password@$SENTINELS/0?$QUERY" \
  SPECUS_TEST_UNNAMED_URI="$SCHEME://:$PASSWORD@$SENTINELS/0?sentinelMasterId=mymaster" \
  SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
  SPECUS_PUBLIC_TRANSFER_REDIS_URI="$SCHEME://:$PASSWORD@$SENTINELS/0?$QUERY" \
  SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="specus:test:sentinel" \
  SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=300 \
  "$TEST_BINARY"; then
  dump_logs
  exit 1
fi
