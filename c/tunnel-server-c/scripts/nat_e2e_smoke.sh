#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
C_DIR="$ROOT_DIR/c/tunnel-server-c"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shuai-tunnel-c-smoke.XXXXXX")"
CONTROL_PORT="${CONTROL_PORT:-17010}"
PUBLIC_PORT="${PUBLIC_PORT:-18080}"
ECHO_PORT="${ECHO_PORT:-19090}"
JAVA_CLIENT_JAR="$ROOT_DIR/tunnel-client/target/tunnel-client-0.0.1-SNAPSHOT-exec.jar"

cleanup() {
  set +e
  if [[ -n "${JAVA_PID:-}" ]]; then kill "$JAVA_PID" 2>/dev/null || true; fi
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [[ -n "${ECHO_PID:-}" ]]; then kill "$ECHO_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ ! -f "$JAVA_CLIENT_JAR" ]]; then
  echo "missing Java client jar: $JAVA_CLIENT_JAR" >&2
  echo "build it first with: mvn -pl tunnel-client -am package -DskipTests" >&2
  exit 1
fi

make -C "$C_DIR" test

python3 - "$ECHO_PORT" <<'PY' &
import socket
import sys
port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(32)
while True:
    conn, _ = server.accept()
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
PY
ECHO_PID=$!

TUNNEL_NETTY_PORT="$CONTROL_PORT" \
TUNNEL_CLIENT_NAME="Demo client" \
TUNNEL_CLIENT_PASSWORD="test1234" \
TUNNEL_TCP_MAPPINGS="$PUBLIC_PORT=127.0.0.1:$ECHO_PORT" \
"$C_DIR/build/shuai-tunnel-server-c" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

cat >"$TMP_DIR/tunnelClientConfig.json" <<JSON
{
  "clientName": "Demo client",
  "password": "test1234",
  "tunnelConfigList": [],
  "httpTunnelConfigList": [],
  "remoteAddress": "127.0.0.1",
  "remotePort": $CONTROL_PORT
}
JSON

(cd "$TMP_DIR" && java -jar "$JAVA_CLIENT_JAR" --server.port=0 >"$TMP_DIR/client.log" 2>&1) &
JAVA_PID=$!

python3 - "$PUBLIC_PORT" <<'PY'
import socket
import sys
import time
port = int(sys.argv[1])
deadline = time.time() + 30
payload = b"shuai-tunnel-c-nat-smoke"
last = None
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.sendall(payload)
            got = s.recv(len(payload))
            if got == payload:
                print("NAT smoke passed")
                raise SystemExit(0)
            last = f"unexpected payload: {got!r}"
    except Exception as exc:
        last = str(exc)
        time.sleep(1)
print(f"NAT smoke failed: {last}", file=sys.stderr)
raise SystemExit(1)
PY
