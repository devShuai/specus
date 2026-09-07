#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
C_BINARY="${1:-$ROOT_DIR/implementations/c/server/build/specus-server-c}"
JAVA_JAR="$ROOT_DIR/implementations/java/server/target/specus-server.jar"
TMP_DIR="$(mktemp -d /tmp/specus-java-c.XXXXXX)"
JAVA_DB_WSL=""
REDIS_PORT=16391
C_CONTROL=17410
C_ADMIN=17411
JAVA_CONTROL=17420
JAVA_ADMIN=17421
JAVA_HOST="127.0.0.1"

cleanup() {
  set +e
  [[ -n "${C_PID:-}" ]] && kill "$C_PID" 2>/dev/null || true
  [[ -n "${JAVA_PID:-}" ]] && kill "$JAVA_PID" 2>/dev/null || true
  [[ -n "${REDIS_PID:-}" ]] && kill "$REDIS_PID" 2>/dev/null || true
  [[ -n "${JAVA_PID:-}" ]] && wait "$JAVA_PID" 2>/dev/null || true
  if [[ -n "$JAVA_DB_WSL" ]]; then
    for _ in $(seq 1 20); do
      rm -f "$JAVA_DB_WSL" "$JAVA_DB_WSL-shm" "$JAVA_DB_WSL-wal" 2>/dev/null && break
      sleep 0.1
    done
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

redis-server --bind 127.0.0.1 --port "$REDIS_PORT" --save '' --appendonly no \
  --dir "$TMP_DIR" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!
for _ in $(seq 1 60); do
  redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && break
  sleep 0.05
done

COMMON_PREFIX="specus:test:java-c"
SPECUS_ENV=dev SPECUS_DB_SEED_DEMO_CLIENT=false \
SPECUS_CLIENT_NAME=interop-c SPECUS_CLIENT_ACCESS_TOKEN=interop-token \
SPECUS_NETTY_PORT="$C_CONTROL" SPECUS_ADMIN_PORT="$C_ADMIN" \
SPECUS_TRUSTED_PROXIES=0.0.0.0/0 \
SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://127.0.0.1:$REDIS_PORT/0" \
SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="$COMMON_PREFIX" \
"$C_BINARY" >"$TMP_DIR/c.log" 2>&1 &
C_PID=$!

export SPECUS_ENV=dev
export SPECUS_DB_SEED_DEMO_CLIENT=false
export SPECUS_NETTY_PORT="$JAVA_CONTROL"
export SPECUS_PEER_MESH_ENABLED=false
export SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true
export SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://127.0.0.1:$REDIS_PORT/0"
export SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="$COMMON_PREFIX"
export SPECUS_TRUSTED_PROXIES=0.0.0.0/0
if command -v java >/dev/null 2>&1; then
  JAVA_EXE="$(command -v java)"
  JAVA_JAR_ARG="$JAVA_JAR"
  export SPECUS_DB_URL="jdbc:sqlite:$TMP_DIR/java.db"
elif command -v java.exe >/dev/null 2>&1; then
  JAVA_EXE="$(command -v java.exe)"
  JAVA_JAR_ARG="$(wslpath -w "$JAVA_JAR")"
  JAVA_DB_WSL="$ROOT_DIR/.tmp-java-c-interop-$$.db"
  export SPECUS_DB_URL="jdbc:sqlite:$(wslpath -w "$JAVA_DB_WSL")"
  JAVA_HOST="$(ip route show default | awk '{print $3; exit}')"
  export WSLENV="SPECUS_ENV:SPECUS_DB_URL:SPECUS_DB_SEED_DEMO_CLIENT:SPECUS_NETTY_PORT:SPECUS_PEER_MESH_ENABLED:SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED:SPECUS_PUBLIC_TRANSFER_REDIS_URI:SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX:SPECUS_TRUSTED_PROXIES"
else
  echo "missing Java runtime" >&2
  exit 1
fi
"$JAVA_EXE" -jar "$JAVA_JAR_ARG" --server.port="$JAVA_ADMIN" >"$TMP_DIR/java.log" 2>&1 &
JAVA_PID=$!

if ! python3 - "$C_ADMIN" "$JAVA_HOST" "$JAVA_ADMIN" <<'PY'
import base64, hashlib, http.client, json, os, socket, struct, sys, time, urllib.parse
c_port = int(sys.argv[1]); java_host = sys.argv[2]; java_port = int(sys.argv[3])

def request(host, port, method, path, body=None):
    conn = http.client.HTTPConnection(host, port, timeout=4)
    data = None if body is None else json.dumps(body).encode()
    conn.request(method, path, data, {"Content-Type": "application/json",
                                     "X-Real-IP": "203.0.113.44"})
    response = conn.getresponse()
    raw = response.read()
    conn.close()
    return response.status, json.loads(raw or b"{}")

deadline = time.time() + 30
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", c_port), timeout=.2): pass
        with socket.create_connection((java_host, java_port), timeout=.2): pass
        break
    except Exception:
        pass
    time.sleep(.1)
else:
    raise RuntimeError("servers did not become ready")

def ticket(host, port, peer, name):
    status, value = request(host, port, "POST", "/api/public/transfer/ws-tickets", {
        "roomId": "interop", "peerId": peer,
        "displayName": name, "discoverable": True})
    if status != 200:
        raise RuntimeError((port, status, value))
    return value["ticket"]

class WS:
    def __init__(self, host, port, token):
        self.s = socket.create_connection((host, port), timeout=5)
        self.s.settimeout(5)
        key = base64.b64encode(os.urandom(16)).decode()
        path = "/ws/public-transfer/discovery?ticket=" + urllib.parse.quote(token, safe="")
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\n"
                        f"Upgrade: websocket\r\nSec-WebSocket-Key: {key}\r\n"
                        "X-Real-IP: 203.0.113.44\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        data = bytearray()
        while b"\r\n\r\n" not in data:
            data.extend(self.s.recv(4096))
        header, rest = bytes(data).split(b"\r\n\r\n", 1)
        if not header.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(header)
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if b"Sec-WebSocket-Accept: " + expected not in header:
            raise RuntimeError("accept mismatch")
        self.b = bytearray(rest)

    def exact(self, n):
        while len(self.b) < n:
            chunk = self.s.recv(max(4096, n - len(self.b)))
            if not chunk: raise EOFError()
            self.b.extend(chunk)
        value = bytes(self.b[:n]); del self.b[:n]; return value

    def recv(self):
        first, second = self.exact(2)
        n = second & 127
        if n == 126: n = struct.unpack("!H", self.exact(2))[0]
        elif n == 127: n = struct.unpack("!Q", self.exact(8))[0]
        return first & 15, self.exact(n)

    def send_text(self, value):
        payload = json.dumps(value, separators=(",", ":")).encode()
        mask = os.urandom(4); n = len(payload)
        header = bytes((0x81, 0x80 | n)) if n <= 125 else bytes((0x81, 0xfe)) + struct.pack("!H", n)
        self.s.sendall(header + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))

    def until(self, predicate):
        deadline = time.time() + 8
        while time.time() < deadline:
            opcode, payload = self.recv()
            if opcode == 1:
                value = json.loads(payload)
                if predicate(value): return value
        raise TimeoutError()

c = WS("127.0.0.1", c_port, ticket("127.0.0.1", c_port, "peer-c", "C-Client"))
j = WS(java_host, java_port, ticket(java_host, java_port, "peer-java", "Java-Client"))
c.until(lambda x: x.get("type") == "hello")
j.until(lambda x: x.get("type") == "hello")
c.until(lambda x: x.get("type") == "roster" and {p["peerId"] for p in x["peers"]} >= {"peer-c", "peer-java"})
j.until(lambda x: x.get("type") == "roster" and {p["peerId"] for p in x["peers"]} >= {"peer-c", "peer-java"})
c.send_text({"type": "signal", "targetPeerId": "peer-java", "payload": {"from": "c"}})
received = j.until(lambda x: x.get("sourcePeerId") == "peer-c")
if received.get("sourceRole") != "EDITOR" or received.get("payload") != {"from": "c"}:
    raise RuntimeError(received)
j.send_text({"type": "signal", "targetPeerId": "peer-c", "payload": {"from": "java"}})
received = c.until(lambda x: x.get("sourcePeerId") == "peer-java")
if received.get("payload") != {"from": "java"}:
    raise RuntimeError(received)
status, value = request(java_host, java_port, "GET",
                        "/api/public/transfer/clients/name-availability?clientName=C-Client")
if status != 200 or value.get("available") is not False:
    raise RuntimeError((status, value))
print("C/Java Redis discovery interop passed")
PY
then
  echo "--- C ---" >&2; tail -n 100 "$TMP_DIR/c.log" >&2 || true
  echo "--- Java ---" >&2; tail -n 160 "$TMP_DIR/java.log" >&2 || true
  exit 1
fi
