#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
C_DIR="$ROOT_DIR/implementations/c/server"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-smoke.XXXXXX")"
CONTROL_PORT="${CONTROL_PORT:-17010}"
ADMIN_PORT="${ADMIN_PORT:-17011}"
PUBLIC_PORT="${PUBLIC_PORT:-18080}"
ECHO_PORT="${ECHO_PORT:-19090}"
HTTP_UPSTREAM_PORT="${HTTP_UPSTREAM_PORT:-19091}"
WS_UPSTREAM_PORT="${WS_UPSTREAM_PORT:-19092}"
JAVA_CLIENT_JAR="$ROOT_DIR/implementations/java/client/target/specus-client-exec.jar"
ACCESS_TOKEN="${ACCESS_TOKEN:-c-smoke-access-token}"
if command -v java >/dev/null 2>&1; then
  JAVA_COMMAND="${JAVA_COMMAND:-java}"
elif command -v java.exe >/dev/null 2>&1; then
  JAVA_COMMAND="${JAVA_COMMAND:-java.exe}"
else
  echo "missing Java runtime (java or java.exe)" >&2
  exit 1
fi
JAVA_CLIENT_JAR_ARG="$JAVA_CLIENT_JAR"
UPSTREAM_HOST="127.0.0.1"
if [[ "$JAVA_COMMAND" == *.exe ]]; then
  JAVA_CLIENT_JAR_ARG="$(wslpath -w "$JAVA_CLIENT_JAR")"
  # A Windows JVM resolves 127.0.0.1 in the Windows network namespace. Use the
  # WSL interface address for upstreams hosted by this script inside WSL.
  UPSTREAM_HOST="${UPSTREAM_HOST_OVERRIDE:-$(hostname -I | awk '{print $1}')}"
fi

cleanup() {
  set +e
  if [[ -n "${JAVA_PID:-}" ]]; then kill "$JAVA_PID" 2>/dev/null || true; fi
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [[ -n "${ECHO_PID:-}" ]]; then kill "$ECHO_PID" 2>/dev/null || true; fi
  if [[ -n "${HTTP_PID:-}" ]]; then kill "$HTTP_PID" 2>/dev/null || true; fi
  if [[ -n "${WS_PID:-}" ]]; then kill "$WS_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ ! -f "$JAVA_CLIENT_JAR" ]]; then
  echo "missing Java client jar: $JAVA_CLIENT_JAR" >&2
  echo "build it first with: mvn -pl :specus-client -am package -DskipTests" >&2
  exit 1
fi

make -C "$C_DIR" test

python3 - "$ECHO_PORT" <<'PY' &
import socket
import sys
port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", port))
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

python3 - "$HTTP_UPSTREAM_PORT" <<'PY' >"$TMP_DIR/http-upstream.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length)
        response_body = b"upstream:" + self.path.encode() + b":" + request_body
        self.send_response(201)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
PY
HTTP_PID=$!

python3 - "$WS_UPSTREAM_PORT" <<'PY' >"$TMP_DIR/ws-upstream.log" 2>&1 &
import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def read_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)

def send_frame(conn, fin, opcode, payload):
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length <= 125:
        header = bytes((first, length))
    elif length <= 0xffff:
        header = bytes((first, 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, 127)) + struct.pack("!Q", length)
    conn.sendall(header + payload)

def serve(conn):
    with conn:
        request = bytearray()
        while b"\r\n\r\n" not in request:
            request.extend(read_exact(conn, 1))
        headers = {}
        for line in request.decode("iso-8859-1").split("\r\n")[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.lower()] = value.strip()
        key = headers["sec-websocket-key"]
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        conn.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode())
        while True:
            first, second = read_exact(conn, 2)
            fin = bool(first & 0x80)
            opcode = first & 0x0f
            length = second & 0x7f
            if length == 126:
                length = struct.unpack("!H", read_exact(conn, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", read_exact(conn, 8))[0]
            mask = read_exact(conn, 4) if second & 0x80 else None
            payload = bytearray(read_exact(conn, length))
            if mask is not None:
                for index in range(length):
                    payload[index] ^= mask[index % 4]
            if opcode == 0x9:
                send_frame(conn, True, 0xA, payload)
            else:
                send_frame(conn, fin, opcode, payload)
            if opcode == 0x8:
                return

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", int(sys.argv[1])))
listener.listen(32)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
WS_PID=$!

SPECUS_NETTY_PORT="$CONTROL_PORT" \
SPECUS_ENV=dev \
SPECUS_CLIENT_NAME="Demo client" \
SPECUS_CLIENT_SESSION_ID="1" \
SPECUS_CLIENT_ACCESS_TOKEN="$ACCESS_TOKEN" \
SPECUS_ADMIN_PORT="$ADMIN_PORT" \
SPECUS_TCP_MAPPINGS="$PUBLIC_PORT=$UPSTREAM_HOST:$ECHO_PORT" \
SPECUS_HTTP_ROUTES="api=http://$UPSTREAM_HOST:$HTTP_UPSTREAM_PORT,ws=ws://$UPSTREAM_HOST:$WS_UPSTREAM_PORT" \
stdbuf -oL -eL "$C_DIR/build/specus-server-c" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

cat >"$TMP_DIR/client.jsonc" <<JSON
{
  "serverBaseUrl": "http://127.0.0.1:$ADMIN_PORT",
  "apiKey": "c-smoke",
  "secret": "not-used-by-c-auth-stub"
}
JSON

(cd "$TMP_DIR" && "$JAVA_COMMAND" -jar "$JAVA_CLIENT_JAR_ARG" >"$TMP_DIR/client.log" 2>&1) &
JAVA_PID=$!

if ! python3 - "$PUBLIC_PORT" "$ADMIN_PORT" <<'PY'
import base64
import hashlib
import http.client
import os
import socket
import struct
import sys
import time
port = int(sys.argv[1])
admin_port = int(sys.argv[2])
deadline = time.time() + 15
payloads = [
    b"specus-c-nat-smoke",
    bytes((index % 251 for index in range(1024 * 1024))),
    b"specus-c-reconnect-smoke",
]
last = None
while time.time() < deadline:
    try:
        for payload in payloads:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(payload)
                got = bytearray()
                while len(got) < len(payload):
                    try:
                        chunk = s.recv(min(65536, len(payload) - len(got)))
                    except socket.timeout as exc:
                        raise RuntimeError(f"payload receive timeout: {len(got)}/{len(payload)}") from exc
                    if not chunk:
                        break
                    got.extend(chunk)
                if got != payload:
                    raise RuntimeError(f"unexpected payload length: {len(got)}/{len(payload)}")
        direct = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
        direct.request("POST",
                       "/http/Demo%20client/api/v1/items?shape={ok}",
                       body=b"direct-body",
                       headers={"Content-Type": "application/octet-stream"})
        response = direct.getresponse()
        direct_body = response.read()
        direct.close()
        expected = b"upstream:/v1/items?shape=%7Bok%7D:direct-body"
        if response.status != 201 or direct_body != expected:
            raise RuntimeError(f"Direct HTTP mismatch: {response.status} {direct_body!r}")

        def read_exact(sock, length):
            data = bytearray()
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    raise RuntimeError("WebSocket closed unexpectedly")
                data.extend(chunk)
            return bytes(data)

        def send_masked(sock, fin, opcode, payload):
            mask = os.urandom(4)
            first = (0x80 if fin else 0) | opcode
            length = len(payload)
            if length <= 125:
                header = bytes((first, 0x80 | length))
            elif length <= 0xffff:
                header = bytes((first, 0xfe)) + struct.pack("!H", length)
            else:
                header = bytes((first, 0xff)) + struct.pack("!Q", length)
            masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            sock.sendall(header + mask + masked)

        def receive_frame(sock):
            first, second = read_exact(sock, 2)
            if second & 0x80:
                raise RuntimeError("server WebSocket frame must not be masked")
            length = second & 0x7f
            if length == 126:
                length = struct.unpack("!H", read_exact(sock, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", read_exact(sock, 8))[0]
            return bool(first & 0x80), first & 0x0f, read_exact(sock, length)

        with socket.create_connection(("127.0.0.1", admin_port), timeout=10) as ws:
            ws.settimeout(10)
            key = base64.b64encode(os.urandom(16)).decode()
            request = (
                "GET /http/Demo%20client/ws/echo?channel={0} HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
            ws.sendall(request)
            handshake = bytearray()
            while b"\r\n\r\n" not in handshake:
                handshake.extend(ws.recv(4096))
            if not handshake.startswith(b"HTTP/1.1 101"):
                raise RuntimeError(f"WebSocket handshake failed: {handshake!r}")
            expected_accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            if b"Sec-WebSocket-Accept: " + expected_accept not in handshake:
                raise RuntimeError("WebSocket accept key mismatch")
            time.sleep(0.25)
            send_masked(ws, True, 0x1, b"ws-smoke")
            if receive_frame(ws) != (True, 0x1, b"ws-smoke"):
                raise RuntimeError("WebSocket text echo mismatch")
            send_masked(ws, False, 0x1, b"frag-")
            send_masked(ws, True, 0x0, b"done")
            if receive_frame(ws) != (False, 0x1, b"frag-") \
                    or receive_frame(ws) != (True, 0x0, b"done"):
                raise RuntimeError("WebSocket continuation echo mismatch")
            send_masked(ws, True, 0x9, b"ping")
            if receive_frame(ws) != (True, 0xA, b"ping"):
                raise RuntimeError("WebSocket pong mismatch")
            close_payload = struct.pack("!H", 1000) + b"done"
            send_masked(ws, True, 0x8, close_payload)
            if receive_frame(ws) != (True, 0x8, close_payload):
                raise RuntimeError("WebSocket close handshake mismatch")

        print("NAT/Direct HTTP/WebSocket smoke passed (small + 1 MiB + reconnect + POST/query + SWS2)")
        raise SystemExit(0)
    except Exception as exc:
        last = str(exc)
        time.sleep(1)
print(f"NAT smoke failed: {last}", file=sys.stderr)
raise SystemExit(1)
PY
then
  echo "--- C server log ---" >&2
  tail -n 200 "$TMP_DIR/server.log" >&2 || true
  echo "--- Java client log ---" >&2
  tail -n 200 "$TMP_DIR/client.log" >&2 || true
  echo "--- HTTP upstream log ---" >&2
  tail -n 200 "$TMP_DIR/http-upstream.log" >&2 || true
  echo "--- WebSocket upstream log ---" >&2
  tail -n 200 "$TMP_DIR/ws-upstream.log" >&2 || true
  exit 1
fi
