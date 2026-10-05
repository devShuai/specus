#!/usr/bin/env bash
set -euo pipefail

# Direct HTTP and Direct WebSocket (SWS2) through the C server, end to end: a client publishes one
# local web app (plain HTTP and a WebSocket endpoint on the same port) as the HTTP route "app", and
# public requests to /http/{clientName}/app/** must reach it and come back intact. curl makes the
# plain HTTP requests; a small RFC 6455 client in Python drives the WebSocket sessions.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
C_DIR="$ROOT_DIR/implementations/c/server"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-direct.XXXXXX")"
CONTROL_PORT="${CONTROL_PORT:-17210}"
ADMIN_PORT="${ADMIN_PORT:-17211}"
APP_PORT="${APP_PORT:-19290}"
JAVA_CLIENT_JAR="$ROOT_DIR/implementations/java/client/target/specus-client-exec.jar"
ACCESS_TOKEN="${ACCESS_TOKEN:-c-direct-access-token}"
UPSTREAM_HOST="127.0.0.1"
# SPECUS_CLIENT_COMMAND runs another client against the C server, as in nat_e2e_smoke.sh; without
# it the Java reference client runs. Every client takes the same arguments.
if [[ -n "${SPECUS_CLIENT_COMMAND:-}" ]]; then
  read -r -a CLIENT_COMMAND <<<"$SPECUS_CLIENT_COMMAND"
  CLIENT_LABEL="${SPECUS_CLIENT_LABEL:-${CLIENT_COMMAND[0]##*/}}"
  if [[ "${CLIENT_COMMAND[0]}" == *.exe ]]; then
    UPSTREAM_HOST="${UPSTREAM_HOST_OVERRIDE:-$(hostname -I | awk '{print $1}')}"
  fi
else
  if command -v java >/dev/null 2>&1; then
    JAVA_COMMAND="${JAVA_COMMAND:-java}"
  elif command -v java.exe >/dev/null 2>&1; then
    JAVA_COMMAND="${JAVA_COMMAND:-java.exe}"
  else
    echo "missing Java runtime (java or java.exe)" >&2
    exit 1
  fi
  JAVA_CLIENT_JAR_ARG="$JAVA_CLIENT_JAR"
  if [[ "$JAVA_COMMAND" == *.exe ]]; then
    JAVA_CLIENT_JAR_ARG="$(wslpath -w "$JAVA_CLIENT_JAR")"
    UPSTREAM_HOST="${UPSTREAM_HOST_OVERRIDE:-$(hostname -I | awk '{print $1}')}"
  fi
  CLIENT_COMMAND=("$JAVA_COMMAND" -jar "$JAVA_CLIENT_JAR_ARG")
  CLIENT_LABEL="Java"
fi

# Stops a background process and waits until it is gone, so a client of this run never logs in to
# the next run's server (see nat_e2e_smoke.sh).
stop_process() {
  local pid="$1"
  kill "$pid" 2>/dev/null || return 0
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
  set +e
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${APP_PID:-}"; do
    if [[ -n "$pid" ]]; then stop_process "$pid"; fi
  done
  # SPECUS_E2E_LOG_DIR keeps this run's logs (C server, client, upstreams) once the temporary
  # directory is gone, whether the run passed or failed; CI uploads that directory as an artifact.
  if [[ -n "${SPECUS_E2E_LOG_DIR:-}" ]]; then
    local label="${CLIENT_LABEL:-client}"
    local log_dir="$SPECUS_E2E_LOG_DIR/direct_route_e2e-${label//[^A-Za-z0-9._-]/_}"
    mkdir -p "$log_dir" && cp "$TMP_DIR"/*.log "$log_dir"/ 2>/dev/null
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

if [[ -z "${SPECUS_CLIENT_COMMAND:-}" && ! -f "$JAVA_CLIENT_JAR" ]]; then
  echo "missing Java client jar: $JAVA_CLIENT_JAR" >&2
  echo "build it first with: mvn -pl :specus-client -am package -DskipTests" >&2
  exit 1
fi

# SPECUS_SMOKE_REUSE_BUILD=1 reuses a server an earlier run built and unit-tested.
if [[ "${SPECUS_SMOKE_REUSE_BUILD:-}" != 1 || ! -x "$C_DIR/build/specus-server-c" ]]; then
  make -C "$C_DIR" test
fi

# The local web app the route publishes. Plain HTTP answers describe what arrived, so a check can
# tell the request reached it unchanged; GET with "Upgrade: websocket" becomes a WebSocket that
# greets with the request target it saw and then echoes every frame as it came (opcode, FIN and
# payload). WebSocket events go to a line-buffered log the checks read.
python3 - "$APP_PORT" "$TMP_DIR/app-events.log" <<'PY' >"$TMP_DIR/app.log" 2>&1 &
import base64
import hashlib
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
events = open(sys.argv[2], "a", buffering=1, encoding="utf-8")


def pattern(length):
    return (bytes(range(251)) * (length // 251 + 1))[:length]


def unmask(payload, mask):
    if not payload:
        return b""
    key = (mask * (len(payload) // 4 + 1))[:len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(len(payload), "big")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def send_body(self, status, body, content_type="application/octet-stream", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.websocket()
            return
        if self.path.startswith("/hello"):
            body = (f"hello method=GET target={self.path} "
                    f"probe={self.headers.get('X-Request-Probe')}").encode()
            self.send_body(200, body, "text/plain; charset=utf-8",
                           [("X-Upstream-Probe", "ok"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
        elif self.path.startswith("/blob/"):
            self.send_body(200, pattern(int(self.path[len("/blob/"):])))
        elif self.path.startswith("/pct/"):
            self.send_body(200, self.path.encode())
        elif self.path == "/stream":
            # No length up front: the body arrives in pieces, as from a streaming endpoint.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"first;", b"second;", b"third"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.flush()
                time.sleep(0.05)
            self.wfile.write(b"0\r\n\r\n")
        else:
            self.send_body(404, b"no such page: " + self.path.encode(), "text/plain")

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return bytes(body)
                body.extend(self.rfile.read(size))
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def do_POST(self):
        body = self.read_body()
        self.send_body(201, body, extra=[
            ("X-Body-Length", str(len(body))),
            ("X-Body-Sha256", hashlib.sha256(body).hexdigest()),
        ])

    def read_exact(self, length):
        data = self.rfile.read(length)
        if len(data) != length:
            raise EOFError()
        return data

    def send_frame(self, fin, opcode, payload):
        first = (0x80 if fin else 0) | opcode
        length = len(payload)
        if length <= 125:
            header = bytes((first, length))
        elif length <= 0xffff:
            header = bytes((first, 126)) + struct.pack("!H", length)
        else:
            header = bytes((first, 127)) + struct.pack("!Q", length)
        self.wfile.write(header + payload)
        self.wfile.flush()

    def websocket(self):
        self.close_connection = True
        accept = base64.b64encode(hashlib.sha1(
            (self.headers["Sec-WebSocket-Key"] + GUID).encode()).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()
        self.send_frame(True, 0x1, f"welcome {self.path}".encode())
        closing = False
        message = bytearray()
        try:
            while True:
                first, second = self.read_exact(2)
                fin, opcode, length = bool(first & 0x80), first & 0x0f, second & 0x7f
                if length == 126:
                    length = struct.unpack("!H", self.read_exact(2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", self.read_exact(8))[0]
                mask = self.read_exact(4) if second & 0x80 else None
                payload = self.read_exact(length)
                if mask is not None:
                    payload = unmask(payload, mask)
                if opcode == 0x8:
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 0
                    reason = payload[2:].decode("utf-8", "replace")
                    if closing:
                        events.write(f"close-reply {code} {reason}\n")
                    else:
                        events.write(f"close-received {code} {reason}\n")
                        self.send_frame(True, 0x8, payload)
                    return
                if opcode == 0x9:
                    self.send_frame(True, 0xA, payload)
                    continue
                if opcode == 0xA:
                    continue
                message.extend(payload)
                if fin:
                    events.write(f"message opcode={opcode} bytes={len(message)}\n")
                    if bytes(message) == b"please-close":
                        # The app ends the session itself; the browser side has to answer.
                        closing = True
                        self.send_frame(True, 0x8, struct.pack("!H", 1001) + b"app going away")
                        message = bytearray()
                        continue
                    message = bytearray()
                self.send_frame(fin, opcode, payload)
        except (EOFError, ConnectionError, OSError):
            events.write("socket-ended\n")


ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
PY
APP_PID=$!

SPECUS_NETTY_PORT="$CONTROL_PORT" \
SPECUS_ENV=dev \
SPECUS_CLIENT_NAME="Demo client" \
SPECUS_CLIENT_SESSION_ID="1" \
SPECUS_CLIENT_ACCESS_TOKEN="$ACCESS_TOKEN" \
SPECUS_ADMIN_PORT="$ADMIN_PORT" \
SPECUS_HTTP_ROUTES="app=http://$UPSTREAM_HOST:$APP_PORT" \
stdbuf -oL -eL "$C_DIR/build/specus-server-c" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

cat >"$TMP_DIR/client.jsonc" <<JSON
{
  "serverBaseUrl": "http://127.0.0.1:$ADMIN_PORT",
  "apiKey": "c-direct",
  "secret": "not-used-by-c-auth-stub"
}
JSON

# exec makes CLIENT_PID the client itself, so cleanup stops the client and not just a subshell.
(cd "$TMP_DIR" && exec "${CLIENT_COMMAND[@]}" run --config client.jsonc --no-update-check >"$TMP_DIR/client.log" 2>&1) &
CLIENT_PID=$!

dump_logs() {
  echo "--- C server log ---" >&2
  tail -n 200 "$TMP_DIR/server.log" >&2 || true
  echo "--- $CLIENT_LABEL client log ---" >&2
  tail -n 200 "$TMP_DIR/client.log" >&2 || true
  echo "--- app log ---" >&2
  tail -n 100 "$TMP_DIR/app.log" >&2 || true
  echo "--- app WebSocket events ---" >&2
  tail -n 100 "$TMP_DIR/app-events.log" >&2 || true
}

fail() {
  echo "Direct route E2E failed ($CLIENT_LABEL client): $*" >&2
  dump_logs
  exit 1
}

BASE="http://127.0.0.1:$ADMIN_PORT/http/Demo%20client/app"

# The route answers once the client is online and has the route from the login NAT_CONTROL.
ready=0
for _ in $(seq 1 120); do
  if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/hello" || true)" == 200 ]]; then
    ready=1
    break
  fi
  sleep 0.25
done
[[ "$ready" == 1 ]] || fail "the route never answered 200"

# expect_http NAME STATUS EXPECTED_BODY_FILE CURL_ARGS... runs one request and compares the status
# and the exact body bytes; the response headers stay in $TMP_DIR/headers for further checks.
expect_http() {
  local name="$1" expected_status="$2" expected_body="$3"
  shift 3
  local status
  status="$(curl -sS --max-time 60 -o "$TMP_DIR/body" -D "$TMP_DIR/headers" -w '%{http_code}' "$@")" \
    || fail "$name: curl failed"
  [[ "$status" == "$expected_status" ]] || fail "$name: status $status, expected $expected_status"
  cmp -s "$TMP_DIR/body" "$expected_body" \
    || fail "$name: body differs ($(wc -c <"$TMP_DIR/body") bytes: $(head -c 200 "$TMP_DIR/body" | tr -c '[:print:]' '.'))"
}

expect_header() {
  tr -d '\r' <"$TMP_DIR/headers" | grep -qix "$1: *$2" \
    || fail "missing response header '$1: $2' in: $(tr -d '\r' <"$TMP_DIR/headers" | tr '\n' '|')"
}

python3 - "$TMP_DIR" <<'PY'
import os
import sys

directory = sys.argv[1]


def pattern(length):
    return (bytes(range(251)) * (length // 251 + 1))[:length]


def write(name, data):
    with open(os.path.join(directory, name), "wb") as handle:
        handle.write(data)


write("expect-hello", b"hello method=GET target=/hello/world?lang=zh&q=%2F probe=probe-1")
write("expect-pct", "/pct/a+b/c%20d/%E4%BD%A0/x%2Fy?q=a+b%26c".encode())
write("expect-missing", b"no such page: /missing")
write("expect-stream", b"first;second;third")
write("small-body", "direct POST body 你好".encode())
write("blob-6m", pattern(6 * 1024 * 1024))
write("upload-2m", os.urandom(2 * 1024 * 1024))
PY

# GET: status, body, a request header in and response headers (one of them repeated) out.
expect_http "GET" 200 "$TMP_DIR/expect-hello" -H "X-Request-Probe: probe-1" "$BASE/hello/world?lang=zh&q=%2F"
expect_header "X-Upstream-Probe" "ok"
expect_header "Set-Cookie" "a=1"
expect_header "Set-Cookie" "b=2"
# The path after the route and the query reach the app with their original percent-encoding.
expect_http "GET (percent-encoded path)" 200 "$TMP_DIR/expect-pct" "$BASE/pct/a+b/c%20d/%E4%BD%A0/x%2Fy?q=a+b%26c"
# A non-2xx answer is the app's answer, passed through with its body.
expect_http "GET (404 from the app)" 404 "$TMP_DIR/expect-missing" "$BASE/missing"
# 6 MiB down is several times the 1 MiB initial stream window, so it only arrives whole if the
# server keeps granting credit as it writes.
expect_http "GET (6 MiB)" 200 "$TMP_DIR/blob-6m" "$BASE/blob/$((6 * 1024 * 1024))"
# A response of unknown length, streamed by the app in pieces.
expect_http "GET (streamed)" 200 "$TMP_DIR/expect-stream" "$BASE/stream"
# POST: the app echoes the body, so the same bytes must make the round trip.
expect_http "POST" 201 "$TMP_DIR/small-body" -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary "@$TMP_DIR/small-body" "$BASE/echo"
expect_header "X-Body-Length" "$(wc -c <"$TMP_DIR/small-body" | tr -d ' ')"
# 2 MiB up (and back): the request body also outgrows the initial window.
expect_http "POST (2 MiB)" 201 "$TMP_DIR/upload-2m" -H "Content-Type: application/octet-stream" \
  --data-binary "@$TMP_DIR/upload-2m" "$BASE/echo"
expect_header "X-Body-Sha256" "$(sha256sum "$TMP_DIR/upload-2m" | cut -d' ' -f1)"
# The same body without a length, as chunked transfer encoding.
expect_http "POST (chunked)" 201 "$TMP_DIR/small-body" -H "Transfer-Encoding: chunked" \
  --data-binary "@$TMP_DIR/small-body" "$BASE/echo"
echo "Direct HTTP passed ($CLIENT_LABEL client): GET + headers, percent-encoded path, 404, 6 MiB down, streamed, POST, 2 MiB up, chunked POST"

if ! python3 - "$ADMIN_PORT" "$TMP_DIR/app-events.log" <<'PY'
import base64
import hashlib
import os
import socket
import struct
import sys
import time

admin_port = int(sys.argv[1])
events_path = sys.argv[2]
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def mask_bytes(payload, mask):
    if not payload:
        return b""
    key = (mask * (len(payload) // 4 + 1))[:len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(len(payload), "big")


class Browser:
    def __init__(self, target):
        self.sock = socket.create_connection(("127.0.0.1", admin_port), timeout=20)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET /http/Demo%20client/app{target} HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(1)
            if not chunk:
                raise RuntimeError(f"connection closed during the handshake: {bytes(response)!r}")
            response.extend(chunk)
        if not response.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"handshake failed: {bytes(response)!r}")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest())
        if b"Sec-WebSocket-Accept: " + accept not in response:
            raise RuntimeError("Sec-WebSocket-Accept mismatch")
        self.pongs = []

    def send(self, fin, opcode, payload):
        mask = os.urandom(4)
        first = (0x80 if fin else 0) | opcode
        length = len(payload)
        if length <= 125:
            header = bytes((first, 0x80 | length))
        elif length <= 0xffff:
            header = bytes((first, 0xfe)) + struct.pack("!H", length)
        else:
            header = bytes((first, 0xff)) + struct.pack("!Q", length)
        self.sock.sendall(header + mask + mask_bytes(payload, mask))

    def read_exact(self, length):
        data = bytearray()
        while len(data) < length:
            chunk = self.sock.recv(min(65536, length - len(data)))
            if not chunk:
                raise RuntimeError("WebSocket closed unexpectedly")
            data.extend(chunk)
        return bytes(data)

    def frame(self):
        first, second = self.read_exact(2)
        if second & 0x80:
            raise RuntimeError("a server frame must not be masked")
        if first & 0x70:
            raise RuntimeError(f"unexpected RSV bits in 0x{first:02x}")
        length = second & 0x7f
        if length == 126:
            length = struct.unpack("!H", self.read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.read_exact(8))[0]
        return bool(first & 0x80), first & 0x0f, self.read_exact(length)

    def message(self):
        """The next data message, put back together from its fragments; pongs are collected."""
        opcode, data, frames = None, bytearray(), 0
        while True:
            fin, frame_opcode, payload = self.frame()
            if frame_opcode == 0xA:
                self.pongs.append(payload)
                continue
            if frame_opcode == 0x8:
                return 0x8, payload, 1
            if opcode is None:
                if frame_opcode not in (0x1, 0x2):
                    raise RuntimeError(f"message starts with opcode {frame_opcode}")
                opcode = frame_opcode
            elif frame_opcode != 0x0:
                raise RuntimeError(f"opcode {frame_opcode} inside a fragmented message")
            data.extend(payload)
            frames += 1
            if fin:
                return opcode, bytes(data), frames

    def expect_eof(self):
        self.sock.settimeout(5)
        try:
            leftover = self.sock.recv(1)
        except socket.timeout:
            raise RuntimeError("the server kept the TCP connection open after the close handshake")
        if leftover:
            raise RuntimeError(f"data after the close handshake: {leftover!r}")
        self.sock.close()


def expect(actual, wanted, what):
    if actual != wanted:
        shown = repr(actual)
        raise RuntimeError(f"{what}: got {shown[:200]}{'...' if len(shown) > 200 else ''}")


def wait_event(line):
    deadline = time.time() + 5
    while time.time() < deadline:
        with open(events_path, encoding="utf-8") as handle:
            if line in handle.read().splitlines():
                return
        time.sleep(0.1)
    raise RuntimeError(f"the app never logged '{line}'")


# Session 1: the browser talks first after the greeting, and closes.
ws = Browser("/ws/chat?room=%7Ba%7D")
expect(ws.message(), (0x1, b"welcome /ws/chat?room=%7Ba%7D", 1), "greeting from the app")
text = "text 你好 \U0001f600".encode()
ws.send(True, 0x1, text)
expect(ws.message(), (0x1, text, 1), "text echo")
small_binary = bytes(range(256)) * 4
ws.send(True, 0x2, small_binary)
expect(ws.message(), (0x2, small_binary, 1), "binary echo")
# One 1.5 MiB binary frame: the server splits it into SWS2 envelopes and has to wait for credit
# past the first 1 MiB; it comes back as one message of several frames.
large_binary = os.urandom(1536 * 1024)
ws.send(True, 0x2, large_binary)
opcode, data, frames = ws.message()
if (opcode, data) != (0x2, large_binary):
    raise RuntimeError(f"1.5 MiB binary echo mismatch: opcode {opcode}, {len(data)} bytes")
# A fragmented text message with a ping between its fragments.
ws.send(False, 0x1, b"frag-1|")
ws.send(True, 0x9, b"mid-message ping")
ws.send(False, 0x0, b"frag-2|")
ws.send(True, 0x0, b"frag-3")
expect(ws.message(), (0x1, b"frag-1|frag-2|frag-3", 3), "fragmented text echo")
expect(ws.pongs, [b"mid-message ping"], "pong for the ping between fragments")
close_payload = struct.pack("!H", 1000) + b"browser done"
ws.send(True, 0x8, close_payload)
expect(ws.message(), (0x8, close_payload, 1), "close handshake reply")
ws.expect_eof()
wait_event("close-received 1000 browser done")

# Session 2: the app ends the session and the browser answers its close.
ws = Browser("/ws/leave")
expect(ws.message(), (0x1, b"welcome /ws/leave", 1), "greeting from the app")
ws.send(True, 0x1, b"please-close")
app_close = struct.pack("!H", 1001) + b"app going away"
expect(ws.message(), (0x8, app_close, 1), "close started by the app")
ws.send(True, 0x8, app_close)
ws.expect_eof()
wait_event("close-reply 1001 app going away")

print(f"Direct WebSocket passed: greeting, UTF-8 text, binary, 1.5 MiB binary ({frames} frames back), "
      "fragmented text with an interleaved ping, close from each side")
PY
then
  fail "WebSocket checks"
fi
