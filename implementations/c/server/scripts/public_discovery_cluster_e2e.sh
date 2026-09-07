#!/usr/bin/env bash
set -euo pipefail

SERVER_BINARY="${1:?C server binary is required}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-cluster.XXXXXX")"
REDIS_PORT="${SPECUS_TEST_CLUSTER_REDIS_PORT:-16390}"
CONTROL_ONE="${SPECUS_TEST_CLUSTER_CONTROL_ONE:-17310}"
ADMIN_ONE="${SPECUS_TEST_CLUSTER_ADMIN_ONE:-17311}"
CONTROL_TWO="${SPECUS_TEST_CLUSTER_CONTROL_TWO:-17320}"
ADMIN_TWO="${SPECUS_TEST_CLUSTER_ADMIN_TWO:-17321}"

cleanup() {
  set +e
  if [[ -n "${SERVER_ONE_PID:-}" ]]; then kill "$SERVER_ONE_PID" 2>/dev/null || true; fi
  if [[ -n "${SERVER_TWO_PID:-}" ]]; then kill "$SERVER_TWO_PID" 2>/dev/null || true; fi
  if [[ -n "${REDIS_PID:-}" ]]; then kill "$REDIS_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

redis-server --bind 127.0.0.1 --port "$REDIS_PORT" --protected-mode yes \
  --save '' --appendonly no --dir "$TMP_DIR" >"$TMP_DIR/redis.log" 2>&1 &
REDIS_PID=$!
for _ in $(seq 1 60); do
  if redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping >/dev/null 2>&1; then break; fi
  sleep 0.05
done
redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping >/dev/null

start_server() {
  local control_port="$1"
  local admin_port="$2"
  local log="$3"
  SPECUS_ENV=dev \
  SPECUS_DB_SEED_DEMO_CLIENT=false \
  SPECUS_CLIENT_NAME="cluster-$admin_port" \
  SPECUS_CLIENT_ACCESS_TOKEN="cluster-test-token-$admin_port" \
  SPECUS_NETTY_PORT="$control_port" \
  SPECUS_ADMIN_PORT="$admin_port" \
  SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=true \
  SPECUS_PUBLIC_TRANSFER_REDIS_URI="redis://127.0.0.1:$REDIS_PORT/0" \
  SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX="specus:test:discovery-e2e" \
  SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS=2 \
  SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS=200 \
  SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS=500 \
  "$SERVER_BINARY" >"$log" 2>&1 &
}

start_server "$CONTROL_ONE" "$ADMIN_ONE" "$TMP_DIR/server-one.log"
SERVER_ONE_PID=$!
start_server "$CONTROL_TWO" "$ADMIN_TWO" "$TMP_DIR/server-two.log"
SERVER_TWO_PID=$!

if ! python3 - "$ADMIN_ONE" "$ADMIN_TWO" "$REDIS_PORT" <<'PY'
import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

ADMIN_ONE, ADMIN_TWO, REDIS_PORT = map(int, sys.argv[1:])

def request(port, method, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    headers = {"Content-Type": "application/json"}
    encoded = None if body is None else json.dumps(body).encode()
    connection.request(method, path, encoded, headers)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, json.loads(payload or b"{}")

def issue_ticket(port, peer_id, display_name, room_id="nearby", discoverable=True):
    status, payload = request(port, "POST", "/api/public/transfer/ws-tickets", {
        "roomId": room_id,
        "peerId": peer_id,
        "displayName": display_name,
        "discoverable": discoverable,
    })
    if status != 200:
        raise RuntimeError(f"ticket failed on {port}: {status} {payload}")
    return payload["ticket"]

class WebSocket:
    def __init__(self, port, ticket):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(5)
        key = base64.b64encode(os.urandom(16)).decode()
        path = "/ws/public-transfer/discovery?ticket=" + urllib.parse.quote(ticket, safe="")
        request_data = (
            f"GET {path} HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        self.sock.sendall(request_data)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(self.sock.recv(4096))
        header, remainder = bytes(response).split(b"\r\n\r\n", 1)
        if not header.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"websocket handshake failed: {header!r}")
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if b"Sec-WebSocket-Accept: " + expected not in header:
            raise RuntimeError("websocket accept mismatch")
        self.buffer = bytearray(remainder)

    def exact(self, length):
        while len(self.buffer) < length:
            chunk = self.sock.recv(max(4096, length - len(self.buffer)))
            if not chunk:
                raise EOFError("websocket closed")
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def receive(self):
        first, second = self.exact(2)
        if second & 0x80:
            raise RuntimeError("server frame was masked")
        length = second & 0x7f
        if length == 126:
            length = struct.unpack("!H", self.exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.exact(8))[0]
        return first & 0x0f, self.exact(length)

    def send(self, opcode, payload):
        mask = os.urandom(4)
        length = len(payload)
        header = bytes((0x80 | opcode, 0x80 | length)) if length <= 125 else (
            bytes((0x80 | opcode, 0xfe)) + struct.pack("!H", length)
            if length <= 0xffff else bytes((0x80 | opcode, 0xff)) + struct.pack("!Q", length)
        )
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def json_until(self, predicate, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.sock.settimeout(max(0.1, deadline - time.time()))
            opcode, payload = self.receive()
            if opcode == 1:
                value = json.loads(payload)
                if predicate(value):
                    return value
            elif opcode == 8:
                raise EOFError(f"websocket closed: {payload!r}")
        raise TimeoutError("matching websocket JSON was not received")

def wait_ready():
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            first = request(ADMIN_ONE, "GET", "/api/public/transfer/clients/name-availability?clientName=probe")
            second = request(ADMIN_TWO, "GET", "/api/public/transfer/clients/name-availability?clientName=probe")
            if first[0] == 200 and second[0] == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError("cluster servers did not become ready")

wait_ready()
one = WebSocket(ADMIN_ONE, issue_ticket(ADMIN_ONE, "peer-a", "Alice"))
two = WebSocket(ADMIN_TWO, issue_ticket(ADMIN_TWO, "peer-b", "Bob"))
one.json_until(lambda value: value.get("type") == "hello")
two.json_until(lambda value: value.get("type") == "hello")
one_roster = one.json_until(lambda value: value.get("type") == "roster"
                           and {peer["peerId"] for peer in value["peers"]} >= {"peer-a", "peer-b"})
two_roster = two.json_until(lambda value: value.get("type") == "roster"
                           and {peer["peerId"] for peer in value["peers"]} >= {"peer-a", "peer-b"})
if one_roster["rosterRevision"] <= 0 or two_roster["rosterRevision"] <= 0:
    raise RuntimeError("cluster roster revision was not positive")

status, availability = request(ADMIN_ONE, "GET",
    "/api/public/transfer/clients/name-availability?clientName=Bob")
if status != 200 or availability.get("available") is not False:
    raise RuntimeError(f"cross-instance name availability mismatch: {status} {availability}")

duplicate = WebSocket(ADMIN_TWO, issue_ticket(ADMIN_TWO, "peer-a", "Duplicate"))
error = duplicate.json_until(lambda value: value.get("type") == "error")
if "peer id" not in error.get("error", ""):
    raise RuntimeError(f"cross-instance duplicate peer mismatch: {error}")

one.send(1, json.dumps({"type": "signal", "targetPeerId": "peer-b",
                        "payload": {"hello": "redis"}}, separators=(",", ":")).encode())
message = two.json_until(lambda value: value.get("type") == "signal"
                        and value.get("sourcePeerId") == "peer-a")
if message.get("sourceRole") != "EDITOR" or message.get("payload") != {"hello": "redis"}:
    raise RuntimeError(f"cross-instance targeted text mismatch: {message}")

app = bytearray(72)
app[:4] = b"STAP"
app[4] = 2
app[5] = 1
struct.pack_into("!I", app, 28, 1)
target = b"peer-b"
relay = b"STWR" + bytes((2, 0)) + struct.pack("!HHI", len(target), 0, len(app)) + target + app
one.send(2, relay)
opcode, binary = two.receive()
if opcode != 2 or binary[:4] != b"STWR":
    raise RuntimeError("cross-instance binary relay was not delivered")
target_len, source_len, app_len = struct.unpack("!HHI", binary[6:14])
offset = 14
if (binary[offset:offset + target_len] != b"peer-b"
        or binary[offset + target_len:offset + target_len + source_len] != b"peer-a"
        or app_len != 72):
    raise RuntimeError("cross-instance binary envelope mismatch")

three = WebSocket(ADMIN_TWO, issue_ticket(ADMIN_TWO, "peer-c", "Carol", room_id="other-room"))
three.json_until(lambda value: value.get("type") == "hello")
one.json_until(lambda value: value.get("type") == "roster"
               and "peer-c" in {peer["peerId"] for peer in value["peers"]})

hidden = WebSocket(ADMIN_TWO, issue_ticket(ADMIN_TWO, "peer-hidden", "Hidden", discoverable=False))
hidden.json_until(lambda value: value.get("type") == "hello")
one.send(1, json.dumps({"type": "signal", "targetPeerId": "peer-hidden",
                        "payload": {"hidden": True}}, separators=(",", ":")).encode())
hidden_message = hidden.json_until(lambda value: value.get("type") == "signal")
if hidden_message.get("payload") != {"hidden": True}:
    raise RuntimeError(f"hidden peer fallback mismatch: {hidden_message}")

subprocess.run(["redis-cli", "-h", "127.0.0.1", "-p", str(REDIS_PORT),
                "shutdown", "nosave"], check=True, stdout=subprocess.DEVNULL)
deadline = time.time() + 5
closed = 0
for websocket in (one, two):
    websocket.sock.settimeout(max(0.1, deadline - time.time()))
    try:
        while time.time() < deadline:
            opcode, _ = websocket.receive()
            if opcode == 8:
                closed += 1
                break
    except (EOFError, OSError, socket.timeout):
        closed += 1
if closed != 2:
    raise RuntimeError("Redis outage did not fail closed across both instances")

print("two-process Redis public discovery E2E passed")
PY
then
  echo "--- server one ---" >&2
  tail -n 200 "$TMP_DIR/server-one.log" >&2 || true
  echo "--- server two ---" >&2
  tail -n 200 "$TMP_DIR/server-two.log" >&2 || true
  echo "--- Redis ---" >&2
  tail -n 100 "$TMP_DIR/redis.log" >&2 || true
  exit 1
fi
