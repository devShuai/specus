#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
C_DIR="$ROOT_DIR/implementations/c/server"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-runtime.XXXXXX")"
CONTROL_PORT="${CONTROL_PORT:-17110}"
ADMIN_PORT="${ADMIN_PORT:-17111}"
PUBLIC_PORT="${PUBLIC_PORT:-18180}"
ECHO_PORT="${ECHO_PORT:-19190}"
HTTP_UPSTREAM_PORT="${HTTP_UPSTREAM_PORT:-19191}"
JAVA_CLIENT_JAR="$ROOT_DIR/implementations/java/client/target/specus-client-exec.jar"
ADMIN_USERNAME="runtime-admin"
ADMIN_PASSWORD="runtime-admin-password"
ADMIN_JWT_SECRET="runtime-e2e-jwt-secret-that-is-long-and-random-enough-2026"
CLIENT_API_KEY="c-runtime-e2e"
CLIENT_SECRET="runtime-client-secret"

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
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${ECHO_PID:-}" "${HTTP_PID:-}"; do
    if [[ -n "$pid" ]]; then stop_process "$pid"; fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

if [[ -z "${SPECUS_CLIENT_COMMAND:-}" && ! -f "$JAVA_CLIENT_JAR" ]]; then
  echo "missing Java client jar: $JAVA_CLIENT_JAR" >&2
  exit 1
fi

# SPECUS_SMOKE_REUSE_BUILD=1 reuses a server an earlier run built and unit-tested.
if [[ "${SPECUS_SMOKE_REUSE_BUILD:-}" != 1 || ! -x "$C_DIR/build/specus-server-c" ]]; then
  make -C "$C_DIR" test
fi

python3 - "$ECHO_PORT" <<'PY' &
import socket
import sys
import threading

def serve(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                return
            conn.sendall(data)

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", int(sys.argv[1])))
listener.listen(32)
while True:
    conn, _ = listener.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
ECHO_PID=$!

python3 - "$HTTP_UPSTREAM_PORT" <<'PY' >"$TMP_DIR/http-upstream.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        response = b"runtime:" + self.path.encode() + b":" + body
        self.send_response(202)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
PY
HTTP_PID=$!

SPECUS_ENV=dev \
SPECUS_DATABASE_PATH="$TMP_DIR/specus.db" \
SPECUS_DB_SEED_DEMO_CLIENT=1 \
SPECUS_NETTY_PORT="$CONTROL_PORT" \
SPECUS_ADMIN_PORT="$ADMIN_PORT" \
SPECUS_AUTH_USERNAME="$ADMIN_USERNAME" \
SPECUS_AUTH_PASSWORD="$ADMIN_PASSWORD" \
SPECUS_AUTH_JWT_SECRET="$ADMIN_JWT_SECRET" \
stdbuf -oL -eL "$C_DIR/build/specus-server-c" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

ADMIN_TOKEN="$(python3 - "$ADMIN_PORT" "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "$CLIENT_API_KEY" "$CLIENT_SECRET" <<'PY'
import http.client
import json
import sys
import time

port = int(sys.argv[1])
username, password, api_key, secret = sys.argv[2:]

def request(method, path, body=None, token=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    encoded = None if body is None else json.dumps(body).encode()
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, json.loads(payload or b"{}")

deadline = time.time() + 30
while True:
    try:
        status, payload = request("POST", "/auth/login", {"username": username, "password": password})
        if status == 200:
            token = payload["accessToken"]
            break
    except Exception:
        pass
    if time.time() >= deadline:
        raise SystemExit("admin login did not become ready")
    time.sleep(0.25)

status, payload = request("POST", "/api/admin/client-credentials", {
    "apiKey": api_key,
    "secret": secret,
    "enabled": True,
    "maxOnlineInstances": 2,
}, token)
if status != 201:
    raise SystemExit(f"credential create failed: {status} {payload}")
print(token)
PY
)"

cat >"$TMP_DIR/client.jsonc" <<JSON
{
  "serverBaseUrl": "http://127.0.0.1:$ADMIN_PORT",
  "apiKey": "$CLIENT_API_KEY",
  "secret": "$CLIENT_SECRET"
}
JSON

# exec makes CLIENT_PID the client itself, so cleanup stops the client and not just a subshell.
(cd "$TMP_DIR" && exec "${CLIENT_COMMAND[@]}" run --config client.jsonc --no-update-check >"$TMP_DIR/client.log" 2>&1) &
CLIENT_PID=$!

if ! python3 - "$ADMIN_PORT" "$PUBLIC_PORT" "$ECHO_PORT" "$HTTP_UPSTREAM_PORT" \
        "$UPSTREAM_HOST" "$ADMIN_TOKEN" <<'PY'
import http.client
import json
import socket
import sys
import time
import urllib.parse

admin_port, public_port, echo_port, http_port = map(int, sys.argv[1:5])
upstream_host, token = sys.argv[5:7]

def request(method, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    encoded = None if body is None else json.dumps(body).encode()
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    parsed = json.loads(payload) if payload else None
    return response.status, parsed

deadline = time.time() + 45
client = None
while time.time() < deadline:
    try:
        status, clients = request("GET", "/api/admin/clients")
        if status == 200:
            candidates = [
                item for item in clients
                if item.get("clientName") != "Demo client" and item.get("online") is True
            ]
            if candidates:
                client = candidates[0]
                break
    except Exception:
        pass
    time.sleep(0.25)
if client is None:
    raise RuntimeError("database-backed client did not become online in the management projection")

if not isinstance(client.get("connectedSinceMs"), int) or client["connectedSinceMs"] <= 0:
    raise RuntimeError(f"online client connectedSinceMs mismatch: {client}")
if not client.get("clientVersion"):
    raise RuntimeError(f"online client version was not projected: {client}")

client_id = client["id"]
client_name = client["clientName"]
status, mapping = request("POST", f"/api/admin/clients/{client_id}/specus-mappings", {
    "listenPort": public_port,
    "targetAddress": upstream_host,
    "targetPort": echo_port,
    "enabled": True,
})
if status != 201:
    raise RuntimeError(f"mapping create failed: {status} {mapping}")
mapping_id = mapping["id"]

status, route = request("POST", f"/api/admin/clients/{client_id}/http-routes", {
    "route": "api",
    "targetBaseUrl": f"http://{upstream_host}:{http_port}",
    "enabled": True,
})
if status != 201:
    raise RuntimeError(f"route create failed: {status} {route}")
route_id = route["id"]

encoded_name = urllib.parse.quote(client_name, safe="")


def direct_http():
    connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
    try:
        connection.request("POST", f"/http/{encoded_name}/api/live?shape={{ok}}", body=b"hot-route")
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_direct_http(expected, what):
    # No manual NAT_CONTROL push: the client learns where a route goes only from the push the
    # mutation itself sends, so an answer through the route is that push arriving.
    last = None
    for _ in range(80):
        try:
            last = direct_http()
            if last == (202, expected):
                return
        except Exception as error:
            last = error
        time.sleep(0.25)
    raise RuntimeError(f"{what}: Direct HTTP never answered through the pushed route: {last!r}")


wait_direct_http(b"runtime:/live?shape=%7Bok%7D:hot-route", "route create")

def echo(payload, timeout=5):
    with socket.create_connection(("127.0.0.1", public_port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = connection.recv(len(payload) - len(received))
            if not chunk:
                break
            received.extend(chunk)
        if received != payload:
            raise RuntimeError(f"runtime TCP mismatch: {len(received)}/{len(payload)}")

last_error = None
for _ in range(60):
    try:
        echo(b"runtime-config-online")
        last_error = None
        break
    except Exception as error:
        last_error = error
        time.sleep(0.25)
if last_error is not None:
    raise last_error

# A changed target reaches the running client the same way: the upstream echoes the path, so the
# new base path shows the client is forwarding with what the update pushed.
status, updated = request("PUT", f"/api/admin/http-routes/{route_id}", {
    "targetBaseUrl": f"http://{upstream_host}:{http_port}/v2",
})
if status != 200:
    raise RuntimeError(f"route update failed: {status} {updated}")
wait_direct_http(b"runtime:/v2/live?shape=%7Bok%7D:hot-route", "route update")

status, _ = request("DELETE", f"/api/admin/specus-mappings/{mapping_id}")
if status != 204:
    raise RuntimeError(f"mapping delete failed: {status}")
for _ in range(40):
    try:
        probe = socket.create_connection(("127.0.0.1", public_port), timeout=0.25)
        probe.close()
    except OSError:
        break
    time.sleep(0.1)
else:
    raise RuntimeError("deleted mapping listener remained reachable")

status, mapping = request("POST", f"/api/admin/clients/{client_id}/specus-mappings", {
    "listenPort": public_port,
    "targetAddress": upstream_host,
    "targetPort": echo_port,
    "enabled": True,
})
if status != 201:
    raise RuntimeError(f"mapping recreate failed: {status} {mapping}")
for _ in range(60):
    try:
        echo(b"runtime-config-restored")
        break
    except Exception:
        time.sleep(0.25)
else:
    raise RuntimeError("recreated mapping never became reachable")

# The explicit push endpoint still answers with what it sent.
status, pushed = request("POST", f"/api/admin/clients/{client_id}/nat-control")
if status != 200 or pushed.get("pushed") != 1 or pushed.get("specusMappings") != 1 \
        or pushed.get("httpRoutes") != 1:
    raise RuntimeError(f"manual NAT_CONTROL push failed: {status} {pushed}")

print(f"Runtime NAT_CONTROL smoke passed (client={client_name}, pushed on route create/update and "
      "mapping create/delete/recreate + Direct HTTP + manual push)")
PY
then
  echo "--- C server log ---" >&2
  tail -n 240 "$TMP_DIR/server.log" >&2 || true
  echo "--- $CLIENT_LABEL client log ---" >&2
  tail -n 240 "$TMP_DIR/client.log" >&2 || true
  echo "--- HTTP upstream log ---" >&2
  tail -n 120 "$TMP_DIR/http-upstream.log" >&2 || true
  exit 1
fi
