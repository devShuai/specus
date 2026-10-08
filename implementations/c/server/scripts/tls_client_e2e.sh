#!/usr/bin/env bash
set -euo pipefail

# A real client against a C server whose control/data listener runs PEM file TLS under a throwaway
# test CA, for the host name specus-c.test (which never has to resolve: the client dials the
# nettyHost 127.0.0.1 and checks the certificate against controlTls.serverName). The server holds
# the listener to the production TLS rule through SPECUS_TLS_REQUIRE_ENCRYPTION=true; it runs as
# SPECUS_ENV=test only because a production SQLite deployment needs a pre-created runtime client
# (SPECUS_CLIENT_NAME), which this run takes from the test seed instead.
#
# 1. The signed HTTP login advertises "nettyTls":true, and the same signed body again is refused.
# 2. A client without any controlTls settings follows nettyTls and starts TLS, which fails: its
#    system roots do not know the test CA.
# 3. controlTls.caCertificatePath naming another CA: the chain is refused.
# 4. The right CA but controlTls.serverName "wrong.specus-c.test": the host name is refused.
# 5. The right CA and serverName: control and data log in over TLS, and bytes make a round trip
#    through a TCP mapping, i.e. over the TLS data connection.
# In 2-4 the client must report a certificate error and the server must see no login.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
C_DIR="$ROOT_DIR/implementations/c/server"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-tls-client.XXXXXX")"
CONTROL_PORT="${CONTROL_PORT:-17510}"
ADMIN_PORT="${ADMIN_PORT:-17511}"
PUBLIC_PORT="${PUBLIC_PORT:-18510}"
ECHO_PORT="${ECHO_PORT:-19510}"
JAVA_CLIENT_JAR="$ROOT_DIR/implementations/java/client/target/specus-client-exec.jar"
ADMIN_USERNAME="tls-admin"
ADMIN_PASSWORD="tls-e2e-admin-password-2026"
ADMIN_JWT_SECRET="tls-e2e-jwt-secret-that-is-long-and-random-enough-2026"
CLIENT_API_KEY="c-tls-e2e"
CLIENT_SECRET="tls-e2e-client-secret"
TLS_HOST="specus-c.test"
UPSTREAM_HOST="127.0.0.1"
# Paths handed to the client; a Windows client started from WSL needs Windows paths.
to_client_path() { printf '%s' "$1"; }

# SPECUS_CLIENT_COMMAND runs another client against the C server, as in nat_e2e_smoke.sh; without
# it the Java reference client runs. Every client takes the same arguments.
if [[ -n "${SPECUS_CLIENT_COMMAND:-}" ]]; then
  read -r -a CLIENT_COMMAND <<<"$SPECUS_CLIENT_COMMAND"
  CLIENT_LABEL="${SPECUS_CLIENT_LABEL:-${CLIENT_COMMAND[0]##*/}}"
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
  fi
  CLIENT_COMMAND=("$JAVA_COMMAND" -jar "$JAVA_CLIENT_JAR_ARG")
  CLIENT_LABEL="Java"
fi
if [[ "${CLIENT_COMMAND[0]}" == *.exe ]]; then
  # A Windows client started from WSL reaches the echo upstream through the WSL interface address.
  UPSTREAM_HOST="${UPSTREAM_HOST_OVERRIDE:-$(hostname -I | awk '{print $1}')}"
  to_client_path() { wslpath -w "$1"; }
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
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${ECHO_PID:-}"; do
    if [[ -n "$pid" ]]; then stop_process "$pid"; fi
  done
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

# shellcheck source=tls_test_pki.sh
source "$C_DIR/scripts/tls_test_pki.sh"
make_test_pki "$TMP_DIR" "$TLS_HOST"

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

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", int(sys.argv[1])))
server.listen(16)
while True:
    conn, _ = server.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
ECHO_PID=$!

SPECUS_ENV=test \
SPECUS_DB_SEED_DEMO_CLIENT=1 \
SPECUS_TLS_REQUIRE_ENCRYPTION=true \
SPECUS_TLS_MODE=file \
SPECUS_TLS_CERTIFICATE="$TMP_DIR/server.pem" \
SPECUS_TLS_PRIVATE_KEY="$TMP_DIR/server.key" \
SPECUS_DATABASE_PATH="$TMP_DIR/specus.db" \
SPECUS_NETTY_PORT="$CONTROL_PORT" \
SPECUS_ADMIN_PORT="$ADMIN_PORT" \
SPECUS_AUTH_USERNAME="$ADMIN_USERNAME" \
SPECUS_AUTH_PASSWORD="$ADMIN_PASSWORD" \
SPECUS_AUTH_JWT_SECRET="$ADMIN_JWT_SECRET" \
stdbuf -oL -eL "$C_DIR/build/specus-server-c" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

dump_logs() {
  echo "--- C server log ---" >&2
  tail -n 120 "$TMP_DIR/server.log" >&2 || true
  for log in "$TMP_DIR"/client-*.log; do
    [[ -f "$log" ]] || continue
    echo "--- $CLIENT_LABEL client log ($(basename "$log")) ---" >&2
    tail -n 60 "$log" >&2 || true
  done
}

fail() {
  echo "Control TLS E2E failed ($CLIENT_LABEL client): $*" >&2
  dump_logs
  exit 1
}

# Admin token and client credential, then the signed login checks of step 1.
ADMIN_TOKEN="$(python3 - "$ADMIN_PORT" "$ADMIN_USERNAME" "$ADMIN_PASSWORD" "$CLIENT_API_KEY" "$CLIENT_SECRET" <<'PY'
import hashlib
import hmac
import http.client
import json
import secrets
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
    "apiKey": api_key, "secret": secret, "enabled": True, "maxOnlineInstances": 2}, token)
if status != 201:
    raise SystemExit(f"credential create failed: {status} {payload}")

# Signed exactly as protocol/spec/client-auth.md describes, from a machine the clients never use.
timestamp = str(int(time.time() * 1000))
nonce = secrets.token_hex(16)
fingerprint, os_user = "tls-e2e-probe", "probe"
message = "\n".join([api_key, timestamp, nonce, fingerprint, os_user]).encode()
signature = hmac.new(hashlib.sha256(secret.encode()).digest(), message, hashlib.sha256).hexdigest()
login = {"apiKey": api_key, "timestamp": timestamp, "nonce": nonce, "signature": signature,
         "environment": {"machineFingerprint": fingerprint, "osUser": os_user}}
status, payload = request("POST", "/api/client/auth/login", login)
if status != 200 or payload.get("nettyTls") is not True or payload.get("nettyPort") is None:
    raise SystemExit(f"login did not advertise nettyTls=true: {status} {payload}")
status, replay = request("POST", "/api/client/auth/login", login)
if status != 400 or replay.get("error") != "客户端签名 nonce 已使用" or "accessToken" in replay:
    raise SystemExit(f"replayed login was not refused: {status} {replay}")
print(f"login advertises nettyTls=true for {payload['nettyHost']}:{payload['nettyPort']}; "
      f"replay answered {status} {replay['error']}", file=sys.stderr)
print(token)
PY
)" || fail "admin setup or login checks"

# write_config NAME CONTROL_TLS_JSON writes a client configuration with that controlTls block.
write_config() {
  mkdir -p "$TMP_DIR/$1"
  cat >"$TMP_DIR/$1/client.jsonc" <<JSON
{
  "serverBaseUrl": "http://127.0.0.1:$ADMIN_PORT",
  "apiKey": "$CLIENT_API_KEY",
  "secret": "$CLIENT_SECRET"$2
}
JSON
}

json_string() { python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"; }

start_client() {
  local name="$1"
  CASE_START_LINE=$(($(wc -l <"$TMP_DIR/server.log") + 1))
  # exec makes CLIENT_PID the client itself, so stopping it stops the client and not a subshell.
  # --debug makes every client log why a TLS handshake failed, not just that it did.
  (cd "$TMP_DIR/$name" && exec "${CLIENT_COMMAND[@]}" run --config client.jsonc --no-update-check --debug \
    >"$TMP_DIR/client-$name.log" 2>&1) &
  CLIENT_PID=$!
}

stop_client() {
  stop_process "$CLIENT_PID"
  CLIENT_PID=""
}

case_server_log() { tail -n "+$CASE_START_LINE" "$TMP_DIR/server.log"; }

# Whether this case's server log has a line matching the extended regex $1. grep -q would stop at
# the first match, and on a long log tail then dies of SIGPIPE, which pipefail turns into a "no"
# (or, negated, a "yes") with the line there; grep -c reads everything.
case_server_log_has() { case_server_log | grep -cE -- "$1" >/dev/null; }

# How each client words a failed certificate check (Go x509, Java PKIX/SAN, .NET SslPolicyErrors).
CERTIFICATE_ERROR='x509|certificat|PKIX|subject alternative|RemoteCertificate|UntrustedRoot|NameMismatch'

# A LOGIN_REQUEST, accepted or not, would mean the client sent its token over an unverified channel.
expect_no_login() {
  if case_server_log_has "login (ok|rejected)"; then
    fail "$1: the client sent a login over a connection it should not have trusted"
  fi
}

# expect_rejected NAME: within 45 s the client reports a certificate error, the server saw it speak
# TLS (Go and Java abort the handshake with an alert; .NET on Linux checks the chain once OpenSSL has
# finished the handshake and then closes), and no login ever reaches the server.
expect_rejected() {
  local name="$1" line=""
  start_client "$name"
  for _ in $(seq 1 180); do
    expect_no_login "$name"
    line="$(grep -m 1 -iE "$CERTIFICATE_ERROR" "$TMP_DIR/client-$name.log" || true)"
    if [[ -n "$line" ]] && case_server_log_has "\[tls\] handshake (complete|rejected .*alert)"; then
      break
    fi
    line=""
    sleep 0.25
  done
  [[ -n "$line" ]] || fail "$name: no certificate error from the client, or the server saw no TLS from it"
  sleep 1
  expect_no_login "$name"
  stop_client
  echo "ok   $name: rejected; client: $(printf '%s' "$line" | sed 's/^ *//' | cut -c1-220)"
  echo "     server: $(case_server_log | grep -E '^\[(tls|control)\] (handshake|bad frame|closed)' | head -n 2 \
    | cut -c1-140 | paste -sd '|' -)"
}

CA_PATH="$(json_string "$(to_client_path "$TMP_DIR/ca.pem")")"
OTHER_CA_PATH="$(json_string "$(to_client_path "$TMP_DIR/other-ca.pem")")"

write_config follows-netty-tls ""
expect_rejected follows-netty-tls

write_config wrong-ca ",
  \"controlTls\": {\"caCertificatePath\": $OTHER_CA_PATH, \"serverName\": \"$TLS_HOST\"}"
expect_rejected wrong-ca

write_config wrong-name ",
  \"controlTls\": {\"caCertificatePath\": $CA_PATH, \"serverName\": \"wrong.$TLS_HOST\"}"
expect_rejected wrong-name

write_config trusted ",
  \"controlTls\": {\"caCertificatePath\": $CA_PATH, \"serverName\": \"$TLS_HOST\"}"
start_client trusted
for _ in $(seq 1 180); do
  if case_server_log_has "\[control\] login ok" && case_server_log_has "\[data\] login ok"; then
    break
  fi
  sleep 0.25
done
case_server_log_has "\[data\] login ok" || fail "trusted: control and data did not log in"
handshakes="$(case_server_log | grep -c "\[tls\] handshake complete" || true)"
[[ "$handshakes" -ge 2 ]] || fail "trusted: $handshakes completed TLS handshake(s), expected control and data"
! case_server_log_has "\[tls\] handshake rejected" || fail "trusted: a TLS handshake was rejected"

# Bytes through a TCP mapping travel over the TLS data connection.
python3 - "$ADMIN_PORT" "$PUBLIC_PORT" "$ECHO_PORT" "$UPSTREAM_HOST" "$ADMIN_TOKEN" <<'PY' || fail "trusted: TCP round trip"
import http.client
import json
import os
import socket
import sys
import time

admin_port, public_port, echo_port = map(int, sys.argv[1:4])
upstream_host, token = sys.argv[4:6]

def request(method, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    connection.request(method, path, body=None if body is None else json.dumps(body).encode(), headers=headers)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, json.loads(payload) if payload else None

deadline = time.time() + 30
client = None
while client is None and time.time() < deadline:
    status, clients = request("GET", "/api/admin/clients")
    if status == 200:
        online = [item for item in clients if item.get("online") is True]
        client = online[0] if online else None
    if client is None:
        time.sleep(0.25)
if client is None:
    raise SystemExit("no online client in the management projection")
status, mapping = request("POST", f"/api/admin/clients/{client['id']}/specus-mappings", {
    "listenPort": public_port, "targetAddress": upstream_host, "targetPort": echo_port, "enabled": True})
if status != 201:
    raise SystemExit(f"mapping create failed: {status} {mapping}")
payload = os.urandom(256 * 1024)
deadline = time.time() + 30
last = None
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", public_port), timeout=5) as stream:
            stream.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = stream.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
        if bytes(received) == payload:
            print(f"     {len(payload)} bytes made the round trip through {client['clientName']}")
            sys.exit(0)
        last = f"{len(received)}/{len(payload)} bytes came back"
    except OSError as error:
        last = error
    time.sleep(0.5)
raise SystemExit(f"TCP round trip through the mapping failed: {last}")
PY
stop_client
echo "ok   trusted: control and data logged in over TLS ($handshakes TLS handshakes, each verified by the client), TCP round trip"
echo "Control TLS E2E passed ($CLIENT_LABEL client)"
