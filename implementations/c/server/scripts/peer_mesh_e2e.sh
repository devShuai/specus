#!/usr/bin/env bash
set -euo pipefail

# Peer Mesh through the C server with two real clients (issue #35, P3): roster, session grant,
# candidate exchange and path reports over PEER_CONTROL, then the standard TURN relay.
#
# Phase one runs both clients next to the server, in a namespace whose only interface is loopback.
# Their candidates are the server-reflexive addresses the C STUN service reports (and, for a client
# that offers them, 127.0.0.1 host candidates), so they must settle on a DIRECT path over loopback. Phase two restarts the same two clients each in a network namespace of its own that reaches
# the server and nothing else: the namespaces are joined to the server's by veth pairs and the
# server's namespace does not forward, so no datagram can pass between the clients except through
# the C server's TURN allocations, and the path must become RELAY. Each phase ends with one client
# leaving and the other's roster showing it offline.
#
# The clients run with peerMeshDevice "noop", so there is no TUN device and no virtual-IP traffic.
# What crosses the relay is what a noop client sends on its own: the session-token-bound
# connectivity checks and their responses, which the C TURN server forwards only after checking the
# token against the session it granted.
#
# Nothing here touches the machine's own network. The script first re-executes itself in a private
# network namespace (unshare -rn where an unprivileged user namespace may configure its network,
# sudo -n unshare -n otherwise, as on CI runners) and refuses to run in a namespace that has any
# interface besides loopback or any route in its main table.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
C_DIR="$ROOT_DIR/implementations/c/server"
SCRIPT_PATH="$C_DIR/scripts/peer_mesh_e2e.sh"
JAVA_CLIENT_JAR="$ROOT_DIR/implementations/java/client/target/specus-client-exec.jar"

if [[ "${SPECUS_PEER_MESH_E2E_ISOLATED:-}" != 1 ]]; then
  # Built as the invoking user, before anything runs as root or as a namespace's fake root.
  # SPECUS_SMOKE_REUSE_BUILD=1 reuses a server an earlier run built and unit-tested.
  if [[ "${SPECUS_SMOKE_REUSE_BUILD:-}" != 1 || ! -x "$C_DIR/build/specus-server-c" ]]; then
    make -C "$C_DIR" test
  fi
  forwarded=("SPECUS_PEER_MESH_E2E_ISOLATED=1" "PATH=$PATH" "HOME=$HOME")
  for name in SPECUS_CLIENT_COMMAND SPECUS_CLIENT_LABEL JAVA_COMMAND JAVA_HOME DOTNET_ROOT TMPDIR \
      CONTROL_PORT ADMIN_PORT STUN_TURN_PORT; do
    if [[ -n "${!name:-}" ]]; then forwarded+=("$name=${!name}"); fi
  done
  if unshare -rn sh -c 'ip link set lo up' >/dev/null 2>&1; then
    exec unshare -rn env "${forwarded[@]}" bash "$SCRIPT_PATH" "$@"
  fi
  if sudo -n true >/dev/null 2>&1; then
    exec sudo -n unshare -n env "${forwarded[@]}" bash "$SCRIPT_PATH" "$@"
  fi
  echo "peer_mesh_e2e.sh needs a private network namespace: an unprivileged 'unshare -rn' that may" >&2
  echo "configure its own network, or passwordless sudo for 'sudo -n unshare -n'" >&2
  exit 1
fi

# From here on this process is root (or the fake root of a user namespace) in a fresh network
# namespace. Refuse anything that looks like a real network before changing a single setting.
if [[ "$(id -u)" != 0 ]]; then
  echo "expected to run as the (fake) root of a private namespace" >&2
  exit 1
fi
if [[ -n "$(ip -4 route show table main)" || "$(ip -o link show | awk -F': ' '{print $2}')" != "lo" ]]; then
  echo "refusing to run outside a fresh network namespace: it has routes or interfaces besides lo" >&2
  ip -o link show >&2 || true
  exit 1
fi

CONTROL_PORT="${CONTROL_PORT:-17410}"
ADMIN_PORT="${ADMIN_PORT:-17411}"
STUN_TURN_PORT="${STUN_TURN_PORT:-3478}"
RELAY_MIN_PORT=40000
RELAY_MAX_PORT=40099
# The server's address, on the loopback interface of the server's namespace. Phase-two clients
# reach it through their veth and a route to it; phase-one clients reach it locally.
SERVER_IP=10.77.0.1
NET_A_GW=10.77.1.1
NET_A_IP=10.77.1.2
NET_B_GW=10.77.2.1
NET_B_IP=10.77.2.2
ADMIN_USERNAME="mesh-admin"
ADMIN_PASSWORD="mesh-admin-password"
ADMIN_JWT_SECRET="peer-mesh-e2e-jwt-secret-that-is-long-and-random-enough-2026"
TURN_SECRET="peer-mesh-e2e-turn-shared-secret"

if [[ -n "${SPECUS_CLIENT_COMMAND:-}" ]]; then
  read -r -a CLIENT_COMMAND <<<"$SPECUS_CLIENT_COMMAND"
  CLIENT_LABEL="${SPECUS_CLIENT_LABEL:-${CLIENT_COMMAND[0]##*/}}"
else
  if [[ ! -f "$JAVA_CLIENT_JAR" ]]; then
    echo "missing Java client jar: $JAVA_CLIENT_JAR" >&2
    echo "build it first with: mvn -pl :specus-client -am package -DskipTests" >&2
    exit 1
  fi
  CLIENT_COMMAND=("${JAVA_COMMAND:-java}" -jar "$JAVA_CLIENT_JAR")
  CLIENT_LABEL="Java"
fi
if [[ "${CLIENT_COMMAND[0]}" == *.exe ]]; then
  echo "a Windows client cannot join the Linux network namespaces this E2E is built on" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-peer-mesh.XXXXXX")"
STATE_DIR="$TMP_DIR/cli-state"
mkdir -m 700 "$STATE_DIR"
export SPECUS_CLI_STATE_DIR="$STATE_DIR"

# Stops a background process and waits until it is gone, so a client of this run never outlives it
# (see nat_e2e_smoke.sh).
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
  for pid in "${CLIENT_A_PID:-}" "${CLIENT_B_PID:-}" "${SERVER_PID:-}" "${HOLDER_A_PID:-}" \
      "${HOLDER_B_PID:-}"; do
    if [[ -n "$pid" ]]; then stop_process "$pid"; fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

dump_logs() {
  echo "--- C server log ---" >&2
  tail -n 200 "$TMP_DIR/server.log" >&2 || true
  for log in "$TMP_DIR"/client-*.log; do
    [[ -f "$log" ]] || continue
    echo "--- $CLIENT_LABEL client log ${log##*/} ---" >&2
    tail -n 120 "$log" >&2 || true
  done
}

fail() {
  echo "Peer Mesh E2E failed ($CLIENT_LABEL): $*" >&2
  dump_logs
  exit 1
}

ip link set lo up
ip addr add "$SERVER_IP/32" dev lo

# The checks shared by both phases. Every wait is bounded; each subcommand prints what it proved.
cat >"$TMP_DIR/mesh_checks.py" <<'PY'
import http.client
import json
import subprocess
import sys
import time


def request(port, method, path, body=None, token=None):
    connection = http.client.HTTPConnection(SERVER_IP, port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        connection.request(method, path, body=None if body is None else json.dumps(body).encode(),
                           headers=headers)
        response = connection.getresponse()
        payload = response.read()
    finally:
        connection.close()
    return response.status, json.loads(payload) if payload else None


def wait(what, probe, timeout):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            result = probe()
            if result is not None:
                return result
        except Exception as error:  # the server or client may still be starting
            last = error
        time.sleep(0.5)
    raise SystemExit(f"timed out after {timeout} s waiting for {what}" + (f": {last}" if last else ""))


def provision(port, username, password, *pairs):
    def login():
        status, payload = request(port, "POST", "/auth/login",
                                  {"username": username, "password": password})
        return payload["accessToken"] if status == 200 else None
    token = wait("the management login", login, 30)
    for api_key, secret in zip(pairs[0::2], pairs[1::2]):
        status, payload = request(port, "POST", "/api/admin/client-credentials", {
            "apiKey": api_key, "secret": secret, "enabled": True, "maxOnlineInstances": 1}, token)
        if status != 201:
            raise SystemExit(f"credential {api_key} create failed: {status} {payload}")
    print(token)


def online_clients(port, token):
    status, clients = request(port, "GET", "/api/admin/clients", token=token)
    if status != 200:
        raise RuntimeError(f"client list failed: {status}")
    return {item["clientName"]: item for item in clients}


def wait_client(port, token, expected_name, state):
    """Waits for one client to be online (state=online) or offline; with expected_name "-" it
    waits for exactly one online client not among the known ones and prints its name."""
    want_online = state == "online"

    def probe():
        clients = online_clients(port, token)
        if expected_name != "-":
            item = clients.get(expected_name)
            return item["clientName"] if item and bool(item.get("online")) == want_online else None
        fresh = [name for name, item in clients.items() if item.get("online") is True
                 and name not in KNOWN]
        return fresh[0] if len(fresh) == 1 else None
    print(wait(f"client {expected_name} to be {state} in the management projection", probe, 60))


def enable_device(port, token, name):
    """Peer Mesh devices start disabled, as in Java; the management API opts a client in, and the
    refresh that mutation triggers pushes the enabled peer-config to the online client."""
    client = online_clients(port, token)[name]
    status, device = request(port, "PUT", f"/api/admin/peer-mesh/devices/{client['id']}",
                             {"enabled": True}, token)
    if status != 200 or device.get("enabled") is not True:
        raise SystemExit(f"enabling the Peer Mesh device of {name} failed: {status} {device}")
    print(f"Peer Mesh device enabled: {name} virtualIp={device.get('virtualIp')}")


def roster(config, peer_name, state, *command):
    """Reads the running client's own CLI state (specus-client peers --json): the roster the
    server pushed to it must list the peer, online or offline as asked."""
    want_online = state == "online"
    last = {}

    def probe():
        output = subprocess.run([*command, "peers", "--config", config, "--json"],
                                capture_output=True, text=True, timeout=30)
        document = json.loads(output.stdout)
        last["document"] = document
        for instance in (document.get("data") or {}).get("instances", []):
            for peer in instance.get("peers") or []:
                if peer.get("clientName") == peer_name and bool(peer.get("online")) == want_online:
                    return peer
        return None
    try:
        peer = wait(f"{peer_name} {state} in the roster of the client using {config}", probe, 60)
    except SystemExit:
        print(f"last peers output: {json.dumps(last.get('document'))}", file=sys.stderr)
        raise
    print(f"roster lists {peer_name} {state}: {json.dumps(peer, sort_keys=True)}")


def session(port, token, name_a, name_b, path_type, min_id):
    """Waits for an ACTIVE Peer Mesh session between the two clients, newer than min_id, whose
    reported path is path_type, and prints it."""
    pair = {name_a, name_b}
    last = {}

    def probe():
        status, sessions = request(port, "GET", "/api/admin/peer-mesh/sessions?limit=100", token=token)
        if status != 200:
            raise RuntimeError(f"session list failed: {status}")
        last["sessions"] = sessions
        for item in sessions:
            if item["id"] <= int(min_id) or {item["sourceClientName"], item["targetClientName"]} != pair:
                continue
            remote = item.get("remoteEndpoint") or ""
            if item.get("status") != "ACTIVE" or item.get("pathType") != path_type:
                continue
            if path_type == "RELAY" and not remote.startswith("relay:"):
                continue
            if path_type == "DIRECT" and (remote.startswith("relay:") or not remote):
                continue
            if item.get("rttMillis") is None:
                continue
            return item
        return None
    try:
        item = wait(f"a {path_type} session between {name_a} and {name_b}", probe, 90)
    except SystemExit:
        print(f"last sessions: {json.dumps(last.get('sessions'))}", file=sys.stderr)
        raise
    print(json.dumps(item, sort_keys=True))


def relay_sockets(low, high):
    """Counts the UDP sockets bound in the relay port range in this namespace: the server's TURN
    allocations, one per client."""
    count = 0
    for table in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(table, encoding="ascii") as handle:
                next(handle)
                for line in handle:
                    port = int(line.split()[1].rsplit(":", 1)[1], 16)
                    if int(low) <= port <= int(high):
                        count += 1
        except FileNotFoundError:
            pass
    print(count)


SERVER_IP = sys.argv[1]
KNOWN = set(filter(None, sys.argv[2].split(",")))
commands = {"provision": provision, "wait-client": wait_client, "enable-device": enable_device,
            "roster": roster,
            "session": session, "relay-sockets": relay_sockets}
commands[sys.argv[3]](*sys.argv[4:])
PY

check() {
  python3 "$TMP_DIR/mesh_checks.py" "$SERVER_IP" "${KNOWN_CLIENTS:-}" "$@"
}

# The STUN/TURN sockets are bound to the advertised address rather than the wildcard. A wildcard
# UDP socket answers from whichever address the route back leaves by -- here the veth gateway, not
# the address the client sent to -- and clients reject STUN and TURN responses from an endpoint
# other than the one they asked, as a client behind a real multi-homed server would.
SPECUS_ENV=dev \
SPECUS_DATABASE_PATH="$TMP_DIR/specus.db" \
SPECUS_NETTY_PORT="$CONTROL_PORT" \
SPECUS_ADMIN_PORT="$ADMIN_PORT" \
SPECUS_PUBLIC_ADDRESS="$SERVER_IP" \
SPECUS_AUTH_USERNAME="$ADMIN_USERNAME" \
SPECUS_AUTH_PASSWORD="$ADMIN_PASSWORD" \
SPECUS_AUTH_JWT_SECRET="$ADMIN_JWT_SECRET" \
SPECUS_PEER_MESH_ENABLED=true \
SPECUS_PEER_MESH_PUBLIC_ADDRESS="$SERVER_IP" \
SPECUS_PEER_MESH_BIND_ADDRESS="$SERVER_IP" \
SPECUS_PEER_MESH_STUN_TURN_PORT="$STUN_TURN_PORT" \
SPECUS_PEER_MESH_TURN_SHARED_SECRET="$TURN_SECRET" \
SPECUS_PEER_MESH_RELAY_MIN_PORT="$RELAY_MIN_PORT" \
SPECUS_PEER_MESH_RELAY_MAX_PORT="$RELAY_MAX_PORT" \
stdbuf -oL -eL "$C_DIR/build/specus-server-c" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

ADMIN_TOKEN="$(check provision "$ADMIN_PORT" "$ADMIN_USERNAME" "$ADMIN_PASSWORD" \
  mesh-e2e-a mesh-e2e-secret-a mesh-e2e-b mesh-e2e-secret-b)" || fail "provisioning"
grep -q "STUN/TURN UDP listener active on port $STUN_TURN_PORT" "$TMP_DIR/server.log" \
  || fail "the STUN/TURN listener did not start on $STUN_TURN_PORT"

for role in a b; do
  mkdir -p "$TMP_DIR/client-$role/home"
  cat >"$TMP_DIR/client-$role/client.jsonc" <<JSON
{
  "serverBaseUrl": "http://$SERVER_IP:$ADMIN_PORT",
  "apiKey": "mesh-e2e-$role",
  "secret": "mesh-e2e-secret-$role",
  "peerMeshDevice": "noop",
  "updateCheckEnabled": false
}
JSON
done

# Starts one client, in the namespace of the holder process given, or in this one. Each client has
# a HOME of its own, where its Peer Mesh key lives (and, for the Android core on a JVM, the machine
# id that keeps it the same device across restarts); the JVM reads its home from the password
# database rather than HOME, so it is told. exec keeps the recorded pid the client itself.
start_client() {
  local role="$1" phase="$2" holder="${3:-}"
  local dir="$TMP_DIR/client-$role"
  local enter=()
  if [[ -n "$holder" ]]; then enter=(nsenter -t "$holder" -n --); fi
  (cd "$dir" && exec ${enter[@]+"${enter[@]}"} env HOME="$dir/home" \
      JAVA_TOOL_OPTIONS="-Duser.home=$dir/home" \
      "${CLIENT_COMMAND[@]}" run --config "$dir/client.jsonc" --no-update-check \
      >"$TMP_DIR/client-$role-$phase.log" 2>&1) &
  if [[ "$role" == a ]]; then CLIENT_A_PID=$!; else CLIENT_B_PID=$!; fi
}

roster_of() {
  local role="$1" peer="$2" state="$3"
  check roster "$TMP_DIR/client-$role/client.jsonc" "$peer" "$state" "${CLIENT_COMMAND[@]}"
}

# Waits up to 30 s for a client log to show a line; each side logs its own path once its own
# connectivity check comes back, which can be a little after the other side's report.
wait_log() {
  local file="$1" pattern="$2"
  for _ in $(seq 1 60); do
    grep -qi "$pattern" "$file" && return 0
    sleep 0.5
  done
  return 1
}

# Server log lines from a given line on, so each phase is judged on its own signalling.
server_log_since() {
  tail -n +"$(( $1 + 1 ))" "$TMP_DIR/server.log"
}

# --- Phase one: both clients beside the server, a DIRECT path over loopback --------------------

start_client a direct
CLIENT_A="$(check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" - online)" || fail "client A never came online"
KNOWN_CLIENTS="$CLIENT_A"
start_client b direct
CLIENT_B="$(check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" - online)" || fail "client B never came online"
KNOWN_CLIENTS="$CLIENT_A,$CLIENT_B"
echo "clients: A=$CLIENT_A B=$CLIENT_B"
# The first logins only register the two clients. Their devices are enabled with B offline and B
# then logs in again, which is the order a deployment sees: an operator enables a device and the
# client starts with Peer Mesh on. Enabling both while both are online would race the enabled
# peer-config to B against A's candidates for B, which the server sends from different threads.
stop_process "$CLIENT_B_PID"
CLIENT_B_PID=""
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_B" offline >/dev/null \
  || fail "B stayed online after it stopped"
check enable-device "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_A" || fail "enabling A's Peer Mesh device"
check enable-device "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_B" || fail "enabling B's Peer Mesh device"
start_client b direct
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_B" online >/dev/null \
  || fail "client B never came back online"

roster_of a "$CLIENT_B" online || fail "A's roster never listed B online"
roster_of b "$CLIENT_A" online || fail "B's roster never listed A online"

DIRECT_SESSION="$(check session "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_A" "$CLIENT_B" DIRECT 0)" \
  || fail "no DIRECT session between A and B"
echo "direct session: $DIRECT_SESSION"
DIRECT_REMOTE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["remoteEndpoint"])' "$DIRECT_SESSION")"
# Over the loopback interface either way: the server-reflexive address the C STUN service reports
# (Go, .NET), or a 127.0.0.1 host candidate (Java offers loopback host candidates).
[[ "$DIRECT_REMOTE" == "$SERVER_IP:"* || "$DIRECT_REMOTE" == 127.* ]] \
  || fail "the direct path should run over the loopback interface, not $DIRECT_REMOTE"

server_log_since 0 | grep -q "signal accepted source=$CLIENT_A target=$CLIENT_B" \
  || fail "the server never accepted a signal from A to B"
server_log_since 0 | grep -q "signal accepted source=$CLIENT_B target=$CLIENT_A" \
  || fail "the server never accepted a signal from B to A"
if [[ "$CLIENT_LABEL" != Java && "$CLIENT_LABEL" != Android ]]; then
  # Go and .NET log the path at info. Java logs it at debug level, and the Android core reports it
  # only to the server (the path report behind the session above) and to no log of its own.
  for role in a b; do
    wait_log "$TMP_DIR/client-$role-direct.log" "direct UDP path active" \
      || fail "client $role never logged an active direct path"
  done
fi

# B leaves: A's roster must show it offline, from the push the departure triggers.
stop_process "$CLIENT_B_PID"
CLIENT_B_PID=""
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_B" offline >/dev/null \
  || fail "B stayed online after it stopped"
roster_of a "$CLIENT_B" offline || fail "A's roster never showed B offline after B left"
stop_process "$CLIENT_A_PID"
CLIENT_A_PID=""
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_A" offline >/dev/null \
  || fail "A stayed online after it stopped"
echo "Phase one passed: roster, session grant, candidate exchange and a DIRECT path on loopback; logout reflected in the roster"

# --- Phase two: each client in a namespace of its own, the path must be RELAY -----------------

# Each namespace is held open by a sleeping process; its veth peer in this namespace is the
# client's gateway. This namespace does not forward, so A and B reach the server and not each other.
echo 0 >/proc/sys/net/ipv4/ip_forward
make_namespace() {
  local name="$1" gateway="$2" address="$3"
  unshare -n sleep infinity &
  local holder=$!
  for _ in $(seq 1 50); do
    [[ "$(readlink "/proc/$holder/ns/net" 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ]] && break
    sleep 0.1
  done
  ip link add "pm-$name" type veth peer name "pm-$name-in"
  ip link set "pm-$name-in" netns "$holder"
  ip addr add "$gateway/24" dev "pm-$name"
  ip link set "pm-$name" up
  nsenter -t "$holder" -n -- ip link set lo up
  nsenter -t "$holder" -n -- ip link set "pm-$name-in" up
  nsenter -t "$holder" -n -- ip addr add "$address/24" dev "pm-$name-in"
  nsenter -t "$holder" -n -- ip route add default via "$gateway"
  if [[ "$name" == a ]]; then HOLDER_A_PID=$holder; else HOLDER_B_PID=$holder; fi
}
make_namespace a "$NET_A_GW" "$NET_A_IP"
make_namespace b "$NET_B_GW" "$NET_B_IP"

# The premise of this phase, checked rather than assumed: from either namespace the server answers,
# and a datagram to the other namespace never arrives.
isolation_probe() {
  local holder="$1" target="$2" listener_holder="$3"
  nsenter -t "$listener_holder" -n -- python3 - "$target" <<'PY' &
import socket
import sys
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind((sys.argv[1], 41999))
listener.settimeout(4)
try:
    listener.recvfrom(64)
    print("LEAK")
except socket.timeout:
    print("isolated")
PY
  local listener=$!
  sleep 0.5
  nsenter -t "$holder" -n -- python3 - "$target" "$SERVER_IP" "$ADMIN_PORT" <<'PY' || true
import socket
import sys
target, server, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
socket.create_connection((server, port), timeout=5).close()
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(5):
    try:
        sender.sendto(b"direct", (target, 41999))
    except OSError:
        pass
PY
  wait "$listener"
}
[[ "$(isolation_probe "$HOLDER_A_PID" "$NET_B_IP" "$HOLDER_B_PID")" == isolated ]] \
  || fail "a datagram from namespace A reached namespace B"
[[ "$(isolation_probe "$HOLDER_B_PID" "$NET_A_IP" "$HOLDER_A_PID")" == isolated ]] \
  || fail "a datagram from namespace B reached namespace A"
echo "namespaces ready: A=$NET_A_IP B=$NET_B_IP reach $SERVER_IP and not each other"

PHASE_TWO_LOG_START="$(wc -l <"$TMP_DIR/server.log")"
# Phase one's allocations outlive its clients until their lifetime ends, so phase two counts its own.
RELAY_SOCKETS_BEFORE="$(check relay-sockets "$RELAY_MIN_PORT" "$RELAY_MAX_PORT")"
KNOWN_CLIENTS=""
start_client a relay "$HOLDER_A_PID"
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_A" online >/dev/null \
  || fail "client A never came back online from its namespace"
start_client b relay "$HOLDER_B_PID"
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_B" online >/dev/null \
  || fail "client B never came back online from its namespace"

roster_of a "$CLIENT_B" online || fail "A's roster never listed B online in phase two"
roster_of b "$CLIENT_A" online || fail "B's roster never listed A online in phase two"

# Phase one's session between A and B is still open, and the server grants an open session between
# the same pair again while it holds its token (Java PeerMeshService.reusableSessionGrant), so phase
# two may run on that session rather than a new one. Its state is what proves phase two: phase one
# left the pair DIRECT over loopback, and only phase two's clients can report it RELAY through a TURN
# relay address.
RELAY_SESSION="$(check session "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_A" "$CLIENT_B" RELAY 0)" \
  || fail "no RELAY session between A and B"
echo "relay session: $RELAY_SESSION"

server_log_since "$PHASE_TWO_LOG_START" | grep -q "signal accepted source=$CLIENT_A target=$CLIENT_B" \
  || fail "the server accepted no signal from A to B in phase two"
server_log_since "$PHASE_TWO_LOG_START" | grep -q "signal accepted source=$CLIENT_B target=$CLIENT_A" \
  || fail "the server accepted no signal from B to A in phase two"
RELAY_SOCKETS="$(( $(check relay-sockets "$RELAY_MIN_PORT" "$RELAY_MAX_PORT") - RELAY_SOCKETS_BEFORE ))"
(( RELAY_SOCKETS >= 2 )) \
  || fail "expected a new TURN allocation per client in phase two, found $RELAY_SOCKETS new relay sockets"
if [[ "$CLIENT_LABEL" != Java && "$CLIENT_LABEL" != Android ]]; then
  for role in a b; do
    wait_log "$TMP_DIR/client-$role-relay.log" "relay UDP path active" \
      || fail "client $role never logged an active relay path"
    if grep -qi "direct UDP path active" "$TMP_DIR/client-$role-relay.log"; then
      fail "client $role found a direct path although the namespaces are isolated"
    fi
  done
fi

stop_process "$CLIENT_B_PID"
CLIENT_B_PID=""
check wait-client "$ADMIN_PORT" "$ADMIN_TOKEN" "$CLIENT_B" offline >/dev/null \
  || fail "B stayed online after it stopped in phase two"
roster_of a "$CLIENT_B" offline || fail "A's roster never showed B offline after B left in phase two"

echo "Phase two passed: with direct UDP between the clients impossible, the path is RELAY through" \
  "$RELAY_SOCKETS new C TURN allocations, the token-checked connectivity checks cross it both ways," \
  "and B's departure reaches A's roster"
echo "Peer Mesh E2E passed ($CLIENT_LABEL client): roster, session grant, candidates, DIRECT path," \
  "TURN RELAY path and logout through the C server"
