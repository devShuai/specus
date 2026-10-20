#!/usr/bin/env python3
"""Real Redis and C processes: management events, authorization and committed revocation.

Only private temporary SQLite databases, synthetic credentials and loopback sockets.
Sharing SQLite here is a test fixture, not a database HA deployment recommendation.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
import urllib.parse

PASSWORD = "cluster-e2e-password-2026"
ADMIN = "cluster-admin"
PREFIX = "specus:test:management:" + secrets.token_hex(8)


def free_port():
    with socket.socket() as channel:
        channel.bind(("127.0.0.1", 0))
        return channel.getsockname()[1]


def request(port, method, path, body=None, token=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as channel:
        channel.request(method, path, None if body is None else json.dumps(body), headers)
        response = channel.getresponse()
        data = response.read()
    assert response.status == expected, (method, path, response.status, data)
    return json.loads(data) if data else {}


def login(port, username=ADMIN, tenant="default"):
    return request(port, "POST", "/auth/login", {"username": username, "password": PASSWORD,
                                                   "tenantId": tenant})["accessToken"]


def ticket_status(port, endpoint, ticket):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as channel:
        channel.sendall((f"GET /ws/{endpoint}?ticket={urllib.parse.quote(ticket)} HTTP/1.1\r\n"
                         "Host: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                         "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            response.extend(exact(channel, 1))
        return int(response.split(b" ")[1])


def resp_command(channel, *parts):
    parts = [part if isinstance(part, bytes) else str(part).encode() for part in parts]
    channel.sendall(b"*%d\r\n" % len(parts) + b"".join(b"$%d\r\n" % len(part) + part + b"\r\n" for part in parts))


def exact(channel, length):
    data = bytearray()
    while len(data) < length:
        chunk = channel.recv(length - len(data))
        if not chunk:
            raise EOFError("socket ended before expected frame")
        data.extend(chunk)
    return bytes(data)


def resp_read(channel):
    line = bytearray()
    while not line.endswith(b"\r\n"):
        line.extend(exact(channel, 1))
    tag, value = line[:1], bytes(line[1:-2])
    if tag == b"*":
        return [resp_read(channel) for _ in range(int(value))]
    if tag == b"$":
        value = exact(channel, int(value) + 2)
        assert value.endswith(b"\r\n")
        return value[:-2]
    if tag == b":":
        return int(value)
    if tag == b"+":
        return value
    raise AssertionError((tag, value))


def frame(kind, payload, group=None, flags=0, revision=0):
    if isinstance(payload, dict):
        payload = json.dumps(payload, separators=(",", ":")).encode()
    group = group or hashlib.sha256(b"default").hexdigest()
    group = group.encode()
    return struct.pack(">4sBBBBQHHHI", b"STCE", 2, kind, flags, 0, revision, len(group), 0, 0, len(payload)) + group + payload


class WebSocket:
    def __init__(self, port, token, endpoint):
        self.endpoint = endpoint
        self.channel = socket.create_connection(("127.0.0.1", port), timeout=5)
        ticket = request(port, "POST", "/api/admin/ws-tickets", {"endpoint": endpoint}, token)["ticket"]
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        self.channel.sendall((f"GET /ws/{endpoint}?ticket={urllib.parse.quote(ticket)} HTTP/1.1\r\n"
                              "Host: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            response.extend(exact(self.channel, 1))
        assert response.startswith(b"HTTP/1.1 101"), response
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert b"Sec-WebSocket-Accept: " + expected in response
        if endpoint == "client-messages":
            assert self.read_json()["type"] == "hello"

    def close(self):
        self.channel.close()

    def read(self, timeout=3):
        self.channel.settimeout(timeout)
        first, second = exact(self.channel, 2)
        assert first & 0x80 and not second & 0x80, "server frame must be final and unmasked"
        length = second & 127
        if length == 126:
            length = struct.unpack(">H", exact(self.channel, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", exact(self.channel, 8))[0]
        assert length <= 256 * 1024
        return first & 15, exact(self.channel, length)

    def read_json(self):
        opcode, data = self.read()
        assert opcode == 1, (opcode, data)
        return json.loads(data)

    def quiet(self):
        try:
            received = self.read(0.15)
        except socket.timeout:
            return
        raise AssertionError(("unexpected or duplicate event", received))

    def alive(self):
        self.quiet()
        payload, mask = b"probe", secrets.token_bytes(4)
        self.channel.sendall(bytes([0x89, 0x80 | len(payload)]) + mask +
                             bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
        assert self.read() == (10, payload), "socket must remain open and responsive"

    def revoked(self, reason):
        opcode, data = self.read()
        assert opcode == 8 and struct.unpack(">H", data[:2])[0] == 1008, (opcode, data)
        assert data[2:].decode() == reason, data


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def text(value):
    value = value.encode()
    return varint(len(value) + 1) + value


def read_varint(data):
    value = 0
    for index, byte in enumerate(data[:10]):
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value, index + 1
    raise AssertionError("invalid compact varint")


class Fixture:
    def __init__(self, binary, stack):
        self.stack = stack
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="specus-management-cluster-")))
        self.processes = []
        self.binary = str(Path(binary).resolve())
        self.redis_port = free_port()
        self.start_redis("redis")

    def start_redis(self, name):
        self.spawn(name, ["redis-server", "--bind", "127.0.0.1", "--port", str(self.redis_port),
                          "--protected-mode", "yes", "--save", "", "--appendonly", "no",
                          "--dir", str(self.directory)])
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", self.redis_port), timeout=0.2) as channel:
                    resp_command(channel, "PING")
                    if resp_read(channel) == b"PONG":
                        break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("private Redis did not start")

    def subscribers(self):
        with contextlib.closing(socket.create_connection(("127.0.0.1", self.redis_port), timeout=3)) as channel:
            resp_command(channel, "PUBSUB", "NUMSUB", PREFIX + ":events")
            return resp_read(channel)[1]

    def spawn(self, name, command, env=None):
        log = self.stack.enter_context((self.directory / (name + ".log")).open("wb"))
        process = subprocess.Popen(command, env=env, cwd=self.directory, stdout=log, stderr=log,
                                   stdin=subprocess.DEVNULL)
        self.processes.append(process)
        self.stack.callback(self.stop, process, (0, 143) if name == "java" else (0,),
                            self.directory / (name + ".log"))
        return process

    @staticmethod
    def stop(process, allowed=(0,), log=None):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process.returncode not in allowed:
            details = "" if log is None else log.read_text(errors="replace")[-8000:]
            raise AssertionError(f"fixture child exited {process.returncode}; sanitizer/shutdown failure: {details}")

    def server(self, name, tenant="default", database="shared.db", cluster=True):
        admin, control = free_port(), free_port()
        env = {key: value for key, value in os.environ.items() if not key.startswith("SPECUS_")}
        env.update(SPECUS_ENV="dev", SPECUS_DATABASE_PATH=str(self.directory / database),
                   # C binds its environment-token Demo client at startup. Seed
                   # only in this isolated dev fixture, as server_harness.c does.
                   SPECUS_DB_SEED_DEMO_CLIENT="true", SPECUS_NETTY_BIND_ADDRESS="127.0.0.1",
                   SPECUS_NETTY_PORT=str(control), SPECUS_ADMIN_PORT=str(admin),
                   SPECUS_AUTH_USERNAME=ADMIN, SPECUS_AUTH_PASSWORD=PASSWORD,
                   SPECUS_AUTH_TENANT_ID=tenant, SPECUS_AUTH_JWT_SECRET="cluster-test-jwt-secret-long-and-random-2026",
                   SPECUS_PEER_MESH_ENABLED="false", SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED=str(cluster).lower(),
                   SPECUS_PUBLIC_TRANSFER_REDIS_URI=f"redis://127.0.0.1:{self.redis_port}/0",
                   SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX=PREFIX, SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS="200")
        process = self.spawn(name, [self.binary], env)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log = (self.directory / (name + ".log")).read_text(errors="replace")
                raise AssertionError(f"{name} exited before readiness: {log[-8000:]}")
            try:
                token = login(admin, tenant=tenant)
                return admin, control, token
            except (OSError, AssertionError):
                time.sleep(0.05)
        raise AssertionError(f"{name} did not become ready")

    def redis(self):
        channel = self.stack.enter_context(socket.create_connection(("127.0.0.1", self.redis_port), timeout=3))
        return channel

    def java_server(self, jar, executable):
        admin, control = free_port(), free_port()
        env = {key: value for key, value in os.environ.items() if not key.startswith("SPECUS_")}
        env.update(SPECUS_ENV="dev", SPECUS_DB_URL="jdbc:sqlite:" + str(self.directory / "java.db"),
                   SPECUS_DB_SEED_DEMO_CLIENT="false", SPECUS_NETTY_PORT=str(control),
                   SPECUS_AUTH_USERNAME=ADMIN, SPECUS_AUTH_PASSWORD=PASSWORD, SPECUS_AUTH_TENANT_ID="default",
                   SPECUS_AUTH_JWT_SECRET="cluster-test-jwt-secret-long-and-random-2026",
                   SPECUS_PEER_MESH_ENABLED="false", SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED="true",
                   SPECUS_PUBLIC_TRANSFER_REDIS_URI=f"redis://127.0.0.1:{self.redis_port}/0",
                   SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX=PREFIX)
        process = self.spawn("java", [executable, "-jar", str(Path(jar).resolve()),
                                      f"--server.port={admin}", "--server.address=127.0.0.1"], env)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("Java exited: " + (self.directory / "java.log").read_text(errors="replace")[-8000:])
            try:
                token = login(admin)
                return admin, control, token
            except (OSError, AssertionError):
                time.sleep(0.2)
        raise AssertionError("Java did not become ready: " + (self.directory / "java.log").read_text(errors="replace")[-8000:])

    def publish(self, raw):
        channel = self.redis()
        resp_command(channel, "PUBLISH", PREFIX + ":events", raw)
        assert resp_read(channel) >= 2, "both server subscriptions must be live"

    def ws(self, port, token, endpoint="connections"):
        websocket = WebSocket(port, token, endpoint)
        self.stack.callback(websocket.close)
        return websocket

    def sql(self, statement, args=()):
        with sqlite3.connect(self.directory / "shared.db") as database:
            database.execute(statement, args)


def check(binary):
    with contextlib.ExitStack() as stack:
        fixture = Fixture(binary, stack)
        one, control, admin_token = fixture.server("one")
        two, _, second_admin = fixture.server("two")
        foreign, _, foreign_admin = fixture.server("foreign", "tenant-b", "foreign.db")
        for username in ("alice", "bob", "eve"):
            request(one, "POST", "/api/admin/users", {"username": username, "password": PASSWORD,
                                                      "role": "USER", "enabled": True}, admin_token, expected=201)
        request(foreign, "POST", "/api/admin/users", {"username": "alice", "password": PASSWORD,
                                                      "role": "USER", "enabled": True}, foreign_admin, expected=201)
        alice, alice_remote = login(one, "alice"), login(two, "alice")
        alice_ws = [fixture.ws(one, alice), fixture.ws(two, alice_remote)]
        admin_ws = [fixture.ws(one, admin_token), fixture.ws(two, second_admin)]
        bob_ws = fixture.ws(two, login(two, "bob"))
        foreign_ws = fixture.ws(foreign, login(foreign, "alice", "tenant-b"))
        key, secret = "cluster-device-key", "cluster-device-secret"
        fixture.sql("INSERT INTO specus_client_credential(tenant_id,owner_username,api_key,secret_hash,enabled,"
                    "max_online_instances,created_at,updated_at) VALUES(?,?,?,?,1,2,?,?)",
                    ("default", "alice", key, hashlib.sha256(secret.encode()).hexdigest(),
                     "2026-10-13T00:00:00Z", "2026-10-13T00:00:00Z"))
        timestamp, nonce = str(int(time.time() * 1000)), secrets.token_hex(16)
        canonical = "\n".join((key, timestamp, nonce, "cluster-machine", "cluster-user"))
        signature = hmac.new(hashlib.sha256(secret.encode()).digest(), canonical.encode(), hashlib.sha256).hexdigest()
        runtime = request(one, "POST", "/api/client/auth/login", {"apiKey": key, "timestamp": timestamp,
                          "nonce": nonce, "signature": signature, "environment": {
                          "machineFingerprint": "cluster-machine", "osUser": "cluster-user", "hostname": "fixture"}})
        device = stack.enter_context(socket.create_connection(("127.0.0.1", control), timeout=3))
        body = text(runtime["clientName"]) + b"\x01" + varint(runtime["clientSessionId"] << 1)
        body += text(runtime["accessToken"]) + text("control")
        device.sendall(struct.pack(">IBBBI", 0x14353565, 2, 4, 1, len(body)) + body)
        header = exact(device, 11)
        assert header[6] == 255, "real control LOGIN_RESPONSE (-1)"
        answer = exact(device, struct.unpack(">I", header[7:])[0])
        marker, offset = read_varint(answer)
        assert marker > 0 and answer[offset:offset + marker - 1].decode() == runtime["clientName"]
        assert answer[offset + marker - 1] == 1, "control login must succeed"
        for websocket in admin_ws + alice_ws:
            event = websocket.read_json()
            assert event["tenantId"] == "default" and event["type"] == "created"
            assert event["connection"]["clientId"] == runtime["clientId"]
            websocket.quiet()
        bob_ws.alive()
        foreign_ws.alive()
        print("ok real connection event reaches both instances exactly once; owner and tenant filtered", flush=True)

        # ConnectionEventsWebSocketHandlerTests tenant binding: a kind-4 frame is delivered only when its
        # group is the management group of the payload's own tenant, in either direction of a mismatch.
        foreign_admin_ws = fixture.ws(foreign, foreign_admin)
        default_group, foreign_group = (hashlib.sha256(t.encode()).hexdigest() for t in ("default", "tenant-b"))
        connection = {"id": 4242, "clientId": runtime["clientId"], "clientName": runtime["clientName"],
                      "connectedAt": "2026-10-13T00:00:00Z", "success": True}
        for payload_tenant, group in (("default", foreign_group), ("tenant-b", default_group)):
            fixture.publish(frame(4, {"tenantId": payload_tenant, "type": "created", "connection": connection},
                                  group=group))
            for websocket in admin_ws + alice_ws + [bob_ws, foreign_ws, foreign_admin_ws]:
                websocket.alive()
        fixture.publish(frame(4, {"tenantId": "default", "type": "created", "connection": connection},
                              group=default_group))
        for websocket in admin_ws + alice_ws:
            event = websocket.read_json()
            assert event["tenantId"] == "default" and event["connection"]["id"] == 4242, event
        for websocket in admin_ws + alice_ws + [bob_ws, foreign_ws, foreign_admin_ws]:
            websocket.alive()
        print("ok management frames bound to another tenant's group reach no admin socket", flush=True)

        observer = fixture.redis()
        resp_command(observer, "SUBSCRIBE", PREFIX + ":events")
        assert resp_read(observer)[0] == b"subscribe"
        fixture.sql("CREATE TRIGGER refuse_alice_update BEFORE UPDATE ON specus_management_user "
                    "WHEN OLD.login_name='alice' BEGIN SELECT RAISE(ABORT,'injected rollback'); END")
        request(one, "PUT", "/api/admin/users/alice", {"enabled": False}, admin_token, expected=409)
        observer.settimeout(0.2)
        try:
            event = resp_read(observer)
        except socket.timeout:
            event = None
        assert event is None, "rolled-back mutation must not publish"
        for websocket in alice_ws:
            websocket.alive()
        fixture.sql("DROP TRIGGER refuse_alice_update")
        print("ok rollback preserves local/remote sockets and publishes nothing", flush=True)

        for unchanged_access in ({"password": PASSWORD}, {"role": "USER", "enabled": True}):
            request(one, "PUT", "/api/admin/users/alice", unchanged_access, admin_token)
            for websocket in alice_ws:
                websocket.alive()
            try:
                unexpected = resp_read(observer)
            except socket.timeout:
                unexpected = None
            assert unexpected is None, "unchanged access must not publish revocation"
        print("ok password-only and unchanged rights do not revoke or publish", flush=True)

        valid_revoke = {"tenantId": "default", "username": "alice", "reason": "disabled"}
        invalid = [frame(5, valid_revoke, group=hashlib.sha256(b"wrong-tenant").hexdigest()),
                   frame(5, valid_revoke, flags=1), frame(5, valid_revoke, revision=1),
                   frame(5, b'{"tenantId":"default","username":"alice\\u0000other"}'),
                   frame(5, b'{"tenantId":"default","tenantId":"default","username":"alice"}'),
                   frame(5, b'{"tenantId":"default","username":"alice","reason":"\xff"}'),
                   frame(5, b'{"tenantId":"default","username":{}}')]
        for raw in invalid:
            fixture.publish(raw)
            for websocket in alice_ws:
                websocket.alive()
        print("ok malformed and tenant-misbound revocations cannot close either instance", flush=True)

        message_ws = fixture.ws(two, alice_remote, "client-messages")
        unused_tickets = [(endpoint, request(two, "POST", "/api/admin/ws-tickets", {"endpoint": endpoint},
                                            alice_remote)["ticket"]) for endpoint in ("connections", "client-messages")]
        request(one, "PUT", "/api/admin/users/alice", {"enabled": False}, admin_token)
        for websocket in alice_ws + [message_ws]:
            websocket.revoked("account disabled")
        for websocket in admin_ws + [bob_ws, foreign_ws]:
            websocket.alive()
        print("ok committed disable closes both endpoints across instances; bystanders remain", flush=True)
        request(one, "PUT", "/api/admin/users/alice", {"enabled": True}, admin_token)
        for endpoint, ticket in unused_tickets:
            assert ticket_status(two, endpoint, ticket) == 403, "remote tickets must stay revoked after re-enable"
        print("ok unused remote tickets are removed, not merely blocked while account is disabled", flush=True)

        for mutation, expected_reason in (({"role": "ADMIN"}, "account role changed"),
                                          ({"role": "USER"}, "account role changed"),
                                          (None, "account deleted")):
            eve = login(two, "eve")
            eve_sockets = [fixture.ws(two, eve, endpoint) for endpoint in ("connections", "client-messages")]
            request(one, "DELETE" if mutation is None else "PUT", "/api/admin/users/eve", mutation, admin_token,
                    expected=204 if mutation is None else 200)
            for websocket in eve_sockets:
                websocket.revoked(expected_reason)
        print("ok role upgrades/downgrades and deletion revoke both remote endpoints", flush=True)

        unknown = fixture.ws(two, login(two, "bob"))
        fixture.publish(frame(5, {"tenantId": "default", "username": "bob", "reason": "future-reason"}))
        unknown.revoked("account revoked")
        bob_ws.revoked("account revoked")
        bob_ws = fixture.ws(two, login(two, "bob"))
        print("ok unknown revocation reason fails closed", flush=True)

        fixture.stop(fixture.processes[0])
        # The actual device's disconnect is a production ConnectionEvent, not
        # a synthetic Redis frame. Publish failure must still deliver locally.
        device.close()
        local_event = admin_ws[0].read_json()
        assert local_event["type"] == "updated" and local_event["connection"]["clientId"] == runtime["clientId"]
        admin_ws[1].alive()
        # Database change must still commit and close locally when Redis is gone.
        local_bob = fixture.ws(one, login(one, "bob"))
        request(one, "PUT", "/api/admin/users/bob", {"enabled": False}, admin_token)
        local_bob.revoked("account disabled")
        bob_ws.alive()  # Documented missed Pub/Sub delivery, not fake remote success.
        print("ok Redis failure preserves local event fallback and committed local revocation", flush=True)

        # Lettuce reconnects on its own: with Redis back on the same port every instance subscribes
        # again and publishes again, so a committed revocation crosses instances without a restart.
        fixture.start_redis("redis-restarted")
        deadline = time.monotonic() + 15
        while fixture.subscribers() < 3:
            assert time.monotonic() < deadline, "the three C instances did not subscribe again"
            time.sleep(0.05)
        request(one, "PUT", "/api/admin/users/bob", {"enabled": True}, admin_token)
        remote_bob = fixture.ws(two, login(two, "bob"))
        request(one, "PUT", "/api/admin/users/bob", {"enabled": False}, admin_token)
        remote_bob.revoked("account disabled")
        admin_ws[1].alive()
        print("ok after Redis returns, revocations cross instances again without a restart", flush=True)


def check_interop(binary, java_jar, java_executable):
    # Independently initialized stores exercise wire interoperability, not shared
    # database HA. Revocation targets have no clients or credentials to transfer.
    with contextlib.ExitStack() as stack:
        fixture = Fixture(binary, stack)
        c_admin, c_control, c_token = fixture.server("c")
        j_admin, j_control, j_token = fixture.java_server(java_jar, java_executable)
        c_events, j_events = fixture.ws(c_admin, c_token), fixture.ws(j_admin, j_token)
        for control, client_name in ((c_control, "c-missing-device"), (j_control, "java-missing-device")):
            with socket.create_connection(("127.0.0.1", control), timeout=5) as device:
                body = text(client_name) + b"\x01" + varint(2) + text("invalid-token") + text("control")
                device.sendall(struct.pack(">IBBBI", 0x14353565, 2, 4, 1, len(body)) + body)
                answer = exact(device, 11)
                assert answer[6] == 255
                exact(device, struct.unpack(">I", answer[7:])[0])
            for websocket in (c_events, j_events):
                event = websocket.read_json()
                assert event["tenantId"] == "default" and event["type"] == "created"
                assert event["connection"]["clientName"] == client_name
                assert event["connection"]["success"] is False
                websocket.quiet()
        print("ok C and Java native connection events reach both implementations once", flush=True)
        for port, token in ((c_admin, c_token), (j_admin, j_token)):
            for username in ("from-c", "from-java"):
                request(port, "POST", "/api/admin/users", {"username": username, "password": PASSWORD,
                                                           "role": "USER", "enabled": True}, token, expected=201)
        for source, token, target, username in ((c_admin, c_token, j_admin, "from-c"),
                                               (j_admin, j_token, c_admin, "from-java")):
            user_token = login(target, username)
            sockets = [fixture.ws(target, user_token, endpoint) for endpoint in ("connections", "client-messages")]
            request(source, "PUT", f"/api/admin/users/{username}", {"enabled": False}, token)
            for websocket in sockets:
                websocket.revoked("account disabled")
        c_events.alive()
        j_events.alive()
        print("ok native committed revocations close both endpoints C to Java and Java to C", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server")
    parser.add_argument("--java-jar", help="run real C/Java wire interoperability instead of the C-only matrix")
    parser.add_argument("--java", default="java", help="Java executable for the optional interoperability test")
    args = parser.parse_args()
    if args.java_jar:
        check_interop(args.server, args.java_jar, args.java)
    else:
        check(args.server)
    print("management cluster e2e passed")
