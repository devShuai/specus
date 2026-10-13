#!/usr/bin/env bash
set -euo pipefail

C_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="${1:-$C_DIR/build/specus-server-c}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-object-storage.XXXXXX")"
CONTROL_PORT="${CONTROL_PORT:-17380}"
ADMIN_PORT="${ADMIN_PORT:-17381}"
OSS_PORT="${OSS_PORT:-17382}"
ADMIN_USER="object-admin"
ADMIN_PASSWORD="object-e2e-password"
JWT_SECRET="object-e2e-jwt-secret-that-is-long-and-random-2026"
BUCKET="examplebucket"

cleanup() {
  local status=$?
  set +e
  if [[ $status -ne 0 ]]; then
    [[ -f "$TMP_DIR/server.log" ]] && sed -n '1,160p' "$TMP_DIR/server.log" >&2
    [[ -f "$TMP_DIR/oss.log" ]] && sed -n '1,160p' "$TMP_DIR/oss.log" >&2
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  if [[ -n "${OSS_PID:-}" ]]; then kill "$OSS_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
  return "$status"
}
trap cleanup EXIT

python3 - "$OSS_PORT" <<'PY' >"$TMP_DIR/oss.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import threading
import urllib.parse

objects = {}
lock = threading.Lock()
# Every request the server sends to the object store; read back through a control path so the
# E2E can prove the capability snapshot never contacts storage.
request_count = 0
COUNT_PATH = "/__specus-e2e/request-count"

class Handler(BaseHTTPRequestHandler):
    def key(self):
        return urllib.parse.urlsplit(self.path).path

    def parse_request(self):
        global request_count
        parsed = super().parse_request()
        if parsed and self.path != COUNT_PATH:
            with lock:
                request_count += 1
        return parsed

    def do_PUT(self):
        size = int(self.headers.get("Content-Length", "0"))
        value = self.rfile.read(size)
        with lock:
            objects[self.key()] = value
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        with lock:
            value = objects.get(self.key())
        if value is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(value)))
        self.end_headers()

    def do_GET(self):
        if self.path == COUNT_PATH:
            with lock:
                body = str(request_count).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        with lock:
            value = objects.get(self.key())
        if value is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(value)))
        self.end_headers()
        self.wfile.write(value)

    def do_DELETE(self):
        with lock:
            objects.pop(self.key(), None)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
OSS_PID=$!

SPECUS_ENV=dev \
SPECUS_DATABASE_PATH="$TMP_DIR/specus.db" \
SPECUS_DB_SEED_DEMO_CLIENT=1 \
SPECUS_NETTY_PORT="$CONTROL_PORT" \
SPECUS_ADMIN_PORT="$ADMIN_PORT" \
SPECUS_AUTH_USERNAME="$ADMIN_USER" \
SPECUS_AUTH_PASSWORD="$ADMIN_PASSWORD" \
SPECUS_AUTH_JWT_SECRET="$JWT_SECRET" \
SPECUS_OBJECT_STORAGE_PROVIDER=aliyun-oss \
SPECUS_OBJECT_STORAGE_ENDPOINT="http://localhost:$OSS_PORT" \
SPECUS_OBJECT_STORAGE_REGION=cn-hangzhou \
SPECUS_OBJECT_STORAGE_BUCKET="$BUCKET" \
SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID=test-access-key \
SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET=test-secret-key \
SPECUS_OBJECT_STORAGE_PREFIX=prefix \
SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS=127.0.0.1 \
SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP=2 \
stdbuf -oL -eL "$SERVER" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

python3 - "$ADMIN_PORT" "$OSS_PORT" "$ADMIN_USER" "$ADMIN_PASSWORD" "$TMP_DIR/specus.db" <<'PY'
import contextlib
import http.client
import json
import re
import sqlite3
import sys
import time
import urllib.parse

admin_port, oss_port = map(int, sys.argv[1:3])
username, password, database = sys.argv[3:]
payload_bytes = b"C attachment e2e payload"
CAPABILITIES = "/api/public/transfer/attachments/capabilities"
GIB = 1024 * 1024 * 1024

def api(method, path, body=None, token=None):
    connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    encoded = None if body is None else json.dumps(body).encode()
    connection.request(method, path, encoded, headers)
    response = connection.getresponse()
    data = response.read()
    result_headers = dict(response.getheaders())
    status = response.status
    connection.close()
    parsed = json.loads(data) if data else None
    return status, result_headers, parsed

def oss_request_count():
    connection = http.client.HTTPConnection("127.0.0.1", oss_port, timeout=10)
    connection.request("GET", "/__specus-e2e/request-count")
    response = connection.getresponse()
    count = int(response.read())
    connection.close()
    return count

def attachment_state():
    with contextlib.closing(sqlite3.connect(database)) as db:
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'transfer_attachment%' ORDER BY name")]
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY id").fetchall() for table in tables}

def charged_downloads(month):
    with contextlib.closing(sqlite3.connect(database)) as db:
        try:
            return db.execute("SELECT COALESCE(SUM(size_bytes),0) FROM transfer_attachment_download_usage "
                              "WHERE tenant_id='default' AND username=? AND usage_month=?",
                              (username, month)).fetchone()[0]
        except sqlite3.OperationalError as error:
            # The attachment schema is created by the first attachment operation.
            if "no such table" not in str(error):
                raise
            return 0

def capabilities(storage_used, label):
    """Reads the snapshot over HTTP and proves the read touched neither OSS nor the database."""
    oss_before, state_before = oss_request_count(), attachment_state()
    # Selector-looking parameters are ignored: the account comes from the bearer token only.
    status, headers, snapshot = api("GET", CAPABILITIES + "?tenantId=other&username=intruder", token=token)
    if status != 200 or headers.get("Cache-Control") != "private, no-store":
        raise RuntimeError(f"capabilities {label}: {status} {headers} {snapshot}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", snapshot.get("checkedAt", "")):
        raise RuntimeError(f"capabilities {label} checkedAt: {snapshot}")
    month = snapshot["checkedAt"][:7]
    year, number = map(int, month.split("-"))
    resets = f"{year + number // 12:04d}-{number % 12 + 1:02d}-01T00:00:00Z"
    downloaded = charged_downloads(month)
    expected = {
        "schemaVersion": 1, "storageEnabled": True, "maxAttachmentBytes": 512 * 1024 * 1024,
        "retentionHours": 72, "storageQuotaBytes": GIB, "storageUsedBytes": storage_used,
        "storageRemainingBytes": GIB - storage_used, "monthlyDownloadQuotaBytes": GIB,
        "monthlyDownloadUsedBytes": downloaded, "monthlyDownloadRemainingBytes": GIB - downloaded,
        "downloadUsageMonth": month, "downloadResetsAt": resets, "downloadGrantSingleUse": True,
    }
    actual = {key: snapshot.get(key) for key in expected}
    if (actual != expected or set(snapshot) != set(expected) | {"checkedAt"}
            or any(type(actual[key]) is not type(value) for key, value in expected.items())):
        raise RuntimeError(f"capabilities {label} mismatch: {snapshot} != {expected}")
    if oss_request_count() != oss_before:
        raise RuntimeError(f"capabilities {label} contacted the object store")
    if attachment_state() != state_before:
        raise RuntimeError(f"capabilities {label} changed attachment persistence")
    return snapshot

deadline = time.time() + 30
while True:
    try:
        status, _, login = api("POST", "/auth/login", {"username": username, "password": password})
        if status == 200:
            token = login["accessToken"]
            break
    except Exception:
        pass
    if time.time() >= deadline:
        raise RuntimeError("C server did not become ready")
    time.sleep(0.2)

status, headers, anonymous = api("GET", CAPABILITIES)
if status != 401 or "storageUsedBytes" in json.dumps(anonymous):
    raise RuntimeError(f"anonymous capabilities must be rejected: {status} {anonymous}")
status, headers, _ = api("POST", CAPABILITIES, {}, token)
if status != 405 or headers.get("Allow") != "GET":
    raise RuntimeError(f"capabilities POST contract mismatch: {status} {headers}")
# The server allows two presign uploads per source address in this run: the VIEWER's refused one
# and the owner's. Reading the snapshot first must not consume either, so the owner's upload below
# only succeeds if these reads reserved nothing.
for _ in range(3):
    capabilities(0, "before any upload")

room_token = "object-storage-owner-token"
upload_request = {
    "fileName": "folder/demo.txt",
    "mimeType": "text/plain",
    "sizeBytes": 1,
    "sha256": "a" * 64,
    "roomId": "object-e2e-room",
    "roomToken": room_token,
}
# A VIEWER invite resolves the room but may not upload. As in Java the source-address limiter runs
# before the room is resolved, so the refusal uses the first of the two presigns this run allows.
status, _, invite = api("POST", "/api/public/transfer/rooms/access-tokens",
                        {"roomId": "object-e2e-room", "roomToken": room_token, "role": "VIEWER"})
if status != 200 or not invite.get("token"):
    raise RuntimeError(f"viewer invite failed: {status} {invite}")
viewer_request = dict(upload_request, roomToken=invite["token"])
status, _, refused = api("POST", "/api/public/transfer/attachments/presign-upload", viewer_request, token)
if status != 403 or attachment_state().get("transfer_attachment"):
    raise RuntimeError(f"viewer upload must be refused without a reservation: {status} {refused}")
# The OSS callback needs no bearer token, only a valid OSS signature; a forged one is 403, not 401.
status, _, refused = api("POST", "/api/public/transfer/oss-callback",
                         {"bucket": "examplebucket", "object": "prefix/forged.txt", "size": 1},
                         token="not-a-jwt")
if status != 403:
    raise RuntimeError(f"forged OSS callback must be refused with 403: {status} {refused}")
status, _, refused = api("POST", "/api/public/transfer/attachments/1/complete", {"roomToken": room_token}, token)
if status != 400:
    raise RuntimeError(f"complete of an unknown attachment must be 400: {status} {refused}")

status, _, upload = api("POST", "/api/public/transfer/attachments/presign-upload", upload_request, token)
if status != 200:
    raise RuntimeError(f"presign upload failed: {status} {upload}")
if upload["attachment"]["fileName"] != "demo.txt" or upload["attachment"]["status"] != "PENDING":
    raise RuntimeError(f"upload response mismatch: {upload}")
# The unexpired reservation counts with its declared size until completion replaces it.
capabilities(1, "with a pending reservation")
# Before the PUT the object store has nothing under the key: complete is refused and stays PENDING.
status, _, refused = api("POST", f"/api/public/transfer/attachments/{upload['attachmentId']}/complete",
                         {"roomToken": room_token}, token)
if status != 409 or attachment_state()["transfer_attachment"][0][13] != "PENDING":
    raise RuntimeError(f"complete before the upload must be refused: {status} {refused}")

direct = urllib.parse.urlsplit(upload["uploadUrl"])
connection = http.client.HTTPConnection("127.0.0.1", oss_port, timeout=10)
connection.request("PUT", direct.path + "?" + direct.query, payload_bytes, {
    "Host": direct.netloc,
    **upload["uploadHeaders"],
    "Content-Length": str(len(payload_bytes)),
})
response = connection.getresponse()
response.read()
if response.status != 200:
    raise RuntimeError(f"fake OSS upload failed: {response.status}")
connection.close()

attachment_id = upload["attachmentId"]
status, _, completed = api("POST", f"/api/public/transfer/attachments/{attachment_id}/complete",
                           {"roomToken": room_token}, token)
if status != 200 or completed["status"] != "UPLOADED" or completed["sizeBytes"] != len(payload_bytes):
    raise RuntimeError(f"complete mismatch: {status} {completed}")
capabilities(len(payload_bytes), "after completion")

status, _, grant = api("POST", f"/api/public/transfer/attachments/{attachment_id}/presign-download",
                       {"roomToken": room_token}, token)
if status != 200 or not grant["downloadUrl"].startswith("/api/public/transfer/downloads/"):
    raise RuntimeError(f"download grant mismatch: {status} {grant}")

connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
connection.request("GET", grant["downloadUrl"])
response = connection.getresponse()
response.read()
location = response.getheader("Location")
if response.status != 302 or not location:
    raise RuntimeError(f"download grant consume mismatch: {response.status} {location}")
connection.close()

direct = urllib.parse.urlsplit(location)
query = urllib.parse.parse_qs(direct.query)
if "x-st-grant" not in query:
    raise RuntimeError(f"direct download is missing signed grant marker: {location}")
connection = http.client.HTTPConnection("127.0.0.1", oss_port, timeout=10)
connection.request("GET", direct.path + "?" + direct.query, headers={"Host": direct.netloc})
response = connection.getresponse()
downloaded = response.read()
connection.close()
if response.status != 200 or downloaded != payload_bytes:
    raise RuntimeError("downloaded attachment does not match uploaded bytes")
snapshot = capabilities(len(payload_bytes), "after a charged download")
if snapshot["monthlyDownloadUsedBytes"] != len(payload_bytes):
    raise RuntimeError(f"charged download missing from capabilities: {snapshot}")

status, _, replay = api("GET", grant["downloadUrl"])
if status != 410:
    raise RuntimeError(f"one-time grant replay was not rejected: {status} {replay}")
status, headers, _ = api("HEAD", grant["downloadUrl"])
if status != 405 or headers.get("Allow") != "GET":
    raise RuntimeError(f"download HEAD contract mismatch: {status} {headers}")

# The limiter is really active: a third upload from this address is refused.
status, _, limited = api("POST", "/api/public/transfer/attachments/presign-upload", upload_request, token)
if status != 429:
    raise RuntimeError(f"presign rate limit was not enforced: {status} {limited}")
capabilities(len(payload_bytes), "after a rate-limited upload")

with sqlite3.connect(database) as db:
    row = db.execute("SELECT status,size_bytes FROM transfer_attachment WHERE id=?", (attachment_id,)).fetchone()
    usage = db.execute("SELECT COUNT(*),SUM(size_bytes) FROM transfer_attachment_download_usage").fetchone()
if row != ("UPLOADED", len(payload_bytes)) or usage != (1, len(payload_bytes)):
    raise RuntimeError(f"attachment persistence mismatch: {row} {usage}")

# Another account in the same tenant never leaks into this account's snapshot.
with contextlib.closing(sqlite3.connect(database)) as db:
    db.execute("INSERT INTO transfer_attachment(id,tenant_id,scope,owner_username,object_key,file_name,"
               "mime_type,size_bytes,status,created_at,updated_at,upload_expires_at,expires_at) "
               "VALUES(7,'default','PUBLIC_TRANSFER','someone-else','prefix/e2e/other.bin','other.bin',"
               "'application/octet-stream',4096,'UPLOADED','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z',"
               "'2999-01-01T00:00:00Z','2999-01-01T00:00:00Z')")
    db.execute("INSERT INTO transfer_attachment_download_usage(id,tenant_id,username,attachment_id,"
               "size_bytes,usage_month,created_at) VALUES(7,'default','someone-else',7,2048,?,"
               "'2000-01-01T00:00:00Z')", (snapshot["downloadUsageMonth"],))
    db.commit()
snapshot = capabilities(len(payload_bytes), "beside another account")
if snapshot["monthlyDownloadUsedBytes"] != len(payload_bytes):
    raise RuntimeError(f"another account leaked into capabilities: {snapshot}")

print("object storage e2e passed")
PY
