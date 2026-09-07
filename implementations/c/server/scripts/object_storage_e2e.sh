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

class Handler(BaseHTTPRequestHandler):
    def key(self):
        return urllib.parse.urlsplit(self.path).path

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
stdbuf -oL -eL "$SERVER" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

python3 - "$ADMIN_PORT" "$OSS_PORT" "$ADMIN_USER" "$ADMIN_PASSWORD" "$TMP_DIR/specus.db" <<'PY'
import http.client
import json
import sqlite3
import sys
import time
import urllib.parse

admin_port, oss_port = map(int, sys.argv[1:3])
username, password, database = sys.argv[3:]
payload_bytes = b"C attachment e2e payload"

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

room_token = "object-storage-owner-token"
status, _, upload = api("POST", "/api/public/transfer/attachments/presign-upload", {
    "fileName": "folder/demo.txt",
    "mimeType": "text/plain",
    "sizeBytes": 1,
    "sha256": "a" * 64,
    "roomId": "object-e2e-room",
    "roomToken": room_token,
}, token)
if status != 200:
    raise RuntimeError(f"presign upload failed: {status} {upload}")
if upload["attachment"]["fileName"] != "demo.txt" or upload["attachment"]["status"] != "PENDING":
    raise RuntimeError(f"upload response mismatch: {upload}")

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

status, _, replay = api("GET", grant["downloadUrl"])
if status != 410:
    raise RuntimeError(f"one-time grant replay was not rejected: {status} {replay}")
status, headers, _ = api("HEAD", grant["downloadUrl"])
if status != 405 or headers.get("Allow") != "GET":
    raise RuntimeError(f"download HEAD contract mismatch: {status} {headers}")

with sqlite3.connect(database) as db:
    row = db.execute("SELECT status,size_bytes FROM transfer_attachment WHERE id=?", (attachment_id,)).fetchone()
    usage = db.execute("SELECT COUNT(*),SUM(size_bytes) FROM transfer_attachment_download_usage").fetchone()
if row != ("UPLOADED", len(payload_bytes)) or usage != (1, len(payload_bytes)):
    raise RuntimeError(f"attachment persistence mismatch: {row} {usage}")

print("object storage e2e passed")
PY
