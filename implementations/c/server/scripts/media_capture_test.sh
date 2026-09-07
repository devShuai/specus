#!/usr/bin/env bash
set -euo pipefail

test_binary="${1:?media capture test binary is required}"
tmp_dir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

cat >"$tmp_dir/fake_s3.py" <<'PY'
import hashlib
import http.server
import os
import sys
import urllib.parse

root = sys.argv[1]
uploads = {}
parts = {}
objects = {}
next_upload = 0

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def authorized(self):
        value = self.headers.get("Authorization", "")
        return value.startswith("AWS4-HMAC-SHA256 Credential=media-access/") \
            and "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in value \
            and bool(self.headers.get("x-amz-date")) \
            and len(self.headers.get("x-amz-content-sha256", "")) == 64

    def do_HEAD(self):
        self.reply(200 if self.authorized() and self.path == "/media-bucket" else 403)

    def do_POST(self):
        global next_upload
        if not self.authorized():
            self.reply(403)
            return
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if "uploads" in query:
            next_upload += 1
            upload_id = "upload-" + str(next_upload)
            uploads[upload_id] = parsed.path
            body = ("<InitiateMultipartUploadResult><UploadId>" + upload_id + "</UploadId></InitiateMultipartUploadResult>").encode()
            self.reply(200, body)
            return
        upload_id = query.get("uploadId", [""])[0]
        if upload_id in uploads:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            numbers = sorted(number for (current, number) in parts if current == upload_id)
            if not numbers or any(("<PartNumber>" + number + "</PartNumber>").encode() not in body for number in numbers):
                self.reply(400)
                return
            objects[uploads[upload_id]] = b"".join(parts[(upload_id, number)] for number in numbers)
            self.reply(200, b"<CompleteMultipartUploadResult/>", {"ETag": '"complete-etag"'})
            return
        self.reply(404)

    def do_PUT(self):
        if not self.authorized():
            self.reply(403)
            return
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        number = query.get("partNumber", [""])[0]
        upload_id = query.get("uploadId", [""])[0]
        if upload_id not in uploads or not number.isdigit():
            self.reply(400)
            return
        parts[(upload_id, number)] = body
        with open(os.path.join(root, upload_id + "-part-" + number), "wb") as output:
            output.write(body)
        self.reply(200, headers={"ETag": '"part-' + number + '"'})

    def do_GET(self):
        if not self.authorized():
            self.reply(403)
            return
        parsed = urllib.parse.urlsplit(self.path)
        body = objects.get(parsed.path)
        if body is None:
            self.reply(404)
            return
        requested = self.headers.get("Range", "")
        if requested.startswith("bytes=") and "," not in requested:
            bounds = requested[6:].split("-", 1)
            try:
                start = int(bounds[0])
                end = int(bounds[1]) if bounds[1] else len(body) - 1
            except ValueError:
                self.reply(416, headers={"Content-Range": "bytes */" + str(len(body))})
                return
            if start < 0 or start >= len(body) or end < start:
                self.reply(416, headers={"Content-Range": "bytes */" + str(len(body))})
                return
            end = min(end, len(body) - 1)
            self.reply(206, body[start:end + 1], {
                "Content-Range": "bytes " + str(start) + "-" + str(end) + "/" + str(len(body)),
                "Accept-Ranges": "bytes",
            })
            return
        self.reply(200, body)

    def do_DELETE(self):
        self.reply(204 if self.authorized() else 403)

    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(os.path.join(root, "port"), "w", encoding="ascii") as output:
    output.write(str(server.server_port))
server.serve_forever()
PY

python3 "$tmp_dir/fake_s3.py" "$tmp_dir" &
server_pid="$!"
for _ in $(seq 1 100); do [[ -f "$tmp_dir/port" ]] && break; sleep 0.05; done
port="$(cat "$tmp_dir/port")"
SPECUS_MEDIA_CAPTURE_TEST_ENDPOINT="http://media.test:$port" \
SPECUS_MEDIA_CAPTURE_TEST_RESOLVE_ADDRESS="127.0.0.1" \
  "$test_binary"

find "$tmp_dir" -name 'upload-*-part-1' -size 5242880c | grep -q .
find "$tmp_dir" -name 'upload-*-part-2' -size 3c | grep -q .
