#!/usr/bin/env bash
set -euo pipefail

TEST_BINARY="$1"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-es.XXXXXX")"
ES_PORT="${ES_PORT:-17420}"

cleanup() {
  local status=$?
  set +e
  if [[ $status -ne 0 && -f "$TMP_DIR/es.log" ]]; then sed -n '1,200p' "$TMP_DIR/es.log" >&2; fi
  if [[ -n "${ES_PID:-}" ]]; then kill "$ES_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
  return "$status"
}
trap cleanup EXIT

python3 - "$ES_PORT" <<'PY' >"$TMP_DIR/es.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
import threading
import urllib.parse

indices = {}
lock = threading.Lock()

def term_filters(node):
    filters = node.get("query", {}).get("bool", {}).get("filter", [])
    result = []
    for item in filters:
        if "term" in item:
            result.extend(item["term"].items())
        elif "terms" in item:
            result.extend((key, value) for key, value in item["terms"].items())
    return result

class Handler(BaseHTTPRequestHandler):
    def auth(self):
        return self.headers.get("Authorization") == "ApiKey test-api-key"

    def index_name(self):
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        return parts[0] if parts and parts[0] else ""

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        with lock: exists = self.index_name() in indices
        self.send_json(200 if exists else 404, {})

    def do_PUT(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        with lock:
            index = indices.setdefault(parts[0], {})
            if len(parts) >= 3 and parts[1] == "_doc":
                index[parts[2]] = json.loads(body)
                return self.send_json(201, {"result": "created"})
        self.send_json(200, {"acknowledged": True})

    def do_GET(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        name = self.index_name()
        with lock:
            size = sum(len(json.dumps(value, separators=(",", ":")))
                       for value in indices.get(name, {}).values())
        self.send_json(200, {"indices": {name: {"total": {"store": {
            "size_in_bytes": size, "total_data_set_size_in_bytes": size}}}}})

    def do_POST(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if urllib.parse.urlsplit(self.path).path == "/_bulk":
            operations = [json.loads(line) for line in raw.splitlines() if line]
            with lock:
                for operation in operations:
                    delete = operation["delete"]
                    indices.get(delete["_index"], {}).pop(delete["_id"], None)
            return self.send_json(200, {"errors": False})
        request = json.loads(raw or b"{}")
        index_name = self.index_name()
        with lock: docs = list(indices.get(index_name, {}).items())
        for field, expected in term_filters(request):
            if isinstance(expected, list):
                docs = [(key, doc) for key, doc in docs if doc.get(field) in expected]
            else:
                docs = [(key, doc) for key, doc in docs if doc.get(field) == expected]
        must = request.get("query", {}).get("bool", {}).get("must", [])
        for clause in must:
            query = clause.get("simple_query_string", {}).get("query", "").lower()
            fields = clause.get("simple_query_string", {}).get("fields", [])
            if query:
                docs = [(key, doc) for key, doc in docs
                        if any(query in str(doc.get(field, "")).lower() for field in fields)]
        sort = request.get("sort", [])
        for item in reversed(sort):
            field, options = next(iter(item.items()))
            reverse = options.get("order") == "desc"
            docs.sort(key=lambda row: row[1].get(field, 0), reverse=reverse)
        total = len(docs)
        start = request.get("from", 0)
        size = request.get("size", 10)
        docs = docs[start:start + size]
        self.send_json(200, {"hits": {"total": {"value": total, "relation": "eq"},
                                     "hits": [{"_id": key, "_source": doc} for key, doc in docs]}})

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
ES_PID=$!

for _ in $(seq 1 50); do
  if python3 - "$ES_PORT" <<'PY'
import http.client, sys
try:
    c = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=1)
    c.request("HEAD", "/ready", headers={"Authorization": "ApiKey test-api-key"})
    c.getresponse().read()
    c.close()
except Exception:
    raise SystemExit(1)
PY
  then break; fi
  sleep 0.1
done

SPECUS_ELASTICSEARCH_URIS="http://127.0.0.1:$ES_PORT" \
SPECUS_ELASTICSEARCH_API_KEY=test-api-key \
SPECUS_ELASTICSEARCH_HTTP_INDEX=specus-http-traffic \
SPECUS_ELASTICSEARCH_TCP_INDEX=specus-tcp-traffic \
"$TEST_BINARY" "$TMP_DIR/specus.db"
