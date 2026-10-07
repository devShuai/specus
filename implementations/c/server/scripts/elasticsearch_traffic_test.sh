#!/usr/bin/env bash
# Runs a test binary against a fake Elasticsearch on loopback. The fake keeps documents in memory
# and evaluates the subset of the query DSL the C store sends (bool with filter/must/should and
# minimum_should_match, term, terms, wildcard, multi_match, match_phrase, match_all), so search
# semantics are checked the way a real cluster would apply them. Extra arguments go to the test.
set -euo pipefail

TEST_BINARY="$1"
shift
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/specus-c-es.XXXXXX")"

cleanup() {
  local status=$?
  set +e
  if [[ $status -ne 0 && -f "$TMP_DIR/es.log" ]]; then sed -n '1,200p' "$TMP_DIR/es.log" >&2; fi
  if [[ -n "${ES_PID:-}" ]]; then kill "$ES_PID" 2>/dev/null || true; fi
  rm -rf "$TMP_DIR"
  return "$status"
}
trap cleanup EXIT

python3 - "$TMP_DIR/es.port" <<'PY' >"$TMP_DIR/es.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import sys
import threading
import urllib.parse

indices = {}
lock = threading.Lock()

# Two HTTP indices that exist before the server starts: one made before bodies were stored, and one
# where documents with bodies were written before the mapping had them, so they are text.
LEGACY_HTTP_TYPES = {"id": "long", "tenantId": "keyword", "clientId": "long", "route": "keyword",
                     "statusCode": "integer", "capturedAt": "keyword"}
indices["specus-http-legacy"] = {"types": dict(LEGACY_HTTP_TYPES), "docs": {}}
indices["specus-http-text-bodies"] = {"types": dict(LEGACY_HTTP_TYPES, requestBodyData="text",
                                                    responseBodyData="text"), "docs": {}}

def index_entry(name):
    return indices.setdefault(name, {"types": {}, "docs": {}})

def analyze(value):
    # The standard analyzer, roughly: lower-cased runs of letters and digits.
    return re.findall(r"[0-9a-z]+", str(value).lower())

def field_value(doc_id, doc, field):
    if field == "_id":
        return doc_id
    return doc.get(field)

def scalar(value):
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value

def equal(left, right):
    if left is None:
        return False
    if isinstance(left, bool) or isinstance(right, bool):
        return left == right
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        # Ids are 64-bit; compare whole numbers exactly, not as doubles.
        try:
            return int(str(left)) == int(str(right))
        except (TypeError, ValueError):
            pass
        try:
            return float(left) == float(right)
        except (TypeError, ValueError):
            return False
    return str(left) == str(right)

def wildcard_regex(pattern):
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)

def matches(query, doc_id, doc, types):
    if "match_all" in query:
        return True
    if "bool" in query:
        clause = query["bool"]
        for item in clause.get("filter", []) + clause.get("must", []):
            if not matches(item, doc_id, doc, types):
                return False
        should = clause.get("should", [])
        minimum = clause.get("minimum_should_match")
        if minimum is not None:
            needed = int(minimum)
        elif should and not clause.get("filter") and not clause.get("must"):
            needed = 1
        else:
            needed = 0
        if needed > 0 and sum(1 for item in should if matches(item, doc_id, doc, types)) < needed:
            return False
        return True
    if "term" in query:
        field, expected = next(iter(query["term"].items()))
        expected = scalar(expected)
        value = field_value(doc_id, doc, field)
        if types.get(field) == "text":
            return str(expected) in analyze(value)
        return equal(value, expected)
    if "terms" in query:
        field, expected = next(iter(query["terms"].items()))
        value = field_value(doc_id, doc, field)
        return any(equal(value, item) for item in expected)
    if "wildcard" in query:
        field, spec = next(iter(query["wildcard"].items()))
        pattern = spec["value"] if isinstance(spec, dict) else spec
        insensitive = isinstance(spec, dict) and spec.get("case_insensitive", False)
        value = field_value(doc_id, doc, field)
        if value is None:
            return False
        flags = re.IGNORECASE | re.DOTALL if insensitive else re.DOTALL
        return re.fullmatch(wildcard_regex(pattern), str(value), flags) is not None
    if "multi_match" in query:
        spec = query["multi_match"]
        wanted = analyze(spec["query"])
        for field in spec["fields"]:
            tokens = analyze(field_value(doc_id, doc, field) or "")
            if any(token in tokens for token in wanted):
                return True
        return False
    if "match_phrase" in query:
        field, spec = next(iter(query["match_phrase"].items()))
        phrase = spec["query"] if isinstance(spec, dict) else spec
        value = field_value(doc_id, doc, field)
        if value is None:
            return False
        if types.get(field) != "text":
            return str(value) == str(phrase)
        wanted = analyze(phrase)
        tokens = analyze(value)
        return any(tokens[i:i + len(wanted)] == wanted for i in range(len(tokens) - len(wanted) + 1))
    raise ValueError("unsupported query: %s" % json.dumps(query))

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

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def do_HEAD(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        with lock: exists = self.index_name() in indices
        self.send_json(200 if exists else 404, {})

    def do_PUT(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        body = self.read_body()
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        with lock:
            index = index_entry(parts[0])
            if len(parts) >= 3 and parts[1] == "_doc":
                index["docs"][parts[2]] = json.loads(body)
                return self.send_json(201, {"result": "created"})
            if len(parts) == 2 and parts[1] == "_mapping":
                # As Elasticsearch: a field keeps the type it has; new fields are added.
                properties = json.loads(body).get("properties", {})
                changed = [key for key, value in properties.items()
                           if key in index["types"] and index["types"][key] != value.get("type")]
                if changed:
                    return self.send_json(400, {"error": {"type": "illegal_argument_exception",
                                                          "reason": "mapper [" + changed[0] + "] cannot be changed"}})
                index["types"].update({key: value.get("type") for key, value in properties.items()})
                return self.send_json(200, {"acknowledged": True})
            if body:
                properties = json.loads(body).get("mappings", {}).get("properties", {})
                index["types"].update({key: value.get("type") for key, value in properties.items()})
        self.send_json(200, {"acknowledged": True})

    def do_GET(self):
        name = self.index_name()
        if urllib.parse.urlsplit(self.path).path.endswith("/_mapping"):
            # For the tests to inspect, without credentials: the server never reads a mapping.
            with lock: types = dict(indices.get(name, {}).get("types", {}))
            properties = {key: {"type": value} for key, value in sorted(types.items())}
            return self.send_json(200, {name: {"mappings": {"properties": properties}}})
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        with lock:
            size = sum(len(json.dumps(value, separators=(",", ":")))
                       for value in indices.get(name, {}).get("docs", {}).values())
        self.send_json(200, {"indices": {name: {"total": {"store": {
            "size_in_bytes": size, "total_data_set_size_in_bytes": size}}}}})

    def do_POST(self):
        if not self.auth(): return self.send_json(401, {"error": "unauthorized"})
        raw = self.read_body()
        if urllib.parse.urlsplit(self.path).path == "/_bulk":
            lines = [json.loads(line) for line in raw.splitlines() if line]
            items = []
            with lock:
                i = 0
                while i < len(lines):
                    action = lines[i]
                    if "delete" in action:
                        target = action["delete"]
                        index_entry(target["_index"])["docs"].pop(target["_id"], None)
                        items.append({"delete": {"status": 200}})
                        i += 1
                    elif "index" in action:
                        target = action["index"]
                        index_entry(target["_index"])["docs"][target["_id"]] = lines[i + 1]
                        items.append({"index": {"status": 201}})
                        i += 2
                    else:
                        return self.send_json(400, {"error": "unsupported bulk action"})
            return self.send_json(200, {"errors": False, "items": items})
        request = json.loads(raw or b"{}")
        index_name = self.index_name()
        with lock:
            entry = indices.get(index_name, {"types": {}, "docs": {}})
            docs = list(entry["docs"].items())
            types = dict(entry["types"])
        query = request.get("query", {"match_all": {}})
        try:
            docs = [(key, doc) for key, doc in docs if matches(query, key, doc, types)]
        except ValueError as error:
            return self.send_json(400, {"error": str(error)})
        for item in reversed(request.get("sort", [])):
            field, options = next(iter(item.items()))
            reverse = options.get("order") == "desc"
            docs.sort(key=lambda row: row[1].get(field, 0), reverse=reverse)
        total = len(docs)
        start = request.get("from", 0)
        size = request.get("size", 10)
        docs = docs[start:start + size]
        source = request.get("_source")
        excludes = source.get("excludes", []) if isinstance(source, dict) else []
        if source is False:
            docs = [(key, {}) for key, doc in docs]
        elif excludes:
            docs = [(key, {field: value for field, value in doc.items() if field not in excludes})
                    for key, doc in docs]
        self.send_json(200, {"hits": {"total": {"value": total, "relation": "eq"},
                                     "hits": [{"_id": key, "_source": doc} for key, doc in docs]}})

    def log_message(self, format, *args):
        return

server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1] + ".tmp", "w") as port_file:
    port_file.write(str(server.server_address[1]))
import os
os.rename(sys.argv[1] + ".tmp", sys.argv[1])
server.serve_forever()
PY
ES_PID=$!

for _ in $(seq 1 100); do
  [[ -s "$TMP_DIR/es.port" ]] && break
  sleep 0.1
done
ES_PORT="$(cat "$TMP_DIR/es.port")"

SPECUS_ELASTICSEARCH_URIS="http://127.0.0.1:$ES_PORT" \
SPECUS_ELASTICSEARCH_API_KEY=test-api-key \
SPECUS_ELASTICSEARCH_HTTP_INDEX=specus-http-traffic \
SPECUS_ELASTICSEARCH_TCP_INDEX=specus-tcp-traffic \
"$TEST_BINARY" "$TMP_DIR/specus.db" "$@"
