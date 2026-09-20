#!/usr/bin/env python3
"""The controlled target of the peer egress lab.

An HTTP server and a UDP responder that tell every caller which source address they saw, and
append one JSON line per request to a log the lab reads back. The lab's leak checks are built on
that log: a request that reaches here from the consumer's own address, for a destination a rule
sent through the egress, is the failure the whole feature exists to prevent.

Bytes served and accepted are deterministic, so the lab can verify a transfer without the target
having to tell it a checksum in-band. Standard library only.
"""

import argparse
import hashlib
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CHUNK = 65536
SLOW_TICK = b"tick\n"


def blob_chunks(size):
    """Deterministic content: chunk i is sha256(i) repeated. Independent of any process state."""
    offset = 0
    index = 0
    while offset < size:
        block = hashlib.sha256(index.to_bytes(8, "big")).digest() * (CHUNK // 32)
        take = min(CHUNK, size - offset)
        yield block[:take]
        offset += take
        index += 1


def blob_sha256(size):
    digest = hashlib.sha256()
    for chunk in blob_chunks(size):
        digest.update(chunk)
    return digest.hexdigest()


class RequestLog:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def write(self, **entry):
        entry["time"] = round(time.time(), 3)
        line = json.dumps(entry, sort_keys=True)
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0: every response ends with the connection, so /slow can stream without chunking and a
    # transfer the egress cuts short is visible to curl as a closed connection, not a clean end.
    protocol_version = "HTTP/1.0"
    log = None

    def log_message(self, *_):
        pass

    def _record(self, status, size, **extra):
        self.log.write(
            proto="tcp",
            src=self.client_address[0],
            srcPort=self.client_address[1],
            dst=self.connection.getsockname()[0],
            method=self.command,
            path=self.path,
            status=status,
            bytes=size,
            **extra,
        )

    def _json(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/whoami":
            self._record(200, 0)
            self._json(200, {
                "src": self.client_address[0],
                "srcPort": self.client_address[1],
                "dst": self.connection.getsockname()[0],
            })
            return
        if url.path.startswith("/blob/"):
            try:
                size = int(url.path[len("/blob/"):])
            except ValueError:
                self._record(404, 0)
                self._json(404, {"error": "bad size"})
                return
            self._record(200, size)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            try:
                for chunk in blob_chunks(size):
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, OSError) as error:
                self.log.write(proto="tcp", event="write-failed", src=self.client_address[0],
                               path=self.path, error=type(error).__name__)
            return
        if url.path == "/slow":
            query = parse_qs(url.query)
            seconds = float(query.get("seconds", ["10"])[0])
            interval = float(query.get("interval", ["0.2"])[0])
            ticks = max(1, int(seconds / interval))
            self._record(200, ticks * len(SLOW_TICK), seconds=seconds)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(ticks * len(SLOW_TICK)))
            self.end_headers()
            sent = 0
            try:
                for _ in range(ticks):
                    self.wfile.write(SLOW_TICK)
                    self.wfile.flush()
                    sent += 1
                    time.sleep(interval)
            except (BrokenPipeError, ConnectionResetError, OSError) as error:
                self.log.write(proto="tcp", event="write-failed", src=self.client_address[0],
                               path=self.path, ticksSent=sent, error=type(error).__name__)
            return
        self._record(404, 0)
        self._json(404, {"error": "no such path"})

    def do_POST(self):
        url = urlparse(self.path)
        if url.path != "/upload":
            self._record(404, 0)
            self._json(404, {"error": "no such path"})
            return
        remaining = int(self.headers.get("Content-Length", "0"))
        digest = hashlib.sha256()
        received = 0
        while remaining > 0:
            chunk = self.rfile.read(min(CHUNK, remaining))
            if not chunk:
                break
            digest.update(chunk)
            received += len(chunk)
            remaining -= len(chunk)
        self._record(200, received)
        self._json(200, {"src": self.client_address[0], "bytes": received, "sha256": digest.hexdigest()})


def serve_udp(address, port, log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    while True:
        data, peer = sock.recvfrom(65535)
        log.write(proto="udp", src=peer[0], srcPort=peer[1], dst=address, bytes=len(data))
        sock.sendto(f"src={peer[0]}:{peer[1]} dst={address}\n".encode(), peer)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--udp", action="append", default=[], metavar="ADDRESS:PORT",
                        help="UDP responder to bind; repeatable")
    parser.add_argument("--log", required=True, help="JSON lines, one per request")
    args = parser.parse_args()

    log = RequestLog(args.log)
    Handler.log = log
    for entry in args.udp:
        address, port = entry.rsplit(":", 1)
        threading.Thread(target=serve_udp, args=(address, int(port), log), daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", args.http_port), Handler)
    server.daemon_threads = True
    print("ready", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
