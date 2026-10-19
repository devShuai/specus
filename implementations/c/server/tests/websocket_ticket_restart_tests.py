#!/usr/bin/env python3
"""Real unmodified main executable, real password login, own loopback namespace and SQLite.

Reuses only the frozen management-cluster HTTP/process fixture; Redis is disabled.
The run directory and all child logs are retained, including on failure.
"""
import contextlib
import hashlib
import importlib.util
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

phase = Path(__file__).resolve().parent.parent
fixture_path = phase / "scripts/management_cluster_e2e.py"
spec = importlib.util.spec_from_file_location("frozen_management_fixture", fixture_path)
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)


class MainFixture(fixture_module.Fixture):
    def __init__(self, binary, stack, directory):
        # Keep the actual frozen spawn/server/strict-stop implementations, but preserve evidence.
        self.stack = stack
        self.directory = directory
        self.processes = []
        self.binary = str(binary.resolve())
        self.redis_port = fixture_module.free_port()  # unused: clustering is always disabled here

    def server(self, name, tenant="default", database="shared.db", cluster=False):
        assert cluster is False, "this fixture has no Redis and may not enable clustering"
        return super().server(name, tenant, database, cluster=False)


def ticks(text):
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z", text)
    assert match, "unexpected timestamp representation"
    from calendar import timegm
    from time import strptime
    fraction = match[2] or ""
    assert len(fraction) <= 9 and all(char == "0" for char in fraction[7:])
    return timegm(strptime(match[1], "%Y-%m-%dT%H:%M:%S")) * 10_000_000 + int((fraction + "0000000")[:7])


def snapshot(database):
    with sqlite3.connect(database) as connection:
        rows = connection.execute("SELECT token_hash,scope,attributes_json,remote_address_hash,created_at,expires_at FROM specus_websocket_ticket ORDER BY token_hash").fetchall()
    return {row[0]: tuple(row[1:]) for row in rows}


def digest(ticket):
    return hashlib.sha256(ticket.encode()).hexdigest()


def run(directory):
    database = directory / "shared.db"
    assert not database.exists(), "only the actual main process may initialize this database"
    with contextlib.ExitStack() as stack:
        fixture = MainFixture(Path(sys.argv[1]), stack, directory)
        issuer_port, _, token = fixture.server("issuer")
        issuer_process = fixture.processes[-1]
        assert issuer_process.poll() is None and database.exists()
        endpoints = ["connections", "client-messages", "public-transfer/discovery"]
        tickets = []
        for endpoint in endpoints:
            public = endpoint == endpoints[2]
            body = {"roomId": "cli-restart-room", "peerId": "cli-restart-peer", "displayName": "restart"} if public else {"endpoint": endpoint}
            result = fixture_module.request(issuer_port, "POST", "/api/public/transfer/ws-tickets" if public else "/api/admin/ws-tickets", body, token)
            assert set(result) >= {"ticket", "expiresAt"}
            tickets.append(result)
        original = snapshot(database)
        assert len(original) == 3 and set(original) == {digest(item["ticket"]) for item in tickets}
        for item in tickets:
            row = original[digest(item["ticket"])]
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(?:\d{3}|\d{6}|\d{9}))?Z", row[3]), "createdAt follows Java Instant.toString; only expiresAt uses fixed seven digits"
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z", row[4])
            assert ticks(row[4]) - ticks(row[3]) == 45 * 10_000_000
            assert ticks(item["expiresAt"]) == ticks(row[4])
        fixture.stop(issuer_process, log=directory / "issuer.log")
        assert issuer_process.returncode == 0 and snapshot(database) == original
        consumer_port, _, renewed_token = fixture.server("consumer")
        consumer_process = fixture.processes[-1]
        assert consumer_process.pid != issuer_process.pid and renewed_token
        assert snapshot(database) == original, "real main restart must preserve all six stored fields"
        remaining = dict(original)
        for index, (endpoint, item) in enumerate(zip(endpoints, tickets)):
            wrong = endpoints[(index + 1) % len(endpoints)]
            assert fixture_module.ticket_status(consumer_port, wrong, item["ticket"]) == 403
            assert snapshot(database) == remaining, "wrong purpose must not consume the saved ticket"
            assert fixture_module.ticket_status(consumer_port, endpoint, item["ticket"]) == 101
            remaining.pop(digest(item["ticket"]))
            assert snapshot(database) == remaining
            assert fixture_module.ticket_status(consumer_port, endpoint, item["ticket"]) == 403
        fixture.stop(consumer_process, log=directory / "consumer.log")
        assert consumer_process.returncode == 0
    assert all(process.poll() == 0 for process in fixture.processes)
    print("main CLI ticket: actual executable initialized absent SQLite DB; real password login; issuer process exited0; different consumer process startup preserved all6 ticket fields; three scopes wrong-purpose403/no burn, valid101, replay403; exact45s and100ns/public timestamp agreement passed")
    print("main CLI ticket: both server processes exited0; clustering disabled, no Redis spawned, no test clock or production hooks; temporary fixture cleaned after the test")
    print("main CLI ticket: normal-binary startup/restart only; this is not a production multi-node database/lease acceptance")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: websocket_ticket_restart_tests.py <specus-server-c>")
    with tempfile.TemporaryDirectory(prefix="specus-c-ticket-restart-") as temporary:
        run(Path(temporary))
