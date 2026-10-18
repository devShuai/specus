#!/usr/bin/env python3
"""Real loopback Redis controls for test-fixture ownership, not C feature acceptance."""
import contextlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(os.environ.get("SPECUS_FIXTURE_SOURCE_DIR", Path(__file__).resolve().parents[1]))
HELPER = SOURCE / "scripts/test_fixture_resources.sh"


def cli(port, *args):
    return subprocess.run(["redis-cli", "--raw", "-h", "127.0.0.1", "-p", str(port), *args],
                          capture_output=True, text=True, timeout=3, check=True).stdout.strip()


@contextlib.contextmanager
def other_redis():
    for command in ("redis-server", "redis-cli", "bash"):
        if shutil.which(command) is None:
            raise RuntimeError(f"Required fixture executable missing: {command}")
    with tempfile.TemporaryDirectory(prefix="specus-fixture-owner-") as directory:
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        with open(Path(directory) / "redis.log", "wb") as output:
            child = subprocess.Popen(["redis-server", "--bind", "127.0.0.1", "--port", str(port),
                                      "--protected-mode", "yes", "--save", "", "--appendonly", "no",
                                      "--dir", directory], stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 3
                while True:
                    if child.poll() is not None:
                        raise RuntimeError("Controlled Redis did not start")
                    try:
                        info = cli(port, "INFO", "server")
                        if f"process_id:{child.pid}" in info.splitlines():
                            break
                        raise RuntimeError("Controlled Redis port belongs to another process")
                    except subprocess.CalledProcessError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.02)
                cli(port, "SET", "fixture-owner-sentinel", "unchanged")
                yield child, port, Path(directory) / "redis.log"
                if child.poll() is not None or cli(port, "GET", "fixture-owner-sentinel") != "unchanged":
                    raise AssertionError("The wrapper stopped or changed another fixture's Redis")
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=3)


class FixtureIsolationTests(unittest.TestCase):
    def test_occupied_redis_is_not_reused(self):
        with other_redis() as (_, port, _):
            env = dict(os.environ, SPECUS_TEST_REDIS_PORT=str(port))
            # /bin/true is only a readiness probe: the old wrapper must NOT be
            # allowed to report success against the controlled foreign Redis.
            result = subprocess.run(["bash", str(SOURCE / "scripts/public_coordination_test.sh"), "/bin/true"],
                                    env=env, capture_output=True, text=True, timeout=6)
            self.assertNotEqual(result.returncode, 0,
                                "fixture accepted someone else's Redis as its own and invoked the child")

    def test_owned_readiness_checks_real_redis_pid(self):
        with other_redis() as (_, port, log):
            result = subprocess.run(["bash", "-c", 'source "$1"; specus_test_wait_redis "$$" "$2" "$3"',
                                     "fixture-ownership", str(HELPER), str(port), str(log)],
                                    capture_output=True, text=True, timeout=6)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Redis ownership mismatch", result.stderr)

    def test_port_selection_reserves_distinct_endpoints(self):
        result = subprocess.run(["bash", "-c", 'source "$1"; specus_test_pick_ports "" "" "" "" ""',
                                 "fixture-ports", str(HELPER)], capture_output=True, text=True, timeout=3, check=True)
        ports = [int(value) for value in result.stdout.split()]
        self.assertEqual(len(ports), 5)
        self.assertEqual(len(set(ports)), 5)
        self.assertTrue(all(0 < value <= 65535 for value in ports))

    def test_cluster_occupied_control_port_is_refused_before_start(self):
        with other_redis() as (_, port, _):
            env = dict(os.environ, SPECUS_TEST_CLUSTER_CONTROL_ONE=str(port))
            result = subprocess.run(["bash", str(SOURCE / "scripts/public_discovery_cluster_e2e.sh"), "/bin/true"],
                                    env=env, capture_output=True, text=True, timeout=6)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("test port allocation failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
