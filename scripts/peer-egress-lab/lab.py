#!/usr/bin/env python3
"""The peer egress Linux lab: issue #56's acceptance list, run against real processes.

One router namespace (the one this script runs in) with four node namespaces hanging off it:

    srv  203.0.113.2   the Go server: control, admin HTTP, STUN/TURN   \\  "the internet",
    tgt  203.0.113.10  the controlled target, also 198.51.100.10        /  bridged in the router
    con  10.90.1.2     the Go consumer, behind 10.90.1.1
    egr  10.90.2.2     the Go egress, behind 10.90.2.1

The consumer's rule sends 203.0.113.0/24 through the egress. That prefix holds the server on
purpose: the control connection and STUN only survive if the bypass /32 is really installed, and a
bypass route on a physical interface is what a kill -9 leaves behind for the next start to reclaim.
198.51.100.10 is the same target reached by no rule, which is how "unmatched stays local" and the
leak checks tell the two source addresses apart. The target also answers on 169.254.169.254 and
10.90.9.10, two addresses an egress must refuse, so that a refusal that did not happen shows up in
its log rather than as a connection nobody answered.

Run as root inside a fresh network and mount namespace: `sudo unshare -n -m python3 lab.py ...` on a
machine with sudo, `unshare -rnm python3 lab.py ...` without. It refuses to run in a namespace whose
main table is not empty, so started by hand on a real machine it stops instead of rebuilding its
routing. Standard library only.
"""

import argparse
import concurrent.futures
import contextlib
import datetime
import hashlib
import ipaddress
import itertools
import json
import math
import os
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from target import SLOW_TICK, blob_chunks, blob_sha256  # noqa: E402

SERVER_IP = "203.0.113.2"
TARGET_IP = "203.0.113.10"  # under the consumer's rule
TARGET_DIRECT_IP = "198.51.100.10"  # under no rule
WAN_GW = "203.0.113.1"
WAN_DIRECT_GW = "198.51.100.1"
CONSUMER_IP, CONSUMER_GW = "10.90.1.2", "10.90.1.1"
EGRESS_IP, EGRESS_GW = "10.90.2.2", "10.90.2.1"
RULE_CIDR = "203.0.113.0/24"
USER_ROUTE = "192.0.2.0/24"
MESH_CIDR = "100.96.0.0/11"
ADMIN_PORT, CONTROL_PORT, STUN_PORT, UDP_PORT = 8088, 7010, 3478, 5353
CONSUMER_TUN, EGRESS_TUN = "specusc0", "specuse0"
TARGET_URL = f"http://{TARGET_IP}"
DIRECT_URL = f"http://{TARGET_DIRECT_IP}"

CURL_OK, CURL_CONNECT_FAILED, CURL_PARTIAL, CURL_TIMEOUT, CURL_RECV_FAILED = 0, 7, 18, 28, 56

# The policy's destination rules. RULE_GRANT is the lab's own; BROAD_GRANT is the 0.0.0.0/0 an
# operator writes to let a device out to anything, which the forced-deny list must still beat.
RULE_GRANT = {"cidr": RULE_CIDR, "protocols": ["tcp", "udp"], "portRanges": [[1, 65535]]}
BROAD_GRANT = {"cidr": "0.0.0.0/0", "protocols": ["tcp", "udp"], "portRanges": [[1, 65535]]}

# Issue #42's refusals (protocol/spec/peer-egress.md). Two addresses the target answers on that no
# flow through the egress may reach: the cloud metadata address, on the forced-deny list whatever a
# policy grants, and a private address, outside a PUBLIC egress's scope. The router sends both to the
# target, so the egress's own network reaches them and only its decision stands in the way.
METADATA_IP = "169.254.169.254"
PRIVATE_IP = "10.90.9.10"
CODE_CONSUMER_DENIED = "EGRESS_CONSUMER_DENIED"
CODE_FORBIDDEN = "EGRESS_FORBIDDEN_DESTINATION"
CODE_SCOPE = "EGRESS_SCOPE_DENIED"
CODE_LIMIT = "EGRESS_LIMIT_EXCEEDED"
# The egress's new-flow bucket per consumer: 128 at once, refilled at 64 a second. The burst is three
# buckets, and below the 500 packets a TUN device queues, so none is lost on the consumer's side
# before the egress can judge it. Of what reaches the egress, the egress may admit no more than
# RATE_BUCKET + RATE_REFILL_PER_SECOND x (how long it took over the burst) + RATE_SLACK and must
# refuse the rest; the slack covers the last answer coming a little before the egress finished.
RATE_BUCKET, RATE_REFILL_PER_SECOND = 128, 64
RATE_BURST_FLOWS = 3 * RATE_BUCKET
RATE_SLACK = 32
# The admitted datagram flows stay live until they are idle this long. Short, so that they are gone
# before the flow caps come back down, rather than holding 200 slots for a minute.
RATE_IDLE_SECONDS = 3
CONCURRENCY_CAP = 4

# Phase two (protocol/spec/peer-egress-dns.md). The name exists only in the egress's /etc/hosts: the
# consumer can reach it through the takeover or not at all. The consumer's original nameserver is an
# address nothing answers on, so a name the rules do not claim fails rather than resolving locally.
NAMED_HOST = "named.lab.test"
# DNS rebinding: names under the same rule that the egress resolves to an address it must refuse, and
# one to a public address no destination rule names, which only a domain grant lets through.
REBIND_METADATA_HOST = "metadata.lab.test"
REBIND_PRIVATE_HOST = "private.lab.test"
GRANTED_HOST = "granted.lab.test"
DOMAIN_RULE = "*.lab.test"
CONSUMER_NAMESERVER = "198.51.100.53"
FAKE_IP_POOL = "198.18.0.0/15"
UNMAPPED_FAKE_IP = "198.18.0.77"
RESOLV_CONF_WRITTEN = (
    "# Written by specus for peer egress DNS takeover. The original is kept in the journal\n"
    "# and is put back when the client stops or when `egress dns restore` runs.\n"
    "nameserver 198.18.0.1\n"
)

# Issue #50's performance thresholds for this lab. They were agreed before a baseline was taken and
# are not to be moved towards whatever a run produces: a gate that follows the numbers gates nothing.
GATE_REPEATS = 5
GATE_SINGLE_FLOW_BYTES = 8 * 1048576
GATE_SINGLE_FLOW_MIBPS = 4.0
GATE_CONCURRENT_FLOWS = 64
GATE_CONCURRENT_BYTES = 1048576
GATE_CONCURRENT_MIBPS = 10.0
GATE_LOSS_PERCENT = 2.0
GATE_LOSSY_BYTES = 512 * 1024
GATE_LOSSY_SECONDS = 10.0
GATE_FIRST_BYTE_SAMPLES = 20
GATE_FIRST_BYTE_P95_MS = 50.0
GATE_MEMORY_GROWTH_MIB = 200.0

# Run in the consumer's namespace as `python3 -c BURST_SCRIPT HOST PORT COUNT QUIET`: one datagram
# from each of COUNT sockets, so COUNT new flows, sent back to back. A datagram flow costs the
# egress no handshake with the target, so how fast the burst meets the bucket does not depend on
# how fast the egress can dial. Listens for the answers until QUIET seconds pass without one, and
# prints how many came and when the last did: the egress admits flows for about that long, and the
# bucket refills for as long as it does.
BURST_SCRIPT = """\
import json, selectors, socket, sys, time
host, port, count, quiet = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
selector = selectors.DefaultSelector()
sockets = []
for _ in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    sockets.append(s)
started = time.monotonic()
for s in sockets:
    s.sendto(b'burst', (host, port))
    selector.register(s, selectors.EVENT_READ)
sent = time.monotonic() - started
answered, last = 0, 0.0
deadline = time.monotonic() + quiet
while answered < count and selector.get_map():
    events = selector.select(max(0.0, deadline - time.monotonic()))
    if not events:
        break
    for key, _ in events:
        selector.unregister(key.fileobj)
        try:
            key.fileobj.recv(512)
        except OSError:
            continue
        answered += 1
        last = time.monotonic() - started
        deadline = time.monotonic() + quiet
for s in sockets:
    s.close()
print(json.dumps({'sent': count, 'answered': answered, 'sendSeconds': round(sent, 3), 'lastAnswer': round(last, 3)}))
"""

# Run as `python3 -c HOLD_SCRIPT HOST PORT ATTEMPTS`: connects one at a time and keeps each
# connection open, until one is not accepted or ATTEMPTS is reached; then resets them all. Prints
# how many were held and how the next one ended.
HOLD_SCRIPT = """\
import json, socket, struct, sys
host, port, attempts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
held, outcome = [], 'never refused'
for _ in range(attempts):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((host, port))
    except ConnectionRefusedError:
        outcome = 'refused'
    except socket.timeout:
        outcome = 'timeout'
    except OSError as error:
        outcome = type(error).__name__
    else:
        held.append(s)
        continue
    s.close()
    break
for s in held:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    s.close()
print(json.dumps({'held': len(held), 'next': outcome}))
"""


def p95(samples):
    """Nearest-rank 95th percentile: a value that was actually observed, never an interpolation."""
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def rss_kib(pid):
    """The resident set of a live process in KiB, or None once it is gone."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


class LabAbort(Exception):
    """Bring-up did not reach a state the checks can be run against."""


def ns(name, *args):
    return ["ip", "netns", "exec", name, *args]


def in_child_user_namespace():
    """True inside any user namespace but the initial one, whose uid map is the identity."""
    try:
        with open("/proc/self/uid_map", encoding="ascii") as handle:
            mapping = handle.read().split()
    except OSError:
        return False
    return mapping[:3] != ["0", "0", "4294967295"]


class Proc:
    def __init__(self, lab, label, args, log_path):
        self.lab = lab
        self.label = label
        self.log_path = log_path
        handle = open(log_path, "ab")
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        handle.write(f"=== {label} started {stamp} ===\n".encode())
        handle.flush()
        # `ip netns exec` execs the command in place, so this pid is the process itself and a
        # signal reaches it without an intermediary.
        self.popen = subprocess.Popen(args, stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self.handle = handle
        lab.trace.write(f"$ {' '.join(args)} & pid={self.popen.pid}\n")
        lab.trace.flush()

    @property
    def alive(self):
        return self.popen.poll() is None

    def log_offset(self):
        return self.log_path.stat().st_size

    def log_since(self, offset=0):
        with open(self.log_path, "rb") as handle:
            handle.seek(offset)
            return handle.read().decode("utf-8", "replace")

    def wait_log(self, pattern, timeout, since=0):
        regex = re.compile(pattern, re.IGNORECASE)
        found, _ = self.lab.wait_for(f"{self.label} log /{pattern}/",
                                     lambda: regex.search(self.log_since(since)), timeout)
        return found

    def stop(self, timeout=20):
        if self.alive:
            self.popen.terminate()
            try:
                self.popen.wait(timeout)
            except subprocess.TimeoutExpired:
                self.lab.note(f"{self.label} ignored SIGTERM for {timeout}s and was killed")
                self.popen.kill()
                self.popen.wait(10)
        self.handle.close()
        return self.popen.returncode

    def kill(self):
        if self.alive:
            self.popen.kill()
            self.popen.wait(10)
        self.handle.close()
        return self.popen.returncode


class Admin:
    def __init__(self, base):
        self.base = base
        self.token = None

    def call(self, method, path, body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if auth and self.token:
            request.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"{method} {path} -> {error.code}: {detail}") from None
        return json.loads(raw) if raw.strip() else None

    def login(self, username, password):
        answer = self.call("POST", "/auth/login", {"username": username, "password": password}, auth=False)
        self.token = answer["accessToken"]


class Lab:
    def __init__(self, args):
        self.args = args
        self.work = Path(args.work or tempfile.mkdtemp(prefix="peer-egress-lab-"))
        self.work.mkdir(parents=True, exist_ok=True)
        self.report_dir = Path(args.report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.trace = open(self.work / "trace.log", "a", encoding="utf-8")
        self.trace_lock = threading.Lock()
        self.results = []
        self.measurements = {}
        self.snapshots = {}
        self.notes = []
        self.procs = {}
        self.target_log = self.work / "target.log"
        self.counter = itertools.count(1)
        self.admin = None
        self.egress_id = None
        self.consumer_id = None
        self.password = "lab-" + secrets.token_hex(12)
        self.secrets = {"egress": secrets.token_hex(16), "consumer": secrets.token_hex(16)}
        self.started = time.time()
        self.netem = None
        self.last_refused = None

    # -- plumbing ---------------------------------------------------------------------------------

    def say(self, text):
        stamp = f"[{time.time() - self.started:7.1f}s]"
        print(stamp, text, flush=True)
        with self.trace_lock:
            self.trace.write(f"{stamp} {text}\n")
            self.trace.flush()

    def sh(self, args, check=True, timeout=60, quiet=False):
        """Runs a command and traces it; quiet leaves its output out of the trace."""
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        with self.trace_lock:
            self.trace.write(f"$ {' '.join(args)} -> {completed.returncode}\n")
            if completed.stdout.strip() and not quiet:
                self.trace.write(completed.stdout.rstrip() + "\n")
            if completed.stderr.strip():
                self.trace.write("stderr: " + completed.stderr.rstrip() + "\n")
            self.trace.flush()
        if check and completed.returncode != 0:
            raise RuntimeError(f"{' '.join(args)} failed ({completed.returncode}): {completed.stderr.strip()}")
        return completed

    def check(self, name, ok, evidence=""):
        self.results.append({"name": name, "ok": bool(ok), "evidence": evidence})
        self.say(("PASS " if ok else "FAIL ") + name + (f" -- {evidence}" if evidence else ""))

    def note(self, text):
        self.notes.append(text)
        self.say("note: " + text)

    def measure(self, name, value, unit=""):
        self.measurements[name] = {"value": value, "unit": unit}
        self.say(f"measured {name} = {value} {unit}".rstrip())

    def wait_for(self, what, predicate, timeout, interval=0.5):
        deadline = time.time() + timeout
        start = time.time()
        while True:
            value = predicate()
            if value:
                return value, time.time() - start
            if time.time() >= deadline:
                self.say(f"timed out after {timeout}s waiting for {what}")
                return None, time.time() - start
            time.sleep(interval)

    # -- topology ---------------------------------------------------------------------------------

    def preflight(self):
        if os.geteuid() != 0:
            raise LabAbort("must run as root (or as the fake root of `unshare -rnm`)")
        for tool in ("ip", "curl"):
            if shutil.which(tool) is None:
                raise LabAbort(f"{tool} is not on PATH")
        table = self.sh(["ip", "-4", "route", "show", "table", "main"]).stdout.strip()
        if table:
            raise LabAbort("the main routing table is not empty; run inside a fresh namespace "
                           "(`sudo unshare -n -m` or `unshare -rnm`), never on a machine's own table:\n" + table)
        for binary in (self.args.server, self.client_binary("consumer"), self.client_binary("egress")):
            if not binary or not os.access(binary, os.X_OK):
                raise LabAbort(f"{binary} is not executable")
        # Mount namespaces isolate mounts, not files: root can otherwise create persistent empty
        # /run/netns handles in the host filesystem. Always use private storage, not just when
        # fake root lacks write access. Refuse an invocation missing the mount namespace first.
        try:
            shared = os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt")
        except PermissionError:
            # The fake root of `unshare -rnm` may not read PID 1's handle. It does not need to: a
            # user namespace other than the initial one can only mount inside a mount namespace it
            # owns, so the host's cannot be the one about to be changed, and make-rprivate below
            # would fail on it rather than proceed.
            shared = not in_child_user_namespace()
        if shared:
            raise LabAbort("a private mount namespace is required; use unshare -n -m")
        self.sh(["mount", "--make-rprivate", "/"])
        self.sh(["mount", "-t", "tmpfs", "tmpfs", "/run"])
        os.makedirs("/run/netns", exist_ok=True)
        self.note("mounted a private tmpfs over /run so that ip netns leaves no host files")

    def build_network(self):
        sh = self.sh
        sh(["ip", "link", "set", "lo", "up"])
        sh(["ip", "link", "add", "br-wan", "type", "bridge"])
        sh(["ip", "addr", "add", f"{WAN_GW}/24", "dev", "br-wan"])
        sh(["ip", "addr", "add", f"{WAN_DIRECT_GW}/24", "dev", "br-wan"])
        sh(["ip", "link", "set", "br-wan", "up"])
        for name in ("srv", "tgt"):
            sh(["ip", "netns", "add", name])
            sh(["ip", "link", "add", f"r-{name}", "type", "veth", "peer", "name", f"{name}0"])
            sh(["ip", "link", "set", f"{name}0", "netns", name])
            sh(["ip", "link", "set", f"r-{name}", "master", "br-wan", "up"])
            sh(["ip", "-n", name, "link", "set", "lo", "up"])
            sh(["ip", "-n", name, "link", "set", f"{name}0", "up"])
        sh(["ip", "-n", "srv", "addr", "add", f"{SERVER_IP}/24", "dev", "srv0"])
        sh(["ip", "-n", "srv", "route", "add", "default", "via", WAN_GW])
        sh(["ip", "-n", "tgt", "addr", "add", f"{TARGET_IP}/24", "dev", "tgt0"])
        sh(["ip", "-n", "tgt", "addr", "add", f"{TARGET_DIRECT_IP}/24", "dev", "tgt0"])
        sh(["ip", "-n", "tgt", "route", "add", "default", "via", WAN_GW])
        # The addresses an egress must refuse, on the target too: a refusal that did not happen
        # reaches it and is logged, rather than failing for want of anything listening.
        for address in (METADATA_IP, PRIVATE_IP):
            sh(["ip", "-n", "tgt", "addr", "add", f"{address}/32", "dev", "tgt0"])
            sh(["ip", "route", "add", f"{address}/32", "via", TARGET_IP])
        for name, address, gateway in (("con", CONSUMER_IP, CONSUMER_GW), ("egr", EGRESS_IP, EGRESS_GW)):
            sh(["ip", "netns", "add", name])
            sh(["ip", "link", "add", f"r-{name}", "type", "veth", "peer", "name", f"{name}0"])
            sh(["ip", "link", "set", f"{name}0", "netns", name])
            sh(["ip", "addr", "add", f"{gateway}/24", "dev", f"r-{name}"])
            sh(["ip", "link", "set", f"r-{name}", "up"])
            sh(["ip", "-n", name, "link", "set", "lo", "up"])
            sh(["ip", "-n", name, "link", "set", f"{name}0", "up"])
            sh(["ip", "-n", name, "addr", "add", f"{address}/24", "dev", f"{name}0"])
            sh(["ip", "-n", name, "route", "add", "default", "via", gateway])
        sh(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        # The router forwards between all four and NATs nothing, so the target sees the consumer's
        # and the egress's own addresses and its log can tell them apart.
        for name in ("con", "egr"):
            got = sh(ns(name, "ping", "-c", "1", "-W", "2", TARGET_IP), check=False)
            if got.returncode != 0:
                raise LabAbort(f"{name} cannot reach the target through the router:\n{got.stdout}{got.stderr}")
        self.say("topology up")

    # -- processes --------------------------------------------------------------------------------

    def start(self, label, args):
        proc = Proc(self, label, args, self.work / f"{label}.log")
        self.procs[label] = proc
        return proc

    def stop_all(self):
        for label in ("consumer", "egress", "server", "target"):
            proc = self.procs.get(label)
            if proc is not None and proc.alive:
                proc.stop()

    def http_alive(self, url):
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                response.read()
            return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            return False

    def start_target(self):
        target = Path(__file__).resolve().parent / "target.py"
        self.start("target", ns("tgt", sys.executable, str(target), "--log", str(self.target_log),
                                "--udp", f"{TARGET_IP}:{UDP_PORT}", "--udp", f"{TARGET_DIRECT_IP}:{UDP_PORT}"))
        ready, _ = self.wait_for("target HTTP", lambda: self.http_alive(f"{TARGET_URL}/whoami"), 20)
        if not ready:
            raise LabAbort("the target never answered:\n" + self.procs["target"].log_since())

    def start_server(self):
        config = {
            "env": "test",
            "publicAddress": SERVER_IP,
            "managementAddr": f"0.0.0.0:{ADMIN_PORT}",
            "connectionString": str(self.work / "specus.db"),
            "dataDirectory": str(self.work / "data"),
            "netty": {"bindAddress": "0.0.0.0", "port": CONTROL_PORT},
            "tls": {"mode": "disabled"},
            "database": {"provider": "sqlite", "seedDemoClient": False},
            "auth": {"passwordLoginEnabled": True, "username": "admin", "password": self.password,
                     "tenantId": "default", "jwtSecret": secrets.token_hex(32)},
            # A consumer restarted after kill -9 logs in before the server has necessarily noticed
            # that the old instance is gone; two instances per machine keep that from being refused.
            "clientAuth": {"defaultMaxOnlineInstances": 2, "perMachineUserMaxInstances": 2},
            "peerMesh": {"enabled": True, "cidr": MESH_CIDR, "publicAddress": SERVER_IP,
                         "stunTurnPort": STUN_PORT, "turnAuthRequired": True,
                         "turnSharedSecret": secrets.token_hex(16)},
        }
        path = self.work / "server.json"
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        self.launch_server(path)
        ready, elapsed = self.wait_for("server admin HTTP",
                                       lambda: self.http_alive(f"http://{SERVER_IP}:{ADMIN_PORT}/"), 60)
        if not ready:
            raise LabAbort("the server never listened:\n" + self.procs["server"].log_since()[-4000:])
        self.admin = Admin(f"http://{SERVER_IP}:{ADMIN_PORT}")
        self.admin.login("admin", self.password)
        for role in ("egress", "consumer"):
            self.admin.call("POST", "/api/admin/client-credentials",
                            {"apiKey": f"lab-{role}", "secret": self.secrets[role], "maxOnlineInstances": 2})
        self.say(f"server up in {elapsed:.1f}s, credentials created")

    def restart_server(self):
        """Takes the server away and brings it back on the same config and database.

        The point is the consumer's control connection: every client loses it and reconnects, which
        is the routine event that used to withdraw the consumer's routes for the length of the
        reconnect. Doing it this way makes that window happen on purpose rather than waiting for
        one to turn up.
        """
        self.procs["server"].stop()
        return self.launch_server(self.work / "server.json")

    def launch_server(self, path):
        self.start("server", ns("srv", "env", "SPECUS_ENV=test", self.args.server, "-config", str(path)))
        ready, _ = self.wait_for("the server's admin HTTP",
                                 lambda: self.http_alive(f"http://{SERVER_IP}:{ADMIN_PORT}/"), 60)
        return bool(ready)

    def client_config(self, role, rules=None, dns_takeover=False):
        config = {
            "serverBaseUrl": f"http://{SERVER_IP}:{ADMIN_PORT}",
            "apiKey": f"lab-{role}",
            "secret": self.secrets[role],
            "updateCheckEnabled": False,
            "peerMeshDevice": "auto",
            "peerMeshTunName": CONSUMER_TUN if role == "consumer" else EGRESS_TUN,
            "peerMeshMtu": 1280,
        }
        if rules is not None:
            config["peerEgressRules"] = rules
            # Rules are only saved until the master switch is on (#49).
            config["peerEgressEnabled"] = True
        if dns_takeover:
            config["peerEgressDnsTakeover"] = True
        path = self.work / f"{role}.jsonc"
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return path

    def client_env(self, role):
        home = self.work / f"home-{role}"
        state = self.work / f"state-{role}"
        for directory in (home, state):
            directory.mkdir(mode=0o700, exist_ok=True)
        return ["env", f"HOME={home}", f"SPECUS_CLI_STATE_DIR={state}"]

    def client_binary(self, role):
        return getattr(self.args, f"{role}_client", None) or self.args.client

    def client_label(self, role):
        label = getattr(self.args, f"{role}_implementation", None)
        if label:
            return label
        return "custom" if getattr(self.args, f"{role}_client", None) else "Go"

    def start_client(self, role, config_path):
        netns_name = "con" if role == "consumer" else "egr"
        return self.start(role, ns(netns_name, *self.client_env(role), self.client_binary(role), "run",
                                   "--config", str(config_path), "--no-update-check", "--login-timeout", "60"))

    def client_status(self, role, command="egress"):
        """The one-shot CLI reads a snapshot the running process refreshes; retried because a
        snapshot older than a few seconds is refused."""
        netns_name = "con" if role == "consumer" else "egr"
        for _ in range(6):
            got = self.sh(ns(netns_name, *self.client_env(role), self.client_binary(role), command,
                             "--config", str(self.work / f"{role}.jsonc"), "--json"), check=False)
            if got.returncode == 0:
                try:
                    return json.loads(got.stdout)
                except json.JSONDecodeError:
                    pass
            time.sleep(1)
        return None

    def devices(self):
        return self.admin.call("GET", "/api/admin/peer-mesh/devices") or []

    def policy(self, allowed, destinations=(RULE_GRANT,), domains=(), max_flows=256, per_consumer=128,
               idle_seconds=60):
        # Every field is sent every time. The server keeps whatever a request leaves out, so a grant
        # or a limit set for one check would otherwise outlive it into the next.
        return self.admin.call("POST", "/api/admin/peer-mesh/egress/policies", {
            "egressClientId": self.egress_id, "enabled": True, "scope": "PUBLIC",
            "allowedConsumerClientIds": allowed,
            "destinationRules": list(destinations), "domainRules": list(domains),
            "maxConcurrentFlows": max_flows, "maxFlowsPerConsumer": per_consumer,
            "idleTimeoutSeconds": idle_seconds,
        })

    def set_policy(self, allowed, **fields):
        """policy(), then the egress's word that it applied that push: a check run against the policy
        before it would prove nothing about this one. The log line carries the number of destination
        rules, which tells a push with an extra rule from the one before it."""
        egress = self.procs["egress"]
        offset = egress.log_offset()
        self.policy(allowed, **fields)
        rules = len(fields.get("destinations", (RULE_GRANT,)))
        applied = egress.wait_log(rf"policy applied enabled=true revision=\d+ rules={rules}\b", 15, offset)
        if not applied:
            self.note(f"the egress did not log a policy with {rules} destination rule(s) within 15 s of the change")
        return bool(applied)

    def switch(self, enabled):
        return self.admin.call("PUT", "/api/admin/peer-mesh/egress/switch", {"enabled": enabled})

    # -- the consumer's view --------------------------------------------------------------------

    def consumer_table(self):
        return self.sh(ns("con", "ip", "-4", "route", "show", "table", "main")).stdout

    def lab_routes(self, table):
        """The lines the feature owns: anything over the tunnel, plus the bypass for the server."""
        return [line for line in table.splitlines()
                if f"dev {CONSUMER_TUN}" in line or line.startswith(SERVER_IP + " ")]

    def rule_route_present(self):
        return f"{RULE_CIDR} dev {CONSUMER_TUN}" in self.consumer_table()

    def curl(self, url, *extra, timeout=10, netns_name="con"):
        body = self.work / f"curl-{next(self.counter)}.out"
        args = ns(netns_name, "curl", "-sS", "--max-time", str(timeout), "-o", str(body), "-w",
                  "%{http_code} %{time_connect} %{time_starttransfer} %{time_total} "
                  "%{speed_download} %{speed_upload}", *extra, url)
        completed = self.sh(args, check=False, timeout=timeout + 30)
        fields = completed.stdout.strip().split()
        metrics = {}
        if len(fields) == 6:
            metrics = {"http": fields[0], "connect": float(fields[1]), "firstByte": float(fields[2]),
                       "total": float(fields[3]), "down": float(fields[4]), "up": float(fields[5])}
        return {"code": completed.returncode, "body": body, "stderr": completed.stderr.strip(), **metrics}

    def whoami(self, url, netns_name="con"):
        got = self.curl(f"{url}/whoami", timeout=8, netns_name=netns_name)
        src = None
        if got["code"] == CURL_OK:
            try:
                src = json.loads(got["body"].read_text())["src"]
            except (json.JSONDecodeError, KeyError, OSError):
                src = None
        got["body"].unlink(missing_ok=True)
        got["src"] = src
        return got

    def through_egress(self):
        got = self.whoami(TARGET_URL)
        return got if got["src"] == EGRESS_IP else None

    def target_entries(self, since=0):
        if not self.target_log.exists():
            return []
        entries = []
        for line in self.target_log.read_text(encoding="utf-8").splitlines()[since:]:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return entries

    def target_mark(self):
        if not self.target_log.exists():
            return 0
        return len(self.target_log.read_text(encoding="utf-8").splitlines())

    def leak_check(self, name, mark):
        leaks = [entry for entry in self.target_entries(mark)
                 if entry.get("src") == CONSUMER_IP and entry.get("dst") == TARGET_IP]
        self.check(name, not leaks,
                   f"{len(leaks)} request(s) reached the covered target from the consumer's own address"
                   if leaks else "no request from the consumer's own address reached the covered target")

    def nothing_reached(self, name, mark, address):
        """leak_check for an address no flow may reach at all: not from the consumer's own address,
        and not from the egress's on the consumer's behalf."""
        reached = [entry for entry in self.target_entries(mark) if entry.get("dst") == address]
        sources = ", ".join(sorted({str(entry.get("src")) for entry in reached}))
        self.check(name, not reached, f"{len(reached)} request(s) reached {address} from {sources}"
                   if reached else f"nothing reached {address} from any address")

    # -- the egress's own account of what it refused ------------------------------------------------

    def egress_section(self):
        """The egress role's section of the egress's status: whether it serves, its live flows and its
        cumulative refusals by code. None when the status cannot be read."""
        status = self.client_status("egress")
        for instance in (status or {}).get("data", {}).get("instances", []):
            section = (instance.get("egress") or {}).get("egress")
            if isinstance(section, dict):
                return section
        return None

    def egress_counts(self):
        """The egress's refusals by code and the number of flows it has ever admitted, from its
        status; None for what cannot be read."""
        section = self.egress_section()
        if section is None:
            return None, None
        refused = {code: count for code, count in (section.get("refused") or {}).items() if isinstance(count, int)}
        total = section.get("totalFlows")
        return refused, total if isinstance(total, int) else None

    def egress_refused(self):
        return self.egress_counts()[0]

    def refusal_baseline(self):
        """The egress's refusal counts with the last policy push fully accounted for. A push revokes
        the flows it no longer allows, lingering ones included, and counts each under its code; the
        status file is rewritten every second, so after two and a half the revocations are in it and
        whatever the count gains from here on is the probe's."""
        time.sleep(2.5)
        return self.egress_refused() or {}

    def refused_at_egress(self, code, before, timeout=15, at_least=1):
        """The egress's counts once it has counted `code` at least `at_least` more times than in
        `before`, else None. The egress counts a refusal when it makes it, whether or not its reset
        and flow-reject reach the consumer: this is the evidence that the egress is where the flow
        stopped."""
        last = {}

        def gained():
            counts = self.egress_refused()
            if counts is not None:
                last["counts"] = counts
            return counts if counts is not None and counts.get(code, 0) - before.get(code, 0) >= at_least else None
        counts, _ = self.wait_for(f"the egress to count {code} {at_least} more time(s)", gained, timeout, 1.0)
        self.last_refused = last.get("counts")
        return counts

    def refusal_evidence(self, code, before, counts):
        # When the count never got there, what it last read is the evidence.
        seen = counts if counts is not None else getattr(self, "last_refused", None)
        after = (seen or {}).get(code, before.get(code, 0))
        return f"egress refused[{code}] {before.get(code, 0)} -> {after}"

    def consumer_view(self, code, offset):
        """What the consumer heard about a refusal: the flow-reject it logs, and its rejected count.
        Evidence only: the flow-reject is a datagram, and losing it is allowed."""
        logged = self.procs["consumer"].wait_log(rf"refused flow code={code}\b", 5, offset)
        blocked = ((self.consumer_section() or {}).get("blocked") or {}).get("rejected-" + code.lower(), 0)
        return (f"consumer {'logged the flow-reject' if logged else 'logged no flow-reject'}, "
                f"rejected-{code.lower()}={blocked}")

    @staticmethod
    def human(size):
        if size >= 1048576 and size % 1048576 == 0:
            return f"{size // 1048576} MiB"
        if size >= 1024 and size % 1024 == 0:
            return f"{size // 1024} KiB"
        return f"{size} B"

    @staticmethod
    def describe(got):
        text = f"curl exit {got['code']}"
        if got.get("http"):
            text += f" http {got['http']}"
        if got.get("stderr"):
            text += f" ({got['stderr'][:120]})"
        return text

    # -- bring-up ---------------------------------------------------------------------------------

    def bring_up(self):
        egress = self.start_client("egress", self.client_config("egress"))
        found, _ = self.wait_for("the egress device", lambda: len(self.devices()) >= 1, 60, 1.0)
        if not found:
            raise LabAbort("the egress never logged in:\n" + egress.log_since()[-4000:])
        self.egress_id = self.devices()[0]["clientId"]
        self.admin.call("PUT", f"/api/admin/peer-mesh/devices/{self.egress_id}", {"enabled": True})

        rules = [{"match": RULE_CIDR, "action": "egress", "egressClientId": self.egress_id}]
        consumer_started = time.time()
        consumer = self.start_client("consumer", self.client_config("consumer", rules))
        found, _ = self.wait_for("the consumer device", lambda: len(self.devices()) >= 2, 60, 1.0)
        if not found:
            raise LabAbort("the consumer never logged in:\n" + consumer.log_since()[-4000:])
        self.consumer_id = next(device["clientId"] for device in self.devices()
                                if device["clientId"] != self.egress_id)
        self.admin.call("PUT", f"/api/admin/peer-mesh/devices/{self.consumer_id}", {"enabled": True})
        self.say(f"egress clientId={self.egress_id} consumer clientId={self.consumer_id}")

        self.switch(True)
        self.policy([self.consumer_id])
        if not egress.wait_log(r"policy applied enabled=true", 30):
            raise LabAbort("the egress never applied the policy:\n" + egress.log_since()[-4000:])
        route, _ = self.wait_for("the rule route", self.rule_route_present, 60)
        if not route:
            raise LabAbort("the consumer never installed the rule route:\n" + consumer.log_since()[-4000:]
                           + "\n--- table\n" + self.consumer_table())
        got, _ = self.wait_for("the first request through the egress", self.through_egress, 60, 1.0)
        if not got:
            raise LabAbort("no request ever went through the egress:\n--- consumer\n" + consumer.log_since()[-3000:]
                           + "\n--- egress\n" + egress.log_since()[-3000:] + "\n--- table\n" + self.consumer_table())
        # Successful traffic observed at the target is the session gate. Java logs path
        # selection at DEBUG, so lack of an INFO line is not proof of a failed session.
        path = re.search(r"Peer Mesh (direct|relay) UDP path active",
                         consumer.log_since() + egress.log_since(), re.IGNORECASE)
        self.measure("peer path type", path.group(1).lower() if path else "unreported")
        self.measure("bring-up, consumer start to first request through the egress",
                     round(time.time() - consumer_started, 1), "s")

    def wait_ready(self, timeout=90):
        """After a restart: the rule route is back and a request goes through the egress."""
        route, _ = self.wait_for("the rule route", self.rule_route_present, timeout)
        if not route:
            return False
        got, _ = self.wait_for("a request through the egress", self.through_egress, timeout, 1.0)
        return bool(got)

    # -- acceptance -------------------------------------------------------------------------------

    def acceptance(self):
        got = self.whoami(TARGET_URL)
        self.check("TCP under the rule leaves from the egress's address",
                   got["src"] == EGRESS_IP, f"target saw src={got['src']} ({self.describe(got)})")
        got = self.whoami(DIRECT_URL)
        self.check("TCP under no rule leaves from the consumer's own address",
                   got["src"] == CONSUMER_IP, f"target saw src={got['src']} ({self.describe(got)})")

        table = self.consumer_table()
        self.snapshots["while serving"] = table
        problems = []
        if f"{RULE_CIDR} dev {CONSUMER_TUN}" not in table:
            problems.append("rule prefix missing")
        if not any(line.startswith(f"{SERVER_IP} via {CONSUMER_GW} dev con0") for line in table.splitlines()):
            problems.append("no bypass /32 for the server on the physical interface")
        for line in table.splitlines():
            first = line.split()[0]
            if first == "default" and CONSUMER_TUN in line:
                problems.append("default route over the tunnel")
            if first in ("0.0.0.0/1", "128.0.0.0/1"):
                problems.append(f"half-default route {first}")
            if f"dev {CONSUMER_TUN}" in line and first != RULE_CIDR:
                if "/" in first and not first.endswith("/32"):
                    problems.append(f"unexpected prefix over the tunnel: {line}")
                elif ipaddress.ip_address(first.split("/")[0]) not in ipaddress.ip_network(MESH_CIDR):
                    problems.append(f"unexpected host route over the tunnel: {line}")
        self.check("route table holds the exact prefix, the bypass /32 and mesh host routes only; no default",
                   not problems, "; ".join(problems) if problems else "\n".join(self.lab_routes(table)))
        # Every runtime says which path carries each egress peer's traffic and how many flows it has;
        # a lab consumer that just reached its egress is on one path or the other. The state file is
        # refreshed on the process's own period, so it is read until it lists the peer.
        def egress_peers():
            status = self.client_status("consumer")
            if not status:
                return None
            self.snapshots["consumer status (egress --json)"] = json.dumps(status.get("data", status), indent=2)
            return [peer for instance in status.get("data", {}).get("instances", [])
                    for peer in ((instance.get("egress") or {}).get("consumer") or {}).get("peers", [])] or None
        peers, _ = self.wait_for("the consumer status to list its egress peer", egress_peers, 30, 1.0)
        self.check("status names the path to the egress and its flow count",
                   bool(peers) and all(peer.get("path") in ("direct", "relay") and isinstance(peer.get("flows"), int)
                                       for peer in peers),
                   json.dumps(peers))

        # Up to three datagrams, the way any UDP client that wants an answer behaves: one datagram
        # lost while the path settles is what UDP permits, and a single-shot probe failed runs for it.
        # A reply from the consumer's own address would still fail the check, and a retry is noted,
        # so a first datagram that goes missing every time would show up rather than be absorbed.
        script = ("import socket\n"
                  "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                  "s.settimeout(2)\n"
                  "for attempt in range(1, 4):\n"
                  f"    s.sendto(b'lab', ('{TARGET_IP}', {UDP_PORT}))\n"
                  "    try:\n"
                  "        print(f'attempt={attempt} ' + s.recv(200).decode().strip())\n"
                  "        break\n"
                  "    except socket.timeout:\n"
                  "        continue\n"
                  "else:\n"
                  "    print('no reply to 3 datagrams')\n")
        got = self.sh(ns("con", sys.executable, "-c", script), check=False, timeout=20)
        reply = got.stdout.strip()
        self.check("UDP under the rule leaves from the egress's address",
                   f"src={EGRESS_IP}:" in reply, reply or got.stderr.strip()[-200:])
        if reply.startswith("attempt=") and not reply.startswith("attempt=1 "):
            self.note(f"the UDP probe was answered only on a retry ({reply.split()[0]}); earlier datagrams got no reply")

        samples_via, samples_direct = [], []
        for _ in range(5):
            via = self.whoami(TARGET_URL)
            direct = self.whoami(DIRECT_URL)
            if via["code"] == CURL_OK:
                samples_via.append((via["connect"], via["firstByte"]))
            if direct["code"] == CURL_OK:
                samples_direct.append((direct["connect"], direct["firstByte"]))
        if samples_via:
            self.measure("TCP connect via egress, median of 5",
                         round(statistics.median(s[0] for s in samples_via) * 1000, 1), "ms")
            self.measure("first byte via egress, median of 5",
                         round(statistics.median(s[1] for s in samples_via) * 1000, 1), "ms")
        if samples_direct:
            self.measure("TCP connect direct, median of 5",
                         round(statistics.median(s[0] for s in samples_direct) * 1000, 1), "ms")
            self.measure("first byte direct, median of 5",
                         round(statistics.median(s[1] for s in samples_direct) * 1000, 1), "ms")

        self.transfer("download via egress", TARGET_URL, self.args.blob_bytes, timeout=180)
        self.transfer("download direct", DIRECT_URL, self.args.blob_bytes, timeout=60, record_only=True)
        self.upload("upload via egress", TARGET_URL, self.args.upload_bytes, timeout=180)
        self.downstream_ceiling()

    def downstream_ceiling(self):
        """Probe response sizes beyond the old receiver-buffer ceiling; every size must pass."""
        largest = None
        first_failure = None
        for size in self.args.ceiling_sizes:
            got = self.curl(f"{TARGET_URL}/blob/{size}", timeout=self.args.ceiling_timeout)
            received = got["body"].stat().st_size if got["body"].exists() else 0
            complete = got["code"] == CURL_OK and received == size
            if complete:
                with open(got["body"], "rb") as handle:
                    complete = hashlib.file_digest(handle, "sha256").hexdigest() == blob_sha256(size)
            got["body"].unlink(missing_ok=True)
            self.check(f"large response {size} B arrives intact", complete, self.describe(got))
            self.say(f"downstream ceiling probe: {size} B -> received {received} B, {self.describe(got)}")
            if complete:
                largest = size
                continue
            first_failure = (size, received, got)
            break
        if largest is not None:
            self.measure("largest response the egress delivered", largest, "B")
        if first_failure is not None:
            size, received, got = first_failure
            self.measure("first response size the egress failed to deliver", size, "B")
            self.measure("of which the application received", received, "B")
            self.note(f"a {size} B response through the egress did not arrive: the application got "
                      f"{received} B and then {self.describe(got)}; investigate the send-window "
                      f"regression rather than treating this as an acceptable performance ceiling.")
        else:
            self.note(f"every probed response up to {self.args.ceiling_sizes[-1]} B arrived, which is "
                      f"more than this lab could deliver when it was written")

    def concurrent_downloads(self):
        count, size = self.args.concurrent_flows, self.args.concurrent_bytes
        if count == 0:
            return
        mark = self.target_mark()
        started = time.monotonic()
        # Each curl owns a distinct output file. Only the main thread records checks/metrics.
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            futures = [pool.submit(self.curl, f"{TARGET_URL}/blob/{size}", timeout=90)
                       for _ in range(count)]
            results = [future.result() for future in futures]
        elapsed = time.monotonic() - started
        passed = 0
        expected = blob_sha256(size)
        for got in results:
            complete = got["code"] == CURL_OK and got["body"].exists() and got["body"].stat().st_size == size
            if complete:
                with open(got["body"], "rb") as handle:
                    complete = hashlib.file_digest(handle, "sha256").hexdigest() == expected
            passed += int(complete)
            got["body"].unlink(missing_ok=True)
        self.check(f"{count} concurrent downloads of {self.human(size)} arrive intact",
                   passed == count, f"{passed}/{count} SHA-256 matched in {elapsed:.2f}s")
        if passed == count:
            self.measure("concurrent downstream aggregate", round(count * size / elapsed / 1048576, 2), "MiB/s")
        self.leak_check("concurrent downloads: no local leak", mark)

    def transfer(self, name, url, size, timeout, record_only=False):
        got = self.curl(f"{url}/blob/{size}", timeout=timeout)
        ok = got["code"] == CURL_OK and got["body"].stat().st_size == size
        if ok:
            hasher = hashlib.sha256()
            with open(got["body"], "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    hasher.update(chunk)
            ok = hasher.hexdigest() == blob_sha256(size)
        label = self.human(size)
        if got.get("total"):
            self.measure(f"{name}, {label}", round(size / got["total"] / 1048576, 2), "MiB/s")
            self.measure(f"{name}, {label}, wall", round(got["total"], 2), "s")
        if not record_only:
            self.check(f"{name}: {label} arrives intact across segment boundaries", ok,
                       f"sha256 {'matches' if ok else 'differs or the transfer failed'}; {self.describe(got)}")
        got["body"].unlink(missing_ok=True)
        return ok

    def upload(self, name, url, size, timeout):
        payload = self.work / "upload.bin"
        with open(payload, "wb") as handle:
            for chunk in blob_chunks(size):
                handle.write(chunk)
        got = self.curl(f"{url}/upload", "-X", "POST", "-H", "Content-Type: application/octet-stream",
                        "--data-binary", f"@{payload}", timeout=timeout)
        ok = False
        detail = self.describe(got)
        if got["code"] == CURL_OK:
            try:
                answer = json.loads(got["body"].read_text())
                ok = answer.get("sha256") == blob_sha256(size) and answer.get("bytes") == size
                detail += f"; target saw src={answer.get('src')} bytes={answer.get('bytes')}"
            except (json.JSONDecodeError, OSError):
                pass
        label = self.human(size)
        if got.get("total"):
            self.measure(f"{name}, {label}", round(size / got["total"] / 1048576, 2), "MiB/s")
        self.check(f"{name}: {label} arrives intact", ok, detail)
        got["body"].unlink(missing_ok=True)
        payload.unlink(missing_ok=True)

    @contextlib.contextmanager
    def lossy_link(self, percent):
        """Drops `percent`% each way on the egress's link for the length of the block. Yields whether
        netem went on both sides; when it did not, nothing is left installed."""
        router_side = ["tc", "qdisc", "add", "dev", "r-egr", "root", "netem", "loss", f"{percent}%"]
        egress_side = ns("egr", "tc", "qdisc", "add", "dev", "egr0", "root", "netem", "loss", f"{percent}%")
        if shutil.which("tc") is None or self.sh(router_side, check=False).returncode != 0:
            yield False
            return
        if self.sh(egress_side, check=False).returncode != 0:
            self.sh(["tc", "qdisc", "del", "dev", "r-egr", "root"], check=False)
            yield False
            return
        try:
            yield True
        finally:
            self.sh(["tc", "qdisc", "del", "dev", "r-egr", "root"], check=False)
            self.sh(ns("egr", "tc", "qdisc", "del", "dev", "egr0", "root"), check=False)

    def lossy(self):
        percent = self.args.loss_percent
        with self.lossy_link(percent) as available:
            self.netem = available
            if not available:
                self.note("netem is not available on the router or inside the egress namespace; "
                          "the lossy-link measurement was skipped")
                return
            # Loss recovery is a correctness gate, not only a throughput measurement (#74).
            size = self.args.lossy_blob_bytes
            label = self.human(size)
            got = self.curl(f"{TARGET_URL}/blob/{size}", timeout=self.args.lossy_timeout)
            received = got["body"].stat().st_size if got["body"].exists() else 0
            complete = got["code"] == CURL_OK and received == size
            if complete:
                with open(got["body"], "rb") as handle:
                    complete = hashlib.file_digest(handle, "sha256").hexdigest() == blob_sha256(size)
            self.check(f"download with {percent}% loss each way: {label} arrives intact",
                       complete, self.describe(got))
            if complete and got.get("total"):
                self.measure(f"download via egress with {percent}% loss each way, {label}",
                             round(size / got["total"] / 1048576, 3), "MiB/s")
                self.measure(f"download via egress with {percent}% loss each way, {label}, wall",
                             round(got["total"], 1), "s")
            else:
                self.measure(f"download via egress with {percent}% loss each way, {label}, delivered",
                             received, "B")
                self.note(f"with {percent}% loss each way a {label} response did not arrive: the "
                          f"application got {received} B in {self.args.lossy_timeout}s and then "
                          f"{self.describe(got)}; the loss-recovery correctness gate failed.")
            got["body"].unlink(missing_ok=True)

    # -- performance gate (#50) -------------------------------------------------------------------

    def verified_download(self, size, timeout):
        got = self.curl(f"{TARGET_URL}/blob/{size}", timeout=timeout)
        ok = got["code"] == CURL_OK and got["body"].exists() and got["body"].stat().st_size == size
        if ok:
            with open(got["body"], "rb") as handle:
                ok = hashlib.file_digest(handle, "sha256").hexdigest() == blob_sha256(size)
        got["body"].unlink(missing_ok=True)
        return ok, got

    STALL_SECONDS = 15

    def watched_download(self, size, timeout, label):
        """verified_download, and if it is still running after STALL_SECONDS, a record of where it
        waits taken while it waits: both ends' TCP state and what the consumer says about its egress.

        A lossy download once stopped 688 bytes short of the end and waited out curl's timeout, and
        nothing afterwards could say which side still held those bytes."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.verified_download, size, timeout)
            try:
                return pending.result(timeout=self.STALL_SECONDS)
            except concurrent.futures.TimeoutError:
                pass
            lines = [f"{label} still running after {self.STALL_SECONDS} s:"]
            for name in ("con", "egr", "tgt"):
                sockets = self.sh(ns(name, "ss", "-tin"), check=False, quiet=True).stdout.strip()
                lines.append(f"[{name}] ss -tin\n{sockets or '(nothing)'}")
            status = self.client_status("consumer")
            consumer = [((instance.get("egress") or {}).get("consumer") or {})
                        for instance in (status or {}).get("data", {}).get("instances", [])]
            lines.append("consumer egress status: " + json.dumps(
                [{key: section.get(key) for key in ("flows", "blocked", "peers")} for section in consumer]))
            self.snapshots[f"{label}, stalled"] = "\n".join(lines)
            self.note(f"{label} was still running after {self.STALL_SECONDS} s; the snapshot '{label}, stalled' "
                      "records both ends while it waited")
            return pending.result()

    def verified_upload(self, size, timeout):
        payload = self.work / f"upload-{size}.bin"
        if not payload.exists():
            with open(payload, "wb") as handle:
                for chunk in blob_chunks(size):
                    handle.write(chunk)
        got = self.curl(f"{TARGET_URL}/upload", "-X", "POST", "-H", "Content-Type: application/octet-stream",
                        "--data-binary", f"@{payload}", timeout=timeout)
        ok = False
        if got["code"] == CURL_OK:
            try:
                answer = json.loads(got["body"].read_text())
                ok = answer.get("sha256") == blob_sha256(size) and answer.get("bytes") == size
            except (json.JSONDecodeError, OSError):
                pass
        got["body"].unlink(missing_ok=True)
        return ok, got

    def gate_median(self, name, rates, intact, floor):
        title = f"performance gate: {name} >= {floor:g} MiB/s, median of {GATE_REPEATS}"
        if not intact or len(rates) < GATE_REPEATS:
            self.check(title, False, f"{len(rates)}/{GATE_REPEATS} runs arrived intact")
            return
        median = statistics.median(rates)
        self.measure(f"gate: {name}, median of {GATE_REPEATS}", round(median, 2), "MiB/s")
        self.check(title, median >= floor, "runs " + ", ".join(f"{rate:.2f}" for rate in rates) + " MiB/s")

    TCP_COUNTERS = ("TcpExtTCPSynRetrans", "TcpRetransSegs", "TcpExtListenDrops", "TcpExtListenOverflows",
                    "TcpAttemptFails", "TcpOutRsts", "TcpExtPAWSActive", "TcpExtTCPChallengeACK")

    def tcp_counters(self):
        """The counters that tell where a new flow waited, in the consumer, egress and target namespaces.
        None when nstat is missing, so the gate still runs without the diagnosis."""
        if shutil.which("nstat") is None:
            return None
        values = {}
        for name in ("con", "egr", "tgt"):
            for line in self.sh(ns(name, "nstat", "-az"), check=False, quiet=True).stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] in self.TCP_COUNTERS:
                    values[f"{name}.{parts[0]}"] = int(parts[1])
        return values

    def performance_gate(self):
        """Issue #50's thresholds, agreed before any of these numbers were taken; each is a check."""
        samples, slow = [], []
        for _ in range(GATE_FIRST_BYTE_SAMPLES):
            # A new flow that takes a second waited out one SYN retransmission somewhere. Which kernel
            # retransmitted says where: the consumer's (its SYN or the SYN-ACK was lost in the tunnel or
            # the egress answered late), the egress's (its connect to the target waited) or the target's
            # listen queue. Taken around every sample because a slow one is only known afterwards.
            before = self.tcp_counters()
            got = self.whoami(TARGET_URL)
            if got["code"] == CURL_OK and got["src"] == EGRESS_IP:
                samples.append(got["firstByte"] * 1000)
            if got.get("firstByte", 0) * 1000 > GATE_FIRST_BYTE_P95_MS and before is not None:
                after = self.tcp_counters() or {}
                moved = {key: after[key] - before.get(key, 0) for key in after if after[key] != before.get(key, 0)}
                slow.append(f"{got['firstByte'] * 1000:.0f} ms (connect {got.get('connect', 0) * 1000:.0f} ms) "
                            + (", ".join(f"{key}+{delta}" for key, delta in sorted(moved.items())) or "no counter moved"))
        title = f"performance gate: first byte of a new flow, p95 <= {GATE_FIRST_BYTE_P95_MS:g} ms"
        if len(samples) < GATE_FIRST_BYTE_SAMPLES:
            self.check(title, False, f"only {len(samples)}/{GATE_FIRST_BYTE_SAMPLES} new flows went through the egress")
        else:
            value = p95(samples)
            self.measure(f"gate: first byte of a new flow via egress, p95 of {len(samples)}", round(value, 1), "ms")
            self.check(title, value <= GATE_FIRST_BYTE_P95_MS, f"p95 {value:.1f} ms over {len(samples)} flows")
        if slow:
            self.note("slow new flows in the first-byte gate: " + "; ".join(slow))

        size = GATE_SINGLE_FLOW_BYTES
        for name, transfer in (("single-flow download of 8 MiB", self.verified_download),
                               ("single-flow upload of 8 MiB", self.verified_upload)):
            rates, intact = [], True
            for _ in range(GATE_REPEATS):
                ok, got = transfer(size, 120)
                intact = intact and ok
                if ok and got.get("total"):
                    rates.append(size / got["total"] / 1048576)
            self.gate_median(name, rates, intact, GATE_SINGLE_FLOW_MIBPS)

        self.gate_concurrency()

        with self.lossy_link(GATE_LOSS_PERCENT) as available:
            title = (f"performance gate: {self.human(GATE_LOSSY_BYTES)} with {GATE_LOSS_PERCENT:g}% loss each way "
                     f"within {GATE_LOSSY_SECONDS:g} s, median of {GATE_REPEATS}")
            if not available:
                self.check(title, False, "netem is not available, so the gate could not be measured")
                return
            walls, intact = [], True
            for attempt in range(GATE_REPEATS):
                ok, got = self.watched_download(GATE_LOSSY_BYTES, 60, f"lossy gate run {attempt + 1}")
                intact = intact and ok
                if ok and got.get("total"):
                    walls.append(got["total"])
            if not intact or len(walls) < GATE_REPEATS:
                self.check(title, False, f"{len(walls)}/{GATE_REPEATS} runs arrived intact")
                return
            median = statistics.median(walls)
            self.measure(f"gate: {self.human(GATE_LOSSY_BYTES)} with {GATE_LOSS_PERCENT:g}% loss each way, "
                         f"median of {GATE_REPEATS}", round(median, 2), "s")
            self.check(title, median <= GATE_LOSSY_SECONDS, "runs " + ", ".join(f"{wall:.2f}" for wall in walls) + " s")

    def gate_concurrency(self):
        """A full set of concurrent flows, gated on integrity, aggregate rate and how much memory the
        consumer and the egress took on to carry it."""
        flows, size = GATE_CONCURRENT_FLOWS, GATE_CONCURRENT_BYTES
        roles = ("consumer", "egress")
        baseline = {role: rss_kib(self.procs[role].popen.pid) for role in roles}
        peak = dict(baseline)
        done = threading.Event()

        def sample():
            while not done.is_set():
                for role in roles:
                    value = rss_kib(self.procs[role].popen.pid)
                    if value is not None and (peak[role] is None or value > peak[role]):
                        peak[role] = value
                done.wait(0.1)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        mark = self.target_mark()
        started = time.monotonic()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=flows) as pool:
                results = list(pool.map(lambda _: self.verified_download(size, 90), range(flows)))
        finally:
            elapsed = time.monotonic() - started
            done.set()
            sampler.join()
        intact = sum(1 for ok, _ in results if ok)
        aggregate = flows * size / elapsed / 1048576
        self.measure(f"gate: {flows} concurrent flows of {self.human(size)}, aggregate", round(aggregate, 2), "MiB/s")
        self.check(f"performance gate: {flows} concurrent flows of {self.human(size)} all intact, "
                   f"aggregate >= {GATE_CONCURRENT_MIBPS:g} MiB/s",
                   intact == flows and aggregate >= GATE_CONCURRENT_MIBPS,
                   f"{intact}/{flows} intact, {aggregate:.2f} MiB/s in {elapsed:.2f} s")
        for role in roles:
            title = f"performance gate: {role} memory growth under {flows} flows <= {GATE_MEMORY_GROWTH_MIB:g} MiB"
            if baseline[role] is None or peak[role] is None:
                self.check(title, False, f"could not read the {role}'s resident set")
                continue
            growth = (peak[role] - baseline[role]) / 1024
            self.measure(f"gate: {role} resident set growth under {flows} flows", round(growth, 1), "MiB")
            self.check(title, growth <= GATE_MEMORY_GROWTH_MIB,
                       f"resident set {baseline[role] / 1024:.0f} MiB before, peak {peak[role] / 1024:.0f} MiB")
        self.leak_check("performance gate: no local leak under concurrency", mark)

        # The same set again at once. The flows just finished linger in TIME_WAIT for ten seconds,
        # and while they counted against maxFlowsPerConsumer (#88) the second set was refused until
        # they expired: every flow completed, eleven seconds late.
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=flows) as pool:
            results = list(pool.map(lambda _: self.verified_download(size, 90), range(flows)))
        elapsed = time.monotonic() - started
        intact = sum(1 for ok, _ in results if ok)
        aggregate = flows * size / elapsed / 1048576
        self.measure(f"gate: {flows} concurrent flows again at once, aggregate", round(aggregate, 2), "MiB/s")
        self.check(f"performance gate: {flows} concurrent flows again at once, all intact, "
                   f"aggregate >= {GATE_CONCURRENT_MIBPS:g} MiB/s (finished flows do not hold the limit)",
                   intact == flows and aggregate >= GATE_CONCURRENT_MIBPS,
                   f"{intact}/{flows} intact, {aggregate:.2f} MiB/s in {elapsed:.2f} s")

    # -- fault injection --------------------------------------------------------------------------

    def fault_acl_revoked(self):
        mark = self.target_mark()
        consumer = self.procs["consumer"]
        offset = consumer.log_offset()
        self.policy([])
        time.sleep(1)
        got, _ = self.wait_for("a refused connection",
                               lambda: (lambda r: r if r["code"] != CURL_OK else None)(self.whoami(TARGET_URL)), 20, 1.0)
        self.check("ACL revoked: a new flow under the rule fails", bool(got),
                   self.describe(got) if got else "requests kept succeeding")
        # The server pushes a catalogue without the egress as soon as the policy changes, so the
        # consumer normally blocks the flow itself as not offered and the egress never sees it. A flow
        # that beat the catalogue is refused by the egress instead. Either way the consumer knows why.
        reject = consumer.wait_log(r"refused flow code=(EGRESS_[A-Z_]+)", 3, offset)
        section, _ = self.wait_for("the consumer to see the egress as not offered",
                                   lambda: (lambda c: c if self.standing_of(c, self.egress_id) == "not-offered" else None)(
                                       self.consumer_section()), 10, 1.0)
        blocked = ((section or {}).get("blocked") or {}).get("egress-not-offered", 0)
        self.check("ACL revoked: the consumer is told, by the egress or by the catalogue",
                   bool(reject) or blocked >= 1,
                   f"consumer log: {reject.group(0)}" if reject
                   else json.dumps({"blocked": (section or {}).get("blocked"), "peers": (section or {}).get("peers")}))
        self.check("ACL revoked: the catalogue no longer offers the egress to the consumer", bool(section),
                   json.dumps((section or {}).get("peers")) if section else "standing never became not-offered")
        self.leak_check("ACL revoked: nothing leaked to the target from the consumer's address", mark)
        self.policy([self.consumer_id])
        got, _ = self.wait_for("recovery after restoring the ACL", self.through_egress, 30, 1.0)
        self.check("ACL restored: flows go through the egress again", bool(got))

    def fault_switch_off(self):
        mark = self.target_mark()
        egress = self.procs["egress"]
        offset = egress.log_offset()
        slow_out = self.work / "slow.out"
        slow_out.unlink(missing_ok=True)
        # --no-buffer, because the check below watches the file grow and curl's own buffering would
        # hold a trickle of a few bytes per tick until the transfer ended, which is the thing being
        # measured. The whole stream stays well under the size the egress can deliver.
        slow = subprocess.Popen(ns("con", "curl", "-sS", "--no-buffer", "--max-time", "90",
                                   "-o", str(slow_out), f"{TARGET_URL}/slow?seconds=40&interval=0.2"),
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        started, _ = self.wait_for("the slow download to start",
                                   lambda: slow_out.exists() and slow_out.stat().st_size > 0, 15)
        if not started:
            slow.kill()
            self.check("switch off: an established flow is cut instead of running to its end", False,
                       "the slow download never started")
            return
        cut_at = time.time()
        self.switch(False)
        try:
            _, stderr = slow.communicate(timeout=35)
            elapsed = time.time() - cut_at
            cut = slow.returncode != CURL_OK and elapsed < 30
            self.check("switch off: an established flow is cut instead of running to its end", cut,
                       f"curl exit {slow.returncode} after {elapsed:.1f}s of a 40s stream ({stderr.strip()[:100]})")
            self.measure("established flow cut after the switch went off", round(elapsed, 1), "s")
        except subprocess.TimeoutExpired:
            slow.kill()
            self.check("switch off: an established flow is cut instead of running to its end", False,
                       "the stream was still running 35s after the switch went off")
        applied = egress.wait_log(r"policy applied enabled=false", 15, offset)
        self.check("switch off: the egress applied the disabled policy", bool(applied))
        released = egress.wait_log(r"flows released count=([1-9][0-9]*) active=0", 5, offset)
        self.check("switch off: the egress released its established flows", bool(released),
                   released.group(0) if released else "no completed drain logged")
        got = self.whoami(TARGET_URL)
        self.check("switch off: a new flow under the rule fails", got["code"] != CURL_OK, self.describe(got))
        self.leak_check("switch off: nothing leaked to the target from the consumer's address", mark)
        offset = egress.log_offset()
        self.switch(True)
        egress.wait_log(r"policy applied enabled=true", 15, offset)
        got, _ = self.wait_for("recovery after the switch came back", self.through_egress, 30, 1.0)
        self.check("switch on: flows go through the egress again", bool(got))

    def fault_egress_stopped(self):
        mark = self.target_mark()
        egress = self.procs["egress"]
        egress.stop()
        stopped_at = time.time()
        outcomes = []

        def probe():
            got = self.whoami(TARGET_URL)
            outcomes.append((round(time.time() - stopped_at, 1), got["code"], got.get("src")))
            if got["code"] == CURL_OK:
                # A request that succeeds with the egress gone went somewhere it should not have.
                # The table at this instant is the evidence for where, so take it before anything
                # can reconcile it away.
                self.snapshots[f"while a probe succeeded {outcomes[-1][0]}s after the egress stopped"] = \
                    self.consumer_table()
            return got if got["code"] == CURL_CONNECT_FAILED else None

        fast, elapsed = self.wait_for("a fast failure once the consumer sees the egress offline", probe, 90, 1.0)
        succeeded = [o for o in outcomes if o[1] == CURL_OK]
        self.check("egress stopped: no flow under the rule succeeds", not succeeded,
                   f"{len(outcomes)} probes: " + ", ".join(f"{t}s exit {c}" for t, c, _ in outcomes[:12]))
        self.check("egress stopped: the consumer fails new flows fast once it sees the egress offline", bool(fast),
                   f"connection refused {elapsed:.1f}s after the egress process exited" if fast
                   else "only timeouts within 90s")
        if fast:
            self.measure("egress process gone to refused-at-once", round(elapsed, 1), "s")
        self.leak_check("egress stopped: nothing leaked to the target from the consumer's address", mark)
        if not fast:
            status = self.client_status("consumer")
            if status:
                self.snapshots["consumer status after offline refusal timed out"] = json.dumps(
                    status.get("data", status), indent=2)

        restarted_at = time.time()
        egress = self.start_client("egress", self.work / "egress.jsonc")
        if not egress.wait_log(r"policy applied enabled=true", 30):
            self.note("the restarted egress did not receive the policy on login; the lab re-sent it")
            self.policy([self.consumer_id])
            egress.wait_log(r"policy applied enabled=true", 30)
        got, _ = self.wait_for("recovery after the egress restart", self.through_egress, 90, 1.0)
        self.check("egress restarted: flows go through the egress again", bool(got))
        if got:
            self.measure("egress restart to first flow through it again", round(time.time() - restarted_at, 1), "s")

    def fault_server_restart(self):
        """The control connection going away must not hand the claimed destinations back to the
        machine's own default route.

        Restarting the server drops every client's control connection at a moment this can watch,
        instead of waiting for a blip. While it is down the consumer cannot signal, but the routes
        it installed are still the truth about where that traffic goes: into the tunnel, to be
        carried or refused. Out of the physical interface is the one answer that is never right.
        """
        mark = self.target_mark()
        consumer = self.procs["consumer"]
        offset = consumer.log_offset()
        self.procs["server"].stop()
        dropped = consumer.wait_log(r"control connection closed|Control channel session ended|control连接断开", 30, offset)
        self.check("server gone: the consumer notices its control connection is gone", bool(dropped),
                   dropped.group(0) if dropped else "the consumer never logged a lost connection")

        table = self.consumer_table()
        self.snapshots["while the control connection was down"] = table
        held = f"{RULE_CIDR} dev {CONSUMER_TUN}" in table
        self.check("server gone: the rule's route stays installed while the connection is down",
                   held, "\n".join(self.lab_routes(table)) or "nothing is installed")

        outcomes = []
        for _ in range(4):
            got = self.whoami(TARGET_URL)
            outcomes.append((got["code"], got.get("src")))
        direct = [source for _, source in outcomes if source == CONSUMER_IP]
        self.check("server gone: no request under the rule leaves from the consumer's own address",
                   not direct, f"{len(direct)} of {len(outcomes)} probes came from the consumer itself")
        self.leak_check("server gone: nothing leaked to the target from the consumer's address", mark)

        offset = consumer.log_offset()
        if not self.launch_server(self.work / "server.json"):
            raise LabAbort("the server did not come back:\n" + self.procs["server"].log_since()[-3000:])
        back = consumer.wait_log(r"control connection established|Connected to .*\(awaiting login response\)", 90, offset)
        self.check("server back: the consumer reconnects", bool(back))
        self.check("server back: flows go through the egress again", bool(self.wait_ready()))
        # The restarted server numbers its pushes from 1 again. An egress that kept the last session's
        # revision ignored each of them as older and went on enforcing the policy from before.
        applied = self.set_policy([self.consumer_id])
        self.check("server back: the egress applies a policy change the restarted server pushes", applied,
                   "the egress logged it" if applied else "no 'policy applied' in the egress's log within 15 s")
        # Whatever the reconnect did to the table, what it ends with is what matters.
        table = self.consumer_table()
        self.snapshots["after the control connection came back"] = table
        self.check("server back: the rule's route and the bypass are both in place",
                   f"{RULE_CIDR} dev {CONSUMER_TUN}" in table
                   and any(line.startswith(f"{SERVER_IP} via {CONSUMER_GW}") for line in table.splitlines()),
                   "\n".join(self.lab_routes(table)))

    def fault_rule_block(self):
        consumer = self.procs["consumer"]
        consumer.stop()
        table = self.consumer_table()
        self.snapshots["after normal exit"] = table
        leftover = self.lab_routes(table)
        self.check("normal exit: no route of the feature is left behind", not leftover, "\n".join(leftover))
        mark = self.target_mark()
        self.start_client("consumer", self.client_config("consumer", [{"match": RULE_CIDR, "action": "block"}]))
        route, _ = self.wait_for("the block route", self.rule_route_present, 60)
        got = self.curl(f"{TARGET_URL}/whoami", timeout=4)
        got["body"].unlink(missing_ok=True)
        self.check("rule changed to block: a flow under the rule is dropped, not sent anywhere",
                   bool(route) and got["code"] == CURL_TIMEOUT, self.describe(got))
        self.leak_check("rule changed to block: nothing leaked to the target from the consumer's address", mark)
        self.note("rule changes take a consumer restart: the client has no configuration reload. The in-process "
                  "purge and reset of flows a rule change invalidates is covered by the Go, Java and .NET unit "
                  "tests against the shared failure vector, not by this lab.")
        self.procs["consumer"].stop()
        rules = [{"match": RULE_CIDR, "action": "egress", "egressClientId": self.egress_id}]
        self.start_client("consumer", self.client_config("consumer", rules))
        self.check("rule restored: flows go through the egress again", self.wait_ready())

    def fault_kill_9(self):
        self.sh(ns("con", "ip", "route", "add", USER_ROUTE, "via", CONSUMER_GW, "dev", "con0"))
        consumer = self.procs["consumer"]
        consumer.kill()
        time.sleep(1)
        table = self.consumer_table()
        self.snapshots["after kill -9"] = table
        bypass_left = any(line.startswith(SERVER_IP + " ") for line in table.splitlines())
        tunnel_left = any(f"dev {CONSUMER_TUN}" in line for line in table.splitlines())
        self.check("kill -9: the bypass /32 on the physical interface outlives the process, "
                   "the tunnel routes die with the device",
                   bypass_left and not tunnel_left, "\n".join(self.lab_routes(table)) or "nothing left")
        consumer = self.start_client("consumer", self.work / "consumer.jsonc")
        taken = consumer.wait_log(r"took back (\d+) routes? left by a previous run", 60)
        self.check("restart after kill -9: the journal's leftovers are taken back before reinstalling",
                   bool(taken), taken.group(0) if taken else "no take-back logged")
        ready = self.wait_ready()
        table = self.consumer_table()
        self.snapshots["after restart"] = table
        user_present = any(line.startswith(USER_ROUTE + " ") for line in table.splitlines())
        self.check("restart after kill -9: flows go through the egress again", ready)
        self.check("restart after kill -9: the user's own route is untouched", user_present,
                   f"{USER_ROUTE} via {CONSUMER_GW} still in the table" if user_present else f"{USER_ROUTE} is gone")
        self.procs["consumer"].stop()
        table = self.consumer_table()
        self.snapshots["after normal exit, final"] = table
        leftover = self.lab_routes(table)
        user_present = any(line.startswith(USER_ROUTE + " ") for line in table.splitlines())
        self.check("final normal exit: the feature's routes are gone and the user's route stays",
                   not leftover and user_present, "\n".join(leftover) if leftover else "clean")
        self.sh(ns("con", "ip", "route", "del", USER_ROUTE), check=False)

    # -- refusals at the egress (#42) -------------------------------------------------------------

    def refusals(self):
        """Issue #42's last acceptance item, end to end: an unauthorized device, a restricted target
        and resource exhaustion are refused by the egress. A request failing proves nothing about
        where it was stopped, so every check takes the egress's own refusal count under the expected
        code as the evidence, and reads the target's log for anything that got through. A refused
        connect must also end as one, curl's exit 7, not as a timeout: the egress answers the SYN with
        a reset, and an application left to retransmit into the refusal until its own timeout is the
        failure the explicit-failure rule exists to prevent. DNS rebinding needs the DNS takeover and
        is checked in phase two; the README says why cross-tenant access is left to the servers' unit
        tests."""
        self.say("refusals at the egress")
        consumer = self.procs.get("consumer")
        if consumer is not None and consumer.alive:
            consumer.stop()
        # A second rule sends the metadata address to the egress. A consumer rule names a destination
        # and nothing more, so nothing on the consumer's side refuses it: only the egress can.
        rules = [{"match": RULE_CIDR, "action": "egress", "egressClientId": self.egress_id},
                 {"match": f"{METADATA_IP}/32", "action": "egress", "egressClientId": self.egress_id}]
        self.start_client("consumer", self.client_config("consumer", rules))
        ready = self.wait_ready()
        routed, _ = self.wait_for("the metadata rule's route", self.metadata_route_present, 30)
        self.check("refusals: the consumer routes the metadata address into the tunnel and serves through the egress",
                   ready and bool(routed), "\n".join(self.lab_routes(self.consumer_table())))
        if not ready:
            return
        self.refusal_forbidden_destination()
        self.refusal_concurrency_cap()
        self.refusal_rate_limit()
        self.refusal_consumer_denied()

    def metadata_route_present(self):
        return any(line.split()[0] in (METADATA_IP, f"{METADATA_IP}/32") and f"dev {CONSUMER_TUN}" in line
                   for line in self.consumer_table().splitlines() if line.strip())

    def refusal_forbidden_destination(self):
        """A target on the forced-deny list, under a policy that grants 0.0.0.0/0 as well."""
        got = self.whoami(f"http://{METADATA_IP}", netns_name="egr")
        self.check("restricted target: the egress's own network reaches the metadata address, so only its decision "
                   "stands in the way", got["src"] == EGRESS_IP, f"target saw src={got['src']} ({self.describe(got)})")
        # Two destination rules, so that the applied push is told from the one before it by its count.
        applied = self.set_policy([self.consumer_id], destinations=(RULE_GRANT, BROAD_GRANT))
        before = self.refusal_baseline()
        mark = self.target_mark()
        offset = self.procs["consumer"].log_offset()
        got = self.whoami(f"http://{METADATA_IP}")
        counts = self.refused_at_egress(CODE_FORBIDDEN, before)
        self.check(f"restricted target: {METADATA_IP} under a 0.0.0.0/0 grant is refused by the egress ({CODE_FORBIDDEN})",
                   applied and got["code"] == CURL_CONNECT_FAILED and counts is not None,
                   f"0.0.0.0/0 {'applied' if applied else 'not confirmed applied'}; {self.describe(got)}; "
                   f"{self.refusal_evidence(CODE_FORBIDDEN, before, counts)}; {self.consumer_view(CODE_FORBIDDEN, offset)}")
        self.nothing_reached("restricted target: nothing reached the metadata address", mark, METADATA_IP)
        self.set_policy([self.consumer_id])

    def refusal_concurrency_cap(self):
        """maxFlowsPerConsumer: that many connections held open through the egress, then the next
        one refused by it, and a slot back once the held ones are gone."""
        applied = self.set_policy([self.consumer_id], per_consumer=CONCURRENCY_CAP)
        # Live flows count against the cap and lingering ones do not (#88). Whatever the checks before
        # left open is given a moment to finish, so that the number held is the cap and nothing else.
        idle, _ = self.wait_for("the egress to carry no live flow",
                                lambda: (self.egress_section() or {}).get("flows") == 0, 15, 1.0)
        before = self.refusal_baseline()
        mark = self.target_mark()
        offset = self.procs["consumer"].log_offset()
        held = self.sh(ns("con", sys.executable, "-c", HOLD_SCRIPT, TARGET_IP, "80", str(CONCURRENCY_CAP + 2)),
                       check=False, timeout=90)
        try:
            result = json.loads(held.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            result = {}
        counts = self.refused_at_egress(CODE_LIMIT, before)
        self.check(f"resource exhaustion: with maxFlowsPerConsumer {CONCURRENCY_CAP}, {CONCURRENCY_CAP} flows are held "
                   f"and the next is refused by the egress ({CODE_LIMIT})",
                   applied and result.get("held") == CONCURRENCY_CAP and result.get("next") == "refused"
                   and counts is not None,
                   (f"held {result.get('held')}, the next one {result.get('next')}" if result
                    else f"the probe printed nothing usable: {(held.stdout + held.stderr).strip()[-300:]}")
                   + f"; the egress {'had no live flow' if idle else 'still carried flows'} before; "
                   f"{self.refusal_evidence(CODE_LIMIT, before, counts)}; {self.consumer_view(CODE_LIMIT, offset)}")
        # The probe reset what it held as it exited, which is what frees the slots.
        got, elapsed = self.wait_for("a new flow under the same cap", self.through_egress, 15, 1.0)
        self.check("resource exhaustion: the held flows' slots come back, a new flow goes through under the same cap",
                   bool(got), f"after {elapsed:.1f}s" if got else "no flow went through within 15 s")
        self.leak_check("resource exhaustion, flow cap: nothing leaked to the target from the consumer's address", mark)
        self.set_policy([self.consumer_id])

    def batch_through_egress(self, count):
        """count new flows at once; how many, if every one of them left from the egress."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            sources = [got["src"] for got in pool.map(lambda _: self.whoami(TARGET_URL), range(count))]
        through = sum(1 for source in sources if source == EGRESS_IP)
        return through if through == count else None

    def refusal_rate_limit(self):
        """The new-flow bucket: RATE_BURST_FLOWS new datagram flows at once while one established TCP
        flow runs through it, with both flow caps raised out of reach so that the bucket is the only
        limit the burst can meet.

        A burst of TCP connects could not show it: an admitted connect waits for the egress to dial
        the target, so a slow dial paces the burst to the refill rate, and a refused one was not told
        (fixed alongside this, see TestConsumerKeepsAnOpeningFlowTheEgressRejectedForItsReset) and
        retried until it got in. A datagram flow is admitted without a handshake, so the burst meets
        the bucket as fast as the egress can read it."""
        roomy = 4 * RATE_BURST_FLOWS
        applied = self.set_policy([self.consumer_id], max_flows=roomy, per_consumer=roomy,
                                  idle_seconds=RATE_IDLE_SECONDS)
        mark = self.target_mark()
        seconds, interval = 15, 0.25
        expected = max(1, int(seconds / interval)) * len(SLOW_TICK)
        stream = self.work / "slow-through-burst.out"
        stream.unlink(missing_ok=True)
        slow = subprocess.Popen(ns("con", "curl", "-sS", "--no-buffer", "--max-time", str(seconds + 45), "-o",
                                   str(stream), f"{TARGET_URL}/slow?seconds={seconds}&interval={interval}"),
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        streaming, _ = self.wait_for("the established stream to start",
                                     lambda: stream.exists() and stream.stat().st_size > 0, 15)
        # The pause also refills what the stream and the checks before took from the bucket, and lets
        # the status catch up with the policy push (see refusal_baseline).
        time.sleep(2.5)
        before, admitted_before = self.egress_counts()
        before = before or {}
        offset = self.procs["consumer"].log_offset()
        burst = self.sh(ns("con", sys.executable, "-c", BURST_SCRIPT, TARGET_IP, str(UDP_PORT),
                           str(RATE_BURST_FLOWS), "1"), check=False, timeout=90)
        ended = time.monotonic()
        try:
            result = json.loads(burst.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            result = {}
        # Once the egress has counted a refusal, a moment more for its status to take in the rest.
        self.refused_at_egress(CODE_LIMIT, before, timeout=10)
        time.sleep(1.2)
        after, admitted_after = self.egress_counts()
        refused = after.get(CODE_LIMIT, 0) - before.get(CODE_LIMIT, 0) if after is not None else None
        admitted = (admitted_after - admitted_before
                    if admitted_before is not None and admitted_after is not None else None)
        # The egress admitted flows for about as long as answers kept coming, and the bucket refilled
        # for that long; of what reached it, everything beyond that it must have refused. Judged on
        # what reached the egress rather than on what was sent, so a datagram lost on the way does
        # not count against it.
        window = max(float(result.get("sendSeconds") or 0.0), float(result.get("lastAnswer") or 0.0))
        allowed = RATE_BUCKET + RATE_REFILL_PER_SECOND * window
        answered = int(result.get("answered") or 0)
        judged = refused is not None and admitted is not None
        reached = refused + admitted if judged else None
        floor = max(1, math.ceil(reached - allowed - RATE_SLACK)) if judged else None
        self.check(f"resource exhaustion: a burst of {RATE_BURST_FLOWS} new flows meets the egress's new-flow bucket, "
                   f"which refuses what its {RATE_BUCKET} and {RATE_REFILL_PER_SECOND}/s do not cover ({CODE_LIMIT})",
                   applied and judged and refused >= floor and answered >= RATE_BUCKET // 2,
                   (f"{reached} of {RATE_BURST_FLOWS} reached the egress: {admitted} admitted, which the bucket allows "
                    f"{allowed:.0f} of in the {window:.2f}s until the last answer, and {refused} refused where at "
                    f"least {floor} must be; {answered} answered" if judged and result
                    else f"burst {json.dumps(result) if result else (burst.stdout + burst.stderr).strip()[-300:]}; "
                         f"egress refused/admitted before {before} {admitted_before}, after {after} {admitted_after}")
                   + f"; {self.consumer_view(CODE_LIMIT, offset)}")
        if judged:
            self.measure("new-flow burst: flows the egress admitted out of the burst", admitted)
            self.measure("new-flow burst: how long the egress took over it", round(window, 3), "s")
        # Two seconds refill the whole bucket, so a batch of new flows at once then has to find room.
        time.sleep(max(0.0, 2.0 - (time.monotonic() - ended)))
        batch, waited = self.wait_for("16 new flows at once through the egress",
                                      lambda: self.batch_through_egress(16), 10, 1.0)
        since = time.monotonic() - ended
        self.check("resource exhaustion: two seconds after the burst the bucket is full again, 16 new flows at once "
                   "go through the egress", bool(batch),
                   f"all 16 through the egress {since:.1f}s after the burst ended" if batch
                   else f"not every flow of a batch went through within {since:.0f} s of the burst")
        try:
            _, stderr = slow.communicate(timeout=seconds + 40)
            size = stream.stat().st_size if stream.exists() else 0
            self.check("resource exhaustion: a flow established before the burst runs to its end",
                       bool(streaming) and slow.returncode == CURL_OK and size == expected,
                       f"curl exit {slow.returncode}, {size}/{expected} B ({stderr.strip()[:100]})")
        except subprocess.TimeoutExpired:
            slow.kill()
            self.check("resource exhaustion: a flow established before the burst runs to its end", False,
                       f"the {seconds}s stream was still running {seconds + 40}s later")
        self.leak_check("resource exhaustion, new-flow burst: nothing leaked to the target from the consumer's address",
                        mark)
        # The admitted datagram flows end on the short idle timeout. Gone before the caps come back
        # down, they cannot hold slots against the checks that follow.
        self.wait_for("the burst's flows to go idle", lambda: (self.egress_section() or {}).get("flows") == 0,
                      10 + 2 * RATE_IDLE_SECONDS, 1.0)
        self.set_policy([self.consumer_id])

    def refusal_consumer_denied(self):
        """EGRESS_CONSUMER_DENIED, the egress's own allow-list check.

        The server takes a consumer off an egress in two messages: the egress-config to the egress and
        a catalogue without that egress to the consumer. Delivered together, the consumer blocks the
        flow itself as not-offered and the egress never sees it, which is the ACL-revoked fault. The
        egress checks its allow list again before every connect for the time in between, and on a real
        network that time is however long the consumer's control connection takes to deliver. This
        makes it long on purpose: a blackhole route in the server's namespace holds back everything the
        server sends the consumer, while the peer path, which never passes the server when it is
        direct, still carries the flow to the egress. The server itself is not changed."""
        section = self.consumer_section()
        path = next((peer.get("path") for peer in (section or {}).get("peers") or []
                     if peer.get("clientId") == self.egress_id), None)
        if path != "direct":
            self.note(f"unauthorized device: not checked, the consumer reaches its egress by path {path}; holding "
                      "back what the server sends would hold back the flow as well")
            return
        title = (f"unauthorized device: a consumer taken off the allow list, its catalogue not yet updated, is "
                 f"refused by the egress ({CODE_CONSUMER_DENIED})")
        consumer = self.procs["consumer"]
        mark = self.target_mark()
        blackhole = ["blackhole", f"{CONSUMER_IP}/32"]
        if self.sh(["ip", "-n", "srv", "route", "add", *blackhole], check=False).returncode != 0:
            self.check(title, False, "could not hold back the server's messages to the consumer")
            return
        try:
            applied = self.set_policy([])
            before = self.refusal_baseline()
            standing = self.standing_of(self.consumer_section(), self.egress_id)
            offset = consumer.log_offset()
            got = self.whoami(TARGET_URL)
        finally:
            self.sh(["ip", "-n", "srv", "route", "del", *blackhole], check=False)
        counts = self.refused_at_egress(CODE_CONSUMER_DENIED, before)
        # Offered or still unknown both mean the consumer sent the flow on; not-offered would mean it
        # blocked the flow itself and the egress was never asked.
        self.check(title, applied and standing in ("offered", "unknown") and got["code"] == CURL_CONNECT_FAILED
                   and counts is not None,
                   f"the consumer's catalogue still said {standing}; {self.describe(got)}; "
                   f"{self.refusal_evidence(CODE_CONSUMER_DENIED, before, counts)}; "
                   f"{self.consumer_view(CODE_CONSUMER_DENIED, offset)}")
        self.leak_check("unauthorized device: nothing leaked to the target from the consumer's address", mark)
        self.set_policy([self.consumer_id])
        got, elapsed = self.wait_for("flows through the egress once the server's messages arrive",
                                     self.through_egress, 60, 1.0)
        self.check("unauthorized device: allowed again, flows go through the egress once the held-back messages arrive",
                   bool(got), f"after {elapsed:.1f}s" if got else "no flow went through within 60 s")

    # -- phase two: domain rules through the DNS takeover (#52) -----------------------------------

    def private_etc(self):
        """Gives the consumer its own /etc/resolv.conf and the egress its own /etc/hosts.

        `ip netns exec NAME` bind-mounts every file in /etc/netns/NAME over its namesake in /etc. An
        overlay on /etc in this lab's own mount namespace makes room for those directories without
        writing to the host. /etc/resolv.conf is replaced by a plain file first: on most hosts it is a
        symlink into systemd-resolved, which the takeover refuses to rewrite (resolv-conf-managed), and
        the lab's /run tmpfs has hidden its target anyway. It is replaced by a rename over it, because
        deleting a lower entry would need a whiteout device a user namespace cannot create."""
        upper, workdir = Path("/run/lab-etc/upper"), Path("/run/lab-etc/work")
        upper.mkdir(parents=True, exist_ok=True)
        workdir.mkdir(parents=True, exist_ok=True)
        self.sh(["mount", "-t", "overlay", "overlay", "-o",
                 f"lowerdir=/etc,upperdir={upper},workdir={workdir}", "/etc"])
        staged = Path("/etc/resolv.conf.lab")
        staged.write_text(f"nameserver {CONSUMER_NAMESERVER}\n", encoding="utf-8")
        os.replace(staged, "/etc/resolv.conf")
        names = {NAMED_HOST: TARGET_IP, GRANTED_HOST: TARGET_DIRECT_IP,
                 REBIND_METADATA_HOST: METADATA_IP, REBIND_PRIVATE_HOST: PRIVATE_IP}
        hosts = "127.0.0.1 localhost\n" + "".join(f"{address} {name}\n" for name, address in names.items())
        files = {"con": {"resolv.conf": f"nameserver {CONSUMER_NAMESERVER}\n"}, "egr": {"hosts": hosts}}
        for name, contents in files.items():
            directory = Path("/etc/netns") / name
            directory.mkdir(parents=True, exist_ok=True)
            for file, content in contents.items():
                (directory / file).write_text(content, encoding="utf-8")
        self.note("phase two: an overlay on /etc in the lab's mount namespace holds /etc/netns/con/resolv.conf "
                  f"(nameserver {CONSUMER_NAMESERVER}) and /etc/netns/egr/hosts ("
                  + ", ".join(f"{name} -> {address}" for name, address in names.items())
                  + "); nothing is written to the host")

    @staticmethod
    def consumer_resolv_conf():
        return Path("/etc/netns/con/resolv.conf").read_text(encoding="utf-8")

    def dns_journal(self):
        path = self.work / "home-consumer" / ".specus" / "egress-dns-journal.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def taken_over(self):
        journal = self.dns_journal()
        return (self.consumer_resolv_conf() == RESOLV_CONF_WRITTEN and journal is not None
                and journal.get("state") == "committed")

    def named_request(self, timeout=8, host=NAMED_HOST):
        """The name, fetched from the consumer: through the responder, the pool and the egress."""
        body = self.work / f"curl-{next(self.counter)}.out"
        completed = self.sh(ns("con", "curl", "-sS", "--max-time", str(timeout), "-o", str(body),
                               "-w", "%{remote_ip}", f"http://{host}/whoami"), check=False, timeout=timeout + 30)
        src = None
        if completed.returncode == CURL_OK:
            try:
                src = json.loads(body.read_text())["src"]
            except (json.JSONDecodeError, KeyError, OSError):
                src = None
        body.unlink(missing_ok=True)
        return {"code": completed.returncode, "remote": completed.stdout.strip(), "src": src,
                "stderr": completed.stderr.strip()}

    def consumer_section(self):
        status = self.client_status("consumer")
        for instance in (status or {}).get("data", {}).get("instances", []):
            consumer = (instance.get("egress") or {}).get("consumer")
            if consumer is not None:
                return consumer
        return None

    @staticmethod
    def standing_of(consumer, client_id):
        for peer in (consumer or {}).get("peers") or []:
            if peer.get("clientId") == client_id:
                return peer.get("standing")
        return None

    def dns_section(self):
        status = self.client_status("consumer")
        for instance in (status or {}).get("data", {}).get("instances", []):
            consumer = ((instance.get("egress") or {}).get("consumer") or {})
            if consumer.get("dns") is not None:
                return consumer
        return None

    def phase_two(self):
        self.say("phase two: domain rules through the DNS takeover")
        self.private_etc()
        # Restarted so that both see the files above: a process sees the mounts of the namespace it
        # was started in.
        for role in ("consumer", "egress"):
            proc = self.procs.get(role)
            if proc is not None and proc.alive:
                proc.stop()
        egress = self.start_client("egress", self.work / "egress.jsonc")
        if not egress.wait_log(r"policy applied enabled=true", 60):
            raise LabAbort("phase two: the restarted egress never applied the policy:\n" + egress.log_since()[-4000:])
        rules = [{"match": DOMAIN_RULE, "action": "egress", "egressClientId": self.egress_id}]
        original = self.consumer_resolv_conf()
        consumer = self.start_client("consumer", self.client_config("consumer", rules, dns_takeover=True))
        taken, elapsed = self.wait_for("the DNS takeover", self.taken_over, 90)
        self.snapshots["phase two: consumer resolv.conf while taken over"] = self.consumer_resolv_conf()
        self.check("phase two: the consumer's resolv.conf points at the responder and the journal is committed",
                   bool(taken), f"after {elapsed:.1f}s" if taken else
                   "not taken over:\n" + self.consumer_resolv_conf() + "\n--- consumer\n" + consumer.log_since()[-3000:])
        if not taken:
            return
        mark = self.target_mark()
        got, _ = self.wait_for("the name through the egress",
                               lambda: (lambda r: r if r["src"] == EGRESS_IP else None)(self.named_request()), 60, 1.0)
        got = got or self.named_request()
        in_pool = False
        try:
            in_pool = ipaddress.ip_address(got["remote"]) in ipaddress.ip_network(FAKE_IP_POOL)
        except ValueError:
            pass
        self.check("phase two: a name under a domain rule resolves to a fake IP and leaves from the egress, "
                   "which resolved it itself",
                   got["src"] == EGRESS_IP and in_pool,
                   f"curl exit {got['code']}, connected to {got['remote'] or '-'}, target saw src={got['src']}"
                   + (f" ({got['stderr'][:120]})" if got["stderr"] else ""))
        self.leak_check("phase two: nothing reached the target from the consumer's own address", mark)

        started = time.time()
        body = self.work / f"curl-{next(self.counter)}.out"
        refused = self.sh(ns("con", "curl", "-sS", "--max-time", "5", "-o", str(body), f"http://{UNMAPPED_FAKE_IP}/"),
                          check=False, timeout=40)
        body.unlink(missing_ok=True)
        took = time.time() - started
        self.check("phase two: a fake IP nothing maps is refused at once, not sent anywhere",
                   refused.returncode == CURL_CONNECT_FAILED and took < 3,
                   f"curl exit {refused.returncode} after {took:.1f}s ({refused.stderr.strip()[:120]})")
        section, _ = self.wait_for("the consumer status to count the unmapped address",
                                   lambda: (lambda c: c if c and (c.get("blocked") or {}).get("fake-ip-unmapped") else None)(
                                       self.dns_section()), 30, 1.0)
        dns = (section or {}).get("dns") or {}
        if section:
            self.snapshots["phase two: consumer.dns"] = json.dumps(dns, indent=2)
        self.check("phase two: status says phase two runs, the system DNS is taken over, and counts the unmapped address",
                   dns.get("active") is True and dns.get("takeover") is True and dns.get("journal") == "committed"
                   and (section or {}).get("blocked", {}).get("fake-ip-unmapped", 0) >= 1,
                   json.dumps({"dns": dns, "blocked": (section or {}).get("blocked")}))

        if not self.args.skip_refusals:
            self.rebinding()

        # Killed: the takeover outlives the process, and the journal is what gives it back.
        killed_pid = (self.dns_journal() or {}).get("pid")
        consumer.kill()
        time.sleep(1)
        self.check("phase two: kill -9 leaves the takeover and its journal behind",
                   self.consumer_resolv_conf() == RESOLV_CONF_WRITTEN and self.dns_journal() is not None,
                   self.consumer_resolv_conf())
        restore = self.sh(ns("con", *self.client_env("consumer"), self.client_binary("consumer"),
                             "egress", "dns", "restore"), check=False)
        self.check("phase two: egress dns restore gives the original resolv.conf back and removes the journal",
                   restore.returncode == 0 and self.consumer_resolv_conf() == original and self.dns_journal() is None,
                   f"exit {restore.returncode}: {(restore.stdout + restore.stderr).strip()[:300]}")

        # Killed again, then started: the leftover is rolled back before the new takeover.
        consumer = self.start_client("consumer", self.work / "consumer.jsonc")
        taken, _ = self.wait_for("the DNS takeover after a restart", self.taken_over, 90)
        killed_pid = (self.dns_journal() or {}).get("pid")
        consumer.kill()
        time.sleep(1)
        consumer = self.start_client("consumer", self.work / "consumer.jsonc")
        retaken, _ = self.wait_for("the takeover by the next process",
                                   lambda: self.taken_over() and (self.dns_journal() or {}).get("pid") != killed_pid, 90)
        got, _ = self.wait_for("the name again",
                               lambda: (lambda r: r if r["src"] == EGRESS_IP else None)(self.named_request()), 60, 1.0)
        self.check("phase two: a start after kill -9 rolls the leftover back and takes the DNS over afresh",
                   bool(taken) and bool(retaken) and bool(got),
                   f"journal pid {killed_pid} -> {(self.dns_journal() or {}).get('pid')}; "
                   f"name {'through the egress' if got else 'not reached'}")

        consumer.stop()
        self.snapshots["phase two: consumer resolv.conf after normal exit"] = self.consumer_resolv_conf()
        self.check("phase two: a normal exit gives the system DNS back",
                   self.consumer_resolv_conf() == original and self.dns_journal() is None,
                   self.consumer_resolv_conf())

    @staticmethod
    def in_fake_pool(address):
        try:
            return ipaddress.ip_address(address) in ipaddress.ip_network(FAKE_IP_POOL)
        except (TypeError, ValueError):
            return False

    def consumer_resolves(self, host):
        """The address the consumer's own resolver gives for a name, which under the takeover is the
        fake IP the responder hands out for it."""
        got = self.sh(ns("con", "getent", "ahostsv4", host), check=False, timeout=20)
        fields = got.stdout.split()
        return fields[0] if got.returncode == 0 and fields else None

    def rebinding(self):
        """DNS rebinding (protocol/spec/peer-egress-dns.md, section 5): names under the consumer's
        domain rule that the egress's own resolver answers with the cloud metadata address and with a
        private one, while the policy's domainRules grant every name under the rule. The grant is
        shown to be in force by a public name no destination rule covers going through; the forced-deny
        list and the scope judge the address a name resolves to, so the same grant must not carry the
        other two past them."""
        resolved = []
        for host, address in ((GRANTED_HOST, TARGET_DIRECT_IP), (REBIND_METADATA_HOST, METADATA_IP),
                              (REBIND_PRIVATE_HOST, PRIVATE_IP)):
            got = self.whoami(f"http://{host}", netns_name="egr")
            resolved.append((host, address, got["src"] == EGRESS_IP, self.describe(got)))
        self.check("DNS rebinding: the egress resolves each name to its address and its own network reaches it",
                   all(ok for _, _, ok, _ in resolved),
                   "; ".join(f"{host} -> {address}: {'reached' if ok else detail}"
                             for host, address, ok, detail in resolved))

        grant = ({"match": DOMAIN_RULE, "protocols": ["tcp", "udp"], "portRanges": [[1, 65535]]},)
        applied = self.set_policy([self.consumer_id], domains=grant)
        got, _ = self.wait_for(f"{GRANTED_HOST} through the egress",
                               lambda: (lambda r: r if r["src"] == EGRESS_IP else None)(
                                   self.named_request(host=GRANTED_HOST)), 15, 1.0)
        got = got or self.named_request(host=GRANTED_HOST)
        self.check(f"DNS rebinding: the domain grant is in force: {GRANTED_HOST}, whose {TARGET_DIRECT_IP} no "
                   "destination rule covers, goes through the egress",
                   applied and got["src"] == EGRESS_IP,
                   f"curl exit {got['code']}, target saw src={got['src']}"
                   + (f" ({got['stderr'][:120]})" if got["stderr"] else ""))

        before = self.refusal_baseline()
        consumer = self.procs["consumer"]
        for host, address, code in ((REBIND_METADATA_HOST, METADATA_IP, CODE_FORBIDDEN),
                                    (REBIND_PRIVATE_HOST, PRIVATE_IP, CODE_SCOPE)):
            mark = self.target_mark()
            offset = consumer.log_offset()
            fake = self.consumer_resolves(host)
            got = self.named_request(host=host)
            counts = self.refused_at_egress(code, before)
            self.check(f"DNS rebinding: {host}, granted by name but resolved by the egress to {address}, is refused by "
                       f"the egress ({code})",
                       applied and self.in_fake_pool(fake) and got["code"] == CURL_CONNECT_FAILED and counts is not None,
                       f"the consumer resolved it to {fake or '-'}; curl exit {got['code']}"
                       + (f" ({got['stderr'][:80]})" if got["stderr"] else "")
                       + f"; {self.refusal_evidence(code, before, counts)}; {self.consumer_view(code, offset)}")
            self.nothing_reached(f"DNS rebinding: nothing reached {address}", mark, address)
        self.set_policy([self.consumer_id])

    # -- report -----------------------------------------------------------------------------------

    def report(self, aborted=None):
        failed = [r for r in self.results if not r["ok"]]
        kernel = self.sh(["uname", "-r"], check=False).stdout.strip()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        netem = {None: "the lossy step was not reached", True: "netem available", False: "netem unavailable"}[self.netem]
        lines = ["# Peer egress Linux lab", "",
                 f"Run {now} on kernel {kernel}; {self.client_label('consumer')} consumer and "
                 f"{self.client_label('egress')} egress against the Go server; {netem}.", "",
                 "Topology: the router namespace bridges the server (203.0.113.2) and the target (203.0.113.10 under "
                 "the rule, 198.51.100.10 under none); the consumer (10.90.1.2) and the egress (10.90.2.2) sit "
                 "behind it on their own links. Nothing is NATed. The rule sends 203.0.113.0/24 through the egress. "
                 f"The target also answers on {METADATA_IP} and {PRIVATE_IP}, which the egress must refuse.",
                 ""]
        if aborted:
            lines += ["## Aborted", "", "```", aborted, "```", ""]
        lines += ["## Checks", "", f"{len(self.results) - len(failed)} passed, {len(failed)} failed", "",
                  "| Result | Check | Evidence |", "| --- | --- | --- |"]
        for result in self.results:
            evidence = result["evidence"].replace("|", "\\|").replace("\n", "<br>")
            lines.append(f"| {'PASS' if result['ok'] else 'FAIL'} | {result['name']} | {evidence} |")
        lines += ["", "## Measurements", "", "| Measurement | Value |", "| --- | --- |"]
        for name, entry in self.measurements.items():
            lines.append(f"| {name} | {entry['value']} {entry['unit']}".rstrip() + " |")
        lines += ["", "## The consumer's routing table", ""]
        for title, table in self.snapshots.items():
            lines += [f"### {title}", "", "```", table.rstrip() or "(empty)", "```", ""]
        if self.notes:
            lines += ["## Notes", ""] + [f"- {note}" for note in self.notes] + [""]
        text = "\n".join(lines)
        (self.report_dir / "report.md").write_text(text, encoding="utf-8")
        (self.report_dir / "report.json").write_text(json.dumps({
            "kernel": kernel, "time": now, "aborted": aborted, "results": self.results,
            "measurements": self.measurements, "snapshots": self.snapshots, "notes": self.notes,
        }, indent=2), encoding="utf-8")
        for name in ("server.log", "egress.log", "consumer.log", "target.log", "trace.log"):
            source = self.work / name
            if source.exists():
                shutil.copy(source, self.report_dir / name)
        print("\n" + text)
        return not failed and aborted is None

    def run(self):
        aborted = None
        try:
            self.preflight()
            self.build_network()
            self.start_target()
            self.start_server()
            self.bring_up()
            self.acceptance()
            self.concurrent_downloads()
            if not self.args.skip_lossy:
                self.lossy()
            if self.args.performance_gate:
                self.performance_gate()
            if not self.args.skip_faults:
                self.fault_acl_revoked()
                for attempt in range(self.args.switch_off_repetitions):
                    self.say(f"switch-off regression round {attempt + 1}/{self.args.switch_off_repetitions}")
                    self.fault_switch_off()
                self.fault_egress_stopped()
                self.fault_server_restart()
                self.fault_rule_block()
                self.fault_kill_9()
            if not self.args.skip_refusals:
                self.refusals()
            if not self.args.skip_dns:
                self.phase_two()
        except LabAbort as error:
            aborted = str(error)
            self.say("aborted: " + aborted)
        except Exception:  # noqa: BLE001 - the report must still be written
            aborted = "unexpected error: " + traceback.format_exc()
            self.say(aborted)
        finally:
            try:
                self.stop_all()
            finally:
                ok = self.report(aborted)
        return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--server", required=True, help="specus-server binary (Go)")
    parser.add_argument("--client", help="default Go specus-client binary for both roles")
    parser.add_argument("--consumer-client", help="consumer executable or exec wrapper; overrides --client")
    parser.add_argument("--egress-client", help="egress executable or exec wrapper; overrides --client")
    parser.add_argument("--consumer-implementation", choices=["Go", "Java", ".NET"], help="report label")
    parser.add_argument("--egress-implementation", choices=["Go", "Java", ".NET"], help="report label")
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", help="working directory; a fresh temporary one by default")
    # Well beyond the old sub-MiB failure ceiling; a small smoke download would miss regression.
    parser.add_argument("--blob-bytes", type=int, default=8 * 1048576)
    parser.add_argument("--upload-bytes", type=int, default=8 * 1048576)
    parser.add_argument("--concurrent-flows", type=int, choices=range(0, 65), default=16,
                        help="parallel downstream integrity probes (0 disables, max 64)")
    parser.add_argument("--concurrent-bytes", type=int, default=1048576)
    parser.add_argument("--lossy-blob-bytes", type=int, default=512 * 1024)
    parser.add_argument("--lossy-timeout", type=int, default=60)
    parser.add_argument("--ceiling-sizes", type=int, nargs="+",
                        default=[512 * 1024, 1048576, 8 * 1048576])
    parser.add_argument("--ceiling-timeout", type=int, default=20)
    parser.add_argument("--loss-percent", type=float, default=2.0)
    parser.add_argument("--skip-lossy", action="store_true")
    parser.add_argument("--skip-faults", action="store_true")
    parser.add_argument("--skip-dns", action="store_true", help="skip phase two (domain rules, DNS takeover)")
    parser.add_argument("--skip-refusals", action="store_true",
                        help="skip the refusals at the egress (#42) and the DNS rebinding checks of phase two")
    parser.add_argument("--switch-off-repetitions", type=int, choices=range(1, 21), default=1,
                        help="repeat established-flow revocation (1-20 rounds)")
    parser.add_argument("--performance-gate", action="store_true",
                        help="check issue #50's agreed throughput, latency, loss and memory thresholds")
    args = parser.parse_args()
    if not args.client and not (args.consumer_client and args.egress_client):
        parser.error("provide --client or both --consumer-client and --egress-client")
    return Lab(args).run()


if __name__ == "__main__":
    sys.exit(main())
