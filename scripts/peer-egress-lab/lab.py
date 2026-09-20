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
leak checks tell the two source addresses apart.

Run as root inside a fresh network and mount namespace: `sudo unshare -n -m python3 lab.py ...` on a
machine with sudo, `unshare -rnm python3 lab.py ...` without. It refuses to run in a namespace whose
main table is not empty, so started by hand on a real machine it stops instead of rebuilding its
routing. Standard library only.
"""

import argparse
import datetime
import hashlib
import ipaddress
import itertools
import json
import os
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from target import blob_chunks, blob_sha256  # noqa: E402

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


class LabAbort(Exception):
    """Bring-up did not reach a state the checks can be run against."""


def ns(name, *args):
    return ["ip", "netns", "exec", name, *args]


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
        regex = re.compile(pattern)
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

    # -- plumbing ---------------------------------------------------------------------------------

    def say(self, text):
        stamp = f"[{time.time() - self.started:7.1f}s]"
        print(stamp, text, flush=True)
        self.trace.write(f"{stamp} {text}\n")
        self.trace.flush()

    def sh(self, args, check=True, timeout=60):
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        self.trace.write(f"$ {' '.join(args)} -> {completed.returncode}\n")
        if completed.stdout.strip():
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
        for binary in (self.args.server, self.args.client):
            if not os.access(binary, os.X_OK):
                raise LabAbort(f"{binary} is not executable")
        # `ip netns add` keeps its handles under /run/netns. The fake root of a user namespace
        # cannot create that directory on the host's /run, but it can mount a tmpfs over /run in
        # the private mount namespace this runs in, which is invisible outside it.
        try:
            os.makedirs("/run/netns", exist_ok=True)
            probe = Path("/run/netns/.lab-probe")
            probe.touch()
            probe.unlink()
        except PermissionError:
            self.sh(["mount", "-t", "tmpfs", "tmpfs", "/run"])
            os.makedirs("/run/netns", exist_ok=True)
            self.note("mounted a private tmpfs over /run so that ip netns can keep its handles there")

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
        self.start("server", ns("srv", "env", "SPECUS_ENV=test", self.args.server, "-config", str(path)))
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

    def client_config(self, role, rules=None):
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
        path = self.work / f"{role}.jsonc"
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return path

    def client_env(self, role):
        home = self.work / f"home-{role}"
        state = self.work / f"state-{role}"
        for directory in (home, state):
            directory.mkdir(mode=0o700, exist_ok=True)
        return ["env", f"HOME={home}", f"SPECUS_CLI_STATE_DIR={state}"]

    def start_client(self, role, config_path):
        netns_name = "con" if role == "consumer" else "egr"
        return self.start(role, ns(netns_name, *self.client_env(role), self.args.client, "run",
                                   "--config", str(config_path), "--no-update-check", "--login-timeout", "60"))

    def client_status(self, role, command="egress"):
        """The one-shot CLI reads a snapshot the running process refreshes; retried because a
        snapshot older than a few seconds is refused."""
        netns_name = "con" if role == "consumer" else "egr"
        for _ in range(6):
            got = self.sh(ns(netns_name, *self.client_env(role), self.args.client, command,
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

    def policy(self, allowed):
        return self.admin.call("POST", "/api/admin/peer-mesh/egress/policies", {
            "egressClientId": self.egress_id, "enabled": True, "scope": "PUBLIC",
            "allowedConsumerClientIds": allowed,
            "destinationRules": [{"cidr": RULE_CIDR, "protocols": ["tcp", "udp"], "portRanges": [[1, 65535]]}],
            "maxConcurrentFlows": 256, "maxFlowsPerConsumer": 128, "idleTimeoutSeconds": 60,
        })

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

    def whoami(self, url):
        got = self.curl(f"{url}/whoami", timeout=8)
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

        path = consumer.wait_log(r"Peer Mesh (direct|relay) UDP path active", 90)
        if not path:
            raise LabAbort("no peer session between consumer and egress:\n--- consumer\n"
                           + consumer.log_since()[-3000:] + "\n--- egress\n" + egress.log_since()[-3000:])
        self.measure("peer path type", path.group(1))
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
        status = self.client_status("consumer")
        if status:
            self.snapshots["consumer status (egress --json)"] = json.dumps(status.get("data", status), indent=2)

        script = ("import socket\n"
                  "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
                  "s.settimeout(5)\n"
                  f"s.sendto(b'lab', ('{TARGET_IP}', {UDP_PORT}))\n"
                  "print(s.recv(200).decode().strip())\n")
        got = self.sh(ns("con", sys.executable, "-c", script), check=False, timeout=15)
        reply = got.stdout.strip()
        self.check("UDP under the rule leaves from the egress's address",
                   f"src={EGRESS_IP}:" in reply, reply or got.stderr.strip()[-200:])

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
        """How large a response the egress can actually deliver.

        The egress reads from the target as fast as the target will serve and sends it on without
        looking at what the consumer advertised, so a response only survives while it fits in what
        the receiver can hold. Past that the consumer's kernel drops what it cannot take, the
        egress's stack retransmits the same segments into the same full window until it runs out of
        attempts, and the application gets a reset minutes later. This measures where that starts
        rather than asserting it away.
        """
        largest = None
        first_failure = None
        for size in self.args.ceiling_sizes:
            got = self.curl(f"{TARGET_URL}/blob/{size}", timeout=self.args.ceiling_timeout)
            received = got["body"].stat().st_size if got["body"].exists() else 0
            got["body"].unlink(missing_ok=True)
            complete = got["code"] == CURL_OK and received == size
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
                      f"{received} B and then {self.describe(got)}. The egress does not pace itself "
                      f"against what the consumer advertises, so a response larger than the "
                      f"receiver's buffer stalls and is reset instead of slowing down. This is the "
                      f"known missing send-side flow control, measured rather than assumed.")
        else:
            self.note(f"every probed response up to {self.args.ceiling_sizes[-1]} B arrived, which is "
                      f"more than this lab could deliver when it was written")

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

    def lossy(self):
        percent = self.args.loss_percent
        router_side = ["tc", "qdisc", "add", "dev", "r-egr", "root", "netem", "loss", f"{percent}%"]
        egress_side = ns("egr", "tc", "qdisc", "add", "dev", "egr0", "root", "netem", "loss", f"{percent}%")
        if shutil.which("tc") is None or self.sh(router_side, check=False).returncode != 0:
            self.netem = False
            self.note("netem is not available here; the lossy-link measurement was skipped")
            return
        if self.sh(egress_side, check=False).returncode != 0:
            self.sh(["tc", "qdisc", "del", "dev", "r-egr", "root"], check=False)
            self.netem = False
            self.note("netem is not available inside the egress namespace; the lossy-link measurement was skipped")
            return
        self.netem = True
        try:
            # Recorded, not asserted. What the user-space stack does on a lossy link is the thing
            # issue #56 asks to be shown with numbers rather than described, and with a fixed window
            # and no congestion control the honest number may well be a transfer that never lands.
            size = self.args.lossy_blob_bytes
            label = self.human(size)
            got = self.curl(f"{TARGET_URL}/blob/{size}", timeout=self.args.lossy_timeout)
            received = got["body"].stat().st_size if got["body"].exists() else 0
            complete = got["code"] == CURL_OK and received == size
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
                          f"{self.describe(got)}. Loss is recovered only by the retransmission timer, "
                          f"so the same missing send-side pacing that caps a clean link stops a lossy "
                          f"one outright.")
            got["body"].unlink(missing_ok=True)
        finally:
            self.sh(["tc", "qdisc", "del", "dev", "r-egr", "root"], check=False)
            self.sh(ns("egr", "tc", "qdisc", "del", "dev", "egr0", "root"), check=False)

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
        reject = consumer.wait_log(rf"refused {re.escape(TARGET_IP)}:80 code=(EGRESS_[A-Z_]+)", 10, offset)
        self.check("ACL revoked: the consumer receives flow-reject", bool(reject),
                   f"consumer log: {reject.group(0)}" if reject else "no refusal logged by the consumer")
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

    # -- report -----------------------------------------------------------------------------------

    def report(self, aborted=None):
        failed = [r for r in self.results if not r["ok"]]
        kernel = self.sh(["uname", "-r"], check=False).stdout.strip()
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        netem = {None: "the lossy step was not reached", True: "netem available", False: "netem unavailable"}[self.netem]
        lines = ["# Peer egress Linux lab", "",
                 f"Run {now} on kernel {kernel}; Go consumer and Go egress against the Go server; {netem}.", "",
                 "Topology: the router namespace bridges the server (203.0.113.2) and the target (203.0.113.10 under "
                 "the rule, 198.51.100.10 under none); the consumer (10.90.1.2) and the egress (10.90.2.2) sit "
                 "behind it on their own links. Nothing is NATed. The rule sends 203.0.113.0/24 through the egress.",
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
            if not self.args.skip_lossy:
                self.lossy()
            if not self.args.skip_faults:
                self.fault_acl_revoked()
                self.fault_switch_off()
                self.fault_egress_stopped()
                self.fault_rule_block()
                self.fault_kill_9()
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
    parser.add_argument("--client", required=True, help="specus-client binary (Go)")
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", help="working directory; a fresh temporary one by default")
    # Sized clear of the ceiling the egress can currently deliver, which downstream_ceiling
    # measures and the report states. That ceiling moves with the receiver's socket buffer, and a
    # size sitting on it makes this check flap: one CI run had 256 KiB pass the ceiling probe and
    # fail this check minutes apart. 64 KiB is still fifty-odd segments at this MTU, which is what
    # the intact-arrival check is there to exercise, and it survives the lossy link too.
    parser.add_argument("--blob-bytes", type=int, default=64 * 1024)
    parser.add_argument("--upload-bytes", type=int, default=8 * 1048576)
    parser.add_argument("--lossy-blob-bytes", type=int, default=64 * 1024)
    parser.add_argument("--lossy-timeout", type=int, default=60)
    parser.add_argument("--ceiling-sizes", type=int, nargs="+",
                        default=[128 * 1024, 256 * 1024, 512 * 1024, 1048576])
    parser.add_argument("--ceiling-timeout", type=int, default=20)
    parser.add_argument("--loss-percent", type=float, default=2.0)
    parser.add_argument("--skip-lossy", action="store_true")
    parser.add_argument("--skip-faults", action="store_true")
    args = parser.parse_args()
    return Lab(args).run()


if __name__ == "__main__":
    sys.exit(main())
