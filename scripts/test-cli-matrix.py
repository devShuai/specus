"""Real-process CLI acceptance. Uses isolated configs/state and loopback fixture servers only.

python test-cli-matrix.py --name go -- <absolute binary> [launcher arguments]
Run separately for each implementation on Windows and Unix. No third-party packages.
"""
import argparse
import contextlib
import http.server
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time


SECRET = "CLI_TEST_SECRET_MUST_NOT_LEAK"
TOKEN = "CLI_TEST_TOKEN_MUST_NOT_LEAK"


def compact(text):
    raw = text.encode()
    value, prefix = len(raw) + 1, bytearray()
    while value > 127:
        prefix.append((value & 127) | 128)
        value >>= 7
    return bytes(prefix) + bytes([value]) + raw


def packet(command, body):
    return struct.pack(">IBBbI", 0x14353565, 2, 4, command, len(body)) + body


class Control(socketserver.BaseRequestHandler):
    def handle(self):
        def read(size):
            result = b""
            while len(result) < size:
                part = self.request.recv(size - len(result))
                if not part:
                    raise EOFError()
                result += part
            return result
        try:
            while True:
                header = read(11)
                _, _, _, command, size = struct.unpack(">IBBbI", header)
                body = read(size)
                if command == 1:
                    if body.endswith(compact("data")) and self.server.data_delay:
                        time.sleep(self.server.data_delay)
                    self.request.sendall(packet(-1, compact("cli-test") + bytes([not self.server.reject])
                                                + compact("policy denied" if self.server.reject else "")))
                elif command == 4:
                    self.request.sendall(packet(-4, b""))
        except (OSError, EOFError):
            pass


class ControlServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    reject = False
    data_delay = 0


class Http(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def read_body(self):
        # .NET's PostAsJsonAsync streams the body with chunked transfer encoding and no
        # Content-Length. Reading by length alone yields an empty body for that client, which went
        # unnoticed only because the body used to be thrown away.
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    # Trailers, if any, end at an empty line.
                    while self.rfile.readline().strip():
                        pass
                    return b"".join(chunks)
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def do_POST(self):
        body = self.read_body()
        self.server.post_paths = getattr(self.server, "post_paths", []) + [self.path]
        if self.path.endswith("/auth/login"):
            try:
                self.server.last_login = json.loads(body)
            except ValueError:
                self.server.last_login = None
        self.server.logins += 1
        status = self.server.status
        if self.server.recover and self.server.logins > 1:
            status = 200
        if self.server.stall:
            time.sleep(4)
        data = dict(clientName="cli-test", clientSessionId=1, accessToken=TOKEN,
                    tokenTtlSeconds=3600, nettyHost="127.0.0.1", nettyPort=self.server.control_port,
                    nettyTls=False, specusConfigList=[], httpSpecusConfigList=[], peerMesh={"enabled": False})
        body = json.dumps(data if status == 200 else {"error": SECRET + TOKEN}).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self):
        self.server.updates += 1
        time.sleep(8)  # slow catalogue must not hold up login, readiness or SIGINT
        try:
            self.send_response(503)
            self.end_headers()
        except OSError:
            pass


class Matrix:
    def __init__(self, command, name, directory):
        self.command, self.name, self.directory = command, name, Path(directory)
        self.env = dict(os.environ, SPECUS_CLI_STATE_DIR=str(self.directory / "state"),
                        HOME=directory, USERPROFILE=directory, CLI_TEST_SECRET=SECRET)
        # Java keeps its identity in user.home, independent of HOME.
        if name == "java":
            self.command = command[:1] + ["-Duser.home=" + directory] + command[1:]
        self.config = self.directory / "config with spaces.jsonc"
        self.checks = 0
        self.saw_control_only = False

    def fixture(self, url):
        self.config.write_text(json.dumps(dict(serverBaseUrl=url, apiKey="CLI_TEST_KEY_MUST_NOT_LEAK",
            secret="env:CLI_TEST_SECRET", peerMeshMtu=9999, updateCheckIntervalHours=9999)), encoding="utf-8")

    def egress_rule_warnings(self, url):
        # A rule that will not be in force has to be named before anything connects, in the same
        # words by every runtime, as a warning rather than a failure, and without printing the
        # rule's match: configuration warnings do not print configuration values.
        rules = [
            dict(match="203.0.113.0/24", action="egress", egressClientId=42),
            dict(match="0.0.0.0/0", action="egress", egressClientId=42),
            dict(match="example.com", action="egress", egressClientId=42),
            dict(match="2001:db8::/32", action="egress", egressClientId=42),
            dict(match="100.96.0.0/12", action="egress", egressClientId=42),
            dict(match="198.51.100.0/24", action="egress"),
            # Switched off by the user: out of force by choice, so never warned about.
            dict(match="192.0.2.0/24", action="block", enabled=False),
        ]
        path = self.directory / "egress rules.jsonc"
        path.write_text(json.dumps(dict(serverBaseUrl=url, apiKey="CLI_TEST_KEY_MUST_NOT_LEAK",
            secret="env:CLI_TEST_SECRET", peerEgressRules=rules)), encoding="utf-8")
        result = subprocess.run(self.command + ["config", "validate", "--config", str(path)], cwd=self.directory,
                                env=self.env, capture_output=True, timeout=20)
        err = result.stderr.decode("utf-8", "replace")
        assert result.returncode == 0, ("a refused egress rule failed the whole configuration", err)
        # No peerEgressEnabled in this file, so the switch is off: said once, by count.
        expected = ["peerEgressRules has 7 rule(s) but peerEgressEnabled is false: none is in force",
                    "peerEgressRules[1] is not in force: EGRESS_RULE_DEFAULT_ROUTE",
                    "peerEgressRules[2] is not in force: EGRESS_RULE_DOMAIN_UNSUPPORTED",
                    "peerEgressRules[3] is not in force: EGRESS_RULE_IPV6_UNSUPPORTED",
                    "peerEgressRules[4] is not in force: EGRESS_RULE_MESH_OVERLAP",
                    "peerEgressRules[5] is not in force: EGRESS_RULE_MISSING_TARGET"]
        for line in expected:
            assert line in err, ("missing egress rule warning", line, err)
        assert "peerEgressRules[0]" not in err, ("a usable rule was warned about", err)
        assert "peerEgressRules[6]" not in err and "EGRESS_RULE_DISABLED" not in err, (
            "a rule the user switched off was warned about", err)
        assert "Unknown configuration field" not in err, ("peerEgressRules treated as unknown", err)
        for match in ("example.com", "2001:db8", "100.96.0.0/12"):
            assert match not in err, ("a configuration value was printed in a warning", match)
        self.checks += 1

    def run_text(self, args, code=0):
        """A person's view of a command: stdout and stderr, line endings normalised."""
        result = subprocess.run(self.command + args, cwd=self.directory, env=self.env, capture_output=True, timeout=20)
        out = result.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
        err = result.stderr.decode("utf-8", "replace").replace("\r\n", "\n")
        assert result.returncode == code, (args, result.returncode, out, err)
        assert SECRET not in out + err and TOKEN not in out + err, ("sensitive output", args)
        self.checks += 1
        return out, err

    def egress_editing(self, url):
        # The editing commands write the configuration file and print the same lines in every
        # runtime. The first line of a write names the absolute path, which runtimes may spell
        # differently on Windows, so only its fixed part is compared; the listing after it is exact.
        path = self.directory / "egress edit.jsonc"
        path.write_text('{\n  // kept across edits\n  "serverBaseUrl": "' + url + '",\n'
                        '  "apiKey": "CLI_TEST_KEY_MUST_NOT_LEAK",\n  "secret": "env:CLI_TEST_SECRET"\n}\n',
                        encoding="utf-8")
        cfg = ["--config", str(path)]
        off_saved = "takeover: off (peerEgressEnabled is false); rules are saved, none is in force"
        restart = ". A running client applies the change after a restart."

        def written(args, listing, code=0):
            out, err = self.run_text(args + cfg, code)
            lines = out.rstrip("\n").split("\n")
            saved = [index for index, line in enumerate(lines) if line.startswith("Saved ")]
            assert len(saved) == 1 and lines[saved[0]].endswith(restart), ("no save line", args, out, err)
            assert lines[saved[0] + 1:] == listing, ("listing", args, lines[saved[0] + 1:], listing)
            return lines[:saved[0]]

        out, _ = self.run_text(["egress", "rules"] + cfg)
        assert out == "takeover: off (peerEgressEnabled is false)\n  No egress rules configured.\n", out
        written(["egress", "rule", "add", "--match", "203.0.113.0/24", "--action", "egress", "--egress-client-id", "42"],
                [off_saved, "  [0] on 203.0.113.0/24 egress 42"])
        _, err = self.run_text(["egress", "rule", "add", "--match", "example.com", "--action", "egress",
                                "--egress-client-id", "42"] + cfg, 2)
        assert "Rule not added: EGRESS_RULE_DOMAIN_UNSUPPORTED (domain rules are not supported yet; use an IPv4 address or CIDR range)" in err, err
        written(["egress", "rule", "add", "--match", "198.51.100.0/24", "--action", "block", "--at", "0", "--disabled"],
                [off_saved, "  [0] off 198.51.100.0/24 block", "  [1] on 203.0.113.0/24 egress 42"])
        written(["egress", "rule", "move", "--index", "0", "--to", "1"],
                [off_saved, "  [0] on 203.0.113.0/24 egress 42", "  [1] off 198.51.100.0/24 block"])
        out, _ = self.run_text(["egress", "test", "203.0.113.9"] + cfg)
        assert out == ("Preview for 203.0.113.9 from the configuration (no connection is made; --connect PORT tests one)\n"
                       "  takeover: off\n  rule: [0] 203.0.113.0/24 egress 42\n"
                       "  result: takeover is off, so it stays local (direct); with takeover on: through egress 42\n"), out

        notice = ["Turning on egress takeover:",
                  "  - needs permission to create a virtual interface and install routes (administrator or root; peerMeshDevice must not be noop)",
                  "  - takes over only the destinations a rule covers; everything else stays local",
                  "  - blocks a destination covered by an egress rule while its egress is unavailable, instead of sending it locally"]
        before = path.read_text(encoding="utf-8")
        _, err = self.run_text(["egress", "enable"] + cfg, 2)
        assert err.rstrip("\n").split("\n") == notice + ["Not changed. Re-run with --yes to confirm."], err
        assert path.read_text(encoding="utf-8") == before, "enable without --yes changed the file"
        preface = written(["egress", "enable", "--yes"],
                          ["takeover: on", "  [0] on 203.0.113.0/24 egress 42", "  [1] off 198.51.100.0/24 block"])
        assert preface == notice + ["Warning: peerMeshDevice is noop, so there is no interface to route into; set it to auto."], preface
        out, _ = self.run_text(["egress", "test", "203.0.113.9"] + cfg)
        assert out.endswith("  takeover: on\n  rule: [0] 203.0.113.0/24 egress 42\n  result: through egress 42\n"), out
        out, _ = self.run_text(["egress", "test", "8.8.8.8"] + cfg)
        assert out.endswith("  rule: none\n  result: not covered by any rule; stays local (direct)\n"), out
        _, err = self.run_text(["egress", "test", "example.com"] + cfg, 2)
        assert "ADDRESS is a domain name; rules match IPv4 addresses only for now. Give the address it resolves to." in err, err

        written(["egress", "rule", "disable", "--index", "0"],
                ["takeover: on", "  [0] off 203.0.113.0/24 egress 42", "  [1] off 198.51.100.0/24 block"])
        written(["egress", "rule", "enable", "--index", "1"],
                ["takeover: on", "  [0] off 203.0.113.0/24 egress 42", "  [1] on 198.51.100.0/24 block"])
        written(["egress", "rule", "remove", "--index", "1"],
                ["takeover: on", "  [0] off 203.0.113.0/24 egress 42"])
        written(["egress", "disable"], [off_saved, "  [0] off 203.0.113.0/24 egress 42"])
        _, err = self.run_text(["egress", "rule", "remove", "--index", "5"] + cfg, 2)
        assert "No rule at index 5; there are 1 rule(s). List them with egress rules." in err, err
        self.run_text(["egress", "rules", "--at", "1"] + cfg, 2)

        text = path.read_text(encoding="utf-8")
        assert "// kept across edits" in text, "an edit dropped a comment outside the rule list"
        assert '{"match": "203.0.113.0/24", "action": "egress", "egressClientId": 42, "enabled": false}' in text, text
        assert '"peerEgressEnabled": false' in text, text
        listing = self.run(["egress", "rules"] + cfg)["data"]
        assert listing["enabled"] is False and len(listing["rules"]) == 1, listing
        rule = listing["rules"][0]
        assert rule["enabled"] is False and rule["inForce"] is False and rule["code"] == "EGRESS_RULE_DISABLED", rule
        self.run(["config", "validate"] + cfg)

        # A file with CRLF line breaks keeps them: what an edit adds follows the file.
        crlf = self.directory / "egress crlf.jsonc"
        crlf.write_bytes(('{\r\n  "serverBaseUrl": "' + url + '",\r\n  "apiKey": "CLI_TEST_KEY_MUST_NOT_LEAK",\r\n'
                          '  "secret": "env:CLI_TEST_SECRET"\r\n}\r\n').encode("utf-8"))
        self.run_text(["egress", "rule", "add", "--match", "203.0.113.0/24", "--action", "block", "--config", str(crlf)])
        self.run_text(["egress", "rule", "add", "--match", "198.51.100.0/24", "--action", "direct", "--config", str(crlf)])
        self.run_text(["egress", "disable", "--config", str(crlf)])
        self.run_text(["egress", "enable", "--yes", "--config", str(crlf)])
        edited = crlf.read_bytes()
        assert edited.count(b"\n") == edited.count(b"\r\n") and b'"peerEgressEnabled": true' in edited, edited
        self.egress_dns(url, restart)

    def egress_dns(self, url, restart):
        # Phase two (protocol/spec/peer-egress-dns.md, 命令): the switch states what it changes every
        # time it is turned on, domain rules are accepted once it is on, and the status and restore
        # commands say the same things in every runtime. HOME and the state directory point into the
        # test directory, so no journal of the machine running the tests is ever read or acted on.
        path = self.directory / "egress dns.jsonc"
        path.write_text('{\n  "serverBaseUrl": "' + url + '",\n  "apiKey": "CLI_TEST_KEY_MUST_NOT_LEAK",\n'
                        '  "secret": "env:CLI_TEST_SECRET"\n}\n', encoding="utf-8")
        cfg = ["--config", str(path)]
        notice = [
            "Turning on DNS takeover for domain rules:",
            "  - points the system DNS at this client while it runs and gives it back when it stops "
            "(resolvectl or /etc/resolv.conf on Linux, networksetup on macOS, an NRPT rule on Windows)",
            "  - keeps a journal in ~/.specus, so a change left by a killed client is undone at its next start "
            "or by egress dns restore",
            "  - domain rules do not match applications that bring their own DoH/DoT, use the system cache, "
            "or connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules",
        ]
        before = path.read_text(encoding="utf-8")
        _, err = self.run_text(["egress", "dns", "enable"] + cfg, 2)
        assert err.rstrip("\n").split("\n") == notice + ["Not changed. Re-run with --yes to confirm."], err
        assert path.read_text(encoding="utf-8") == before, "dns enable without --yes changed the file"
        out, _ = self.run_text(["egress", "dns", "enable", "--yes"] + cfg)
        lines = out.rstrip("\n").split("\n")
        assert lines[:4] == notice, lines
        assert lines[4] == "Warning: peerEgressEnabled is false, so domain rules take effect only after egress enable.", lines
        assert lines[5].startswith("Saved ") and lines[5].endswith(restart), lines
        assert lines[6:] == ["dns takeover: on (pool 198.18.0.0/15)"], lines
        assert '"peerEgressDnsTakeover": true' in path.read_text(encoding="utf-8")
        data = self.run(["egress", "dns", "enable", "--yes"] + cfg)["data"]
        assert data["dnsTakeover"] is True and data["pool"] == "198.18.0.0/15", data

        # With the switch on, a domain rule is a rule, and an address rule inside the pool is not.
        out, _ = self.run_text(["egress", "rule", "add", "--match", "example.com", "--action", "egress",
                                "--egress-client-id", "42"] + cfg)
        assert "  [0] on example.com egress 42" in out.split("\n"), out
        _, err = self.run_text(["egress", "rule", "add", "--match", "198.18.0.0/16", "--action", "direct"] + cfg, 2)
        assert ("Rule not added: EGRESS_RULE_FAKE_IP_OVERLAP (overlaps the fake-IP pool (peerEgressFakeIpCidr), "
                "whose addresses only domain rules hand out)") in err, err
        listing = self.run(["egress", "rules"] + cfg)["data"]
        # Out of force only because peerEgressEnabled is off: as a domain rule it is valid now.
        assert [rule.get("code") for rule in listing["rules"]] == ["EGRESS_CONSUMER_DISABLED"], listing

        out, _ = self.run_text(["egress", "dns", "status"] + cfg)
        assert "No running client for this config." in out.split("\n"), out
        assert "journal: none (the system DNS is not taken over)" in out.split("\n"), out
        status = self.run(["egress", "dns", "status"] + cfg)["data"]
        assert status["instances"] == [] and status["journal"]["state"] == "none", status

        journal = self.directory / ".specus" / "egress-dns-journal.json"
        out, _ = self.run_text(["egress", "dns", "restore"])
        # The path is spelled by each runtime (short names, case), so only its ends are compared.
        last = out.rstrip("\n").split("\n")[-1]
        assert last.startswith("No DNS takeover journal at ") and last.endswith(
            "egress-dns-journal.json; there is nothing to restore."), out
        assert self.run(["egress", "dns", "restore"])["data"]["restored"] is False
        # A running process id is not a running client (peer-egress-dns.md, 事务日志): with no state
        # published as this test process, restore goes on to give its journal back. The journal names
        # a platform no client knows, which stops that before anything runs on the machine running the
        # tests; --force is never passed. The refusal for a client that does publish is in
        # dns_restore_refused, once a client has made the state directory.
        self.write_test_journal(journal)
        try:
            _, err = self.run_text(["egress", "dns", "restore"], 1)
            assert any(line.startswith("Giving the system DNS back failed at ") and "specus-test-none" in line
                       and line.endswith(". The journal is kept; fix what the step reports and run egress dns restore again.")
                       for line in err.split("\n")), err
            status = self.run(["egress", "dns", "status"] + cfg)["data"]
            assert status["journal"]["state"] == "committed" and status["journal"]["pid"] == os.getpid(), status
        finally:
            journal.unlink()

        out, _ = self.run_text(["egress", "dns", "disable"] + cfg)
        lines = out.rstrip("\n").split("\n")
        assert lines[0].startswith("Saved ") and lines[0].endswith(restart) and lines[1:] == ["dns takeover: off"], lines
        assert '"peerEgressDnsTakeover": false' in path.read_text(encoding="utf-8")

        # The recognisable boundary is in the help of every runtime.
        out, _ = self.run_text(["--help"])
        assert ("Domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect "
                "to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules.") in " ".join(out.split()), out

        # An unusable pool asked for is named before anything connects, in the same words everywhere.
        bad = self.directory / "egress bad pool.jsonc"
        bad.write_text(json.dumps(dict(serverBaseUrl=url, apiKey="CLI_TEST_KEY_MUST_NOT_LEAK",
                                       secret="env:CLI_TEST_SECRET", peerEgressDnsTakeover=True,
                                       peerEgressFakeIpCidr="100.96.0.0/16")), encoding="utf-8")
        result = subprocess.run(self.command + ["config", "validate", "--config", str(bad)], cwd=self.directory,
                                env=self.env, capture_output=True, timeout=20)
        err = result.stderr.decode("utf-8", "replace")
        assert result.returncode == 0, ("an unusable pool failed the whole configuration", err)
        assert ("peerEgressFakeIpCidr is not usable: EGRESS_FAKE_IP_POOL_INVALID; domain rules are not in force"
                in err), err
        assert "100.96.0.0/16" not in err, ("a configuration value was printed in a warning", err)
        self.checks += 1

    @staticmethod
    def write_test_journal(journal):
        # Taken over by this test process, on a platform no client knows how to give back.
        journal.parent.mkdir(exist_ok=True)
        if os.name != "nt":
            os.chmod(journal.parent, 0o700)
        journal.write_text(json.dumps({"version": 1, "state": "committed", "platform": "specus-test-none",
                                       "pid": os.getpid(), "listen": "198.18.0.1", "upstreams": ["192.0.2.53"],
                                       "startedAtUnixMs": 1757000000000}), encoding="utf-8")

    def dns_restore_refused(self, state, snapshot):
        # The client that took over still runs when it publishes fresh state, whatever its runtime
        # and configuration (peer-egress-dns.md, 事务日志). This test process stands in for it through
        # a state file a client wrote, rewritten in place so it keeps that client's private owner and
        # ACL. Should the refusal be missed, the journal's unknown platform still runs nothing.
        journal = self.directory / ".specus" / "egress-dns-journal.json"
        self.write_test_journal(journal)
        refused = (f"The client that took over the system DNS (PID {os.getpid()}) is still running, and gives it back "
                   "itself when it stops. Stop it, or set peerEgressDnsTakeover to false and restart it. --force skips "
                   "this check, for when that PID now belongs to another client.")
        try:
            for _ in range(3):
                # Fresh is the last five seconds by the CLI's clock: stamped just before each run, and
                # run again should a cold start (a JVM on a slow runner) outlast it.
                state.write_text(json.dumps(dict(snapshot, pid=os.getpid(), configPath=str(self.directory / "another.jsonc"),
                                                 updatedAtUnixMs=int(time.time() * 1000))), encoding="utf-8")
                _, err = self.run_text(["egress", "dns", "restore"], 1)
                if refused in err:
                    break
            else:
                raise AssertionError(("a client publishing fresh state was not recognised", err))
            assert journal.exists(), "a refused restore removed the journal"
        finally:
            state.write_text(json.dumps(dict(snapshot, pid=os.getpid(), updatedAtUnixMs=0)), encoding="utf-8")
            journal.unlink()
        self.checks += 1

    def run(self, args, code=0, machine=True):
        command = self.command + args + (["--json"] if machine else [])
        result = subprocess.run(command, cwd=self.directory, env=self.env, capture_output=True, timeout=20)
        out, err = result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")
        assert result.returncode == code, (args, result.returncode, out, err)
        assert SECRET not in out + err and TOKEN not in out + err, ("sensitive output", args)
        if machine:
            data = json.loads(out)
            assert data["schemaVersion"] == 1 and data["exitCode"] == code and data["ok"] == (code == 0)
            assert "Warning:" not in out
        else:
            data = None
        self.checks += 1
        return data

    @contextlib.contextmanager
    def start(self, *extra):
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(self.command + ["--config", str(self.config)] + list(extra),
                cwd=self.directory, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            try:
                yield process
            except BaseException:
                stderr.seek(0)
                details = stderr.read().decode("utf-8", "replace")
                print(details.replace(SECRET, "<redacted>").replace(TOKEN, "<redacted>"), flush=True)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=15)
                stdout.seek(0); stderr.seek(0)
                output = stdout.read() + stderr.read()
                assert SECRET.encode() not in output and TOKEN.encode() not in output, "sensitive runtime log"

    def wait_ready(self, process):
        # Generous because it is spent only when readiness is late: a cold JVM on a Windows runner,
        # where every status query is itself a JVM start, has taken more than 18 s.
        deadline = time.monotonic() + 45
        last = ""
        while time.monotonic() < deadline:
            assert process.poll() is None, ("runtime exited before readiness", process.returncode)
            result = subprocess.run(self.command + ["status", "--config", str(self.config), "--json"],
                                    cwd=self.directory, env=self.env, capture_output=True, timeout=15)
            last = result.stdout.decode("utf-8", "replace") + result.stderr.decode("utf-8", "replace")
            if result.returncode == 0:
                instances = json.loads(result.stdout)["data"]["instances"]
                if any(row["controlAuthenticated"] and not row["businessReady"] for row in instances):
                    self.saw_control_only = True
                if any(row["businessReady"] and row["controlAuthenticated"] for row in instances):
                    return instances
            time.sleep(.15)
        raise AssertionError(("not ready", last))

    def tty_ctrl_c(self):
        import pty
        import select
        pid, master = pty.fork()
        if pid == 0:
            os.chdir(self.directory)
            os.execvpe(self.command[0], self.command + ["--config", str(self.config)], self.env)
        captured = bytearray()
        done = threading.Event()
        def drain():
            while not done.is_set():
                try:
                    if select.select([master], [], [], .1)[0]:
                        part = os.read(master, 65536)
                        if not part:
                            return
                        captured.extend(part)
                except OSError:
                    return
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        class Child:
            returncode = None
            def poll(self):
                return self.returncode
        child = Child()
        reaped = False
        try:
            self.wait_ready(child)
            os.write(master, b"\x03")  # terminal line discipline must deliver SIGINT
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                found, status = os.waitpid(pid, os.WNOHANG)
                if found:
                    reaped = True
                    assert os.waitstatus_to_exitcode(status) in (0, 130), bytes(captured).decode("utf-8", "replace")
                    self.checks += 1
                    return
                time.sleep(.1)
            raise AssertionError("TTY Ctrl+C did not stop the client within 8 seconds")
        finally:
            if not reaped:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            done.set(); reader.join(2); os.close(master)
            assert SECRET.encode() not in captured and TOKEN.encode() not in captured

    def test(self):
        for args, code in [(["--help"], 0), (["--version"], 0), (["unknown-command"], 2),
                           (["--unknown"], 2), (["--config"], 2), (["--login-timeout=0"], 2),
                           (["--probe"], 2), (["--config", "missing.jsonc"], 2)]:
            self.run(args, code)
        self.run(["status"], 5)
        with ControlServer(("127.0.0.1", 0), Control) as control, ThreadingHTTPServer(("127.0.0.1", 0), Http) as http:
            http.daemon_threads = True
            http.status, http.logins, http.updates, http.recover, http.stall = 200, 0, 0, False, False
            http.control_port = control.server_address[1]
            for server in (control, http):
                threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                self.fixture("http://127.0.0.1:" + str(http.server_port))
                cfg = ["--config", str(self.config)]
                self.run(["config", "validate"] + cfg)
                self.egress_rule_warnings("http://127.0.0.1:" + str(http.server_port))
                self.egress_editing("http://127.0.0.1:" + str(http.server_port))
                shown = self.run(["config", "show"] + cfg)["data"]["config"]
                assert shown["apiKey"] == shown["secret"] == "<redacted>"
                assert shown["peerMeshMtu"] == 1280 and shown["updateCheckIntervalHours"] == 168
                self.run(["doctor"] + cfg)
                self.run(["doctor", "--probe"] + cfg)
                assert http.logins == http.updates == 0, "offline/query commands caused a login/update"
                # Slow updater and closed stdin must not block connection, queries or shutdown.
                control.data_delay = 4
                with self.start() as process:
                    self.wait_ready(process)
                    assert self.saw_control_only, "status conflated control authentication with forwarding readiness"
                    # Every server gates egress-config on this, so a client that does not send it can
                    # never be made an egress. Checked on the real login the real binary sent: the
                    # unit tests assert each runtime's own serialiser, this asserts what arrives.
                    capabilities = ((getattr(http, "last_login", None) or {}).get("environment") or {}).get("clientEgressCapabilities")
                    assert isinstance(capabilities, dict),                         f"login announced no clientEgressCapabilities (POST paths seen: {getattr(http, 'post_paths', [])}, "                         f"environment keys: {sorted(((getattr(http, 'last_login', None) or {}).get('environment') or {}).keys())})"
                    assert isinstance(capabilities.get("version"), int) and capabilities["version"] >= 1,                         f"login announced egress version {capabilities.get('version')!r}; servers skip egress-config below 1"
                    assert capabilities.get("egressCapable") is True, "login did not announce egressCapable"
                    # The egress side of phase two resolves names (peer-egress-dns.md); IPv6 targets are not carried.
                    assert capabilities.get("domainTargetCapable") is True, "login did not announce domain targets"
                    assert capabilities.get("ipv6TargetCapable") is False, "IPv6 targets must not be announced"
                    self.checks += 1
                    self.checks += 1
                    control.data_delay = 0
                    count = http.logins
                    for command in ("status", "peers", "services", "egress"):
                        self.run([command] + cfg)
                        self.run([command] + cfg, machine=False)
                    # The egress section is a cross-runtime contract: whichever client wrote the
                    # state file, any of the three CLIs reads it, so the shape is checked here
                    # rather than only in each runtime's own tests.
                    egress = self.run(["egress"] + cfg)["data"]["instances"][0]["egress"]
                    for half in ("consumer", "egress"):
                        assert isinstance(egress.get(half), dict), f"egress.{half} missing"
                        assert isinstance(egress[half].get("active"), bool),                             f"egress.{half}.active is not a boolean"
                    consumer = egress["consumer"]
                    for field, kind in (("rules", list), ("routes", list), ("peers", list),
                                        ("blocked", dict)):
                        assert isinstance(consumer.get(field), kind),                             f"egress.consumer.{field} is not a {kind.__name__}"
                    assert isinstance(egress["egress"].get("refused"), dict),                         "egress.egress.refused is not an object"
                    # Nothing here may carry a credential. The section is configuration and
                    # counters; a runtime that started projecting a token into it would pass its
                    # own tests and fail this one.
                    rendered = json.dumps(egress)
                    for secret in (SECRET, TOKEN):
                        assert secret not in rendered, "the egress section leaked a credential"
                    assert http.logins == count == 1, "query created another login instance"
                    if os.name == "nt":
                        self.run(["status", "--config", str(self.config).upper()])
                    if os.name != "nt":
                        process.send_signal(signal.SIGINT)
                        assert process.wait(timeout=8) in (0, 130), "user stop was reported as failure"
                self.run(["status"] + cfg, 5)
                # Multiple explicitly started processes are listed, not silently selected.
                http.logins = 0
                with self.start("--no-update-check") as first, self.start("--no-update-check") as second:
                    self.wait_ready(first); self.wait_ready(second)
                    deadline = time.monotonic() + 10
                    while True:
                        result = self.run(["status"] + cfg)["data"]["instances"]
                        if len(result) == 2 and all(row["businessReady"] for row in result):
                            break
                        assert time.monotonic() < deadline, "missing concurrent instance"
                    assert http.logins == 2
                    preserved = result[0]
                # A killed process's recently written file is ignored by PID liveness checks.
                self.run(["status"] + cfg, 5)
                # An old snapshot referencing a live PID is still stale and must be ignored.
                prefix = next(iter((self.directory / "state").glob("*.json")), None)
                if prefix is not None:
                    preserved.update(pid=os.getpid(), updatedAtUnixMs=0)
                    prefix.write_text(json.dumps(preserved), encoding="utf-8")
                    self.run(["status"] + cfg, 5)
                    self.dns_restore_refused(prefix, preserved)
                    self.run(["status"] + cfg, 5)
                else:
                    raise AssertionError("no state file was left by the killed instances")
                if os.name != "nt":
                    self.tty_ctrl_c()
                # Stable credential rejection vs transient failure/first-login timeout codes.
                for status, code in ((401, 3), (403, 3), (503, 4)):
                    http.status, http.logins = status, 0
                    self.run(cfg + ["--no-update-check", "--login-timeout", "1"], code, machine=False)
                    assert http.logins == 1, ("unexpected retry", status, http.logins)
                http.status, http.recover, http.logins = 503, True, 0
                with self.start("--no-update-check", "--login-timeout", "10") as process:
                    self.wait_ready(process)
                    assert http.logins == 2, "transient HTTP failure did not recover"
                http.status, http.recover, http.stall, http.logins = 200, False, True, 0
                self.run(cfg + ["--no-update-check", "--login-timeout", "1"], 4, machine=False)
                http.stall = False
                control.reject = True
                self.run(cfg + ["--no-update-check", "--login-timeout", "3"], 3, machine=False)
                control.reject = False
                # DNS failure is retryable but bounded; no external login endpoint is contacted.
                self.fixture("http://specus-cli-test.invalid:1")
                self.env.update(HTTP_PROXY="", HTTPS_PROXY="", ALL_PROXY="", NO_PROXY="*")
                self.run(cfg + ["--no-update-check", "--login-timeout", "1"], 4, machine=False)
                if os.name != "nt":
                    os.chmod(self.directory / "state", 0o755)
                    self.run(["status"] + cfg, 2)
                    os.chmod(self.directory / "state", 0o700)
                    # Symlinked state roots are rejected even if their target is private.
                    original = self.directory / "state"
                    moved = self.directory / "private-target"
                    original.rename(moved)
                    original.symlink_to(moved, target_is_directory=True)
                    try:
                        self.run(["status"] + cfg, 2)
                    finally:
                        original.unlink(); moved.rename(original)
                else:
                    root = str(self.directory / "state")
                    flags = dict(capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    subprocess.run(["icacls", root, "/grant", "*S-1-1-0:(OI)(CI)R"], check=True, **flags)
                    try:
                        self.run(["status"] + cfg, 2)
                    finally:
                        subprocess.run(["icacls", root, "/remove:g", "*S-1-1-0"], check=True, **flags)
            finally:
                http.shutdown(); control.shutdown()
        print(json.dumps(dict(implementation=self.name, platform=os.name, checks=self.checks, result="passed")))


if __name__ == "__main__":
    # A Windows runner's console is cp1252; a runtime log with any other character must still print
    # rather than replace the failure being reported with an encoding error.
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, choices=["go", "dotnet", "java"])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert command, "provide executable after --"
    with tempfile.TemporaryDirectory(prefix="specus-cli-matrix-") as directory:
        Matrix(command, args.name, directory).test()
