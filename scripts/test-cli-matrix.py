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

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
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
        deadline = time.monotonic() + 18
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, choices=["go", "dotnet", "java"])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    assert command, "provide executable after --"
    with tempfile.TemporaryDirectory(prefix="specus-cli-matrix-") as directory:
        Matrix(command, args.name, directory).test()
