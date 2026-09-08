"""CLI local UI: real packaged process, loopback auth/control fixtures, optional Chrome QA.

python scripts/test-cli-ui.py --binary /absolute/specus-client [--browser] [--output PATH]
Browser tests use Python Playwright and an installed Chrome (no shared browser profile).
The generic with_server helper cannot exchange this UI's one-use stdout/stdin codes,
so this harness owns and cleans up its dedicated server processes instead.
"""
import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("cli_matrix", Path(__file__).with_name("test-cli-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def wait_for(check, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError("Timed out waiting for fixture state")


def run(command, name, browser_enabled, output, peers=()):
    checks = 0
    with tempfile.TemporaryDirectory(prefix="specus-ui-fixture-") as directory:
        fixture = matrix.Matrix(command, name, directory)
        command = fixture.command
        lines = queue.Queue()
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        with matrix.ControlServer(("127.0.0.1", 0), matrix.Control) as control, ThreadingHTTPServer(("127.0.0.1", 0), matrix.Http) as auth:
            control.data_delay = 4
            auth.daemon_threads = True
            auth.status, auth.logins, auth.updates, auth.recover, auth.stall = 200, 0, 0, False, False
            auth.control_port = control.server_address[1]
            for server in (control, auth):
                threading.Thread(target=server.serve_forever, daemon=True).start()
            process = subprocess.Popen(command + ["ui", "--config", str(fixture.config), "--no-open"], cwd=directory,
                env=fixture.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", creationflags=flags)
            threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True).start()
            base = code = ""
            def next_code():
                for _ in range(10):
                    line = lines.get(timeout=10)
                    found = re.search(r"[0-9a-f]{64}$", line.strip())
                    if found:
                        return found.group()
                raise AssertionError("No one-use code from test process")
            try:
                while not base:
                    line = lines.get(timeout=10)
                    found = re.search(r"http://127\.0\.0\.1:\d+", line)
                    if found:
                        base = found.group()
                code = next_code()
                def request(path, body=None, token="", expected=200, origin=None):
                    headers = {"Origin": origin or base, "X-Specus-UI": "1", "Content-Type": "application/json", "Authorization": "Bearer " + token}
                    req = urllib.request.Request(base + path, None if body is None else json.dumps(body).encode(), headers)
                    try:
                        response = urllib.request.urlopen(req, timeout=20)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        raw = response.read()
                        assert response.status == expected, (path, response.status)
                        assert matrix.SECRET.encode() not in raw and matrix.TOKEN.encode() not in raw, "secret in API response"
                        return json.loads(raw)
                request("/api/config", expected=401)
                token = request("/api/session", {"code": code})["token"]
                request("/api/session", {"code": code}, expected=401)
                request("/api/config", token=token, origin="https://evil.invalid", expected=403)
                def wire(method, path, body=b"", override=None, remove=(), expected=(200,)):
                    headers = {"Host": base[7:], "Origin": base, "X-Specus-UI": "1", "Content-Type": "application/json", "Authorization": "Bearer " + token}
                    headers.update(override or {})
                    for key in remove:
                        headers.pop(key, None)
                    conn = http.client.HTTPConnection("127.0.0.1", int(base.rsplit(":", 1)[1]), timeout=15)
                    try:
                        conn.request(method, path, body, headers)
                        response = conn.getresponse()
                        raw = response.read()
                        assert response.status in expected, (method, path, response.status)
                        assert response.getheader("Access-Control-Allow-Origin") is None
                        assert matrix.SECRET.encode() not in raw and matrix.TOKEN.encode() not in raw
                        return raw
                    finally:
                        conn.close()
                wire("GET", "/api/config", override={"Host": "evil.invalid"}, expected=(403,))
                wire("GET", "/api/config", override={"Sec-Fetch-Site": "cross-site"}, expected=(403,))
                wire("POST", "/api/config/save", b"{}", remove=("Origin",), expected=(403,))
                wire("POST", "/api/config/save", b"{}", remove=("X-Specus-UI",), expected=(403,))
                wire("POST", "/api/config/save", b"{}", override={"Content-Type": "text/plain"}, expected=(415,))
                wire("POST", "/api/config/save", b"not-json", expected=(400,))
                wire("GET", "/api/connection", expected=(405,))
                wire("OPTIONS", "/api/config", expected=(405,))
                wire("GET", "/api/config?token=NO_QUERY", expected=(400,))
                wire("GET", "/api/%63onfig", expected=(400,))
                wire("POST", "/api/config/save", b"x" * 65537, expected=(400, 413))
                assert b"Content-Security-Policy" not in wire("GET", "/")  # headers aren't reflected into the shell
                checks += 12
                initial = request("/api/config", token=token)
                assert initial["revision"] == "missing"
                changes = dict(serverBaseUrl=f"http://127.0.0.1:{auth.server_port}", apiKey="UI_FIXTURE_KEY", secret="env:CLI_TEST_SECRET")
                request("/api/config/validate", dict(revision="missing", changes=changes), token)
                assert not fixture.config.exists() and auth.logins == auth.updates == 0
                request("/api/config/save", dict(revision="missing", changes=changes), token)
                assert auth.logins == auth.updates == 0
                saved = request("/api/config", token=token)
                request("/api/config/save", dict(revision="missing", changes=changes), token, expected=409)
                duplicate = subprocess.run(command + ["ui", "--no-open", "--config", str(fixture.config)],
                    env=fixture.env, cwd=directory, capture_output=True, timeout=15, creationflags=flags)
                assert duplicate.returncode == 2 and auth.logins == 0
                checks += 8
                for peer_name, peer_command in peers:
                    launcher = matrix.Matrix(peer_command, peer_name, directory).command
                    duplicate = subprocess.run(launcher + ["ui", "--no-open", "--config", str(fixture.config)],
                        env=fixture.env, cwd=directory, capture_output=True, timeout=15, creationflags=flags)
                    assert duplicate.returncode == 2, "another implementation bypassed the UI config lock"
                    # A failed competing manager must not unlink the live owner's lock.
                    duplicate = subprocess.run(command + ["ui", "--no-open", "--config", str(fixture.config)],
                        env=fixture.env, cwd=directory, capture_output=True, timeout=15, creationflags=flags)
                    assert duplicate.returncode == 2
                    checks += 2

                request("/api/connection", dict(action="start", revision=saved["revision"]), token)
                request("/api/connection", dict(action="start", revision=saved["revision"]), token, expected=409)
                wait_for(lambda: request("/api/status", token=token)["runtime"]["controlAuthenticated"])
                assert not request("/api/status", token=token)["runtime"]["businessReady"]
                wait_for(lambda: request("/api/status", token=token)["runtime"]["businessReady"])
                assert auth.logins == 1 and auth.updates == 0
                request("/api/connection", dict(action="stop", revision=saved["revision"]), token)
                assert not request("/api/status", token=token)["runtime"]["processRunning"]
                checks += 4

                # Rejection and a cancelled in-flight HTTP login must leave management alive.
                auth.status = 403
                count = auth.logins
                request("/api/connection", dict(action="start", revision=saved["revision"]), token)
                wait_for(lambda: auth.logins > count)
                wait_for(lambda: not request("/api/status", token=token)["runtime"]["processRunning"])
                assert auth.logins == count + 1
                auth.status, auth.stall = 200, True
                request("/api/connection", dict(action="start", revision=saved["revision"]), token)
                wait_for(lambda: auth.logins > count + 1)
                started = time.monotonic()
                request("/api/connection", dict(action="stop", revision=""), token)
                assert time.monotonic() - started < 10
                assert not request("/api/status", token=token)["runtime"]["processRunning"]
                auth.stall = False
                checks += 2

                # A separate pure CLI remains read-only. Opening this page cannot own/stop it.
                external = subprocess.Popen(command + ["--config", str(fixture.config), "--no-update-check"],
                    cwd=directory, env=fixture.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, creationflags=flags)
                try:
                    wait_for(lambda: request("/api/status", token=token)["otherInstances"])
                    request("/api/connection", dict(action="start", revision=saved["revision"]), token, expected=409)
                    request("/api/connection", dict(action="stop", revision=saved["revision"]), token)
                    assert external.poll() is None
                finally:
                    external.terminate()
                    external.wait(timeout=10)
                checks += 2

                if browser_enabled:
                    from playwright.sync_api import sync_playwright, expect
                    output.mkdir(parents=True, exist_ok=True)
                    # Browser-only first-run fixture: reset the selected TEST configuration.
                    fixture.config.unlink()
                    process.stdin.write("\n"); process.stdin.flush()
                    fresh_code = next_code()
                    with sync_playwright() as playwright:
                        browser = playwright.chromium.launch(channel="chrome", headless=True)
                        context = browser.new_context(viewport={"width": 1280, "height": 900})
                        unexpected, errors = [], []
                        def route_handler(route):
                            if route.request.url.startswith(base + "/"):
                                route.continue_()
                            else:
                                unexpected.append(route.request.url); route.abort()
                        context.route("**/*", route_handler)
                        page = context.new_page()
                        page.on("pageerror", lambda error: errors.append(str(error)))
                        page.on("dialog", lambda dialog: dialog.accept())
                        page.goto(base + "/#" + fresh_code)
                        page.wait_for_load_state("networkidle")
                        expect(page.get_by_role("heading", name="连接设置", exact=True)).to_be_visible()
                        assert page.url == base + "/" and page.evaluate("localStorage.length + sessionStorage.length") == 0
                        # Reconnaissance: rendered page before exercising controls.
                        page.screenshot(path=str(output / "setup-desktop.png"), full_page=True)
                        assert page.get_by_label("服务地址", exact=True).count() == 1
                        page.get_by_label("服务地址", exact=True).fill(f"http://127.0.0.1:{auth.server_port}")
                        page.get_by_label("API Key", exact=True).fill("UI_BROWSER_KEY")
                        page.get_by_label("Secret", exact=True).fill("env:CLI_TEST_SECRET")
                        count = auth.logins
                        page.get_by_role("button", name="离线校验", exact=True).click()
                        expect(page.get_by_role("status")).to_contain_text("离线校验通过")
                        assert not fixture.config.exists() and auth.logins == count
                        page.get_by_role("button", name="保存配置", exact=True).click()
                        expect(page.get_by_role("status")).to_contain_text("配置已保存")
                        assert fixture.config.exists() and auth.logins == count
                        expect(page.get_by_label("Secret", exact=True)).to_have_value("")
                        page.get_by_role("button", name="连接与服务", exact=True).click()
                        page.get_by_role("button", name="连接", exact=True).click()
                        expect(page.get_by_role("heading", name="转发通道就绪", exact=True)).to_be_visible(timeout=18000)
                        assert auth.logins == count + 1 and auth.updates == 0
                        page.screenshot(path=str(output / "connected-desktop.png"), full_page=True)
                        page.set_viewport_size({"width": 360, "height": 800})
                        page.screenshot(path=str(output / "connected-mobile.png"), full_page=True)
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        page.get_by_role("button", name="连接设置", exact=True).click()
                        page.screenshot(path=str(output / "settings-mobile.png"), full_page=True)
                        # Refresh must lock the browser, not stop a running tunnel.
                        page.reload(); page.wait_for_load_state("networkidle")
                        expect(page.get_by_role("button", name="打开工作台")).to_be_visible()
                        assert request("/api/status", token=token)["runtime"]["businessReady"]
                        process.stdin.write("\n"); process.stdin.flush()
                        page.get_by_label("终端中的一次性连接码").fill(next_code())
                        page.get_by_role("button", name="打开工作台").click()
                        expect(page.get_by_role("heading", name="转发通道就绪", exact=True)).to_be_visible(timeout=10000)
                        context.close(); browser.close()
                        assert request("/api/status", token=token)["runtime"]["businessReady"]
                        assert not unexpected and not errors, (unexpected, errors)
                        checks += 10

                request("/api/connection", dict(action="stop", revision=""), token)
                if os.name != "nt":
                    # Real Unix signal semantics, not a Windows executable under WSL.
                    process.send_signal(signal.SIGINT)
                    assert process.wait(timeout=15) in ((0, 130) if name == "java" else (0,))
                    assert not list((Path(directory) / "state").glob("*ui.lock"))
                    checks += 1
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=15)
                auth.shutdown(); control.shutdown()
    print(json.dumps(dict(implementation=name, platform=os.name, browser=browser_enabled, checks=checks, result="passed")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary")
    parser.add_argument("--name", choices=["go", "java", "dotnet"], default="go")
    parser.add_argument("--peer", nargs=2, action="append", default=[], metavar=("NAME", "COMMAND_JSON"))
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(".tmp/ui41/screenshots"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.binary:
        assert not command, "use --binary or command after --, not both"
        command = [str(Path(args.binary).resolve())]
    assert command, "provide --binary or an executable command after --"
    peers = [(name, json.loads(command)) for name, command in args.peer]
    run(command, args.name, args.browser, args.output.resolve(), peers)
