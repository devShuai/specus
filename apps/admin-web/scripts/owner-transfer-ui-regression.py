"""Headless UI regression against a local Vite dev/preview server; all APIs are mocked.

pip install playwright && python -m playwright install chromium
OWNER_UI_URL=http://127.0.0.1:5178 python scripts/owner-transfer-ui-regression.py
This checks browser accessibility/interaction, NOT server authorization or persistence.
"""
import json
import os
import re
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright

base = os.environ.get("OWNER_UI_URL", "http://127.0.0.1:5178").rstrip("/")
assert urlparse(base).hostname in ("127.0.0.1", "localhost", "::1"), "Use an isolated local server"
errors = []
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    try:
        def setup(is_admin):
            context = browser.new_context(viewport={"width": 390, "height": 844})
            context.add_init_script("sessionStorage.setItem('access_token','isolated-ui-fixture');sessionStorage.setItem('login_type','password')")
            clients = [dict(id=10, clientName="离线设备", ownerUsername="alice", enabled=False, online=False),
                       dict(id=11, clientName="另一台设备", ownerUsername="carol", enabled=True, online=False)]
            credential = dict(id=50, apiKey="synthetic-fixture-key", ownerUsername="alice", enabled=False, maxOnlineInstances=4)
            users = [dict(username=name, role="ADMIN" if name == "operator" else "USER", enabled=True, builtIn=name == "operator")
                     for name in ("operator", "alice", "Bob", "carol")]
            posts = []

            def route_request(route):
                req = route.request
                url = urlparse(req.url)
                if not req.url.startswith(base + "/"):
                    return route.abort()
                if url.path == "/oidc-config":
                    return route.fulfill(json=dict(configured=False, passwordLoginEnabled=True, registrationEnabled=False))
                if not url.path.startswith("/api/"):
                    return route.continue_()
                path = url.path.removeprefix("/api/admin")
                if path == "/me":
                    return route.fulfill(json=dict(username="operator" if is_admin else "alice", admin=is_admin, roles=["ADMIN" if is_admin else "USER"]))
                if path == "/clients":
                    return route.fulfill(json=clients)
                if path == "/client-credentials":
                    return route.fulfill(json=[credential])
                if path == "/users":
                    return route.fulfill(json=users)
                if path == "/users/Bob" and req.method == "DELETE":
                    return route.fulfill(status=409, json=dict(error="resources remain", clients=2, credentials=1))
                if path in ("/clients/10/owner-transfer", "/client-credentials/50/owner-transfer"):
                    group = path.startswith("/client-credentials/")
                    if req.method == "POST":
                        posts.append(dict(path=path, body=req.post_data_json))
                        assert group and posts[-1]["body"] == dict(scope="credential-group", targetUsername="Bob", expectedRevision="fixture-revision")
                        credential["ownerUsername"] = "Bob"
                        for client in clients:
                            client["ownerUsername"] = "Bob"
                        return route.fulfill(json=dict(scope="credential-group", targetUsername="Bob", credentialId=50,
                                                       affectedClientIds=[10, 11], changed=True, accessRetained=True))
                    return route.fulfill(json=dict(scope="credential-group" if group else "single", clientId=None if group else 10,
                        credentialId=50, credentialOwnerUsername=credential["ownerUsername"], credentialEnabled=False,
                        affectedClients=[{key: row[key] for key in ("id", "clientName", "ownerUsername", "enabled")} for row in clients],
                        affectedClientCount=2, canTransfer=group, conflictCode=None if group else "CREDENTIAL_SHARED",
                        revision="fixture-revision" if group else None, accessRetained=True))
                return route.fulfill(status=404, json=dict(error="isolated fixture endpoint not configured"))

            context.route("**/*", route_request)
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            return context, page, posts

        context, page, posts = setup(True)
        page.goto(base + "/#/clients")
        page.wait_for_load_state("networkidle")
        # Mobile cards have no row role. The credential entry comes first, then this client.
        page.get_by_role("button", name="转移管理归属", exact=True).nth(1).click()
        modal = page.get_by_role("dialog", name="转移管理归属", exact=True)
        expect(modal.get_by_role("button", name="查看凭证整组预览")).to_be_visible()
        modal.get_by_role("button", name=re.compile("目标账号")).press("Enter")
        # A body-level Select portal inside Modal was aria-hidden: this must use the accessible role.
        page.get_by_role("option", name="Bob", exact=True).press("Enter")
        checkbox = modal.get_by_role("checkbox")
        expect(checkbox).to_be_disabled()
        assert posts == []
        modal.get_by_role("button", name="查看凭证整组预览").click()
        expect(modal.get_by_role("button", name="转移此凭证及 2 台设备")).to_be_visible()
        expect(checkbox).not_to_be_checked()
        expect(modal.get_by_role("button", name=re.compile("目标账号"))).to_contain_text("Bob")
        expect(modal).to_contain_text("不是安全交接")
        expect(modal).not_to_contain_text("synthetic-fixture-key")
        # The native checkbox input is visually hidden behind its labelled control.
        # Exercise its real keyboard interaction, without forcing a pointer click.
        checkbox.focus()
        page.keyboard.press("Space")
        expect(checkbox).to_be_checked()
        modal.get_by_role("button", name="转移此凭证及 2 台设备").click()
        expect(modal.get_by_role("heading", name="管理归属已转移")).to_be_visible()
        expect(modal.get_by_role("link", name="查看新归属资源")).to_have_attribute("href", "#/clients?owner=Bob&section=credentials")
        assert len(posts) == 1
        modal.get_by_role("button", name="完成", exact=True).click()
        page.set_viewport_size(dict(width=1440, height=1080))
        page.goto(base + "/#/system")
        page.wait_for_load_state("networkidle")
        page.get_by_role("row").filter(has_text=re.compile("^Bob")).get_by_role("button", name="删除", exact=True).click()
        page.get_by_role("dialog").get_by_role("button", name="删除", exact=True).click()
        blocked = page.get_by_role("dialog", name="先处理名下资源，再删除账号")
        expect(blocked).to_contain_text("2 个客户端")
        expect(blocked).to_contain_text("1 个接入凭证")
        expect(blocked.get_by_role("link", name="查看并转移客户端")).to_have_attribute("href", "#/clients?owner=Bob&section=clients")
        blocked.get_by_role("link", name="查看并转移接入凭证").click()
        expect(page.get_by_text("正在处理「Bob」的资源", exact=True)).to_be_visible()
        context.close()
        member, page, member_posts = setup(False)
        page.goto(base + "/#/clients")
        page.wait_for_load_state("networkidle")
        expect(page.get_by_role("button", name="转移管理归属", exact=True)).to_have_count(0)
        assert not member_posts and not errors, errors
        member.close()
        print("PASS mocked UI: accessible keyboard account selection, explicit shared-group confirmation, scope-bound POST, navigation links, deletion409, mobile and nonadmin entry visibility")
    finally:
        browser.close()
