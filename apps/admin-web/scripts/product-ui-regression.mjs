/** Isolated admin product regression. Run against local Vite with mocked APIs only.
 * PRODUCT_TEST_URL=http://127.0.0.1:5178 node scripts/product-ui-regression.mjs
 * PLAYWRIGHT_MODULE_PATH may point to an existing installation.
 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir, readFile } from "node:fs/promises";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE_PATH || "playwright");
const base = process.env.PRODUCT_TEST_URL || "http://127.0.0.1:5178";
const output = process.env.PRODUCT_TEST_OUTPUT || "../../.tmp/product-ui-results";
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || "chrome", headless: true });
const checks = [], errors = [], unexpected = [];
const now = new Date().toISOString();
const mockSecret = "isolated-config-secret";
const device = { id: 10, clientName: "UX-device", enabled: true, online: true, connectedSinceMs: null,
  messageReceiveCapable: false, uploadBytes: 0, downloadBytes: 0, createdAt: now, updatedAt: now };
const initialRoutes = [
  { id: 20, route: "protected-app", authEnabled: true, authUsername: "visitor", authPasswordConfigured: true },
  { id: 21, route: "public-app", authEnabled: false, authUsername: null, authPasswordConfigured: false },
].map((route) => ({ clientId: 10, clientName: device.clientName, enabled: true, targetBaseUrl: "http://127.0.0.1:8080",
  createdAt: now, updatedAt: now, ...route }));
function pass(name) { checks.push(name); console.log(`PASS ${name}`); }
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn, label) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) { if (await fn()) return; await delay(70); }
  throw new Error(`Timed out: ${label}`);
}
async function setup(hash, options = {}) {
  const context = await browser.newContext({ viewport: { width: options.mobile ? 390 : 1440, height: options.mobile ? 844 : 1100 }, acceptDownloads: true });
  const state = { clients: options.empty ? [] : [device], credentials: [], routes: structuredClone(initialRoutes), writes: [],
    failClients: false, failServices: false, sharing: true };
  await context.addInitScript(() => {
    sessionStorage.setItem("access_token", "isolated-test-session");
    window.__clipboardWrites = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true,
      value: { writeText: async (text) => window.__clipboardWrites.push(text) } });
  });
  await context.route("**/*", async (route) => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method();
    // The existing static analytics script is blocked too; no browser traffic leaves localhost.
    if (url.origin !== base) {
      if (url.origin !== "https://www.googletagmanager.com") unexpected.push(url.origin);
      return route.abort();
    }
    if (path === "/oidc-config") return route.fulfill({ json: { configured: false, passwordLoginEnabled: true, registrationEnabled: false } });
    if (!path.startsWith("/api/")) return route.continue();
    const body = request.postDataJSON();
    if (method !== "GET") state.writes.push({ path, method, body });
    const json = (value) => route.fulfill({ json: value });
    if (path === "/api/admin/me") return json({ id: 1, username: "UX-test", admin: true, roles: ["ADMIN"] });
    if (path === "/api/admin/clients") return state.failClients
      ? route.fulfill({ status: 503, json: { error: "simulated client listing failure" } }) : json(state.clients);
    if (path === "/api/admin/client-credentials") {
      if (method === "GET") return json(state.credentials);
      const credential = { id: 1, apiKey: body.apiKey || "isolated-api-key", enabled: true, maxOnlineInstances: 2, createdAt: now, updatedAt: now };
      state.credentials.push(credential);
      return json({ credential, secret: mockSecret });
    }
    if (path === "/api/admin/http-routes") return json(state.routes);
    if (path === "/api/admin/clients/10/http-routes" && method === "POST") {
      const created = { ...initialRoutes[0], ...body, id: 30 + state.routes.length, authPasswordConfigured: body.authEnabled };
      state.routes.push(created); return json(created);
    }
    const routeMatch = path.match(/^\/api\/admin\/http-routes\/(\d+)$/);
    if (routeMatch && method === "PUT") {
      const found = state.routes.find((item) => item.id === Number(routeMatch[1]));
      Object.assign(found, body); return json(found);
    }
    if (path === "/api/admin/peer-mesh/status") return json({ enabled: true, cidr: "100.96.0.0/16" });
    if (path === "/api/admin/peer-mesh/stats") return json({ activeSessions: 0, activeDirectSessions: 0, activeRelaySessions: 0, pathTypes: [] });
    if (path === "/api/admin/peer-mesh/devices") return json([]);
    if (path === "/api/admin/peer-mesh/acls" || path === "/api/admin/peer-mesh/service-audit") return json([]);
    if (path === "/api/admin/peer-mesh/sessions") return json({ items: [], total: 0, totalPages: 1 });
    if (path === "/api/admin/peer-mesh/service-sharing") return json({ deploymentEnabled: true, configuredEnabled: state.sharing,
      effectiveEnabled: state.sharing, peerServiceDiscoveryVersion: 1, supportedApplications: ["http"], enabledServiceCount: 1, updatedAt: now });
    if (path === "/api/admin/peer-mesh/services") return state.failServices
      ? route.fulfill({ status: 503, json: { error: "simulated directory failure" } })
      : json([{ id: 1, serviceId: "svc-1", clientId: 10, clientName: "UX-device", name: "UX-service", description: "", transport: "tcp",
        application: "http", targetHost: "127.0.0.1", targetPort: 8080, publishedPort: 18080, path: "/", enabled: true, visibility: "OWNER",
        publishedAddress: "http://100.96.0.10:18080/", createdAt: now, updatedAt: now,
        instances: [{ publisherSessionId: 101, instanceId: "ux-instance", online: true, advertised: true, revision: 1,
          expiresAt: new Date(Date.now() + 600000).toISOString() }] }]);
    if (path === "/api/admin/client-downloads") return json([]);
    unexpected.push(`${method} ${path}`);
    return route.fulfill({ status: 404, json: { error: "unconfigured isolated endpoint" } });
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(`${base}/#/${hash}`);
  await page.waitForLoadState("networkidle");
  return { context, page, state };
}
async function selectDevice(page) {
  const select = page.locator("form").getByRole("button", { name: /客户端/ });
  if ((await select.innerText()).includes("UX-device")) return;
  await select.click();
  await page.getByRole("option", { name: "UX-device", exact: true }).click();
}
async function routeDraft(page, name) {
  await selectDevice(page);
  await page.locator("form").getByRole("textbox", { name: /^路由名/ }).fill(name);
  await page.locator("form").getByRole("textbox", { name: /^目标地址/ }).fill("http://127.0.0.1:8080");
}
async function editRoute(page, name) {
  const row = page.getByRole("row").filter({ hasText: name });
  await row.getByRole("button", { name: "编辑", exact: true }).click();
  const modal = page.getByRole("dialog");
  await modal.waitFor();
  return modal;
}
async function noOverflow(page) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), "page must fit viewport");
}
try {
  const onboarding = await setup("clients", { empty: true });
  const { page: p, state: s } = onboarding;
  await p.getByRole("heading", { name: "接入设备 → 发布第一个服务", exact: true }).waitFor();
  assert.match(await p.locator("main").innerText(), /从下载客户端开始/);
  await p.getByRole("button", { name: "新建接入凭证", exact: true }).click();
  const config = p.getByRole("dialog");
  await config.waitFor();
  const configText = config.locator("textarea");
  assert.deepEqual(JSON.parse(await configText.inputValue()), { serverBaseUrl: base, apiKey: "isolated-api-key", secret: mockSecret });
  const serverInput = config.getByRole("textbox", { name: "服务端地址", exact: true });
  await serverInput.fill("javascript:alert(1)");
  assert.equal(await config.getByRole("button", { name: "下载配置", exact: true }).isDisabled(), true);
  await serverInput.fill(base);
  await config.getByRole("button", { name: "复制配置", exact: true }).click();
  assert.equal(JSON.parse((await p.evaluate(() => window.__clipboardWrites)).at(-1)).secret, mockSecret);
  const downloadEvent = p.waitForEvent("download");
  await config.getByRole("button", { name: "下载配置", exact: true }).click();
  const download = await downloadEvent;
  assert.equal(download.suggestedFilename(), "client.jsonc");
  assert.equal(JSON.parse(await readFile(await download.path(), "utf8")).secret, mockSecret);
  await config.getByRole("button", { name: "关闭配置", exact: true }).click();
  await config.waitFor({ state: "hidden" });
  assert.ok(!(await p.locator("body").innerText()).includes(mockSecret));
  assert.ok(!(await p.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).includes(mockSecret));
  assert.match(await p.locator("main").innerText(), /尚无客户端实例；请先启动客户端/);
  pass("onboarding generates, copies and downloads valid sensitive config, validates URL and clears on close");
  s.clients = [device];
  await p.getByRole("button", { name: "检查设备上线", exact: true }).click();
  await until(async () => (await p.locator("main").innerText()).includes("已有 1 台设备在线"), "online guide");
  assert.match(await p.locator("main").innerText(), /目标应用仍需实际验证/);
  s.failClients = true;
  await p.getByRole("button", { name: "检查设备上线", exact: true }).click();
  await until(async () => (await p.locator("main").innerText()).includes("接入状态未知"), "failure guide");
  pass("onboarding refresh distinguishes online, no instance and unavailable state");
  s.failClients = false;
  await p.getByRole("button", { name: "重新加载接入状态", exact: true }).click();
  await until(async () => (await p.locator("main").innerText()).includes("已有 1 台设备在线"), "online recovered");
  await p.reload(); await p.waitForLoadState("networkidle");
  await p.getByRole("button", { name: "查看接入步骤", exact: true }).waitFor();
  assert.equal(await p.getByRole("button", { name: "查看接入步骤", exact: true }).getAttribute("aria-expanded"), "false");
  await p.setViewportSize({ width: 390, height: 844 });
  await delay(400); await noOverflow(p);
  await p.screenshot({ path: `${output}/onboarding-mobile.png`, fullPage: true });
  await p.goto(`${base}/#/help/quickstart`); await p.waitForLoadState("networkidle");
  await p.getByRole("heading", { name: /创建接入凭证并保存配置/ }).waitFor();
  const help = await p.locator("main").innerText();
  assert.ok(help.indexOf("下载客户端") < help.indexOf("创建接入凭证并保存配置"));
  assert.ok(help.indexOf("创建接入凭证并保存配置") < help.indexOf("启动客户端，确认设备上线"));
  assert.ok(help.indexOf("启动客户端，确认设备上线") < help.indexOf("发布服务并验证访问"));
  pass("help uses real labels and first-login-before-publishing sequence; onboarding fits mobile");

  const empty = await setup("http-routes", { empty: true });
  await empty.page.getByRole("button", { name: "去接入设备", exact: true }).waitFor();
  assert.equal(await empty.page.getByRole("button", { name: "发布受保护的服务", exact: true }).isDisabled(), true);
  assert.equal(empty.state.writes.length, 0);
  empty.state.failClients = true;
  await empty.page.getByRole("button", { name: "刷新", exact: true }).click();
  await until(async () => (await empty.page.locator("main").innerText()).includes("客户端状态读取失败"), "client load failed");
  assert.equal(await empty.page.getByRole("button", { name: "去接入设备", exact: true }).count(), 0);
  pass("HTTP empty state links to onboarding; load failure does not masquerade as no clients");

  const http = await setup("http-routes");
  const h = http.page, hs = http.state;
  await h.getByRole("radio", { name: "受保护访问（用户名与密码）", exact: true }).waitFor();
  assert.equal(await h.getByRole("radio", { name: "受保护访问（用户名与密码）", exact: true }).isChecked(), true);
  assert.equal(hs.routes[1].authEnabled, false);
  await routeDraft(h, "new-protected");
  await h.getByRole("button", { name: "发布受保护的服务", exact: true }).click();
  await delay(200); assert.equal(hs.writes.length, 0);
  await h.getByRole("textbox", { name: /^访问用户名/ }).fill("visitor");
  await h.getByLabel(/^访问密码/).fill("isolated-route-password");
  await h.getByRole("button", { name: "发布受保护的服务", exact: true }).click();
  await h.getByText("已创建 · 待验证访问", { exact: true }).waitFor();
  assert.equal(hs.writes.at(-1).body.authEnabled, true);
  pass("HTTP defaults protected, requires credentials and never equates created with reachable");
  await routeDraft(h, "new-public");
  await h.getByRole("radio", { name: "公开访问（无需认证）", exact: true }).click();
  await h.getByRole("button", { name: "检查并公开发布", exact: true }).click();
  let dialog = h.getByRole("dialog"); await dialog.waitFor();
  assert.match(await dialog.innerText(), /无需登录管理后台；链接不是访问口令/);
  const beforePublic = hs.writes.length;
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  assert.equal(hs.writes.length, beforePublic);
  assert.equal(await h.getByRole("textbox", { name: /^路由名/ }).inputValue(), "new-public");
  await h.getByRole("button", { name: "检查并公开发布", exact: true }).click();
  dialog = h.getByRole("dialog"); await dialog.waitFor();
  await dialog.getByRole("button", { name: "确认公开发布", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  assert.equal(hs.writes.length, beforePublic + 1);
  assert.equal(hs.writes.at(-1).body.authEnabled, false);
  assert.ok(!("authPassword" in hs.writes.at(-1).body));
  pass("public creation requires confirmation; cancel retains draft and writes nothing");
  dialog = await editRoute(h, "protected-app");
  await dialog.getByRole("radio", { name: "公开访问（无需认证）", exact: true }).click();
  assert.equal(await dialog.getByRole("button", { name: "保存", exact: true }).isDisabled(), true);
  const beforeEdit = hs.writes.length;
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  assert.equal(hs.writes.length, beforeEdit);
  dialog = await editRoute(h, "protected-app");
  assert.equal(await dialog.getByRole("radio", { name: "受保护访问（用户名与密码）", exact: true }).isChecked(), true);
  await dialog.getByRole("button", { name: "保存", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  assert.equal(hs.writes.at(-1).body.authEnabled, true);
  assert.ok(!("authPassword" in hs.writes.at(-1).body));
  pass("editing cancel restores access choice; protected save retains configured password");
  dialog = await editRoute(h, "protected-app");
  await dialog.getByRole("radio", { name: "公开访问（无需认证）", exact: true }).click();
  await dialog.getByRole("checkbox", { name: /我确认关闭访问认证/ }).check();
  await dialog.getByRole("button", { name: "保存", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  assert.equal(hs.writes.at(-1).body.authEnabled, false);
  dialog = await editRoute(h, "public-app");
  assert.equal(await dialog.getByRole("radio", { name: "公开访问（无需认证）", exact: true }).isChecked(), true);
  assert.equal(await dialog.getByRole("checkbox", { name: /我确认关闭访问认证/ }).count(), 0);
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await dialog.waitFor({ state: "hidden" });
  pass("protected-to-public edit requires explicit acknowledgement; existing public routes remain unchanged");
  await h.screenshot({ path: `${output}/http-desktop.png`, fullPage: true });
  for (const width of [390, 320]) {
    await h.setViewportSize({ width, height: 844 }); await delay(400); await noOverflow(h);
    await h.screenshot({ path: `${output}/http-${width}.png`, fullPage: true });
  }
  pass("HTTP form and access scope fit 390px and 320px viewports");

  const peer = await setup("peer-mesh");
  await peer.page.getByRole("tab", { name: "服务", exact: true }).click();
  const check = peer.page.getByRole("button", { name: "检查目录状态", exact: true });
  await check.waitFor();
  assert.equal(await peer.page.getByRole("button", { name: "测试可用性", exact: true }).count(), 0);
  await check.click();
  await until(async () => (await peer.page.locator("main").innerText()).includes("目录有效"), "directory result");
  assert.match(await peer.page.locator("main").innerText(), /目标连通性未检测/);
  peer.state.sharing = false;
  await check.click();
  await until(async () => (await peer.page.locator("main").innerText()).includes("全局服务共享已关闭"), "fresh sharing state");
  pass("directory check reads current sharing and reported instance state, not a target probe");
  peer.state.failServices = true;
  await check.click();
  await until(async () => (await peer.page.locator("main").innerText()).includes("检查失败"), "directory error");
  assert.match(await peer.page.locator("main").innerText(), /状态未知/);
  assert.equal(peer.state.writes.length, 0);
  await peer.page.screenshot({ path: `${output}/directory-failure.png`, fullPage: true });
  pass("directory check failure exposes unknown state and retry direction without any mutation");
  peer.state.failServices = false; peer.state.sharing = true;
  await check.click();
  await until(async () => (await peer.page.locator("main").innerText()).includes("目录有效"), "directory recovered");
  assert.ok(!(await peer.page.locator("main").innerText()).includes("Peer 服务状态未知"));
  pass("directory check remains usable after failure and clears the stale error on recovery");
  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, []);
  console.log(`PASS ${checks.length} product browser checks; no page errors or unexpected network requests`);
} catch (error) {
  for (const [index, context] of browser.contexts().entries()) {
    const page = context.pages()[0];
    if (page) {
      console.error(`PAGE ${index}`, (await page.locator("body").innerText()).slice(0, 4500));
      await page.screenshot({ path: `${output}/failure-${index}.png`, fullPage: true }).catch(() => {});
    }
  }
  console.error("page errors", errors, "unexpected network", unexpected);
  throw error;
} finally { await browser.close(); }
