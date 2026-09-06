/** Run against Vite: TRANSFER_TEST_URL=http://127.0.0.1:5178 node scripts/transfer-ui-regression.mjs
 * Uses isolated browser profiles and a mocked discovery/control service; file bytes use real WebRTC.
 * PLAYWRIGHT_MODULE_PATH may point at an existing Playwright installation; no production services are used.
 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE_PATH || "playwright");
const base = process.env.TRANSFER_TEST_URL || "http://127.0.0.1:5178";
const output = process.env.TRANSFER_TEST_OUTPUT || "../../.tmp/transfer-ui-results";
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || "chrome", headless: true });
const tickets = new Map();
const members = new Map();
const apiCalls = [];
const relays = [];
let revision = 0;
let failTickets = false;
const errors = [];
const checks = [];
function pass(name) { checks.push(name); console.log(`PASS ${name}`); }
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(fn, label, timeout = 15000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await fn()) return; await delay(80); }
  throw new Error(`Timed out: ${label}`);
}
function roster() {
  revision += 1;
  for (const recipient of members.values()) {
    recipient.ws.send(JSON.stringify({ type: "roster", rosterRevision: revision, peers: [...members.values()]
      .filter((peer) => peer.peerId !== recipient.peerId && peer.discoverable !== false)
      .map((peer) => ({ peerId: peer.peerId, displayName: peer.displayName,
        connectedAt: new Date().toISOString(), roomRole: "EDITOR", sameRoom: peer.roomId === recipient.roomId && peer.roomToken === recipient.roomToken,
        publicAddress: peer.publicAddress })) }));
  }
}
function relayFrame(target, source, app) {
  const t = Buffer.from(target), s = Buffer.from(source), header = Buffer.alloc(14);
  header.write("STWR"); header[4] = 2;
  header.writeUInt16BE(t.length, 6); header.writeUInt16BE(s.length, 8); header.writeUInt32BE(app.length, 10);
  return Buffer.concat([header, t, s, app]);
}
async function setup(name, shared = false, mobile = false, noRtc = false, authenticated = false, remote = false, brokenRtc = false) {
  const context = await browser.newContext({ viewport: mobile ? { width: 390, height: 844 } : { width: 1440, height: 1000 },
    isMobile: mobile, hasTouch: mobile, acceptDownloads: true });
  await context.addInitScript(({ name, noRtc, authenticated, brokenRtc }) => {
    if (noRtc) window.RTCPeerConnection = undefined;
    if (brokenRtc) window.RTCPeerConnection = class { constructor() { throw new Error("isolated RTC failure"); } };
    if (authenticated) sessionStorage.setItem("access_token", "isolated-test-session");
    localStorage.setItem("public-transfer-client-name", name);
    window.__clipboardWrites = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: {
      read: async () => [{ types: ["text/plain"], getType: async () => new Blob(["read-draft-only"], { type: "text/plain" }) }],
      readText: async () => "read-draft-only",
      writeText: async (text) => { window.__clipboardWrites.push(text); },
      write: async () => {},
    } });
    Object.defineProperty(navigator, "canShare", { configurable: true, value: () => false });
    Object.defineProperty(navigator, "share", { configurable: true, value: undefined });
  }, { name, noRtc, authenticated, brokenRtc });
  let storedAttachment;
  await context.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== base) return route.abort();
    if (url.pathname === "/oidc-config") return route.fulfill({ json: { configured: false, passwordLoginEnabled: true, registrationEnabled: false } });
    if (url.pathname === "/test-object" && route.request().method() === "PUT") return route.fulfill({ status: 200, body: "" });
    if (!url.pathname.startsWith("/api/")) return route.continue();
    const body = route.request().postDataJSON();
    apiCalls.push({ path: url.pathname, body });
    if (url.pathname === "/api/admin/me") return route.fulfill({ json: { id: 1, username: "UX-test", roles: ["USER"] } });
    if (url.pathname.endsWith("attachments/presign-upload")) {
      storedAttachment = { ...body, attachmentId: 901, objectId: "ux-object", status: "PENDING", expiresAt: new Date(Date.now() + 86400000).toISOString() };
      return route.fulfill({ json: { attachmentId: 901, objectId: "ux-object", objectKey: "ux-object", uploadUrl: `${base}/test-object`, uploadHeaders: {}, expiresAt: storedAttachment.expiresAt, attachment: storedAttachment } });
    }
    if (url.pathname.endsWith("attachments/901/complete")) return route.fulfill({ json: { ...storedAttachment, status: "UPLOADED" } });
    if (url.pathname.endsWith("ice-config")) return route.fulfill({ json: { iceServers: [], turnAuthRequired: false } });
    if (url.pathname.endsWith("name-availability")) return route.fulfill({ json: { available: true, clientName: url.searchParams.get("clientName") } });
    if (url.pathname.endsWith("ws-tickets")) {
      if (failTickets) return route.fulfill({ status: 403, json: { error: "invalid room token" } });
      const ticket = `test-ticket-${tickets.size}`; tickets.set(ticket, body);
      return route.fulfill({ json: { ticket, expiresAt: new Date(Date.now() + 60000).toISOString() } });
    }
    if (url.pathname.endsWith("access-tokens/list")) return route.fulfill({ json: [] });
    if (url.pathname.endsWith("access-tokens")) return route.fulfill({ json: { token: "test-member-token", access: { id: 1, role: "EDITOR", label: "test", createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(), revokedAt: null } } });
    if (url.pathname.endsWith("pairing-codes")) return route.fulfill({ json: { id: 1, code: "12345678", role: "EDITOR", label: "test", createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300000).toISOString(), maxUses: 1, usedCount: 0 } });
    if (url.pathname.endsWith("pairing-codes/redeem")) return route.fulfill({ json: { roomId: "ux-team", roomToken: "test-team", role: "EDITOR", expiresAt: new Date(Date.now() + 300000).toISOString() } });
    return route.fulfill({ status: 404, json: { error: "test endpoint not configured" } });
  });
  await context.routeWebSocket("**/ws/public-transfer/discovery?*", (ws) => {
    const body = tickets.get(new URL(ws.url()).searchParams.get("ticket"));
    assert.ok(body, "ticket must be issued before connecting");
    const peer = { ...body, ws, publicAddress: remote ? "203.0.113.20" : "198.51.100.10" }; members.set(body.peerId, peer);
    ws.onMessage((message) => {
      if (typeof message === "string") {
        const value = JSON.parse(message);
        if (value.type === "ping") ws.send(JSON.stringify({ type: "pong" }));
        else members.get(value.targetPeerId)?.ws.send(JSON.stringify({ ...value, sourcePeerId: peer.peerId }));
      } else {
        const tlen = message.readUInt16BE(6), slen = message.readUInt16BE(8);
        const target = message.subarray(14, 14 + tlen).toString();
        const app = message.subarray(14 + tlen + slen);
        relays.push({ source: peer.peerId, target, type: app[5] });
        members.get(target)?.ws.send(relayFrame(target, peer.peerId, app));
      }
    });
    ws.onClose(() => { if (members.get(peer.peerId)?.ws === ws) { members.delete(peer.peerId); roster(); } });
    // Let the page attach its handlers before delivering the initial snapshot.
    setTimeout(() => { if (members.get(peer.peerId)?.ws !== ws) return;
      ws.send(JSON.stringify({ type: "hello", publicAddress: peer.publicAddress, roomRole: body.roomToken ? "OWNER" : "EDITOR" })); roster();
    }, 60);
  });
  const page = await context.newPage();
  page.on("pageerror", (error) => errors.push(`${name}: ${error.message}`));
  await page.goto(`${base}/transfer${shared ? "?room=ux-team#token=test-team" : ""}`);
  await page.waitForLoadState("networkidle");
  await page.getByRole("heading", { name: "互传", exact: true }).waitFor();
  await until(() => [...members.values()].some((peer) => peer.displayName.startsWith(name)), `${name} online`);
  const peer = [...members.values()].find((peer) => peer.displayName.startsWith(name));
  return { context, page, peer };
}
async function paste(page, text) {
  await page.getByTestId("public-transfer-clipboard-text").evaluate((el, text) => {
    const data = new DataTransfer(); data.setData("text/plain", text);
    el.dispatchEvent(new ClipboardEvent("paste", { bubbles: true, clipboardData: data }));
  }, text);
}
async function confirmFiles(page, cloud = false) {
  await page.getByRole("button", { name: cloud ? "确认上传并生成链接" : "确认发送", exact: true }).click();
}
async function leaveWarningEnabled(page) {
  return page.evaluate(() => {
    const event = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(event);
    return event.defaultPrevented;
  });
}
async function boardCount(page) {
  return page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("public-transfer-whiteboard-draft:"))
    .reduce((sum, key) => sum + (JSON.parse(sessionStorage.getItem(key)).strokes?.length || 0), 0));
}
async function injectBoard(target, sourcePeerId, id) {
  const frames = await target.page.evaluate(async ({ targetId, sourcePeerId, id }) => {
    const { encodeAppMessage, encodeRelayAppFrame } = await import("/src/lib/appMessageProtocol.ts");
    const encoded = await encodeAppMessage({ messageType: "whiteboard", payload: { type: "STWB1", kind: "stroke-start", strokeId: id,
      color: "#0066cc", width: 2, point: { x: 0.2, y: 0.2 }, createdAt: Date.now() } });
    return encoded.frames.map((frame) => Array.from(new Uint8Array(encodeRelayAppFrame(targetId, sourcePeerId, frame))));
  }, { targetId: target.peer.peerId, sourcePeerId, id });
  frames.forEach((frame) => members.get(target.peer.peerId).ws.send(Buffer.from(frame)));
}
try {
  const a = await setup("Alpha"), b = await setup("Beta", false, true);
  console.log("RECON", (await a.page.locator("main").innerText()).slice(0, 1400));
  await a.page.screenshot({ path: `${output}/desktop-initial.png`, fullPage: true });
  await b.page.screenshot({ path: `${output}/mobile-initial.png`, fullPage: true });
  assert.match(await a.page.getByTestId("transfer-recipient-bar").innerText(), /请先选择接收设备/);
  pass("discovery never auto-selects a recipient");
  await a.page.getByRole("radio", { name: b.peer.displayName, exact: true }).first().click();
  await a.page.getByRole("tab", { name: /文字与链接/ }).click();
  await paste(a.page, "draft-not-sent");
  assert.equal(await a.page.getByTestId("public-transfer-clipboard-text").inputValue(), "draft-not-sent");
  await delay(300);
  assert.ok(!(await b.page.locator("body").innerText()).includes("draft-not-sent"));
  await a.page.getByRole("button", { name: "读取剪贴板", exact: true }).click();
  await until(async () => (await a.page.getByTestId("public-transfer-clipboard-text").inputValue()) === "read-draft-only", "read into draft");
  assert.ok(!(await b.page.locator("body").innerText()).includes("read-draft-only"));
  pass("paste and clipboard read remain drafts by default");
  await a.page.getByRole("button", { name: "发送文字", exact: true }).click();
  await b.page.getByRole("tab", { name: /文字与链接/ }).click();
  await until(async () => (await b.page.locator("body").innerText()).includes("read-draft-only"), "explicit text received", 25000);
  pass("explicit text send reaches only the selected peer");
  await a.page.getByRole("switch", { name: /粘贴即发送/ }).click();
  await paste(a.page, "quick-send-opt-in");
  await until(async () => (await b.page.locator("body").innerText()).includes("quick-send-opt-in"), "quick paste received");
  pass("opt-in quick paste still sends");
  await a.page.getByRole("tab", { name: /文件传输/ }).click();
  await b.page.getByRole("tab", { name: /文件传输/ }).click();
  await a.page.locator("#public-transfer-file-input").setInputFiles({ name: "ux-check.txt", mimeType: "text/plain", buffer: Buffer.from("real WebRTC file regression") });
  const preflight = a.page.getByRole("dialog");
  await preflight.waitFor();
  assert.match(await preflight.innerText(), /发送前确认/);
  assert.match(await preflight.innerText(), /128 MiB/);
  assert.match(await preflight.innerText(), /不会上传临时存储/);
  assert.equal(await leaveWarningEnabled(a.page), true);
  await delay(200);
  assert.ok(!(await b.page.locator("body").innerText()).includes("ux-check.txt"));
  await a.page.screenshot({ path: `${output}/file-preflight-desktop.png`, fullPage: true });
  pass("file selection checks recipient, memory limit and transport before any send");
  await confirmFiles(a.page);
  await until(async () => await b.page.getByRole("button", { name: "保存到设备", exact: true }).count() > 0, "WebRTC file received", 25000);
  assert.match(await a.page.locator("body").innerText(), /对方已接收/);
  const incomingBox = await b.page.getByRole("heading", { name: "收到的文件" }).boundingBox();
  const dropBox = await b.page.getByTestId("public-transfer-file-dropzone").boundingBox();
  assert.ok(incomingBox.y < dropBox.y, "received files precede the mobile send area");
  const downloadWait = b.page.waitForEvent("download");
  await b.page.getByRole("button", { name: "保存到设备", exact: true }).click();
  const download = await downloadWait;
  assert.equal(download.suggestedFilename(), "ux-check.txt");
  assert.match(await b.page.locator("body").innerText(), /已开始下载/);
  assert.equal(await leaveWarningEnabled(a.page), false);
  assert.equal(await leaveWarningEnabled(b.page), false);
  pass("completed sends and received files with downloads started do not retain the leave guard");
  const inviteCallsBefore = apiCalls.filter((call) => call.path.endsWith("access-tokens")).length;
  const clipboardWritesBefore = (await b.page.evaluate(() => window.__clipboardWrites)).length;
  await b.page.getByRole("button", { name: "系统分享文件", exact: true }).click();
  assert.match(await b.page.locator("body").innerText(), /不支持系统文件分享/);
  assert.equal(apiCalls.filter((call) => call.path.endsWith("access-tokens")).length, inviteCallsBefore);
  assert.equal((await b.page.evaluate(() => window.__clipboardWrites)).length, clipboardWritesBefore);
  await b.page.screenshot({ path: `${output}/mobile-received.png`, fullPage: true });
  pass("real WebRTC file, receiver-first layout, truthful download and no invite fallback");
  await a.page.locator("#public-transfer-file-input").evaluate((input) => {
    // Metadata-only oversize fixture: no 129 MiB buffer or real file is read.
    const file = new File(["fixture"], "oversize.bin");
    Object.defineProperty(file, "size", { value: 128 * 1024 * 1024 + 1 });
    const files = new DataTransfer(); files.items.add(file);
    input.files = files.files; input.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await a.page.getByRole("dialog").waitFor();
  assert.equal(await a.page.getByRole("button", { name: "确认发送", exact: true }).isDisabled(), true);
  assert.match(await a.page.getByRole("dialog").innerText(), /超过设备传输的单文件内存上限/);
  await a.page.getByRole("button", { name: "移除 oversize.bin", exact: true }).click();
  assert.equal(await a.page.getByRole("button", { name: "确认发送", exact: true }).isDisabled(), true);
  await a.page.getByRole("button", { name: "取消发送", exact: true }).click();
  assert.equal(await leaveWarningEnabled(a.page), false);
  pass("oversize files are rejected before sending; remove and cancel release the draft guard");
  await b.page.getByRole("button", { name: "设置", exact: true }).click();
  const settings = b.page.getByRole("dialog");
  await settings.getByRole("switch", { name: "切换允许被发现" }).click();
  assert.equal(await b.page.evaluate(() => localStorage.getItem("public-transfer-discoverable")), null);
  await settings.getByRole("button", { name: "取消", exact: true }).click();
  assert.equal(await b.page.evaluate(() => localStorage.getItem("public-transfer-discoverable")), null);
  await b.page.getByRole("button", { name: "设置", exact: true }).click();
  assert.equal(await settings.getByRole("switch", { name: "切换允许被发现" }).isChecked(), true);
  await settings.getByRole("switch", { name: "切换接收前确认" }).click();
  await settings.getByRole("button", { name: "保存设置", exact: true }).click();
  assert.equal(await b.page.evaluate(() => sessionStorage.getItem("public-transfer-receive-confirmation")), "true");
  pass("settings cancel does not save; save commits preferences");
  await a.page.getByRole("tab", { name: /文字与链接/ }).click();
  await a.page.getByRole("switch", { name: /粘贴即发送/ }).click();
  await a.page.getByTestId("public-transfer-clipboard-text").evaluate((el) => {
    const data = new DataTransfer(); data.items.add(new File(["staged file bytes"], "staged-file.txt", { type: "text/plain" }));
    el.dispatchEvent(new ClipboardEvent("paste", { bubbles: true, clipboardData: data }));
  });
  await a.page.getByText("待发送文件：staged-file.txt", { exact: true }).waitFor();
  await delay(250);
  assert.ok(!(await b.page.locator("body").innerText()).includes("staged-file.txt"));
  await a.page.getByRole("button", { name: "发送这些文件", exact: true }).click();
  await confirmFiles(a.page);
  await b.page.getByRole("button", { name: "拒绝", exact: true }).click();
  await until(async () => (await a.page.locator("body").innerText()).includes("对方拒绝接收"), "rejection remains a failed task");
  pass("pasted files stay staged until an explicit send; receiving confirmation works");
  await a.page.getByRole("button", { name: "传输任务", exact: true }).click();
  const tasks = a.page.getByRole("dialog");
  await tasks.getByRole("button", { name: "清理已完成", exact: true }).click();
  assert.ok(!(await tasks.innerText()).includes("ux-check.txt"));
  assert.match(await tasks.innerText(), /staged-file.txt/);
  await tasks.getByRole("button", { name: "重试", exact: true }).click();
  await b.page.getByRole("button", { name: "接收", exact: true }).click();
  await until(async () => (await tasks.innerText()).includes("对方已接收"), "failed task retry succeeds");
  await tasks.getByRole("button", { name: "完成", exact: true }).click();
  pass("completed-task cleanup preserves the failed file and its working retry action");
  await a.page.getByRole("button", { name: "添加设备", exact: true }).first().click();
  const invite = a.page.getByRole("dialog");
  await invite.getByRole("tab", { name: "输入配对码", exact: true }).click();
  await invite.getByRole("textbox", { name: "对方的配对码", exact: true }).fill("1234 5678");
  assert.ok(await invite.getByRole("button", { name: "连接对方", exact: true }).isEnabled());
  await a.page.keyboard.press("Escape");
  if (await invite.isVisible()) await invite.getByRole("button", { name: "Close", exact: true }).click();
  await invite.waitFor({ state: "hidden" });
  pass("add-device dialog exposes a distinct pairing-code path");
  const c = await setup("Gamma");
  await a.page.getByRole("tab", { name: /文件传输/ }).click();
  await a.page.locator("#public-transfer-file-input").setInputFiles({ name: "offline-draft.txt", mimeType: "text/plain", buffer: Buffer.from("never retarget") });
  await a.page.getByRole("dialog").waitFor();
  await b.context.close();
  await until(async () => (await a.page.getByTestId("transfer-recipient-bar").innerText()).includes("已离线"), "offline target retained");
  assert.equal(await a.page.getByRole("button", { name: "确认发送", exact: true }).isDisabled(), true);
  assert.match(await a.page.getByRole("dialog").innerText(), /原接收设备已离线/);
  await a.page.getByRole("button", { name: "取消发送", exact: true }).click();
  assert.ok(!(await a.page.getByTestId("transfer-recipient-bar").innerText()).includes(`发送给：${c.peer.displayName}`));
  pass("offline recipient is never replaced by another discovered peer");
  await a.page.getByRole("tab", { name: /多人白板/ }).click();
  assert.match(await a.page.getByTestId("collaboration-audience").innerText(), /尚未与任何设备共享/);
  await injectBoard(a, c.peer.peerId, "outsider-nearby");
  await delay(350);
  assert.equal(await boardCount(a.page), 0);
  pass("nearby mode rejects incoming whiteboard collaboration");
  const d = await setup("Delta", true, false, true), e = await setup("Echo", true, false, true);
  await d.page.getByRole("tab", { name: /多人白板/ }).click();
  await e.page.getByRole("tab", { name: /多人白板/ }).click();
  await until(async () => (await d.page.getByTestId("collaboration-audience").innerText()).includes(e.peer.displayName), "explicit room member appears");
  assert.ok(!(await d.page.getByTestId("collaboration-audience").innerText()).includes(c.peer.displayName));
  await injectBoard(d, c.peer.peerId, "outsider-shared"); await delay(200);
  assert.equal(await boardCount(d.page), 0);
  await injectBoard(d, e.peer.peerId, "member-shared");
  await until(async () => (await boardCount(d.page)) > 0, "joined member accepted");
  pass("shared-space receive filter rejects nearby outsiders and accepts explicit members");
  const relayStart = relays.length;
  await d.page.getByRole("button", { name: "画笔", exact: true }).first().click();
  assert.equal(await d.page.getByRole("heading", { name: "发送给谁", exact: true }).count(), 0);
  const canvas = d.page.getByLabel("多人白板画布", { exact: true });
  const board = await canvas.boundingBox();
  await d.page.mouse.move(board.x + 80, board.y + 80);
  await d.page.mouse.down();
  await d.page.mouse.move(board.x + 140, board.y + 110, { steps: 5 });
  await d.page.mouse.up();
  await until(() => relays.slice(relayStart).some((frame) => frame.source === d.peer.peerId && frame.type === 1), "whiteboard sent over relay");
  assert.ok(relays.slice(relayStart).filter((frame) => frame.source === d.peer.peerId && frame.type === 1).every((frame) => frame.target === e.peer.peerId));
  await until(async () => (await boardCount(e.page)) > 0, "whiteboard drawing reaches member");
  assert.equal(await boardCount(c.page), 0);
  pass("whiteboard sender routes drawings only to explicit members, not nearby peers");
  await d.page.screenshot({ path: `${output}/collaboration-members.png`, fullPage: true });
  await d.page.getByRole("button", { name: /邀请参与者/ }).click();
  await d.page.getByRole("dialog").getByRole("button", { name: "复制邀请链接", exact: true }).waitFor();
  assert.equal(await d.page.getByRole("dialog").getByRole("button", { name: "复制邀请链接", exact: true }).count(), 1);
  assert.ok(!(await d.page.getByRole("dialog").innerText()).includes("Token"));
  await delay(400);
  await d.page.screenshot({ path: `${output}/invite.png`, fullPage: true });
  pass("invite has one copy action and no implementation jargon");
  for (const item of [a, c, d, e]) assert.ok(await item.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "no horizontal overflow");
  await Promise.all([a.context.close(), c.context.close(), d.context.close(), e.context.close()]);
  const logged = await setup("Logged", false, true, false, true);
  const presignsBefore = apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length;
  await logged.page.locator("#public-transfer-file-input").setInputFiles({ name: "cloud-test.txt", mimeType: "text/plain", buffer: Buffer.from("isolated cloud upload") });
  await delay(200);
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, presignsBefore);
  await logged.page.getByRole("button", { name: "改为生成文件链接", exact: true }).click();
  await logged.page.locator("#public-transfer-file-input").setInputFiles({ name: "cloud-test.txt", mimeType: "text/plain", buffer: Buffer.from("isolated cloud upload") });
  await logged.page.getByRole("dialog").waitFor();
  assert.match(await logged.page.getByRole("dialog").innerText(), /存储与额度尚未核验/);
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, presignsBefore);
  assert.equal(await leaveWarningEnabled(logged.page), true);
  await logged.page.setViewportSize({ width: 320, height: 720 });
  await delay(350);
  const fileListBox = await logged.page.getByRole("list", { name: "待确认文件", exact: true }).boundingBox();
  assert.ok(fileListBox.height > 40, "file list must not collapse out of the mobile preflight");
  assert.ok(await logged.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await logged.page.screenshot({ path: `${output}/file-preflight-mobile.png`, fullPage: true });
  await logged.page.getByRole("button", { name: "取消发送", exact: true }).click();
  assert.equal(await leaveWarningEnabled(logged.page), false);
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, presignsBefore);
  pass("cloud preflight is metadata-only, fits mobile and cancels without reserving quota");
  await logged.page.locator("#public-transfer-file-input").setInputFiles({ name: "cloud-test.txt", mimeType: "text/plain", buffer: Buffer.from("isolated cloud upload") });
  await confirmFiles(logged.page, true);
  await logged.page.getByText("文件链接已生成", { exact: true }).waitFor();
  assert.match(await logged.page.locator("body").innerText(), /文件有效期：/);
  assert.ok(!(await logged.page.locator("body").innerText()).includes("对方已接收"));
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, presignsBefore + 1);
  pass("signed-in users explicitly choose file links; upload completion is not recipient receipt");
  await logged.page.setViewportSize({ width: 320, height: 720 });
  await delay(350);
  assert.equal(await logged.page.getByRole("heading", { name: "发送给谁", exact: true }).count(), 0);
  assert.equal(await logged.page.getByRole("radiogroup", { name: "发送目标设备", exact: true }).count(), 0);
  assert.ok(await logged.page.locator(".transfer-room-tools .app-apple-tool-tab .text-small").evaluateAll((labels) => labels.every((label) => label.scrollWidth <= label.clientWidth + 1)), "narrow-screen tool names remain readable");
  assert.ok(await logged.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "320px file view has no horizontal overflow");
  await logged.page.screenshot({ path: `${output}/mobile-320-file-link.png`, fullPage: true });
  await logged.context.close();
  pass("file result and recipient controls fit a 320px viewport");
  const recipient = await setup("Remote-receiver", false, false, false, false, true);
  const sender = await setup("Fallback-sender", false, false, false, true, false, true);
  await sender.page.getByRole("radio", { name: recipient.peer.displayName, exact: true }).first().click();
  const beforeFallback = apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length;
  await sender.page.locator("#public-transfer-file-input").setInputFiles({ name: "consent.txt", mimeType: "text/plain", buffer: Buffer.from("explicit cloud consent") });
  const consent = sender.page.getByRole("checkbox", { name: /允许将这些文件上传临时存储/ });
  await consent.waitFor();
  assert.equal(await consent.isChecked(), false);
  await confirmFiles(sender.page);
  await until(async () => (await sender.page.locator("body").innerText()).includes("本次未允许云端存储"), "failed without consent");
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, beforeFallback);
  await sender.page.getByRole("button", { name: "传输任务", exact: true }).click();
  await sender.page.getByRole("dialog").getByRole("button", { name: "重试", exact: true }).click();
  await until(async () => (await sender.page.getByRole("dialog").innerText()).includes("本次未允许云端存储"), "retry keeps no-cloud consent");
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, beforeFallback);
  await sender.page.getByRole("dialog").getByRole("button", { name: "完成", exact: true }).click();
  await sender.page.locator("#public-transfer-file-input").setInputFiles({ name: "consent.txt", mimeType: "text/plain", buffer: Buffer.from("explicit cloud consent") });
  await consent.check();
  await confirmFiles(sender.page);
  await sender.page.getByText("文件链接已生成", { exact: true }).waitFor();
  assert.equal(apiCalls.filter((call) => call.path.endsWith("attachments/presign-upload")).length, beforeFallback + 1);
  pass("failed device transport and retries never upload without consent; explicit fallback uploads once");
  await sender.context.close(); await recipient.context.close();
  failTickets = true;
  const fContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
  await fContext.route("**/oidc-config", (route) => route.fulfill({ json: { configured: false, passwordLoginEnabled: true } }));
  await fContext.route("**/*", (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== base) return route.abort();
    return url.pathname.startsWith("/api/") ? route.fulfill({ status: 403, json: { error: "invalid room token" } }) : route.fallback();
  });
  const f = await fContext.newPage();
  f.on("pageerror", (error) => errors.push(`offline: ${error.message}`));
  await f.goto(`${base}/transfer`); await f.waitForLoadState("networkidle");
  await f.getByText("暂时无法发现设备", { exact: true }).waitFor();
  assert.equal(await f.locator(".nearby-radar").count(), 0);
  await f.screenshot({ path: `${output}/mobile-offline.png`, fullPage: true });
  await fContext.close();
  pass("failed discovery is not an endless scanning state");
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: checks.length, checks, pageErrors: errors, screenshots: output }, null, 2));
} catch (error) {
  console.error("PAGE_ERRORS", errors);
  for (const [index, context] of browser.contexts().entries()) {
    for (const [pageIndex, page] of context.pages().entries()) {
      console.error(`FAILURE_DOM ${index}/${pageIndex}`, (await page.locator("body").innerText()).slice(0, 1800));
      await page.screenshot({ path: `${output}/failure-${index}-${pageIndex}.png`, fullPage: true }).catch(() => {});
    }
  }
  throw error;
} finally {
  await browser.close();
}
