"use strict";
const $ = id => document.getElementById(id);
let token = "", revision = "", original = {}, dirty = false, busy = false, timer, lastState;
const bootstrap = location.hash.slice(1);
history.replaceState(null, "", location.pathname);
function notice(message, error = false) { $("notice").textContent = message; $("notice").hidden = !message; $("notice").dataset.error = String(error); }
function locked(message) { token = ""; clearTimeout(timer); $("workspace").hidden = true; $("unlock").hidden = false; $("unlock-error").textContent = message; }
async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? "GET" : "POST", signal: AbortSignal.timeout(30000), cache: "no-store", credentials: "omit", headers: {"Authorization": "Bearer " + token, "Content-Type": "application/json", "X-Specus-UI": "1"}, body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) { if (response.status === 401 && path !== "/api/session") locked(data.error); throw new Error(data.error || "请求失败，请稍后重试"); }
  return data;
}
async function unlock(code) {
  try { const data = await api("/api/session", {code}); token = data.token; $("code").value = ""; $("unlock").hidden = true; $("workspace").hidden = false; await loadConfig(); await poll(); }
  catch (error) { if (!token) $("unlock-error").textContent = error.message; else { notice(error.message, true); await poll(); } }
}
$("unlock-form").addEventListener("submit", event => { event.preventDefault(); unlock($("code").value.trim()); });
function view(name) { for (const id of ["overview", "settings"]) $(id).hidden = id !== name; document.querySelectorAll("nav button").forEach(button => { if (button.dataset.view === name) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current"); }); $("page-title").textContent = name === "settings" ? "连接设置" : "连接与服务"; }
document.querySelectorAll("nav button").forEach(button => button.addEventListener("click", () => view(button.dataset.view)));
function markDirty(value) { dirty = value; $("dirty-dot").hidden = !value; $("edit-state").textContent = value ? "有未保存修改" : "没有未保存修改"; }
$("config-form").addEventListener("input", () => markDirty(true));
$("config-form").addEventListener("change", () => markDirty(true));
window.addEventListener("beforeunload", event => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
async function loadConfig() {
  const data = await api("/api/config"); revision = data.revision; original = data.fields;
  $("config-path").textContent = data.configPath;
  $("server").value = original.serverBaseUrl;
  const existingCustom = $("device").querySelector("option[data-custom]"); if (existingCustom) existingCustom.remove();
  if (!["noop", "auto"].includes(original.peerMeshDevice)) { const option = document.createElement("option"); option.value = original.peerMeshDevice; option.textContent = "保留现有模式（外部配置）"; option.dataset.custom = "true"; $("device").append(option); }
  $("device").value = original.peerMeshDevice;
  $("api-key").value = ""; $("secret").value = "";
  $("key-hint").textContent = data.hasApiKey ? "已配置 · 留空保留，不回显原值" : "填写管理后台提供的 API Key";
  $("secret-hint").textContent = data.hasSecret ? "已配置 · 留空保留原值或引用" : "支持 env: / file: 引用，不回显解析结果";
  markDirty(false); if (!data.exists || !data.hasApiKey || !data.hasSecret) view("settings");
}
function changes() {
  const result = {};
  if ($("server").value !== original.serverBaseUrl) result.serverBaseUrl = $("server").value;
  if ($("device").value !== original.peerMeshDevice) result.peerMeshDevice = $("device").value;
  if ($("api-key").value.trim()) result.apiKey = $("api-key").value;
  if ($("secret").value.trim()) result.secret = $("secret").value;
  return result;
}
async function action(work) { if (busy) return; busy = true; document.querySelectorAll(".actions button,#config-form button,#config-form input,#config-form select,#reload").forEach(b => b.disabled = true); try { await work(); } catch (error) { notice(error.message, true); } finally { busy = false; document.querySelectorAll("#config-form button,#config-form input,#config-form select,#reload").forEach(b => b.disabled = false); if (lastState) renderState(lastState); } }
$("reload").addEventListener("click", () => { if (!dirty || confirm("丢弃未保存修改并重新载入磁盘配置？")) action(async () => { await loadConfig(); notice("已重新载入磁盘配置，未改变当前连接。"); }); });
$("validate").addEventListener("click", () => action(async () => { const data = await api("/api/config/validate", {revision, changes: changes()}); notice("离线校验通过，未保存也未连接。" + data.warnings.join("；")); }));
$("config-form").addEventListener("submit", event => { event.preventDefault(); action(async () => { const data = await api("/api/config/save", {revision, changes: changes()}); await loadConfig(); notice("配置已保存；连接不会自动启动，运行中的连接需重新连接后应用。" + data.warnings.join("；")); }); });
async function connection(kind) {
  if (kind !== "stop" && dirty) { notice("请先保存或放弃未保存的配置修改，再连接。"); view("settings"); return; }
  if (kind === "restart" && !confirm("断开本页拥有的连接，并使用磁盘中已保存的配置重新连接？")) return;
  await action(async () => { await api("/api/connection", {action: kind, revision}); notice(kind === "stop" ? "断开操作已完成；页面仍可配置。" : "已请求连接，实际结果以连接阶段为准。"); lastState = await api("/api/status"); });
}
$("connect").addEventListener("click", () => connection("start")); $("disconnect").addEventListener("click", () => connection("stop")); $("restart").addEventListener("click", () => connection("restart"));
function catalog(id, items, empty, render) { const list = $(id); list.replaceChildren(); $(id + "-count").textContent = String(items.length); if (!items.length) { const li = document.createElement("li"); li.className = "empty"; li.textContent = empty; list.append(li); } for (const item of items) { const li = document.createElement("li"); render(li, item); list.append(li); } }
function text(parent, tag, value) { const element = document.createElement(tag); element.textContent = value || "—"; parent.append(element); return element; }
function renderState(data) {
  const state = data.runtime, others = data.otherInstances || [], blocked = others.length > 0 || !!data.instanceWarning;
  $("implementation").textContent = ({go: "Go", java: "Java", dotnet: ".NET"}[data.implementation] || "Specus") + " CLI · " + data.version;
  const names = {stopped: "尚未连接", "http-login": "正在登录", connecting: "正在建立控制通道", "control-authenticated": "控制通道已认证", ready: "转发通道就绪"};
  $("connection-title").textContent = names[state.phase] || "连接状态已变化";
  $("connection-detail").textContent = data.instanceWarning || state.detail || "等待当前连接状态";
  const stage = state.businessReady ? 3 : state.controlAuthenticated ? 2 : state.phase === "connecting" ? 1 : 0;
  document.querySelectorAll("[data-stage]").forEach(li => li.classList.toggle("reached", Number(li.dataset.stage) <= stage));
  $("connect").disabled = busy || blocked || state.processRunning || !revision;
  $("disconnect").disabled = busy || !state.processRunning;
  $("restart").disabled = busy || blocked || !state.processRunning;
  $("pending").hidden = !state.processRunning || state.runningRevision === revision;
  $("others-panel").hidden = !others.length; $("others").replaceChildren(); for (const other of others) text($("others"), "li", "PID " + other.pid + " · " + other.phase + " · 不支持网页控制");
  catalog("peers", state.peers || [], state.controlAuthenticated ? "目录中暂无设备。" : "连接后显示设备；当前没有有效目录。", (li, item) => { text(li, "strong", item.clientName); text(li, "p", (item.virtualIp || "无虚拟地址") + " · " + (item.online ? "在线" : "离线")); });
  catalog("services", state.services || [], state.controlAuthenticated ? "尚未收到可访问服务，请检查服务端发布配置。" : "连接后显示服务，不主动扫描内网。", (li, item) => { text(li, "strong", item.name); text(li, "p", item.publisher + " · " + item.application + " · " + (item.available ? "目录允许访问，未探测" : "目录不可用")); text(li, "code", item.accessTarget); const button = text(li, "button", "复制访问地址"); button.disabled = !item.accessTarget; button.addEventListener("click", async () => { try { await navigator.clipboard.writeText(item.accessTarget); notice("已复制访问地址，未执行连通性探测。"); } catch { notice("浏览器未允许复制，请选择地址手动复制。"); } }); });
  $("freshness").textContent = "本机状态更新于 " + new Date().toLocaleTimeString();
}
async function poll() { clearTimeout(timer); if (!token) return; try { lastState = await api("/api/status"); renderState(lastState); } catch (error) { lastState = null; notice(error.message); $("connection-title").textContent = "状态不可用"; $("connection-detail").textContent = "无法确认当前连接，请恢复管理服务后重试。"; $("freshness").textContent = "状态更新失败 · 旧状态不可作为当前在线证明"; document.querySelectorAll("[data-stage]").forEach(li => li.classList.remove("reached")); for (const id of ["peers", "services"]) catalog(id, [], "目录状态已过期，恢复连接后重新获取。", () => {}); document.querySelectorAll(".actions button").forEach(b => b.disabled = true); } if (token) timer = setTimeout(poll, 3000); }
if (bootstrap) unlock(bootstrap);
