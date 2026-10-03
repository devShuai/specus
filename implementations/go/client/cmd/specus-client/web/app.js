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
function view(name) { for (const id of ["overview", "settings", "rules"]) $(id).hidden = id !== name; document.querySelectorAll("nav button").forEach(button => { if (button.dataset.view === name) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current"); }); $("page-title").textContent = {settings: "连接设置", rules: "出口规则"}[name] || "连接与服务"; if (name === "rules") egressAction(loadRules); }
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
  renderEgress(state);
  $("freshness").textContent = "本机状态更新于 " + new Date().toLocaleTimeString();
}
// Why a rule is not in force, in the words an operator configuring it needs. The code itself is
// always shown next to this, because it is what the CLI and the logs print and what someone
// searching for the problem will have in hand.
const egressRuleReasons = {EGRESS_RULE_DEFAULT_ROUTE: "一期不接管默认路由", EGRESS_RULE_MESH_OVERLAP: "与组网虚拟网段重叠", EGRESS_RULE_MALFORMED: "规则格式不正确（含主机位非零）", EGRESS_RULE_MISSING_TARGET: "没有指定出口设备", EGRESS_RULE_DOMAIN_UNSUPPORTED: "域名规则需要开启系统 DNS 接管（peerEgressDnsTakeover）", EGRESS_RULE_FAKE_IP_OVERLAP: "与 fake-IP 池（peerEgressFakeIpCidr）重叠，池内地址只能由域名规则分配", EGRESS_RULE_EGRESS_NO_DOMAIN: "指向的出口设备在线，但不支持域名目标", EGRESS_RULE_IPV6_UNSUPPORTED: "一期不支持 IPv6 规则", EGRESS_RULE_PORT_UNSUPPORTED: "消费端规则不支持端口字段", EGRESS_RULE_DISABLED: "规则已停用", EGRESS_CONSUMER_DISABLED: "系统接管未开启"};
// Why phase two is not running or has not taken the system DNS over, in the words of the spec's
// refusal table (protocol/spec/peer-egress-dns.md, 开启前检查).
const dnsReasons = {"pool-route-not-installed": "fake-IP 池段的路由没有装上（被别的路由占用，或没有虚拟网卡）", "system-dns-loopback": "系统 DNS 指向回环地址，像是已有别的 DNS 接管者；为免日后回滚时断网，拒绝接管", "system-dns-virtual": "系统 DNS 指向 fake-IP 池、组网网段或别的隧道接口，像是已有别的接管者，拒绝接管", "no-upstream": "读不到可以转发的 IPv4 上游 DNS", "resolv-conf-managed": "/etc/resolv.conf 由别的程序管理（符号链接），不改写它", "nrpt-root-occupied": "已有别人的根命名空间 NRPT 规则", "unsupported-platform": "本平台不支持系统 DNS 接管"};
// Field readers that tolerate state written by another runtime: a wrong type reads as absent, so a
// page never throws on a field somebody spelled differently.
const list = value => Array.isArray(value) ? value.filter(item => item && typeof item === "object") : [];
const count = value => typeof value === "number" && isFinite(value) ? value : 0;
const counters = value => value && typeof value === "object" && !Array.isArray(value) ? Object.entries(value).filter(([, n]) => count(n) !== 0).sort(([a], [b]) => a < b ? -1 : 1).map(([name, n]) => name + "=" + n).join("，") : "";
function issue(parent, title, detail, code, ok = false) { const li = document.createElement("li"); if (ok) li.className = "ok"; text(li, "strong", title); text(li, "p", detail); if (code) text(li, "code", code); parent.append(li); }
// The egress section, following the same rule as the CLI: print what is not working and count the
// rest. A rule that is configured but not in force, a route that was wanted and not installed, and
// an egress device a rule names that is offline are the three ways this feature does nothing while
// everything else looks healthy, so those are listed one by one and nothing that works is.
function renderEgress(state) {
  const section = state.egress && typeof state.egress === "object" ? state.egress : null, issues = $("egress-issues"), badge = $("egress-problems");
  issues.replaceChildren(); badge.removeAttribute("data-problems");
  if (!section) { badge.textContent = "—"; $("egress-summary").textContent = state.processRunning ? "当前运行版本没有提供分流状态。" : "连接后显示本机分流规则是否生效；未连接时不读取路由表。"; $("egress-role").textContent = ""; return; }
  const consumer = section.consumer && typeof section.consumer === "object" ? section.consumer : {}, egress = section.egress && typeof section.egress === "object" ? section.egress : {};
  let problems = 0;
  // Rules saved with takeover off are a state of their own, the one where nothing is in force by
  // design; said as such rather than folded into "not configured" or listed rule by rule as refused.
  if (consumer.enabled === false && list(consumer.rules).length) {
    $("egress-summary").textContent = "系统接管未开启：" + list(consumer.rules).length + " 条规则已保存，均未生效，流量照常从本机出去。在「出口规则」中开启。";
  } else if (consumer.active !== true) {
    $("egress-summary").textContent = "未配置分流规则：所有流量照常从本机出去。";
  } else {
    const rules = list(consumer.rules), routes = list(consumer.routes), peers = list(consumer.peers);
    const refused = rules.filter(rule => rule.inForce !== true), missing = routes.filter(route => route.installed !== true), offline = peers.filter(peer => peer.online !== true);
    const relayed = peers.filter(peer => peer.path === "relay"), pathless = peers.filter(peer => peer.online === true && peer.path === "none");
    $("egress-summary").textContent = rules.length + " 条规则，" + refused.length + " 条未生效 · " + routes.length + " 条路由，" + missing.length + " 条未安装 · " + count(consumer.flows) + " 个流 · " + peers.length + " 个出口设备，" + offline.length + " 个离线，" + relayed.length + " 个经中继";
    for (const rule of refused) issue(issues, "规则 #" + count(rule.index) + "「" + (rule.match || "—") + "」未生效", (egressRuleReasons[rule.code] || "规则被拒绝") + "；这条规则现在不引导任何流量。", rule.code);
    // Each problem says what to do about it, in the words the egress command uses.
    for (const route of missing) issue(issues, "路由 " + (route.cidr || "—") + " 未安装", "该前缀已被本功能之外的路由占用，本该进隧道的流量正从物理网卡出去：" + (route.conflict || "—") + "。处理：删除或缩小那条路由，或修改规则；客户端每 60 秒重试一次。", route.origin);
    for (const peer of offline) issue(issues, "出口设备 " + count(peer.clientId) + " 离线", "指向它的规则已经生效，但流量没有出口可发，会被阻断而不是改走本机。处理：启动该设备或恢复它的网络连接。");
    for (const peer of pathless) issue(issues, "出口设备 " + count(peer.clientId) + " 在线但尚无路径", "直连与中继路径都还没建立，指向它的流量暂时发不出去。处理：稍候；持续如此时检查两台设备到服务端的 UDP 是否可达。");
    if (typeof consumer.routeError === "string" && consumer.routeError) issue(issues, "路由下发失败", consumer.routeError + (consumer.rolledBack === true ? "（本次下发已整体回滚）" : "") + "。处理：" + (/permission|denied|not permitted|elevat|access/i.test(consumer.routeError) ? "以管理员或 root 身份运行客户端，并把虚拟网卡模式设为私有组网（auto）。" : "客户端日志里记录了失败的路由命令，按其提示修正后重启客户端。"));
    for (const peer of relayed) issue(issues, "出口设备 " + count(peer.clientId) + " 经中继连接", "可用，但比直连慢；" + count(peer.flows) + " 个流。直连需要两台设备之间的 UDP 可达。", "", true);
    problems = refused.length + missing.length + offline.length + pathless.length + (consumer.routeError ? 1 : 0);
    if (!problems) issue(issues, "规则均已生效", "路由均已安装，指向的出口设备均在线。", "", true);
    const blocked = counters(consumer.blocked); if (blocked) issue(issues, "拦截计数", "被丢弃、没有放行的包，按原因分别计数：rule 为阻断规则，unsupported-protocol 为不承载的协议（如 ICMP），egress-unavailable 为出口不可用，rejected- 开头为出口拒绝；域名分流另有 fake-ip-unmapped（发往 fake-IP 却没有映射）、fake-ip-stale（映射的名字已不归任何域名规则）、egress-no-domain（出口不支持域名目标）、dns-not-local（不是本机发来的 DNS 查询）。", blocked, !problems);
  }
  // Phase two, present only while peerEgressDnsTakeover is on. Not running, and running without the
  // system DNS pointed at it, both leave every domain rule matching nothing, so each is a problem.
  const dns = consumer.dns && typeof consumer.dns === "object" ? consumer.dns : null;
  if (dns) {
    const upstreams = Array.isArray(dns.upstreams) ? dns.upstreams.filter(item => typeof item === "string") : [];
    if (dns.active !== true) {
      issue(issues, "域名分流未运行", dns.code === "EGRESS_FAKE_IP_POOL_INVALID" ? "fake-IP 池（peerEgressFakeIpCidr）不可用：不是 /8–/24 的 IPv4 网段，或与组网网段、本机网段重叠。域名规则不生效。" : "二期没有运行，域名规则不生效。", dns.code); problems++;
    } else if (dns.takeover !== true) {
      const why = dns.reason ? dnsReasons[dns.reason] || dns.reason : typeof dns.error === "string" ? dns.error : "";
      issue(issues, "系统 DNS 未接管", (why ? why + "。" : "") + "应用的查询没有送到本机应答者，域名规则现在不会命中。处理：按原因修正后重新连接；被强制结束的客户端留下的改动可用 egress dns restore 交还。", dns.code); problems++;
    } else {
      issue(issues, "系统 DNS 已接管", "查询由 " + (dns.listen || "—") + " 应答，" + (upstreams.length ? "其余转发到 " + upstreams.join("、") : "没有上游，需要转发的查询回 SERVFAIL") + "；fake-IP 映射 " + count(dns.mappings) + " 个，隔离中 " + count(dns.quarantined) + " 个。退出客户端时交还系统 DNS。", "", true);
    }
  }
  badge.textContent = problems ? problems + " 个问题" : "正常"; if (problems) badge.dataset.problems = String(problems);
  const refusedByEgress = counters(egress.refused);
  $("egress-role").textContent = egress.active === true ? "本机正在作为出口 · " + count(egress.flows) + " 个流 · 累计 " + count(egress.totalFlows) + " 个" + (refusedByEgress ? " · 拒绝：" + refusedByEgress : "") : "本机未作为出口（尚无策略启用）";
}
async function poll() { clearTimeout(timer); if (!token) return; try { lastState = await api("/api/status"); renderState(lastState); } catch (error) { lastState = null; notice(error.message); $("connection-title").textContent = "状态不可用"; $("connection-detail").textContent = "无法确认当前连接，请恢复管理服务后重试。"; $("freshness").textContent = "状态更新失败 · 旧状态不可作为当前在线证明"; document.querySelectorAll("[data-stage]").forEach(li => li.classList.remove("reached")); for (const id of ["peers", "services"]) catalog(id, [], "目录状态已过期，恢复连接后重新获取。", () => {}); $("egress-issues").replaceChildren(); $("egress-problems").textContent = "—"; $("egress-problems").removeAttribute("data-problems"); $("egress-summary").textContent = "分流状态已过期，不能作为规则仍然生效的证明。"; $("egress-role").textContent = ""; document.querySelectorAll(".actions button").forEach(b => b.disabled = true); } if (token) timer = setTimeout(poll, 3000); }
if (bootstrap) unlock(bootstrap);

// The egress rule editor. Every change goes to the server as one operation with the revision the
// page is showing, and the server writes it the way the egress commands do; the page never builds
// the rule list itself. A change against a file that moved since it was read is refused with 409.
let egressBusy = false, egressState = null;
async function egressAction(work) {
  if (egressBusy || !token) return;
  egressBusy = true; document.querySelectorAll("#rules button, #rules input, #rules select").forEach(element => element.disabled = true);
  try { await work(); } catch (error) { notice(egressError(error.message), true); if (/已被|重新载入/.test(error.message)) { try { await loadRules(); } catch { } } }
  finally { egressBusy = false; document.querySelectorAll("#rules button, #rules input, #rules select").forEach(element => element.disabled = false); if (egressState) renderRules(egressState); }
}
// Server messages carry the rule codes the CLI prints; a person configuring a rule is told the reason
// in their own words with the code next to it.
function egressError(message) { const code = (message.match(/EGRESS_[A-Z0-9_]+/) || [])[0]; return code && egressRuleReasons[code] ? "未修改：" + egressRuleReasons[code] + "（" + code + "）" : message; }
function egressTarget(item) { return item.action === "egress" ? "经出口设备 " + count(item.egressClientId) : item.action === "block" ? "阻断" : item.action === "direct" ? "本地直连" : "未知动作 " + (item.action || "—"); }
async function loadRules() { renderRules(await api("/api/egress")); }
function applyEgress(data) { revision = data.revision; renderRules(data); if (lastState) renderState(lastState); }
async function change(body, done) { const data = await api("/api/egress/change", Object.assign({revision: egressState ? egressState.revision : ""}, body)); applyEgress(data); notice(data.saved === false ? "配置已是所需状态，未做修改。" : done + "已写入配置文件；运行中的连接需重新连接后应用。" + (data.warnings || []).map(egressWarning).join("；")); }
function egressWarning(line) { return /peerMeshDevice is noop/.test(line) ? "注意：虚拟网卡模式为 noop，没有可接管路由的网卡；请在「连接设置」改为私有组网（auto）。" : line; }
function renderRules(data) {
  egressState = data; const rules = list(data.rules), on = data.enabled === true;
  $("takeover-state").textContent = on ? "已开启" : "已关闭";
  $("takeover-detail").textContent = on ? "命中规则的目标由系统接管；出口不可用时这些目标被阻断，不会改走本机。" : rules.length ? rules.length + " 条规则已保存，均未生效：流量照常从本机出去。" : "尚未配置规则；流量照常从本机出去。";
  $("takeover").textContent = on ? "关闭接管" : "开启接管"; $("takeover").disabled = egressBusy;
  $("rules-count").textContent = String(rules.length);
  const target = $("rules-list"); target.replaceChildren();
  if (!rules.length) { const li = document.createElement("li"); li.className = "empty"; li.textContent = "尚未配置规则。添加规则后仍需开启系统接管才会生效。"; target.append(li); }
  rules.forEach((rule, index) => {
    const li = document.createElement("li"); if (rule.enabled === false) li.className = "off";
    text(li, "strong", "#" + index + " " + (rule.match || "—") + " → " + egressTarget(rule));
    const state = rule.refusal ? "不会生效：" + (egressRuleReasons[rule.refusal] || "规则被拒绝") : rule.enabled === false ? "已停用" : on ? "已启用，按配置生效" : "已启用，开启系统接管后生效";
    text(li, "p", state); if (rule.refusal) text(li, "code", rule.refusal);
    const buttons = document.createElement("div"); buttons.className = "rule-actions"; li.append(buttons);
    const add = (label, handler, disabled = false) => { const button = text(buttons, "button", label); button.type = "button"; button.disabled = egressBusy || disabled; button.addEventListener("click", () => egressAction(handler)); };
    add(rule.enabled === false ? "启用" : "停用", () => change({op: rule.enabled === false ? "enable" : "disable", index}, "规则 #" + index + (rule.enabled === false ? " 已启用，" : " 已停用，")));
    add("上移", () => change({op: "move", index, to: index - 1}, "规则已上移，"), index === 0);
    add("下移", () => change({op: "move", index, to: index + 1}, "规则已下移，"), index === rules.length - 1);
    add("删除", async () => { if (confirm("删除规则 #" + index + "「" + rule.match + "」？")) await change({op: "remove", index}, "规则已删除，"); });
    target.append(li);
  });
}
$("rules-reload").addEventListener("click", () => egressAction(async () => { await loadRules(); notice("已重新载入出口规则。"); }));
$("takeover").addEventListener("click", () => egressAction(async () => {
  if (!egressState) return;
  if (egressState.enabled === true) { if (confirm("关闭系统接管？规则保留，但不再接管任何流量；运行中的连接需重新连接后应用。")) await change({op: "takeover", enabled: false}, "系统接管已关闭，"); return; }
  const accepted = confirm("开启系统接管：\n\n· 需要创建虚拟网卡与安装路由的权限（管理员或 root；虚拟网卡模式不能是 noop）\n· 只接管规则命中的目标，其余流量保持本地直连\n· 命中「经出口设备」规则而出口不可用时，这些目标被阻断，不会改走本机\n\n确认开启？");
  if (accepted) await change({op: "takeover", enabled: true, confirmed: true}, "系统接管已开启，");
}));
function syncTargetField() { $("rule-target-field").hidden = $("rule-action").value !== "egress"; }
$("rule-action").addEventListener("change", syncTargetField); syncTargetField();
$("rule-form").addEventListener("submit", event => { event.preventDefault(); egressAction(async () => {
  const body = {op: "add", match: $("rule-match").value.trim(), action: $("rule-action").value, disabled: $("rule-disabled").checked};
  if (body.action === "egress") { const id = Number($("rule-target").value.trim()); if (!Number.isInteger(id) || id <= 0) { notice("请填写出口设备 ID（正整数）。", true); return; } body.egressClientId = id; }
  if ($("rule-position").value === "start") body.at = 0;
  await change(body, "规则已添加，"); $("rule-match").value = ""; $("rule-disabled").checked = false;
}); });
// A real connection from this device, told apart from the preview: it says whether the address
// answers, not which path carried it.
// The preview's refusals, in the words of the CLI (protocol/spec/peer-egress-dns.md, 预演一个域名).
function previewError(message) {
  if (/needs an IPv4 address/.test(message)) return "连通测试只接受 IPv4 地址：名字会在本机解析，不代表出口那边的解析结果。";
  if (/not a name a domain rule can match/.test(message)) return "这个名字不是域名规则能匹配的写法：标签只能用 a-z、0-9 和 -，国际化域名写成 punycode（xn--）。";
  return /IPv4/.test(message) ? "请填写一个 IPv4 地址或域名。" : message;
}
$("preview-connect").addEventListener("click", () => egressAction(async () => {
  const port = Number($("preview-port").value.trim());
  if (!Number.isInteger(port) || port < 1 || port > 65535) { $("preview-result").textContent = "请填写 1–65535 之间的端口。"; return; }
  let data; try { data = await api("/api/egress/test", {address: $("preview-address").value.trim(), connect: port}); }
  catch (error) { $("preview-result").textContent = previewError(error.message); return; }
  const probe = data.connect || {}, target = data.address + ":" + port;
  $("preview-result").textContent = probe.ok === true ? "连通测试：" + target + " 在 " + count(probe.millis) + " ms 内连上。这只说明能连上，不说明走了哪条路径；去向请用预演查看。" : "连通测试：" + target + " 连接失败（" + (probe.error || "未知原因") + "）。";
}));
$("preview-form").addEventListener("submit", event => { event.preventDefault(); egressAction(async () => {
  let data; try { data = await api("/api/egress/test", {address: $("preview-address").value.trim()}); }
  catch (error) { $("preview-result").textContent = previewError(error.message); return; }
  if (data.kind === "domain") {
    // A name is never resolved here: the preview says what the responder would answer and where the
    // name then goes, or why domain rules are not in force.
    const rule = data.matchedRuleIndex >= 0 ? "命中域名规则 #" + data.matchedRuleIndex : "未命中任何域名规则";
    const dns = {fake: "DNS 查询由本机应答者回一个 fake-IP，名字交给出口解析", forward: "DNS 查询转发给系统原来的 DNS，返回的地址再按 IPv4 规则判断"}[data.dns] || "DNS 未接管，名字由系统 DNS 解析";
    const outcome = value => value === "egress" ? "经出口设备 " + count(data.egressClientId) + "（由它解析名字）" : value === "block" ? "阻断" : "由系统 DNS 解析，之后的去向请用预演查看解析出的地址";
    $("preview-result").textContent = data.address + "：" + rule + "；" + dns + "；" + (data.resultWithTakeover ? "域名规则当前不生效，开启后" + outcome(data.resultWithTakeover) : outcome(data.result)) + "。仅按配置判断，未查询 DNS，也未建立连接。";
    return;
  }
  const rule = data.matchedRuleIndex >= 0 ? "命中规则 #" + data.matchedRuleIndex : "未命中任何规则";
  const outcome = value => value === "egress" ? "经出口设备 " + count(data.egressClientId) : value === "block" ? "阻断" : "本地直连";
  $("preview-result").textContent = data.address + "：" + rule + "，" + (data.resultWithTakeover ? "系统接管未开启，当前本地直连；开启后" + outcome(data.resultWithTakeover) : outcome(data.result)) + "。仅按配置判断，未建立连接。";
}); });
