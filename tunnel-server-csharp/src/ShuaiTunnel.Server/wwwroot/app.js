'use strict';

/* ================================================================== *
 *  shuai-tunnel 管理后台前端
 *  - 单文件 + 事件委托（无内联 onclick / onsubmit / onchange，方便启用 CSP）
 *  - 按面板拆分 loadXxx()，变更后只刷新受影响部分
 *  - sessionStorage 中记录 login_type，避免密码登录后 logout 误跳 OIDC end_session
 * ================================================================== */

let clientCache = new Map();
let tunnelCache = new Map();
let httpRouteCache = new Map();
let editTarget = null;
let editTunnelTarget = null;
let editHttpRouteTarget = null;
let oidcConfig = null;
const connectionsState = { clientId: null, success: null, from: null, to: null, page: 0, size: 50, totalPages: 0, total: 0 };
/* HTTP 路由面板过滤态。clientId=null 表示展示全部客户端的路由（包含离线，因为后台是权威）。 */
const httpRoutesState = { clientId: null };

const $ = sel => document.querySelector(sel);
const safeJson = async response => { try { return await response.json(); } catch { return {}; } };

const api = async (path, options = {}) => {
  const headers = { 'Content-Type':'application/json', ...(options.headers || {}) };
  const token = sessionStorage.getItem('access_token');
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const response = await fetch(`/api/admin${path}`, { ...options, headers });
  if (response.status === 401) { handleUnauthorized(); throw new Error('登录已过期，请重新登录'); }
  if (!response.ok) throw new Error((await safeJson(response)).error || response.statusText);
  return response.status === 204 ? null : response.json();
};

/* ---------- format helpers ---------- */
const formatBytes = value => {
  const units = ['B','KB','MB','GB','TB']; let index = 0; let size = Number(value || 0);
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
  return `${size.toFixed(index ? 2 : 0)} ${units[index]}`;
};
const formatDateTime = value => {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString('zh-CN', { hour12:false });
};
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
const tdTime = value => value
  ? `<td title="${escapeHtml(value)}">${escapeHtml(formatDateTime(value))}</td>`
  : `<td class="muted">-</td>`;
const emptyRow = (colspan, text = '暂无数据') => `<tr class="empty"><td colspan="${colspan}">${escapeHtml(text)}</td></tr>`;
const loadingRow = colspan => `<tr class="empty"><td colspan="${colspan}" class="muted">加载中…</td></tr>`;

function formatDuration(from, to) {
  if (!from) return '-';
  const start = new Date(from);
  if (Number.isNaN(start.getTime())) return '-';
  const end = to ? new Date(to) : new Date();
  if (Number.isNaN(end.getTime())) return '-';
  const ms = end - start;
  if (ms < 0) return '-';
  const active = !to;
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return active ? `~${sec}s` : `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return active ? `~${min}m${sec % 60}s` : `${min}m${sec % 60}s`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return active ? `~${hr}h${min % 60}m` : `${hr}h${min % 60}m`;
  const day = Math.floor(hr / 24);
  return active ? `~${day}d${hr % 24}h` : `${day}d${hr % 24}h`;
}

/* ---------- toast ---------- */
function toast(message, type = 'success') {
  const container = $('#toasts');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  const msg = document.createElement('span'); msg.className = 'toast-msg'; msg.textContent = message;
  const close = document.createElement('button'); close.className = 'toast-close'; close.setAttribute('aria-label','关闭'); close.textContent = '×';
  const remove = () => { el.classList.add('toast-out'); setTimeout(() => el.remove(), 220); };
  close.onclick = remove;
  el.append(msg, close);
  container.appendChild(el);
  if (type !== 'error') setTimeout(remove, 4000);
}

/* ---------- dialog helpers ---------- */
function openDialog(id) {
  const dlg = $(`#${id}`);
  if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open','');
}
function closeDialog(id) {
  const dlg = $(`#${id}`);
  if (typeof dlg.close === 'function') dlg.close(); else dlg.removeAttribute('open');
}

function showPassword(password, clientName, note) {
  $('#pw-title').textContent = clientName ? `客户端「${clientName}」密码` : '客户端密码';
  $('#pw-value').value = password;
  $('#pw-note').textContent = note || '这是新生成的密码，仅显示一次。请立即复制并妥善保存。';
  openDialog('passwordDialog');
  setTimeout(() => { try { $('#pw-value').select(); } catch (_) {} }, 50);
}
async function copyPassword() {
  const value = $('#pw-value').value;
  try {
    await navigator.clipboard.writeText(value);
    toast('密码已复制到剪贴板');
  } catch {
    const input = $('#pw-value');
    try {
      input.focus(); input.select(); input.setSelectionRange(0, value.length);
      document.execCommand && document.execCommand('copy');
      toast('密码已复制', 'info');
    } catch { toast('复制失败，请手动选中复制', 'error'); }
  }
}

/* ================================================================== *
 *  Renderers — 输入数据，输出 DOM；不发请求
 * ================================================================== */

function renderOverview(data) {
  $('#overview').innerHTML = [
    ['客户端', data.clients], ['在线', data.onlineClients], ['成功连接', data.successfulConnections],
    ['失败连接', data.failedConnections], ['代理连接', data.externalConnections],
    ['拒绝连接', data.rejectedExternalConnections],
    ['上传', formatBytes(data.uploadBytes)], ['下载', formatBytes(data.downloadBytes)]
  ].map(([label, value]) => `<div class="stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
}

function renderClients(clients) {
  clientCache = new Map(clients.map(c => [c.id, c]));
  $('#clients').innerHTML = clients.length
    ? clients.map(c => {
        const statusText = `${c.online ? '在线' : '离线'} / ${c.enabled ? '启用' : '停用'}`;
        const onlineSuffix = c.online && c.connectedSinceMs
          ? ` · ${formatDuration(c.connectedSinceMs, null)}`
          : '';
        const statusTitle = c.online && c.connectedSinceMs
          ? `登录于 ${formatDateTime(c.connectedSinceMs)}`
          : '';
        return `<tr>
        <td>${c.id}</td>
        <td><code>${escapeHtml(c.clientName)}</code></td>
        <td class="${c.online ? 'ok' : 'muted'}"${statusTitle ? ` title="${escapeHtml(statusTitle)}"` : ''}>${escapeHtml(statusText)}${escapeHtml(onlineSuffix)}</td>
        <td>${c.connectionRateLimitPerMinute || '不限'}</td>
        <td>${formatBytes(c.uploadBytes)}</td>
        <td>${formatBytes(c.downloadBytes)}</td>
        ${tdTime(c.createdAt)}
        <td>
          <div class="actions">
            <button class="secondary" data-action="editClient" data-id="${c.id}">编辑</button>
            <button class="secondary" data-action="pushNatControl" data-id="${c.id}">下发映射</button>
            <button class="danger" data-action="deleteClient" data-id="${c.id}">删除</button>
          </div>
        </td></tr>`;
      }).join('')
    : emptyRow(8);

  syncClientSelectors(clients);
}

function syncClientSelectors(clients) {
  const sel = $('#tunnelClientId');
  if (sel) {
    const prev = sel.value;
    sel.innerHTML = clients.length
      ? clients.map(c => `<option value="${c.id}">${escapeHtml(c.clientName)}</option>`).join('')
      : '<option value="" disabled>无客户端</option>';
    if (prev && [...sel.options].some(o => o.value === prev)) sel.value = prev;
  }
  const httpCreate = $('#httpRouteCreateClientId');
  if (httpCreate) {
    const prevCreate = httpCreate.value;
    httpCreate.innerHTML = clients.length
      ? clients.map(c => `<option value="${c.id}">${escapeHtml(c.clientName)}</option>`).join('')
      : '<option value="" disabled>无客户端</option>';
    if (prevCreate && [...httpCreate.options].some(o => o.value === prevCreate)) httpCreate.value = prevCreate;
  }
  const filt = $('#connClientFilter');
  if (filt) {
    const prevFilt = filt.value;
    filt.innerHTML = '<option value="">全部</option>' +
      clients.map(c => `<option value="${c.id}">${escapeHtml(c.clientName)}</option>`).join('');
    if (prevFilt && [...filt.options].some(o => o.value === prevFilt)) {
      filt.value = prevFilt;
    } else {
      connectionsState.clientId = null;
    }
  }
  const httpFilt = $('#httpRouteClientFilter');
  if (httpFilt) {
    const prevHttp = httpFilt.value;
    httpFilt.innerHTML = '<option value="">全部</option>' +
      clients.map(c => `<option value="${c.id}">${escapeHtml(c.clientName)}</option>`).join('');
    if (prevHttp && [...httpFilt.options].some(o => o.value === prevHttp)) {
      httpFilt.value = prevHttp;
    } else {
      /* 选中的客户端已不存在（被删）——回退到"全部"并清空过滤态 */
      httpRoutesState.clientId = null;
    }
  }
}

function renderTunnels(tunnels) {
  tunnelCache = new Map(tunnels.map(t => [t.id, t]));
  $('#tunnels').innerHTML = tunnels.length
    ? tunnels.map(t => `<tr>
      <td>${t.id}</td>
      <td>${escapeHtml(t.clientName)}</td>
      <td><code>${t.listenPort}</code></td>
      <td><code>${escapeHtml(t.targetAddress)}:${t.targetPort}</code></td>
      <td><span class="status-toggle ${t.enabled ? 'status-on' : 'status-off'}" role="button"
               aria-pressed="${t.enabled ? 'true' : 'false'}" tabindex="0"
               title="点击切换状态" data-action="toggleTunnel" data-id="${t.id}">${t.enabled ? '启用' : '停用'}</span></td>
      ${tdTime(t.updatedAt || t.createdAt)}
      <td>
        <div class="actions">
          <button class="secondary" data-action="editTunnel" data-id="${t.id}">编辑</button>
          <button class="danger" data-action="deleteTunnel" data-id="${t.id}">删除</button>
        </div>
      </td></tr>`).join('')
    : emptyRow(7);
}

function renderHttpRoutes(items) {
  httpRouteCache = new Map(items.map(r => [r.id, r]));
  $('#httpRoutes').innerHTML = items.length
    ? items.map(r => `<tr>
      <td>${r.id}</td>
      <td>${escapeHtml(r.clientName)}</td>
      <td><code>${escapeHtml(r.route)}</code></td>
      <td>${r.targetBaseUrl ? `<code>${escapeHtml(r.targetBaseUrl)}</code>` : '<span class="muted">-</span>'}</td>
      <td><span class="status-toggle ${r.enabled ? 'status-on' : 'status-off'}" role="button"
               aria-pressed="${r.enabled ? 'true' : 'false'}" tabindex="0"
               title="点击切换状态" data-action="toggleHttpRoute" data-id="${r.id}">${r.enabled ? '启用' : '停用'}</span></td>
      ${tdTime(r.updatedAt || r.createdAt)}
      <td>
        <div class="actions">
          <button class="secondary" data-action="editHttpRoute" data-id="${r.id}">编辑</button>
          <button class="danger" data-action="deleteHttpRoute" data-id="${r.id}">删除</button>
        </div>
      </td></tr>`).join('')
    : emptyRow(7, '后台尚未维护 HTTP 路由');
}

function renderTraffic(items) {
  $('#traffic').innerHTML = items.length
    ? items.map(i => `<tr>
      <td>${i.id}</td>
      <td>${escapeHtml(i.clientName)}</td>
      <td>${escapeHtml(i.usageDate)}</td>
      <td>${formatBytes(i.uploadBytes)}</td>
      <td>${formatBytes(i.downloadBytes)}</td>
      ${tdTime(i.updatedAt)}</tr>`).join('')
    : emptyRow(6);
}

function renderConnections(items) {
  $('#connections').innerHTML = items.length
    ? items.map(connectionRowHtml).join('')
    : emptyRow(8);
}

/**
 * 单行 HTML 生成器，被 renderConnections 与 WebSocket 推送公用。
 * 行 / 单元格上加 data-* 属性：
 *  - data-id：用于 WS 推 updated 时定位整行
 *  - data-active="1"：在线行，1Hz 定时器只刷新这些行的时长
 *  - data-connected-at：避免定时器再从 DOM text 反解时间
 *  - td[data-role="duration"|"disconnected"|"reason"|"result"]：updated 事件局部替换
 */
function connectionRowHtml(i) {
  const active = !i.disconnectedAt;
  return `<tr data-id="${i.id}" data-active="${active ? '1' : '0'}" data-connected-at="${escapeHtml(i.connectedAt || '')}">
    <td>${i.id}</td>
    <td>${escapeHtml(i.clientName)}</td>
    <td data-role="result" class="${i.success ? 'ok' : 'off'}">${i.success ? '成功' : '失败'}</td>
    <td>${escapeHtml(i.remoteAddress || '-')}</td>
    ${tdTime(i.connectedAt)}
    ${i.disconnectedAt
        ? `<td data-role="disconnected" title="${escapeHtml(i.disconnectedAt)}">${escapeHtml(formatDateTime(i.disconnectedAt))}</td>`
        : `<td data-role="disconnected" class="muted">-</td>`}
    <td data-role="duration">${escapeHtml(formatDuration(i.connectedAt, i.disconnectedAt))}</td>
    <td data-role="reason">${escapeHtml(formatConnectionReason(i))}</td></tr>`;
}

/**
 * 用最新 record 局部刷新已存在行的可变单元格。命中字段：
 *  - 断开时间 / 时长 / 原因 / 结果 / data-active
 */
function updateConnectionRow(tr, i) {
  tr.dataset.active = i.disconnectedAt ? '0' : '1';
  tr.dataset.connectedAt = i.connectedAt || '';
  const resultCell = tr.querySelector('td[data-role="result"]');
  if (resultCell) {
    resultCell.className = i.success ? 'ok' : 'off';
    resultCell.textContent = i.success ? '成功' : '失败';
  }
  const disconnectedCell = tr.querySelector('td[data-role="disconnected"]');
  if (disconnectedCell) {
    if (i.disconnectedAt) {
      disconnectedCell.className = '';
      disconnectedCell.title = i.disconnectedAt;
      disconnectedCell.textContent = formatDateTime(i.disconnectedAt);
    } else {
      disconnectedCell.className = 'muted';
      disconnectedCell.removeAttribute('title');
      disconnectedCell.textContent = '-';
    }
  }
  const durationCell = tr.querySelector('td[data-role="duration"]');
  if (durationCell) {
    durationCell.textContent = formatDuration(i.connectedAt, i.disconnectedAt);
  }
  const reasonCell = tr.querySelector('td[data-role="reason"]');
  if (reasonCell) {
    reasonCell.textContent = formatConnectionReason(i);
  }
}

/**
 * "原因"列文案：
 *  - 登录失败：直接显示 failureReason（如"签名无效或已过期"）
 *  - 登录成功后断开：显示 disconnectReasonText（如"客户端正常断开"）
 *  - 既无 failureReason 也无 disconnectReason（旧数据 / 在线中）：'-'
 */
function formatConnectionReason(i) {
  if (!i.success) {
    return i.failureReason || i.disconnectReasonText || '登录失败';
  }
  return i.disconnectReasonText || '-';
}

/* ================================================================== *
 *  Per-section loaders + loadAll orchestrator
 * ================================================================== */

async function loadOverview() { renderOverview(await api('/overview')); }
async function loadClients()  { renderClients(await api('/clients')); }
async function loadTunnels()  { renderTunnels(await api('/tunnels')); }
async function loadTraffic()  { renderTraffic(await api('/traffic?limit=100')); }
/* HTTP 路由：clientId=null 拉全量，否则按 clientId 过滤。后端不存在的 id 返回空列表。 */
async function loadHttpRoutes() {
  const query = httpRoutesState.clientId ? `?clientId=${encodeURIComponent(httpRoutesState.clientId)}` : '';
  renderHttpRoutes(await api(`/http-routes${query}`));
}

async function loadConnections() {
  const tbody = $('#connections');
  if (!tbody) return;
  tbody.innerHTML = loadingRow(8);
  try {
    const data = await api(`/connections?${connectionsQuery()}`);
    const items = data.items || [];
    connectionsState.total = data.total || 0;
    connectionsState.totalPages = data.totalPages || 0;
    renderConnections(items);
    updateConnPager();
  } catch (error) {
    $('#connections').innerHTML = emptyRow(8, '加载失败');
    toast(error.message, 'error');
  }
}

function connectionsQuery() {
  const parts = [`page=${connectionsState.page}`, `size=${connectionsState.size}`];
  if (connectionsState.clientId !== null && connectionsState.clientId !== '') parts.push(`clientId=${encodeURIComponent(connectionsState.clientId)}`);
  if (connectionsState.success !== null && connectionsState.success !== '') parts.push(`success=${connectionsState.success}`);
  if (connectionsState.from) parts.push(`from=${encodeURIComponent(connectionsState.from)}`);
  if (connectionsState.to) parts.push(`to=${encodeURIComponent(connectionsState.to)}`);
  return parts.join('&');
}

function updateConnPager() {
  const { page, totalPages, total, size } = connectionsState;
  const from = total === 0 ? 0 : page * size + 1;
  const to = Math.min(total, (page + 1) * size);
  $('#connPagerInfo').textContent = total === 0 ? '共 0 条' : `第 ${from}-${to} 条，共 ${total} 条`;
  $('#connPageLabel').textContent = totalPages > 0 ? `第 ${page + 1} / ${totalPages} 页` : '';
  $('#connPrev').disabled = page <= 0;
  $('#connNext').disabled = page + 1 >= totalPages;
}

async function loadAll() {
  const main = $('#appMain');
  const wasBusy = main.getAttribute('aria-busy') === 'true';
  if (!wasBusy) main.setAttribute('aria-busy', 'true');
  try {
    await Promise.all([loadOverview(), loadClients(), loadTunnels(), loadTraffic(), loadHttpRoutes()]);
    await loadConnections();
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    if (!wasBusy) main.removeAttribute('aria-busy');
  }
}

/* ================================================================== *
 *  Mutations — 完成后只刷新受影响的面板
 * ================================================================== */

async function createClient(_event, form) {
  try {
    const name = $('#clientName').value;
    const result = await api('/clients', { method:'POST', body:JSON.stringify({
      clientName: name,
      password: $('#password').value || null,
      connectionRateLimitPerMinute: Number($('#rateLimit').value),
      enabled: true
    })});
    form.reset(); $('#rateLimit').value = 30;
    await Promise.all([loadOverview(), loadClients()]);
    if (result && result.password) showPassword(result.password, name, '客户端已创建。这是为该客户端生成的密码，仅显示一次，请立即复制并妥善保存。');
    else toast('客户端已创建');
  } catch (error) { toast(error.message, 'error'); }
}

function editClient(id) {
  const client = clientCache.get(id);
  if (!client) return;
  editTarget = client;
  $('#ec-title').textContent = `编辑客户端「${client.clientName}」`;
  $('#ec-name').value = client.clientName;
  $('#ec-password').value = '';
  $('#ec-password').type = 'password';
  setEcPwToggleLabel('显示');
  $('#ec-rate').value = client.connectionRateLimitPerMinute || 0;
  $('#ec-enabled').checked = !!client.enabled;
  openDialog('editClientDialog');
  setTimeout(() => $('#ec-name').focus(), 50);
}

function setEcPwToggleLabel(text) {
  const btn = document.querySelector('[data-action="toggleEcPw"]');
  if (btn) btn.textContent = text;
}

async function submitEditClient() {
  if (!editTarget) return;
  const id = editTarget.id;
  const newName = $('#ec-name').value.trim();
  const newPassword = $('#ec-password').value;
  const body = {
    clientName: newName,
    password: newPassword || null,
    connectionRateLimitPerMinute: Number($('#ec-rate').value),
    enabled: $('#ec-enabled').checked
  };
  try {
    const result = await api(`/clients/${id}`, { method:'PUT', body:JSON.stringify(body) });
    closeDialog('editClientDialog');
    editTarget = null;
    /* 改名 / 启停可能影响在线状态、统计与 NAT 推送，因此 overview/clients/tunnels 都要刷；
     * 改名 / 停用都可能影响在线状态，路由面板的 clientName 列也跟着变 */
    await Promise.all([loadOverview(), loadClients(), loadTunnels(), loadHttpRoutes()]);
    if (result && result.password) showPassword(result.password, newName, '密码已重置，仅显示一次，请立即复制并妥善保存。');
    else toast('客户端已更新');
  } catch (error) { toast(error.message, 'error'); }
}

async function deleteClient(id) {
  const client = clientCache.get(id);
  const name = client ? client.clientName : `#${id}`;
  if (!confirm(`确定删除客户端「${name}」吗？历史连接和流量记录会保留。`)) return;
  try {
    await api(`/clients/${id}`, { method:'DELETE' });
    toast('客户端已删除');
    await Promise.all([loadOverview(), loadClients(), loadTunnels(), loadHttpRoutes()]);
  } catch (error) { toast(error.message, 'error'); }
}

async function createTunnel(_event, _form) {
  try {
    const clientId = $('#tunnelClientId').value;
    await api(`/clients/${clientId}/tunnels`, { method:'POST', body:JSON.stringify({
      listenPort: Number($('#listenPort').value),
      targetAddress: $('#targetAddress').value,
      targetPort: Number($('#targetPort').value),
      enabled: true
    })});
    toast('端口映射已新增');
    /* 仅清空端口/地址三项，保留客户端选择以便连续添加 */
    $('#listenPort').value = ''; $('#targetAddress').value = ''; $('#targetPort').value = '';
    await loadTunnels();
  } catch (error) { toast(error.message, 'error'); }
}

function editTunnel(id) {
  const tunnel = tunnelCache.get(id);
  if (!tunnel) return;
  editTunnelTarget = tunnel;
  $('#et-title').textContent = `编辑端口映射 #${tunnel.id}`;
  $('#et-listenPort').value = tunnel.listenPort;
  $('#et-targetAddress').value = tunnel.targetAddress;
  $('#et-targetPort').value = tunnel.targetPort;
  $('#et-enabled').checked = !!tunnel.enabled;
  openDialog('editTunnelDialog');
  setTimeout(() => $('#et-listenPort').focus(), 50);
}

async function submitEditTunnel() {
  if (!editTunnelTarget) return;
  const id = editTunnelTarget.id;
  const body = {
    listenPort: Number($('#et-listenPort').value),
    targetAddress: $('#et-targetAddress').value.trim(),
    targetPort: Number($('#et-targetPort').value),
    enabled: $('#et-enabled').checked
  };
  try {
    await api(`/tunnels/${id}`, { method:'PUT', body:JSON.stringify(body) });
    closeDialog('editTunnelDialog');
    editTunnelTarget = null;
    toast('端口映射已更新');
    await loadTunnels();
  } catch (error) { toast(error.message, 'error'); }
}

async function toggleTunnel(id) {
  const tunnel = tunnelCache.get(id);
  if (!tunnel) return;
  const next = !tunnel.enabled;
  try {
    await api(`/tunnels/${id}`, { method:'PUT', body:JSON.stringify({
      listenPort: tunnel.listenPort,
      targetAddress: tunnel.targetAddress,
      targetPort: tunnel.targetPort,
      enabled: next
    })});
    toast(`端口映射已${next ? '启用' : '停用'}`);
    await loadTunnels();
  } catch (error) { toast(error.message, 'error'); }
}

async function deleteTunnel(id) {
  if (!confirm('确定删除该端口映射？')) return;
  try {
    await api(`/tunnels/${id}`, { method:'DELETE' });
    toast('端口映射已删除');
    await loadTunnels();
  } catch (error) { toast(error.message, 'error'); }
}

/* ---------- HTTP routes CRUD ----------
 * 服务端是权威，每次写入后会自动通过 NAT_CONTROL 把 TCP+HTTP 全集下发给在线客户端，
 * 由 DirectHttpRequestHandler.applyRoutes 热替换路由表。本前端只负责面板上的增删改查。
 */
async function createHttpRoute(_event, _form) {
  try {
    const clientId = $('#httpRouteCreateClientId').value;
    if (!clientId) { toast('请先选择客户端', 'error'); return; }
    await api(`/clients/${clientId}/http-routes`, { method:'POST', body:JSON.stringify({
      route: $('#httpRouteCreateRoute').value.trim(),
      targetBaseUrl: $('#httpRouteCreateTargetBaseUrl').value.trim(),
      enabled: true
    })});
    toast('HTTP 路由已新增');
    /* 仅清空 route / target，保留客户端选择以便连续添加 */
    $('#httpRouteCreateRoute').value = '';
    $('#httpRouteCreateTargetBaseUrl').value = '';
    await loadHttpRoutes();
  } catch (error) { toast(error.message, 'error'); }
}

function editHttpRoute(id) {
  const route = httpRouteCache.get(id);
  if (!route) return;
  editHttpRouteTarget = route;
  $('#er-title').textContent = `编辑 HTTP 路由 #${route.id}`;
  $('#er-route').value = route.route;
  $('#er-targetBaseUrl').value = route.targetBaseUrl;
  $('#er-enabled').checked = !!route.enabled;
  openDialog('editHttpRouteDialog');
  setTimeout(() => $('#er-route').focus(), 50);
}

async function submitEditHttpRoute() {
  if (!editHttpRouteTarget) return;
  const id = editHttpRouteTarget.id;
  const body = {
    route: $('#er-route').value.trim(),
    targetBaseUrl: $('#er-targetBaseUrl').value.trim(),
    enabled: $('#er-enabled').checked
  };
  try {
    await api(`/http-routes/${id}`, { method:'PUT', body:JSON.stringify(body) });
    closeDialog('editHttpRouteDialog');
    editHttpRouteTarget = null;
    toast('HTTP 路由已更新');
    await loadHttpRoutes();
  } catch (error) { toast(error.message, 'error'); }
}

async function toggleHttpRoute(id) {
  const route = httpRouteCache.get(id);
  if (!route) return;
  const next = !route.enabled;
  try {
    await api(`/http-routes/${id}`, { method:'PUT', body:JSON.stringify({
      route: route.route,
      targetBaseUrl: route.targetBaseUrl,
      enabled: next
    })});
    toast(`HTTP 路由已${next ? '启用' : '停用'}`);
    await loadHttpRoutes();
  } catch (error) { toast(error.message, 'error'); }
}

async function deleteHttpRoute(id) {
  if (!confirm('确定删除该 HTTP 路由？')) return;
  try {
    await api(`/http-routes/${id}`, { method:'DELETE' });
    toast('HTTP 路由已删除');
    await loadHttpRoutes();
  } catch (error) { toast(error.message, 'error'); }
}

async function pushNatControl(id) {
  try {
    const result = await api(`/clients/${id}/nat-control`, { method:'POST' });
    /* httpRoutes == -1 代表"未在后台接管 HTTP 路由"，此时按"-"展示，避免误读为 0 */
    const httpText = (result.httpRoutes === undefined || result.httpRoutes < 0)
      ? '-'
      : String(result.httpRoutes);
    toast(`已下发：TCP ${result.tunnels ?? result.pushed ?? 0} 条 / HTTP ${httpText} 条`);
  }
  catch (error) { toast(error.message, 'error'); }
}

async function initializeDatabase() {
  if (!confirm('确定执行数据库初始化吗？该操作幂等，会确保所需表结构存在。')) return;
  try {
    const result = await api('/database/initialize', { method:'POST' });
    toast(`数据库初始化完成：${result.dialect}，客户端 ${result.clients} 个`);
    await loadAll();
  } catch (error) { toast(error.message, 'error'); }
}

/* ---------- connection filter handlers ---------- */
function onConnectionsFilterChange() {
  const c = $('#connClientFilter').value;
  const r = $('#connResultFilter').value;
  const f = $('#connFromDate').value;
  const t = $('#connToDate').value;
  connectionsState.clientId = c ? Number(c) : null;
  connectionsState.success = r === '' ? null : (r === 'true');
  connectionsState.from = f ? `${f}T00:00:00Z` : null;
  connectionsState.to = t ? `${t}T23:59:59Z` : null;
  connectionsState.page = 0;
  loadConnections();
}

function resetConnFilters() {
  $('#connClientFilter').value = '';
  $('#connResultFilter').value = '';
  $('#connFromDate').value = '';
  $('#connToDate').value = '';
  onConnectionsFilterChange();
}

function prevConnPage() { if (connectionsState.page > 0) { connectionsState.page--; loadConnections(); } }
function nextConnPage() { if (connectionsState.page + 1 < connectionsState.totalPages) { connectionsState.page++; loadConnections(); } }

/* ---------- http routes filter handler ---------- */
function onHttpRoutesFilterChange() {
  const v = $('#httpRouteClientFilter').value;
  httpRoutesState.clientId = v ? Number(v) : null;
  loadHttpRoutes().catch(error => toast(error.message, 'error'));
}

/* ================================================================== *
 *  Event delegation
 * ================================================================== */

const ACTIONS = {
  refresh: () => loadAll(),
  initDb: () => initializeDatabase(),
  logout: () => logout(),
  oidcLogin: () => login(),
  editClient: (id) => editClient(id),
  deleteClient: (id) => deleteClient(id),
  pushNatControl: (id) => pushNatControl(id),
  editTunnel: (id) => editTunnel(id),
  toggleTunnel: (id) => toggleTunnel(id),
  deleteTunnel: (id) => deleteTunnel(id),
  editHttpRoute: (id) => editHttpRoute(id),
  toggleHttpRoute: (id) => toggleHttpRoute(id),
  deleteHttpRoute: (id) => deleteHttpRoute(id),
  resetConnFilters: () => resetConnFilters(),
  prevConnPage: () => prevConnPage(),
  nextConnPage: () => nextConnPage(),
  refreshHttpRoutes: () => loadHttpRoutes().catch(error => toast(error.message, 'error')),
  closeEditClient: () => { closeDialog('editClientDialog'); editTarget = null; },
  closeEditTunnel: () => { closeDialog('editTunnelDialog'); editTunnelTarget = null; },
  closeEditHttpRoute: () => { closeDialog('editHttpRouteDialog'); editHttpRouteTarget = null; },
  closePw: () => closeDialog('passwordDialog'),
  copyPw: () => copyPassword(),
  toggleEcPw: () => {
    const input = $('#ec-password');
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    setEcPwToggleLabel(showing ? '显示' : '隐藏');
  },
};

const FORMS = {
  createClient,
  createTunnel,
  createHttpRoute,
  editClient: () => submitEditClient(),
  editTunnel: () => submitEditTunnel(),
  editHttpRoute: () => submitEditHttpRoute(),
  passwordLogin,
};

function setupDelegation() {
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const handler = ACTIONS[el.dataset.action];
    if (!handler) return;
    const id = el.dataset.id ? Number(el.dataset.id) : undefined;
    handler(id, el, e);
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target.closest('[data-action][role="button"]');
    if (!el) return;
    e.preventDefault();
    const handler = ACTIONS[el.dataset.action];
    if (handler) handler(el.dataset.id ? Number(el.dataset.id) : undefined, el, e);
  });
  document.addEventListener('submit', e => {
    const form = e.target.closest('[data-form]');
    if (!form) return;
    e.preventDefault();
    const handler = FORMS[form.dataset.form];
    if (handler) handler(e, form);
  });
  document.addEventListener('change', e => {
    const el = e.target.closest('[data-onchange]');
    if (!el) return;
    if (el.dataset.onchange === 'connectionsFilter') onConnectionsFilterChange();
    else if (el.dataset.onchange === 'httpRoutesFilter') onHttpRoutesFilterChange();
  });
  $('#editClientDialog').addEventListener('close', () => { editTarget = null; });
  $('#editTunnelDialog').addEventListener('close', () => { editTunnelTarget = null; });
  $('#editHttpRouteDialog').addEventListener('close', () => { editHttpRouteTarget = null; });
}

/* ================================================================== *
 *  Login / OIDC
 *  - 在 sessionStorage 中记录 login_type ('password' | 'oidc')
 *    使密码登录用户在 logout 时不会被跳到 OIDC end_session_endpoint
 * ================================================================== */

const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const randomToken = () => { const bytes = new Uint8Array(32); crypto.getRandomValues(bytes); return b64url(bytes); };
async function sha256b64url(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return b64url(new Uint8Array(digest));
}
function cleanUrl() { history.replaceState({}, document.title, location.pathname); }
function tokenValid() {
  if (!sessionStorage.getItem('access_token')) return false;
  const expiry = Number(sessionStorage.getItem('token_expiry') || 0);
  return !expiry || Date.now() < expiry - 5000;
}
function showApp() { $('#login').hidden = true; $('#appHeader').hidden = false; $('#appMain').hidden = false; }
function showLogin(message) {
  $('#appHeader').hidden = true; $('#appMain').hidden = true; $('#login').hidden = false;
  const passwordEnabled = !!(oidcConfig && oidcConfig.passwordLoginEnabled);
  const oidcEnabled = !!(oidcConfig && oidcConfig.configured);
  $('#pwForm').hidden = !passwordEnabled;
  $('#loginButton').hidden = !oidcEnabled;
  $('#loginDivider').hidden = !(passwordEnabled && oidcEnabled);
  const hint = $('#loginHint');
  if (message) hint.textContent = message;
  else if (!passwordEnabled && !oidcEnabled) hint.textContent = '未配置任何登录方式：请设置用户名/密码或 OIDC';
  else hint.textContent = '请登录';
}

async function passwordLogin(e) {
  if (e) e.preventDefault();
  try {
    const response = await fetch('/auth/login', {
      method:'POST', headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ username:$('#pwUser').value, password:$('#pwPass').value })
    });
    const data = await safeJson(response);
    if (!response.ok || !data.accessToken) { showLogin(data.error || '登录失败'); return; }
    sessionStorage.setItem('access_token', data.accessToken);
    sessionStorage.setItem('login_type', 'password');
    if (data.expiresIn) sessionStorage.setItem('token_expiry', String(Date.now() + data.expiresIn * 1000));
    scheduleTokenRefresh();
    showApp(); await loadAll(); startLiveFeatures();
  } catch (error) { showLogin('登录失败：' + error.message); }
}

function handleUnauthorized() {
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('token_expiry');
  sessionStorage.removeItem('login_type');
  stopTokenRefresh();
  stopLiveFeatures();
  showLogin('登录已过期，请重新登录');
}

async function login() {
  if (!oidcConfig || !oidcConfig.configured) return;
  const verifier = randomToken(); const state = randomToken();
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('oidc_state', state);
  const challenge = await sha256b64url(verifier);
  const url = new URL(oidcConfig.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', oidcConfig.clientId);
  url.searchParams.set('redirect_uri', oidcConfig.redirectUri);
  url.searchParams.set('scope', oidcConfig.scope);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  location.assign(url.toString());
}

function logout() {
  const loginType = sessionStorage.getItem('login_type');
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('token_expiry');
  sessionStorage.removeItem('login_type');
  stopTokenRefresh();
  stopLiveFeatures();
  /* 只有走 OIDC 登录才回到 OIDC end_session；密码登录直接停在本地登录页 */
  if (loginType === 'oidc' && oidcConfig && oidcConfig.endSessionEndpoint) {
    location.assign(oidcConfig.endSessionEndpoint);
    return;
  }
  showLogin('已退出登录');
}

/* ================================================================== *
 *  Token refresh
 *  - 仅密码登录的 HS256 token 走 /auth/refresh 续期
 *  - 每 60 秒检查一次：到期前 5 分钟内自动调一次续期接口
 * ================================================================== */

const TOKEN_REFRESH_LEAD_MS = 5 * 60 * 1000;
const TOKEN_REFRESH_INTERVAL_MS = 60 * 1000;
let tokenRefreshTimer = null;

function scheduleTokenRefresh() {
  stopTokenRefresh();
  tokenRefreshTimer = setInterval(maybeRefreshToken, TOKEN_REFRESH_INTERVAL_MS);
  /* 首次也跑一次，避免页面刚刷新时 token 已经接近过期 */
  maybeRefreshToken();
}

function stopTokenRefresh() {
  if (tokenRefreshTimer) {
    clearInterval(tokenRefreshTimer);
    tokenRefreshTimer = null;
  }
}

async function maybeRefreshToken() {
  if (sessionStorage.getItem('login_type') !== 'password') return;
  const expiry = Number(sessionStorage.getItem('token_expiry') || 0);
  if (!expiry) return;
  if (expiry - Date.now() > TOKEN_REFRESH_LEAD_MS) return;
  try {
    const token = sessionStorage.getItem('access_token');
    if (!token) return;
    const response = await fetch('/auth/refresh', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) return;
    const data = await safeJson(response);
    if (!data.accessToken) return;
    sessionStorage.setItem('access_token', data.accessToken);
    if (data.expiresIn) sessionStorage.setItem('token_expiry', String(Date.now() + data.expiresIn * 1000));
  } catch {
    /* 静默失败，下次 401 会触发重新登录 */
  }
}

/* ================================================================== *
 *  WebSocket：实时推送连接事件 + 1Hz 时长刷新
 *  - 端点 /ws/connections，token 走 query 串（浏览器 WS 不能塞自定义 header）
 *  - onmessage 收到 {type:'created'|'updated', record:{...}}，仅当当前 page=0 且
 *    record 命中过滤器时改 DOM；否则仅忽略（下次手动翻页 / 刷新会从服务端拉回）
 *  - 1Hz 定时器只刷新 data-active="1" 的行的时长单元格
 * ================================================================== */

let liveSocket = null;
let liveDurationTimer = null;
let liveReconnectTimer = null;
let liveReconnectAttempts = 0;
let liveSocketEnabled = false;
const LIVE_RECONNECT_DELAYS_MS = [1000, 2000, 5000, 10000];

function openConnectionsSocket() {
  liveSocketEnabled = true;
  if (liveReconnectTimer) { clearTimeout(liveReconnectTimer); liveReconnectTimer = null; }
  if (liveSocket && (liveSocket.readyState === WebSocket.OPEN || liveSocket.readyState === WebSocket.CONNECTING)) return;
  const token = sessionStorage.getItem('access_token');
  if (!token) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url = `${proto}://${location.host}/ws/connections?token=${encodeURIComponent(token)}`;
  try {
    liveSocket = new WebSocket(url);
  } catch (e) {
    scheduleSocketReconnect();
    return;
  }
  liveSocket.onopen = () => { liveReconnectAttempts = 0; };
  liveSocket.onmessage = (event) => {
    let payload;
    try { payload = JSON.parse(event.data); } catch { return; }
    onLiveConnectionEvent(payload);
  };
  liveSocket.onclose = (event) => {
    liveSocket = null;
    /* 服务端用 4401 表示鉴权失效（token 过期 / 被撤销）—— 进入重新登录流程 */
    if (event.code === 4401) { handleUnauthorized(); return; }
    if (liveSocketEnabled) scheduleSocketReconnect();
  };
  liveSocket.onerror = () => { /* 由 onclose 统一处理 */ };
}

function closeConnectionsSocket() {
  liveSocketEnabled = false;
  if (liveReconnectTimer) { clearTimeout(liveReconnectTimer); liveReconnectTimer = null; }
  if (liveSocket) {
    try { liveSocket.close(); } catch { /* ignore */ }
    liveSocket = null;
  }
  liveReconnectAttempts = 0;
}

function scheduleSocketReconnect() {
  if (!liveSocketEnabled) return;
  const delay = LIVE_RECONNECT_DELAYS_MS[Math.min(liveReconnectAttempts, LIVE_RECONNECT_DELAYS_MS.length - 1)];
  liveReconnectAttempts++;
  liveReconnectTimer = setTimeout(() => {
    liveReconnectTimer = null;
    openConnectionsSocket();
  }, delay);
}

function onLiveConnectionEvent(payload) {
  if (!payload || !payload.type || !payload.record) return;
  const record = payload.record;
  /* 翻页 / 过滤器不命中：忽略，避免把"不该在本页"的行硬塞进表格 */
  if (connectionsState.page !== 0) return;
  if (!recordMatchesFilter(record)) return;
  const tbody = $('#connections');
  if (!tbody) return;
  /* 首次 created：先把 "暂无数据" 空行清掉 */
  const emptyRowEl = tbody.querySelector('tr.empty');
  if (emptyRowEl) emptyRowEl.remove();

  const existing = tbody.querySelector(`tr[data-id="${record.id}"]`);
  if (payload.type === 'updated' && existing) {
    updateConnectionRow(existing, record);
    return;
  }
  if (payload.type === 'created') {
    if (existing) { updateConnectionRow(existing, record); return; }
    tbody.insertAdjacentHTML('afterbegin', connectionRowHtml(record));
    /* 维持当前页最多 size 行，超出的从尾部裁掉 */
    const rows = tbody.querySelectorAll('tr');
    const limit = connectionsState.size || 50;
    for (let idx = rows.length - 1; idx >= limit; idx--) rows[idx].remove();
    connectionsState.total = (connectionsState.total || 0) + 1;
    connectionsState.totalPages = Math.max(1, Math.ceil(connectionsState.total / limit));
    updateConnPager();
  }
}

/** 把 record 和当前 connectionsState 过滤器对照——和后端的过滤语义保持一致。 */
function recordMatchesFilter(record) {
  const s = connectionsState;
  if (s.clientId !== null && s.clientId !== '' && Number(s.clientId) !== Number(record.clientId)) return false;
  if (s.success !== null && s.success !== '' && Boolean(s.success) !== Boolean(record.success)) return false;
  /* connectedAt 与 from/to 都是 ISO-8601 UTC 字符串，字典序即时序 */
  if (s.from && record.connectedAt && record.connectedAt < s.from) return false;
  if (s.to && record.connectedAt && record.connectedAt > s.to) return false;
  return true;
}

function startLiveDurationTimer() {
  if (liveDurationTimer) return;
  liveDurationTimer = setInterval(() => {
    const rows = document.querySelectorAll('#connections tr[data-active="1"]');
    rows.forEach(tr => {
      const cell = tr.querySelector('td[data-role="duration"]');
      if (!cell) return;
      cell.textContent = formatDuration(tr.dataset.connectedAt, null);
    });
  }, 1000);
}

function stopLiveDurationTimer() {
  if (liveDurationTimer) {
    clearInterval(liveDurationTimer);
    liveDurationTimer = null;
  }
}

function startLiveFeatures() {
  openConnectionsSocket();
  startLiveDurationTimer();
}

function stopLiveFeatures() {
  closeConnectionsSocket();
  stopLiveDurationTimer();
}

async function completeLoginFromRedirect() {
  const params = new URLSearchParams(location.search);
  if (params.has('error')) { cleanUrl(); showLogin(params.get('error_description') || params.get('error')); return false; }
  if (!params.has('code')) return false;
  const expectedState = sessionStorage.getItem('oidc_state');
  if (!expectedState || params.get('state') !== expectedState) { cleanUrl(); showLogin('登录状态校验失败，请重试'); return false; }
  try {
    const response = await fetch('/oidc/token', {
      method:'POST', headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ code: params.get('code'), codeVerifier: sessionStorage.getItem('pkce_verifier') })
    });
    const data = await safeJson(response);
    if (!response.ok || !data.accessToken) { cleanUrl(); showLogin(data.error_description || data.error || '令牌交换失败'); return false; }
    sessionStorage.setItem('access_token', data.accessToken);
    sessionStorage.setItem('login_type', 'oidc');
    if (data.expiresIn) sessionStorage.setItem('token_expiry', String(Date.now() + data.expiresIn * 1000));
    sessionStorage.removeItem('pkce_verifier'); sessionStorage.removeItem('oidc_state'); cleanUrl();
    return true;
  } catch (error) { cleanUrl(); showLogin('令牌交换失败：' + error.message); return false; }
}

/* ================================================================== *
 *  Init
 * ================================================================== */

async function fetchOidcConfig() {
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 5000);
    const r = await fetch('/oidc-config', { signal: ac.signal });
    clearTimeout(timer);
    return await r.json();
  } catch { return null; }
}

async function init() {
  setupDelegation();
  oidcConfig = await fetchOidcConfig();
  const justLoggedIn = await completeLoginFromRedirect();
  if (justLoggedIn || tokenValid()) {
    if (sessionStorage.getItem('login_type') === 'password') scheduleTokenRefresh();
    showApp();
    await loadAll();
    startLiveFeatures();
  } else {
    showLogin();
  }
}

init();
