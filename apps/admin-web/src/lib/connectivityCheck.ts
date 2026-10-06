// Presentation of the HTTP route connectivity check (protocol/spec/service-connectivity-check.md).
// The server decides every stage; this module only names them in Chinese, says what to do next and
// keeps the three results apart: passed, failed and "无法判定", which is neither.

export type ConnectivityStageName = "configured" | "device-online" | "target-reachable" | "access-succeeded";
export type ConnectivityStageResult = "passed" | "failed" | "unverified" | "skipped";
export type ConnectivityOutcome = "succeeded" | "failed" | "unverified";

export interface ConnectivityStage {
  stage: ConnectivityStageName;
  result: ConnectivityStageResult;
  code?: string;
  atMs?: number;
}

/** The 200 body of POST /api/admin/http-routes/{id}/connectivity-check. */
export interface ConnectivityCheckResult {
  schemaVersion: number;
  kind: "http-route";
  routeId: number;
  checkedAt: string;
  outcome: ConnectivityOutcome;
  stoppedAt: ConnectivityStageName | null;
  code: string;
  totalMs: number;
  requests: string[];
  stages: ConnectivityStage[];
  statusClass?: string;
}

/** A check the server did not run, or a server that does not offer the check at all. */
export interface ConnectivityCheckRefusal {
  status: number;
  code: string | null;
  retryAfterSeconds: number | null;
}

export type ConnectivityCheckAnswer =
  | { kind: "result"; result: ConnectivityCheckResult }
  | { kind: "refused"; refusal: ConnectivityCheckRefusal };

export const STAGE_ORDER: ConnectivityStageName[] = ["configured", "device-online", "target-reachable", "access-succeeded"];

export const STAGE_LABELS: Record<ConnectivityStageName, string> = {
  configured: "已配置",
  "device-online": "设备在线",
  "target-reachable": "目标可达",
  "access-succeeded": "访问成功",
};

export const RESULT_LABELS: Record<ConnectivityStageResult, string> = {
  passed: "通过",
  failed: "失败",
  unverified: "无法判定",
  skipped: "未执行",
};

export const OUTCOME_LABELS: Record<ConnectivityOutcome, string> = {
  succeeded: "检查通过",
  failed: "检查未通过",
  unverified: "无法判定",
};

/** Shown next to any route: none of these is a passed check. */
export const NOT_A_CHECK_NOTE = "设备显示「在线」、能打开访问链接，都不等于连通性检查通过；检查结果只反映检查那一刻。";

export const UPGRADE_HINT = "升级该设备的客户端可以得到确切原因。";
export const AUTH_REQUIRED_LABEL = "目标需要它自己的登录";
export const UNSUPPORTED_MESSAGE = "服务端不支持连接检查";

interface CodeText {
  label: string;
  next?: string;
}

const CODE_TEXT: Record<string, CodeText> = {
  CONFIGURED: { label: "路由和客户端都已启用，目标地址有效" },
  ROUTE_DISABLED: { label: "路由已停用", next: "启用这条路由后再检查。" },
  CLIENT_DISABLED: { label: "所属客户端已停用", next: "在客户端管理中启用该客户端后再检查。" },
  ROUTE_TARGET_INVALID: { label: "保存的目标地址无效", next: "编辑路由，填写完整的 http:// 或 https:// 目标地址。" },
  DEVICE_ONLINE: { label: "设备已回应" },
  DEVICE_OFFLINE: {
    label: "设备不在线：没有已登录的控制连接",
    next: "确认设备上的客户端正在运行并已登录。多实例部署时，也可能是这次请求落到了不持有该设备连接的实例。",
  },
  DEVICE_DATA_CHANNEL_DOWN: {
    label: "控制连接在线，但数据连接没有建立",
    next: "这就是页面显示「在线」而访问失败的情形：等待客户端重建数据连接，或重启客户端。",
  },
  DEVICE_BUSY: { label: "设备数据连接上的并发流已满", next: "正在进行的访问结束后会释放名额，稍后再试。" },
  DEVICE_ROUTE_NOT_LOADED: {
    label: "设备还没有加载这条路由",
    next: "配置可能还没推送到设备。稍后再试，或重启客户端重新拉取配置。",
  },
  DEVICE_LINK_LOST: { label: "设备回应之前数据连接断开", next: "设备的网络可能不稳定，稍后再试。" },
  TARGET_ANSWERED: { label: "目标返回了响应头" },
  TARGET_CONNECT_REFUSED: { label: "目标端口拒绝连接", next: "确认目标服务已经启动，并且监听在目标地址的端口上。" },
  TARGET_CONNECT_TIMEOUT: { label: "设备连接目标超时", next: "确认设备能访问目标主机，并检查两者之间的防火墙。" },
  TARGET_DNS_FAILED: { label: "目标主机名无法解析", next: "检查目标地址里的主机名，或设备的 DNS 设置。" },
  TARGET_TLS_FAILED: {
    label: "TLS 握手或证书校验失败",
    next: "确认目标确实使用 HTTPS 且证书有效；可信内网的自签名服务可以在路由里关闭证书校验。",
  },
  TARGET_UNREACHABLE: { label: "设备到目标主机或网络不可达", next: "检查设备所在网络到目标主机的路由。" },
  TARGET_ADDRESS_INVALID: { label: "设备认为这个目标地址无法使用", next: "检查目标地址的格式；设备侧的规则可能比服务端更严格。" },
  TARGET_PROTOCOL_ERROR: {
    label: "已连上目标，但没有收到合法的 HTTP 响应",
    next: "常见原因是用 http:// 访问了 HTTPS 端口，或者这个端口上运行的不是 HTTP 服务。",
  },
  TARGET_TIMEOUT: {
    label: "检查时限内没有收到回应",
    next: "目标迟迟没有返回响应头。设备卡住而连接仍在的情况很少见，但在 10 秒的检查里与此无法区分。",
  },
  TARGET_UNVERIFIED: { label: "设备报告了失败，但没有给出可信的原因", next: UPGRADE_HINT },
  ACCESS_OK: { label: "目标正常答复" },
  ACCESS_AUTH_REQUIRED: {
    label: AUTH_REQUIRED_LABEL,
    next: "检查从不携带凭据，无法判断授权用户能否访问。请在浏览器中打开访问链接并登录确认。",
  },
  ACCESS_NOT_FOUND: { label: "目标返回「未找到」", next: "换一个确实存在的路径（例如健康检查地址）再试。" },
  ACCESS_CLIENT_ERROR: { label: "目标拒绝了这个请求", next: "检查路径是否正确，或目标是否限制了请求来源。" },
  ACCESS_SERVER_ERROR: {
    label: "目标返回了服务端错误",
    next: "这个错误来自目标本身（例如它前面的反向代理找不到后端），请查看目标服务的日志。",
  },
  ACCESS_NO_ANSWER: {
    label: "目标不支持 HEAD，随后的 GET 没有得到响应",
    next: "目标可达，但这次访问没有完成，稍后再试。",
  },
};

export function codeLabel(code: string | undefined): string {
  if (!code) return "";
  return CODE_TEXT[code]?.label ?? code;
}

export interface ConnectivityStageView {
  stage: ConnectivityStageName;
  label: string;
  result: ConnectivityStageResult;
  resultLabel: string;
  code?: string;
  codeLabel?: string;
  atMs?: number;
  /** The first stage that did not pass: the one to act on. */
  decisive: boolean;
  next?: string;
}

export interface ConnectivityCheckView {
  outcome: ConnectivityOutcome;
  outcomeLabel: string;
  tone: "success" | "danger" | "warning";
  summary: string;
  checkedAtText: string;
  totalMs: number;
  requestsText: string;
  statusClass?: string;
  stages: ConnectivityStageView[];
  notes: string[];
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

/** hh:mm:ss of checkedAt in the browser's time zone; the instant comes from the server clock. */
export function formatCheckTime(checkedAt: string): string {
  const time = new Date(checkedAt);
  if (Number.isNaN(time.getTime())) return checkedAt;
  return `${pad(time.getHours())}:${pad(time.getMinutes())}:${pad(time.getSeconds())}`;
}

export function describeConnectivityCheck(result: ConnectivityCheckResult): ConnectivityCheckView {
  const byStage = new Map(result.stages.map((stage) => [stage.stage, stage]));
  const stages = STAGE_ORDER.map((name): ConnectivityStageView => {
    const stage = byStage.get(name) ?? { stage: name, result: "skipped" as const };
    const decisive = result.stoppedAt === name && stage.result !== "passed" && stage.result !== "skipped";
    return {
      stage: name,
      label: STAGE_LABELS[name],
      result: stage.result,
      resultLabel: RESULT_LABELS[stage.result] ?? stage.result,
      code: stage.code,
      codeLabel: stage.code ? codeLabel(stage.code) : undefined,
      atMs: stage.atMs,
      decisive,
      next: decisive ? CODE_TEXT[stage.code ?? ""]?.next : undefined,
    };
  });
  const notes: string[] = [];
  if (result.outcome === "unverified") {
    notes.push("「无法判定」既不是失败，也不是通过：检查没有得到足以下结论的信息。");
  }
  if (result.code === "TARGET_UNVERIFIED") {
    notes.push(`可能是设备的客户端版本较旧，还不会报告失败原因。${UPGRADE_HINT}`);
  }
  if (result.code === "ACCESS_AUTH_REQUIRED") {
    notes.push(`${AUTH_REQUIRED_LABEL}：目标已经答复，但要求它自己的凭据。`);
  }
  const outcome = result.outcome;
  const decisiveStage = stages.find((stage) => stage.decisive);
  return {
    outcome,
    outcomeLabel: OUTCOME_LABELS[outcome] ?? outcome,
    tone: outcome === "succeeded" ? "success" : outcome === "failed" ? "danger" : "warning",
    summary: decisiveStage
      ? `停在「${decisiveStage.label}」：${decisiveStage.codeLabel ?? result.code}`
      : "四个阶段全部通过",
    checkedAtText: `检查于 ${formatCheckTime(result.checkedAt)}`,
    totalMs: result.totalMs,
    requestsText: result.requests.length ? `已发送 ${result.requests.join("、")}` : "没有向设备发送请求",
    statusClass: result.statusClass,
    stages,
    notes,
  };
}

/** The message for an answer that is not a check result. */
export function describeConnectivityRefusal(refusal: ConnectivityCheckRefusal): { message: string; unsupported: boolean } {
  const wait = refusal.retryAfterSeconds && refusal.retryAfterSeconds > 0 ? refusal.retryAfterSeconds : null;
  switch (refusal.code) {
    case "CHECK_REQUEST_INVALID":
      return { message: "检查路径无效：须以 / 开头、最长 256 字节，不能含 ?、#、空白，也不能有 . 或 .. 路径段。", unsupported: false };
    case "CHECK_TARGET_NOT_FOUND":
      return { message: "路由不存在，或你没有权限检查它。", unsupported: false };
    case "CHECK_UNAVAILABLE":
      return { message: "暂时无法读取路由或设备状态，请稍后再试。这不代表路由配置有误。", unsupported: false };
    case "CHECK_IN_PROGRESS":
      return { message: "这条路由正在检查中，请等它完成。", unsupported: false };
    case "CHECK_BUSY":
      return { message: "服务端同时进行的检查较多，请稍后再试。", unsupported: false };
    case "CHECK_RATE_LIMITED":
      return {
        message: wait ? `检查过于频繁，请在 ${wait} 秒后再试。` : "检查过于频繁，请稍后再试。",
        unsupported: false,
      };
  }
  // An older server has no such endpoint: 404 without the check's code, or 405.
  if (refusal.status === 404 || refusal.status === 405) {
    return { message: `${UNSUPPORTED_MESSAGE}。这与路由本身是否可用无关。`, unsupported: true };
  }
  if (refusal.status === 409 || refusal.status === 429) {
    return { message: wait ? `请在 ${wait} 秒后再试。` : "请稍后再试。", unsupported: false };
  }
  if (refusal.status === 503) {
    return { message: "服务端暂时无法检查，请稍后再试。", unsupported: false };
  }
  return { message: `检查请求失败（HTTP ${refusal.status}）。`, unsupported: false };
}

/** Retry-After in whole seconds, or null when absent or not a positive number of seconds. */
export function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value.trim());
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return Math.ceil(seconds);
}

/** Mirrors the server's path rule closely enough to stop obvious mistakes before a request is spent. */
export function validCheckPath(path: string): boolean {
  if (path.length < 1 || new TextEncoder().encode(path).length > 256 || !path.startsWith("/") || path.startsWith("//")) {
    return false;
  }
  if (!/^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})*$/.test(path)) return false;
  return path.split("/").every((segment) => {
    const decoded = segment.replace(/%2e/gi, ".");
    return decoded !== "." && decoded !== "..";
  });
}
