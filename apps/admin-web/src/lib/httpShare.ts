/**
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md): the landing page that trades the
 * link's fragment token for the share cookie, and the rules the management dialog follows.
 *
 * The token travels in the URL fragment exactly once. It is read, removed from the address bar
 * before any request, kept in memory only (never in localStorage, sessionStorage or IndexedDB),
 * and posted as JSON to the public exchange endpoint, which answers with the share cookie.
 */

export const SHARE_TOKEN_PATTERN = /^hs1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}$/;
export const SHARE_LINK_ROOT = "/#/http-share/";
export const SHARE_EXCHANGE_PATH = "/api/public/http-shares/exchange";
export const MIN_SHARE_SECONDS = 300;
export const MAX_SHARE_SECONDS = 604_800;
export const SHARE_LABEL_MAX = 60;

const HASH_PREFIX = /^#\/?http-share\//;

/** The token of a `#/http-share/<token>` fragment, or null when the fragment carries none. */
export function readShareToken(hash: string): string | null {
  if (!HASH_PREFIX.test(hash)) return null;
  const token = hash.replace(HASH_PREFIX, "");
  return SHARE_TOKEN_PATTERN.test(token) ? token : null;
}

export interface ShareLocation {
  hash: string;
  pathname: string;
  search: string;
}

export interface ShareHistory {
  replaceState(data: unknown, unused: string, url?: string | null): void;
}

let capturedToken: string | null = null;

/**
 * Reads the token from a `#/http-share/...` fragment and immediately replaces the address with one
 * without the fragment, so the token is left neither in the address bar nor in the history entry.
 * The token stays in this module's memory; once the fragment is gone, calling again returns the
 * token taken earlier.
 */
export function captureShareToken(location: ShareLocation, history: ShareHistory): string | null {
  if (HASH_PREFIX.test(location.hash)) {
    capturedToken = readShareToken(location.hash);
    history.replaceState(null, "", `${location.pathname}${location.search}`);
  }
  return capturedToken;
}

/** Forgets the captured token once it has been exchanged. */
export function forgetShareToken(): void {
  capturedToken = null;
}

export type ShareExchangeResult =
  | { ok: true; location: string; expiresAt: string }
  | { ok: false; code: string; message: string };

const LANDING_MESSAGES: Record<string, string> = {
  SHARE_NOT_FOUND: "链接无效",
  SHARE_REQUEST_INVALID: "链接无效",
  SHARE_EXPIRED: "分享已过期",
  SHARE_REVOKED: "分享已被撤销",
};

/** What a visitor sees for an exchange failure: never the route, the device or the target. */
export function shareLandingMessage(code: string | undefined): string {
  return (code && LANDING_MESSAGES[code]) || "请稍后再试";
}

/** Posts the token to the public exchange; the cookie comes back as HttpOnly and is never read here. */
export async function exchangeShareToken(token: string | null, fetchImpl: typeof fetch = fetch): Promise<ShareExchangeResult> {
  if (!token) {
    return { ok: false, code: "SHARE_NOT_FOUND", message: shareLandingMessage("SHARE_NOT_FOUND") };
  }
  try {
    const response = await fetchImpl(SHARE_EXCHANGE_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
      credentials: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    const body = (await response.json().catch(() => null)) as { code?: string; location?: string; expiresAt?: string } | null;
    if (response.ok && typeof body?.location === "string" && body.location.startsWith("/http-share/")) {
      return { ok: true, location: body.location, expiresAt: String(body.expiresAt ?? "") };
    }
    const code = body?.code ?? "SHARE_UNAVAILABLE";
    return { ok: false, code, message: shareLandingMessage(code) };
  } catch {
    return { ok: false, code: "SHARE_UNAVAILABLE", message: shareLandingMessage(undefined) };
  }
}

// ---- management ---------------------------------------------------------------------------

export type ShareAccess = "read" | "full";
export type ShareStatus = "active" | "expired" | "revoked";

export interface HttpShare {
  shareId: string;
  routeId: number;
  label: string | null;
  access: ShareAccess;
  pathPrefix: string;
  sharePath: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  status: ShareStatus;
  revokedAt: string | null;
  revokedBy: string | null;
  revokeReason: string | null;
}

export interface CreatedHttpShare {
  share: HttpShare;
  token: string;
  linkPath: string;
}

export interface HttpAccessAuditEntry {
  auditId: number;
  at: string;
  actor: string | null;
  action: string;
  routeId: number;
  shareId: string | null;
  detail: Record<string, string>;
}

export interface HttpAccessAuditPage {
  entries: HttpAccessAuditEntry[];
  nextBefore: number | null;
}

export interface CreateShareBody {
  expiresInSeconds: number;
  access: ShareAccess;
  pathPrefix?: string;
  label?: string;
}

const MANAGEMENT_MESSAGES: Record<string, string> = {
  SHARE_REQUEST_INVALID: "分享参数无效，请检查有效期、路径前缀和备注",
  SHARE_UNAVAILABLE: "服务暂时不可用，请稍后再试",
  SHARE_ROUTE_NOT_FOUND: "路由不存在，或你无权管理它",
  SHARE_ROUTE_DISABLED: "路由已停用，不能分享",
  SHARE_CLIENT_DISABLED: "所属客户端已停用，不能分享",
  SHARE_ROUTE_PUBLIC: "公开路由不能创建分享，请先开启访问认证",
  SHARE_LIMIT_REACHED: "该路由已有 20 个有效分享，请先撤销不再使用的分享",
  SHARE_NOT_FOUND: "分享不存在",
  SHARE_FORBIDDEN: "需要租户管理员权限",
};

/** A readable message for a share management error code, or "" for unknown codes. */
export function shareManagementMessage(code: string | undefined): string {
  return (code && MANAGEMENT_MESSAGES[code]) || "";
}

export const SHARE_EXPIRY_PRESETS = [
  { key: "1h", label: "1 小时", seconds: 3_600 },
  { key: "24h", label: "24 小时", seconds: 86_400 },
  { key: "7d", label: "7 天", seconds: 604_800 },
] as const;

export type ShareExpiryUnit = "minutes" | "hours" | "days";
const UNIT_SECONDS: Record<ShareExpiryUnit, number> = { minutes: 60, hours: 3_600, days: 86_400 };

export interface ShareDraft {
  /** A preset key, "custom", or "" while the owner has not chosen: there is no default expiry. */
  expiry: string;
  customAmount: string;
  customUnit: ShareExpiryUnit;
  access: ShareAccess;
  fullAccessConfirmed: boolean;
  pathPrefix: string;
  label: string;
}

export function emptyShareDraft(): ShareDraft {
  return { expiry: "", customAmount: "", customUnit: "hours", access: "read", fullAccessConfirmed: false, pathPrefix: "", label: "" };
}

/** The expiry in seconds, or an error message. */
export function shareExpirySeconds(draft: ShareDraft): number | string {
  if (!draft.expiry) return "请选择有效期";
  const preset = SHARE_EXPIRY_PRESETS.find((item) => item.key === draft.expiry);
  if (preset) return preset.seconds;
  if (draft.expiry !== "custom") return "请选择有效期";
  const amount = Number(draft.customAmount.trim());
  if (!/^\d+$/.test(draft.customAmount.trim()) || !Number.isSafeInteger(amount)) return "请输入整数有效期";
  const seconds = amount * UNIT_SECONDS[draft.customUnit];
  if (seconds < MIN_SHARE_SECONDS || seconds > MAX_SHARE_SECONDS) return "有效期需在 5 分钟到 7 天之间";
  return seconds;
}

/** Builds the create request, or returns the message that explains why it cannot be sent yet. */
export function buildCreateShareBody(draft: ShareDraft): CreateShareBody | string {
  const seconds = shareExpirySeconds(draft);
  if (typeof seconds === "string") return seconds;
  if (draft.access === "full" && !draft.fullAccessConfirmed) return "请确认完整访问的影响";
  const body: CreateShareBody = { expiresInSeconds: seconds, access: draft.access };
  const prefix = draft.pathPrefix.trim();
  if (prefix && prefix !== "/") {
    if (!prefix.startsWith("/")) return "路径前缀需以 / 开头";
    body.pathPrefix = prefix;
  }
  const label = draft.label.replace(/^ +| +$/g, "");
  if ([...label].length > SHARE_LABEL_MAX) return `备注最多 ${SHARE_LABEL_MAX} 个字符`;
  if (/[\u0000-\u001f\u007f]/.test(label)) return "备注不能包含控制字符";
  if (label) body.label = label;
  return body;
}

export interface SharingHost {
  protocol: string;
  hostname: string;
}

/**
 * Shares need HTTPS: the share cookie is always Secure with the __Secure- prefix, which browsers
 * accept over plain HTTP only on localhost.
 */
export function sharingAvailability(host: SharingHost): { available: boolean; reason: string } {
  if (host.protocol === "https:") return { available: true, reason: "" };
  const name = host.hostname.toLowerCase();
  if (name === "localhost" || name === "127.0.0.1" || name === "[::1]" || name === "::1" || name.endsWith(".localhost")) {
    return { available: true, reason: "" };
  }
  return { available: false, reason: "临时分享需要 HTTPS：分享 cookie 只在安全连接上生效，当前通过 HTTP 访问管理后台，无法使用分享。" };
}

export interface ShareableRoute {
  enabled: boolean;
  authEnabled: boolean;
}

/** Why a route cannot be shared, or "" when it can. */
export function routeShareBlocker(route: ShareableRoute, clientEnabled: boolean | undefined): string {
  if (!route.enabled) return "路由已停用，不能分享。";
  if (clientEnabled === false) return "所属客户端已停用，不能分享。";
  if (!route.authEnabled) return "公开路由无需分享，也不能用作临时邀请；需要临时访问请先开启访问认证。";
  return "";
}

/** The full link shown once after creation. */
export function shareLink(origin: string, linkPath: string): string {
  return `${origin}${linkPath}`;
}

const STATUS_LABELS: Record<ShareStatus, string> = { active: "有效", expired: "已过期", revoked: "已撤销" };
const REASON_LABELS: Record<string, string> = {
  "revoked-by-user": "手动撤销",
  "route-disabled": "路由已停用",
  "route-made-public": "路由改为公开",
  "route-deleted": "路由已删除",
  "client-disabled": "客户端已停用",
  "client-deleted": "客户端已删除",
  "creator-lost-access": "创建者失去管理权",
};

export function shareStatusLabel(share: Pick<HttpShare, "status" | "revokeReason">): string {
  const label = STATUS_LABELS[share.status] ?? share.status;
  if (share.status === "revoked" && share.revokeReason) {
    return `${label}（${REASON_LABELS[share.revokeReason] ?? share.revokeReason}）`;
  }
  return label;
}

/** A local-clock hint of the time left; the server's expiresAt stays authoritative. */
export function shareRemaining(expiresAt: string, nowMs: number): string {
  const left = Date.parse(expiresAt) - nowMs;
  if (!Number.isFinite(left) || left <= 0) return "已到期";
  const minutes = Math.ceil(left / 60_000);
  if (minutes < 60) return `约 ${minutes} 分钟后到期`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `约 ${hours} 小时后到期`;
  return `约 ${Math.floor(hours / 24)} 天后到期`;
}

const AUDIT_LABELS: Record<string, string> = {
  "share.created": "创建分享",
  "share.revoked": "撤销分享",
  "share.expired": "分享到期",
  "route.created": "创建路由",
  "route.exposure-changed": "暴露状态变更",
  "route.credentials-changed": "访问凭据变更",
  "route.deleted": "删除路由",
};
const EXPOSURE_LABELS: Record<string, string> = { disabled: "停用", protected: "受保护", public: "公开" };

/** One line describing an audit entry. */
export function describeAuditEntry(entry: HttpAccessAuditEntry): string {
  const action = AUDIT_LABELS[entry.action] ?? entry.action;
  const detail = entry.detail ?? {};
  switch (entry.action) {
    case "share.created":
      return `${action}：${detail.access === "full" ? "完整访问" : "只读"}，前缀 ${detail.pathPrefix ?? "/"}`;
    case "share.revoked":
      return `${action}：${REASON_LABELS[detail.reason] ?? detail.reason}`;
    case "route.exposure-changed":
      return `${action}：${EXPOSURE_LABELS[detail.from] ?? detail.from} → ${EXPOSURE_LABELS[detail.to] ?? detail.to}`;
    case "route.created":
    case "route.deleted":
      return `${action}（${EXPOSURE_LABELS[detail.exposure] ?? detail.exposure}）`;
    default:
      return action;
  }
}
