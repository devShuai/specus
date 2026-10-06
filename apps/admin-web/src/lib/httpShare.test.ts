import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildCreateShareBody,
  captureShareToken,
  describeAuditEntry,
  emptyShareDraft,
  exchangeShareToken,
  forgetShareToken,
  readShareToken,
  routeShareBlocker,
  shareLandingMessage,
  shareRemaining,
  shareStatusLabel,
  sharingAvailability,
  type ShareDraft,
} from "./httpShare";

const TOKEN = "hs1.H4s8XX6aCyxNbo8Q.o8Xn-QsdL0psjgstT2qMDitNb4oMLkttjwosTmuNDyo";

afterEach(() => {
  forgetShareToken();
  vi.unstubAllGlobals();
});

describe("share landing", () => {
  it("reads only a well-formed token from the fragment", () => {
    expect(readShareToken(`#/http-share/${TOKEN}`)).toBe(TOKEN);
    expect(readShareToken(`#http-share/${TOKEN}`)).toBe(TOKEN);
    expect(readShareToken(`#/http-share/${TOKEN}x`)).toBeNull();
    expect(readShareToken(`#/http-share/${TOKEN.toUpperCase()}`)).toBeNull();
    expect(readShareToken("#/http-share/")).toBeNull();
    expect(readShareToken(`#/transfer/${TOKEN}`)).toBeNull();
  });

  it("removes the fragment before anything else and keeps the token in memory only", () => {
    const replaceState = vi.fn();
    const storage = { setItem: vi.fn(), getItem: vi.fn(), removeItem: vi.fn() };
    vi.stubGlobal("localStorage", storage);
    vi.stubGlobal("sessionStorage", storage);
    const location = { hash: `#/http-share/${TOKEN}`, pathname: "/", search: "?lang=zh" };

    expect(captureShareToken(location, { replaceState })).toBe(TOKEN);
    expect(replaceState).toHaveBeenCalledWith(null, "", "/?lang=zh");
    expect(storage.setItem).not.toHaveBeenCalled();
    // After the fragment is gone (a re-render), the same token is still available.
    expect(captureShareToken({ hash: "", pathname: "/", search: "?lang=zh" }, { replaceState })).toBe(TOKEN);
    expect(replaceState).toHaveBeenCalledTimes(1);
    forgetShareToken();
    expect(captureShareToken({ hash: "", pathname: "/", search: "" }, { replaceState })).toBeNull();
  });

  it("clears even a malformed share fragment", () => {
    const replaceState = vi.fn();
    expect(captureShareToken({ hash: "#/http-share/not-a-token", pathname: "/", search: "" }, { replaceState })).toBeNull();
    expect(replaceState).toHaveBeenCalledWith(null, "", "/");
  });

  it("posts the token as JSON without admin credentials and returns where to go", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ shareId: "H4s8XX6aCyxNbo8Q", location: "/http-share/H4s8XX6aCyxNbo8Q/docs/", expiresAt: "2026-10-07T07:00:00Z" }),
    });
    const result = await exchangeShareToken(TOKEN, fetchMock as unknown as typeof fetch);
    expect(result).toEqual({ ok: true, location: "/http-share/H4s8XX6aCyxNbo8Q/docs/", expiresAt: "2026-10-07T07:00:00Z" });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/public/http-shares/exchange");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
    expect(JSON.parse(String(init.body))).toEqual({ token: TOKEN });
    expect(init.referrerPolicy).toBe("no-referrer");
  });

  it.each([
    [404, "SHARE_NOT_FOUND", "链接无效"],
    [410, "SHARE_EXPIRED", "分享已过期"],
    [410, "SHARE_REVOKED", "分享已被撤销"],
    [429, "SHARE_RATE_LIMITED", "请稍后再试"],
    [503, "SHARE_UNAVAILABLE", "请稍后再试"],
  ])("explains a %i %s without naming the route or device", async (status, code, message) => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status, json: async () => ({ code }) });
    expect(await exchangeShareToken(TOKEN, fetchMock as unknown as typeof fetch)).toEqual({ ok: false, code, message });
  });

  it("treats a missing token and a network failure as friendly errors", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("offline"));
    expect(await exchangeShareToken(null, fetchMock as unknown as typeof fetch)).toMatchObject({ ok: false, message: "链接无效" });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await exchangeShareToken(TOKEN, fetchMock as unknown as typeof fetch)).toMatchObject({ ok: false, message: "请稍后再试" });
    expect(shareLandingMessage(undefined)).toBe("请稍后再试");
  });

  it("refuses a location outside the share path", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ location: "https://evil.example/" }) });
    expect(await exchangeShareToken(TOKEN, fetchMock as unknown as typeof fetch)).toMatchObject({ ok: false });
  });
});

describe("share management rules", () => {
  const draft = (patch: Partial<ShareDraft>): ShareDraft => ({ ...emptyShareDraft(), ...patch });

  it("has no default expiry and no permanent option", () => {
    expect(buildCreateShareBody(emptyShareDraft())).toBe("请选择有效期");
    expect(buildCreateShareBody(draft({ expiry: "24h" }))).toEqual({ expiresInSeconds: 86_400, access: "read" });
    expect(buildCreateShareBody(draft({ expiry: "7d" }))).toEqual({ expiresInSeconds: 604_800, access: "read" });
  });

  it("bounds a custom expiry to 5 minutes .. 7 days", () => {
    expect(buildCreateShareBody(draft({ expiry: "custom", customAmount: "5", customUnit: "minutes" })))
      .toEqual({ expiresInSeconds: 300, access: "read" });
    expect(buildCreateShareBody(draft({ expiry: "custom", customAmount: "4", customUnit: "minutes" }))).toBe("有效期需在 5 分钟到 7 天之间");
    expect(buildCreateShareBody(draft({ expiry: "custom", customAmount: "8", customUnit: "days" }))).toBe("有效期需在 5 分钟到 7 天之间");
    expect(buildCreateShareBody(draft({ expiry: "custom", customAmount: "1.5", customUnit: "hours" }))).toBe("请输入整数有效期");
  });

  it("requires an explicit confirmation for full access", () => {
    expect(buildCreateShareBody(draft({ expiry: "1h", access: "full" }))).toBe("请确认完整访问的影响");
    expect(buildCreateShareBody(draft({ expiry: "1h", access: "full", fullAccessConfirmed: true })))
      .toEqual({ expiresInSeconds: 3_600, access: "full" });
  });

  it("sends a prefix and a trimmed label only when given", () => {
    expect(buildCreateShareBody(draft({ expiry: "1h", pathPrefix: " /docs ", label: "  周报评审  " })))
      .toEqual({ expiresInSeconds: 3_600, access: "read", pathPrefix: "/docs", label: "周报评审" });
    expect(buildCreateShareBody(draft({ expiry: "1h", pathPrefix: "/" }))).toEqual({ expiresInSeconds: 3_600, access: "read" });
    expect(buildCreateShareBody(draft({ expiry: "1h", pathPrefix: "docs" }))).toBe("路径前缀需以 / 开头");
    expect(buildCreateShareBody(draft({ expiry: "1h", label: "x".repeat(61) }))).toBe("备注最多 60 个字符");
    expect(buildCreateShareBody(draft({ expiry: "1h", label: "a\nb" }))).toBe("备注不能包含控制字符");
  });

  it("offers sharing on HTTPS and localhost only", () => {
    expect(sharingAvailability({ protocol: "https:", hostname: "tunnel.example" }).available).toBe(true);
    expect(sharingAvailability({ protocol: "http:", hostname: "localhost" }).available).toBe(true);
    expect(sharingAvailability({ protocol: "http:", hostname: "127.0.0.1" }).available).toBe(true);
    const plain = sharingAvailability({ protocol: "http:", hostname: "10.0.0.5" });
    expect(plain.available).toBe(false);
    expect(plain.reason).toContain("HTTPS");
  });

  it("only offers creation on enabled, protected routes of enabled clients", () => {
    expect(routeShareBlocker({ enabled: true, authEnabled: true }, true)).toBe("");
    expect(routeShareBlocker({ enabled: true, authEnabled: false }, true)).toContain("公开路由无需分享");
    expect(routeShareBlocker({ enabled: false, authEnabled: true }, true)).toContain("停用");
    expect(routeShareBlocker({ enabled: true, authEnabled: true }, false)).toContain("客户端已停用");
  });

  it("labels states, reasons, the remaining time and audit entries", () => {
    expect(shareStatusLabel({ status: "revoked", revokeReason: "route-made-public" })).toBe("已撤销（路由改为公开）");
    expect(shareStatusLabel({ status: "expired", revokeReason: null })).toBe("已过期");
    const now = Date.parse("2026-10-06T08:00:00Z");
    expect(shareRemaining("2026-10-06T08:30:00Z", now)).toBe("约 30 分钟后到期");
    expect(shareRemaining("2026-10-07T08:00:00Z", now)).toBe("约 24 小时后到期");
    expect(shareRemaining("2026-10-06T07:00:00Z", now)).toBe("已到期");
    expect(describeAuditEntry({ auditId: 1, at: "", actor: null, action: "route.exposure-changed", routeId: 42, shareId: null,
      detail: { from: "protected", to: "public" } })).toBe("暴露状态变更：受保护 → 公开");
  });
});
