import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.resetModules(); vi.unstubAllGlobals(); });

async function setup() {
  const values = new Map<string, string>([["access_token", "isolated-session"]]);
  vi.stubGlobal("sessionStorage", { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
  return { ...(await import("./client")), fetchMock };
}

function sent(fetchMock: ReturnType<typeof vi.fn>) {
  const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
  return { url, method: init.method ?? "GET", body: init.body ? JSON.parse(String(init.body)) : undefined };
}

describe("temporary HTTP share management requests", () => {
  it("creates a share for the route with exactly the chosen fields", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: true, status: 201, text: async () => JSON.stringify({ token: "t", linkPath: "/#/http-share/t" }) });
    const created = await api.adminApi.createHttpShare(42, { expiresInSeconds: 3600, access: "read", pathPrefix: "/docs/" });
    expect(sent(api.fetchMock)).toEqual({ url: "/api/admin/http-routes/42/shares", method: "POST",
      body: { expiresInSeconds: 3600, access: "read", pathPrefix: "/docs/" } });
    expect(created.linkPath).toBe("/#/http-share/t");
  });

  it("lists, revokes and reads the route audit", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ shares: [{ shareId: "a" }] }) });
    expect(await api.adminApi.listHttpShares(42)).toEqual([{ shareId: "a" }]);
    api.fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ share: { shareId: "a", status: "revoked" } }) });
    expect(await api.adminApi.revokeHttpShare(42, "a")).toEqual({ shareId: "a", status: "revoked" });
    api.fetchMock.mockResolvedValueOnce({ ok: true, status: 200, text: async () => JSON.stringify({ entries: [], nextBefore: null }) });
    await api.adminApi.listHttpRouteAccessAudit(42, 20, 99);
    const calls = api.fetchMock.mock.calls as Array<[string, RequestInit]>;
    expect(calls.map(([url, init]) => `${init.method ?? "GET"} ${url}`)).toEqual([
      "GET /api/admin/http-routes/42/shares",
      "POST /api/admin/http-routes/42/shares/a/revoke",
      "GET /api/admin/http-routes/42/access-audit?limit=20&before=99",
    ]);
    expect(calls[1][1].body).toBe("{}");
  });

  it("turns a share error code into a readable message and keeps the code", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: false, status: 409, statusText: "Conflict",
      text: async () => JSON.stringify({ code: "SHARE_ROUTE_PUBLIC" }) });
    const failure = api.adminApi.createHttpShare(43, { expiresInSeconds: 3600, access: "read" });
    await expect(failure).rejects.toThrow("公开路由不能创建分享，请先开启访问认证");
    await expect(failure).rejects.toMatchObject({ code: "SHARE_ROUTE_PUBLIC" });
  });
});
