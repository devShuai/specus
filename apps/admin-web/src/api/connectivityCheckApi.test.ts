import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.resetModules(); vi.unstubAllGlobals(); });

async function setup() {
  const values = new Map<string, string>([["access_token", "isolated-session"]]);
  vi.stubGlobal("sessionStorage", { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
  return { ...(await import("./client")), fetchMock };
}

function answer(status: number, body: unknown, headers: Record<string, string> = {}) {
  return { ok: status >= 200 && status < 300, status, statusText: "", headers: new Headers(headers),
    text: async () => (body === undefined ? "" : JSON.stringify(body)) };
}

describe("connectivity check request", () => {
  it("is a POST with a JSON body and sends a path only when it is not the root", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue(answer(404, { code: "CHECK_TARGET_NOT_FOUND" }));
    await api.adminApi.checkHttpRouteConnectivity(7);
    await api.adminApi.checkHttpRouteConnectivity(7, "/healthz");
    const [[url, first], [, second]] = api.fetchMock.mock.calls as [string, RequestInit][];
    expect(url).toBe("/api/admin/http-routes/7/connectivity-check");
    expect(first.method).toBe("POST");
    expect(JSON.parse(String(first.body))).toEqual({});
    expect(JSON.parse(String(second.body))).toEqual({ path: "/healthz" });
    expect(new Headers(first.headers).get("Authorization")).toBe("Bearer isolated-session");
  });

  it("returns a check result as is", async () => {
    const api = await setup();
    const body = { schemaVersion: 1, kind: "http-route", routeId: 7, checkedAt: "2026-10-06T08:00:00Z",
      outcome: "failed", stoppedAt: "device-online", code: "DEVICE_OFFLINE", totalMs: 0, requests: [], stages: [] };
    api.fetchMock.mockResolvedValue(answer(200, body));
    expect(await api.adminApi.checkHttpRouteConnectivity(7)).toEqual({ kind: "result", result: body });
  });

  it("returns refusals with their code and Retry-After instead of throwing", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValueOnce(answer(429, { code: "CHECK_RATE_LIMITED" }, { "Retry-After": "10" }));
    expect(await api.adminApi.checkHttpRouteConnectivity(7)).toEqual({ kind: "refused",
      refusal: { status: 429, code: "CHECK_RATE_LIMITED", retryAfterSeconds: 10 } });
    api.fetchMock.mockResolvedValueOnce(answer(405, undefined));
    expect(await api.adminApi.checkHttpRouteConnectivity(7)).toEqual({ kind: "refused",
      refusal: { status: 405, code: null, retryAfterSeconds: null } });
    api.fetchMock.mockResolvedValueOnce({ ...answer(404, undefined), text: async () => "<html>not found</html>" });
    expect(await api.adminApi.checkHttpRouteConnectivity(7)).toEqual({ kind: "refused",
      refusal: { status: 404, code: null, retryAfterSeconds: null } });
  });
});
