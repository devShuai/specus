import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.resetModules(); vi.unstubAllGlobals(); });

async function setup(token: string | null = "member-session") {
  const values = new Map<string, string>();
  if (token) values.set("access_token", token);
  vi.stubGlobal("sessionStorage", { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
  return { ...(await import("./client")), fetchMock };
}

function answer(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, statusText: "", headers: new Headers(),
    text: async () => (body === undefined ? "" : JSON.stringify(body)), json: async () => body };
}

const EVENT = { mode: "device", path: "turn", sizeBucket: "1m-16m", attempt: "retry_after_failure", outcome: "success" } as const;

describe("transfer outcome report", () => {
  it("posts exactly the closed fields, signed in, kept alive on pagehide", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue(answer(200, { collecting: true, accepted: 1 }));
    const result = await api.reportTransferOutcomes([{ ...EVENT, fileName: "a.txt" } as typeof EVENT], true);
    expect(result).toEqual({ status: 200, collecting: true });
    const [url, init] = api.fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/admin/product-metrics/transfer-outcomes");
    expect(init.method).toBe("POST");
    expect(init.keepalive).toBe(true);
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer member-session");
    expect(JSON.parse(String(init.body))).toEqual({ schemaVersion: 1, events: [EVENT] });
  });

  it("sends nothing without a session and passes refusals back without throwing", async () => {
    const signedOut = await setup(null);
    expect(await signedOut.reportTransferOutcomes([EVENT], false)).toEqual({ status: 401 });
    expect(signedOut.fetchMock).not.toHaveBeenCalled();
    vi.resetModules();
    const api = await setup();
    api.fetchMock.mockResolvedValueOnce(answer(429, { code: "PRODUCT_METRICS_RATE_LIMITED" }));
    expect(await api.reportTransferOutcomes([EVENT], false)).toEqual({ status: 429 });
    api.fetchMock.mockResolvedValueOnce(answer(200, { collecting: false, accepted: 0 }));
    expect(await api.reportTransferOutcomes([EVENT], false)).toEqual({ status: 200, collecting: false });
  });

  it("reads the switch silently: errors and 401 mean not collecting and never sign the page out", async () => {
    const api = await setup();
    const unauthorized = vi.fn();
    api.setUnauthorizedHandler(unauthorized);
    api.fetchMock.mockResolvedValueOnce(answer(200, { schemaVersion: 1, enabled: true }));
    expect(await api.fetchProductMetricsCollecting()).toBe(true);
    api.fetchMock.mockResolvedValueOnce(answer(401, undefined));
    expect(await api.fetchProductMetricsCollecting()).toBe(false);
    api.fetchMock.mockResolvedValueOnce(answer(404, undefined));
    expect(await api.fetchProductMetricsCollecting()).toBe(false);
    api.fetchMock.mockRejectedValueOnce(new TypeError("network"));
    expect(await api.fetchProductMetricsCollecting()).toBe(false);
    expect(unauthorized).not.toHaveBeenCalled();
    vi.resetModules();
    const signedOut = await setup(null);
    expect(await signedOut.fetchProductMetricsCollecting()).toBe(false);
    expect(signedOut.fetchMock).not.toHaveBeenCalled();
  });
});

describe("admin endpoints", () => {
  it("confirms the disclosure version when switching on and sends only enabled when switching off", async () => {
    const api = await setup("admin-session");
    api.fetchMock.mockResolvedValue(answer(200, { schemaVersion: 1, enabled: true }));
    await api.adminApi.setProductMetricsEnabled(true);
    await api.adminApi.setProductMetricsEnabled(false);
    const [[url, on], [, off]] = api.fetchMock.mock.calls as [string, RequestInit][];
    expect(url).toBe("/api/admin/product-metrics/settings");
    expect(on.method).toBe("PUT");
    expect(JSON.parse(String(on.body))).toEqual({ enabled: true, disclosureVersion: 1 });
    expect(JSON.parse(String(off.body))).toEqual({ enabled: false });
  });

  it("reads the summary for a range and purges with DELETE", async () => {
    const api = await setup("admin-session");
    api.fetchMock.mockResolvedValue(answer(200, { purged: true, enabled: false }));
    await api.adminApi.productMetricsSummary({ from: "2026-09-01", to: "2026-09-21" });
    await api.adminApi.productMetricsSummary();
    await api.adminApi.purgeProductMetrics();
    const calls = api.fetchMock.mock.calls as [string, RequestInit][];
    expect(calls[0][0]).toBe("/api/admin/product-metrics/summary?from=2026-09-01&to=2026-09-21");
    expect(calls[1][0]).toBe("/api/admin/product-metrics/summary");
    expect(calls[2][0]).toBe("/api/admin/product-metrics/data");
    expect(calls[2][1].method).toBe("DELETE");
  });
});
