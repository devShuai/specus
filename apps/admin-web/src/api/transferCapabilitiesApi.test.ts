import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.resetModules(); vi.unstubAllGlobals(); });

async function setup(token: string | null = "isolated-session") {
  const values = new Map<string, string>(token ? [["access_token", token]] : []);
  vi.stubGlobal("sessionStorage", { getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
  return { ...(await import("./client")), fetchMock, values };
}

describe("authenticated read-only transfer capabilities request", () => {
  it("sends only a no-store GET with bearer and abort signal, never file metadata", async () => {
    const api = await setup(); const controller = new AbortController();
    api.fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => "{}" });
    await api.fetchTransferCapabilities(controller.signal);
    expect(api.fetchMock).toHaveBeenCalledExactlyOnceWith("/api/public/transfer/attachments/capabilities", {
      method: "GET", cache: "no-store", signal: controller.signal, body: undefined,
      headers: { "Content-Type": "application/json", Authorization: "Bearer isolated-session" },
    });
  });
  it("does not send a query without login", async () => {
    const api = await setup(null);
    await expect(api.fetchTransferCapabilities()).rejects.toThrow(/登录/);
    expect(api.fetchMock).not.toHaveBeenCalled();
  });
  it.each([404, 405, 503])("reports unverified quota for status %i", async (status) => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: false, status, text: async () => "<html>error</html>" });
    await expect(api.fetchTransferCapabilities()).rejects.toThrow(/未核验/);
  });
  it("handles a legacy HTML 200 response as unknown rather than success", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => "<html>SPA</html>" });
    await expect(api.fetchTransferCapabilities()).rejects.toThrow(/未核验/);
  });
  it("expires only the session that made the unauthorized request", async () => {
    const api = await setup(); const expired = vi.fn(); api.setUnauthorizedHandler(expired);
    api.fetchMock.mockImplementation(async () => {
      api.values.set("access_token", "different-session");
      return { status: 401 };
    });
    await expect(api.fetchTransferCapabilities()).rejects.toThrow(/过期/);
    expect(expired).not.toHaveBeenCalled();
    api.fetchMock.mockResolvedValue({ status: 401 });
    await expect(api.fetchTransferCapabilities()).rejects.toThrow(/过期/);
    expect(expired).toHaveBeenCalledOnce();
  });
});
