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

describe("peer egress management requests", () => {
  it("always sends enabled on the switch, which some servers would read as off when missing", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => "{}" });
    await api.adminApi.updatePeerEgressSwitch(false);
    expect(sent(api.fetchMock)).toEqual({ url: "/api/admin/peer-mesh/egress/switch", method: "PUT", body: { enabled: false } });
  });

  it("saves a policy with flat limits by posting it for the egress device", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => "{}" });
    await api.adminApi.savePeerEgressPolicy({ egressClientId: 2, enabled: true, maxConcurrentFlows: 8 });
    expect(sent(api.fetchMock)).toEqual({ url: "/api/admin/peer-mesh/egress/policies", method: "POST",
      body: { egressClientId: 2, enabled: true, maxConcurrentFlows: 8 } });
  });

  it("deletes by policy id and accepts any server's empty answer", async () => {
    for (const answer of [{ ok: true, status: 204 }, { ok: true, status: 200, text: async () => "" },
      { ok: true, status: 200, text: async () => "{}" }]) {
      const api = await setup();
      api.fetchMock.mockResolvedValue(answer);
      await api.adminApi.deletePeerEgressPolicy(7);
      expect(sent(api.fetchMock)).toMatchObject({ url: "/api/admin/peer-mesh/egress/policies/7", method: "DELETE" });
      vi.resetModules();
    }
  });

  it("reports the server's message for a refused change", async () => {
    const api = await setup();
    api.fetchMock.mockResolvedValue({ ok: false, status: 400, statusText: "Bad Request",
      text: async () => JSON.stringify({ error: "只有租户 ADMIN 可以管理出口授权" }) });
    await expect(api.adminApi.savePeerEgressPolicy({ egressClientId: 2 })).rejects.toThrow("只有租户 ADMIN 可以管理出口授权");
  });
});
