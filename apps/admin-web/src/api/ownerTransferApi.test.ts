import { afterEach, describe, expect, it, vi } from "vitest";
afterEach(() => { vi.useRealTimers(); vi.resetModules(); vi.unstubAllGlobals(); });
async function setup() {
  vi.stubGlobal("sessionStorage", { getItem: () => "synthetic-test-session" });
  const fetchMock = vi.fn(); vi.stubGlobal("fetch", fetchMock);
  return { ...(await import("./client")), fetchMock };
}
describe("owner transfer endpoints", () => {
  it("bounds stalled writes at 30 seconds without retrying or leaving the deadline armed", async () => {
    vi.useFakeTimers();
    const { adminApi, fetchMock } = await setup();
    fetchMock.mockImplementation((_path, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    }));
    const pending = adminApi.transferClientOwner(10, { scope: "single", targetUsername: "Bob", expectedRevision: "opaque" }).catch(error => error);
    await vi.advanceTimersByTimeAsync(29_999);
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect((await pending).name).toBe("AbortError");
    expect(fetchMock).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
  });
  it("uses separate no-store preview paths and explicit scope-bound POST requests", async () => {
    const { adminApi, fetchMock } = await setup(); fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => "{}" });
    await adminApi.previewClientOwnerTransfer(10); await adminApi.previewCredentialOwnerTransfer(50);
    const single = { scope: "single" as const, targetUsername: "Bob", expectedRevision: "opaque" };
    const group = { ...single, scope: "credential-group" as const };
    await adminApi.transferClientOwner(10, single); await adminApi.transferCredentialOwner(50, group);
    expect(fetchMock.mock.calls.map(call => call[0])).toEqual(["/api/admin/clients/10/owner-transfer", "/api/admin/client-credentials/50/owner-transfer", "/api/admin/clients/10/owner-transfer", "/api/admin/client-credentials/50/owner-transfer"]);
    expect(fetchMock.mock.calls[0][1].cache).toBe("no-store"); expect(fetchMock.mock.calls[1][1].cache).toBe("no-store");
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual(single); expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual(group);
    for (const call of fetchMock.mock.calls) expect(call[1].headers.get("Authorization")).toBe("Bearer synthetic-test-session");
  });
  it("preserves both zero-inclusive deletion counts without copying unrelated response data", async () => {
    const { adminApi, fetchMock } = await setup(); fetchMock.mockResolvedValue({ ok: false, status: 409, statusText: "Conflict", text: async () => JSON.stringify({ error: "still owns", clients: 0, credentials: 1, secret: "do not copy" }) });
    const error = await adminApi.deleteUser("alice").catch(value => value);
    expect(error.ownedResources).toEqual({ clients: 0, credentials: 1 }); expect(error).not.toHaveProperty("secret");
  });
  it.each([-1, 0.5, "2", Number.MAX_SAFE_INTEGER + 1])("does not trust invalid owned count %s", async clients => {
    const { adminApi, fetchMock } = await setup(); fetchMock.mockResolvedValue({ ok: false, status: 409, statusText: "Conflict", text: async () => JSON.stringify({ clients, credentials: 1 }) });
    expect((await adminApi.deleteUser("alice").catch(value => value)).ownedResources).toBeUndefined();
  });
});
