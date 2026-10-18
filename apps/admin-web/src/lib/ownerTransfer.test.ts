import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { ManagementUser, OwnerTransferPreview } from "../api/types";
import { OWNER_TRANSFER_WARNING, OwnerTransferController, countOwnedResources, ownerResourcesHash, readTransferPreview, transferCanSubmit } from "./ownerTransfer";

const bob = { username: "Bob", enabled: true } as ManagementUser;
const admin = { username: "operator", enabled: true, builtIn: true } as ManagementUser;
const single = { kind: "client", id: 10 } as const;
const group = { kind: "credential", id: 50 } as const;
function preview(overrides: Partial<OwnerTransferPreview> = {}): OwnerTransferPreview {
  return { scope: "single", clientId: 10, credentialId: null, credentialOwnerUsername: null, credentialEnabled: null,
    affectedClients: [{ id: 10, clientName: "offline", ownerUsername: "alice", enabled: false }], affectedClientCount: 1,
    canTransfer: true, conflictCode: null, revision: "opaque-1", accessRetained: true, ...overrides };
}
function setup(initial = preview()) {
  const port = { preview: vi.fn().mockResolvedValue(initial), users: vi.fn().mockResolvedValue([bob, admin]), submit: vi.fn() };
  return { port, controller: new OwnerTransferController(port) };
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function result(p = preview(), changed = true) {
  return { scope: p.scope, targetUsername: "Bob", credentialId: p.credentialId, affectedClientIds: p.affectedClients.map(row => row.id), changed, accessRetained: true };
}
async function ready(controller: OwnerTransferController, resource: typeof single | typeof group = single) {
  await controller.load(resource); controller.setTarget("Bob"); controller.confirm(true);
}
describe("complete owner transfer preview", () => {
  it("rejects truncated, duplicate, unsafe, wrong-scope and non-management-only previews", () => {
    const malformed = [preview({ affectedClientCount: 2 }), preview({ affectedClients: [preview().affectedClients[0], preview().affectedClients[0]], affectedClientCount: 2 }),
      preview({ clientId: 11 }), preview({ scope: "credential-group" }), { ...preview(), accessRetained: false },
      preview({ affectedClients: [{ id: Number.MAX_SAFE_INTEGER + 1, clientName: "bad", ownerUsername: null, enabled: true }] }),
      preview({ credentialId: 50, credentialEnabled: null }), preview({ revision: "" })];
    for (const body of malformed) expect(() => readTransferPreview(body, single)).toThrow();
    expect(readTransferPreview({ ...preview(), secret: "must not propagate" }, single)).not.toHaveProperty("secret");
  });
  it("retains all 1050 rows, mixed owners and disabled status, not only a display page", () => {
    const clients = Array.from({ length: 1050 }, (_, n) => ({ id: 1000 + n, clientName: `设备-${n}`, ownerUsername: n % 2 ? "Bob" : "alice", enabled: n % 3 === 0 }));
    const value = preview({ scope: "credential-group", clientId: null, credentialId: 50, credentialOwnerUsername: "missing-old-owner", credentialEnabled: false, affectedClients: clients, affectedClientCount: 1050 });
    const parsed = readTransferPreview(value, group);
    expect(parsed.affectedClients).toEqual(clients); expect(parsed.credentialEnabled).toBe(false); expect(parsed.affectedClients.at(-1)?.id).toBe(2049);
  });
});
describe("explicit confirmation and lifecycle", () => {
  it("needs target plus unchecked-by-default acknowledgement; target changes clear acknowledgement", async () => {
    const { controller, port } = setup(); await controller.load(single);
    controller.confirm(true); expect(transferCanSubmit(controller.snapshot())).toBe(false);
    controller.setTarget("Bob"); expect(controller.snapshot().confirmed).toBe(false);
    await controller.submit(); expect(port.submit).not.toHaveBeenCalled();
    controller.confirm(true); expect(transferCanSubmit(controller.snapshot())).toBe(true);
    controller.setTarget("operator"); expect(controller.snapshot().confirmed).toBe(false);
  });
  it("allows a zero-device credential group without enabling its credential", async () => {
    const p = preview({ scope: "credential-group", clientId: null, credentialId: 50, credentialOwnerUsername: "alice", credentialEnabled: false, affectedClients: [], affectedClientCount: 0 });
    const { controller, port } = setup(p); port.submit.mockResolvedValue(result(p)); await ready(controller, group);
    expect(await controller.submit()).toEqual(result(p));
    expect(port.submit).toHaveBeenCalledWith(group, { scope: "credential-group", targetUsername: "Bob", expectedRevision: "opaque-1" });
    expect(controller.snapshot().preview?.credentialEnabled).toBe(false);
  });
  it("never converts a shared single-device POST into a group POST automatically", async () => {
    const shared = preview({ credentialId: 50, credentialOwnerUsername: "alice", credentialEnabled: true, canTransfer: false,
      conflictCode: "CREDENTIAL_SHARED", revision: null, affectedClients: [...preview().affectedClients, { id: 11, clientName: "other", ownerUsername: "carol", enabled: true }], affectedClientCount: 2 });
    const { controller, port } = setup(shared); await ready(controller); await controller.submit(); expect(port.submit).not.toHaveBeenCalled();
    const grouped = { ...shared, scope: "credential-group" as const, clientId: null, canTransfer: true, conflictCode: null, revision: "group-new" };
    port.preview.mockResolvedValue(grouped); await controller.group();
    expect(port.preview).toHaveBeenLastCalledWith(group); expect(controller.snapshot().target).toBe("Bob"); expect(controller.snapshot().confirmed).toBe(false);
    expect(port.submit).not.toHaveBeenCalled(); controller.confirm(true); port.submit.mockResolvedValue(result(grouped)); await controller.submit();
    expect(port.submit).toHaveBeenCalledOnce(); expect(port.submit.mock.calls[0][1].scope).toBe("credential-group");
  });
  it("fences stale preview completion across resources", async () => {
    const old = deferred<OwnerTransferPreview>(); const { controller, port } = setup(); port.preview.mockReturnValueOnce(old.promise);
    const first = controller.load(single); const next = { kind: "client", id: 11 } as const;
    port.preview.mockResolvedValue(preview({ clientId: 11, affectedClients: [{ id: 11, clientName: "new", ownerUsername: "new", enabled: true }] }));
    await controller.load(next); old.resolve(preview()); await first;
    expect(controller.snapshot().resource).toEqual(next); expect(controller.snapshot().preview?.affectedClients[0].clientName).toBe("new");
  });
  it("blocks duplicate submits and ignores a disposed dialog's late result", async () => {
    const pending = deferred<unknown>(); const { controller, port } = setup(); port.submit.mockReturnValue(pending.promise); await ready(controller);
    const sending = controller.submit(); await controller.submit(); controller.setTarget("operator");
    expect(port.submit).toHaveBeenCalledOnce(); expect(controller.snapshot().target).toBe("Bob");
    controller.dispose(); pending.resolve(result()); expect(await sending).toBeNull(); expect(controller.snapshot().result).toBeNull();
  });
});
describe("conflict and uncertain outcome", () => {
  it("409 rereads complete scope, retains target, clears confirmation, and never auto-retries", async () => {
    const { controller, port } = setup(); await ready(controller);
    port.submit.mockRejectedValueOnce(new ApiError("localized text must not control UI", 409, "TRANSFER_PREVIEW_CHANGED"));
    port.preview.mockResolvedValue(preview({ revision: "opaque-2" })); await controller.submit();
    expect(port.submit).toHaveBeenCalledOnce(); expect(controller.snapshot().target).toBe("Bob"); expect(controller.snapshot().confirmed).toBe(false);
    expect(controller.snapshot().preview?.revision).toBe("opaque-2"); controller.confirm(true); port.submit.mockResolvedValue(result()); await controller.submit();
    expect(port.submit).toHaveBeenLastCalledWith(single, { scope: "single", targetUsername: "Bob", expectedRevision: "opaque-2" });
  });
  it("a disabled target stays visible as the selection but cannot be resubmitted", async () => {
    const { controller, port } = setup(); await ready(controller);
    port.submit.mockRejectedValue(new ApiError("", 400, "INVALID_TARGET_OWNER")); port.users.mockResolvedValue([admin]); await controller.submit(); controller.confirm(true);
    expect(controller.snapshot().target).toBe("Bob"); expect(transferCanSubmit(controller.snapshot())).toBe(false); expect(port.submit).toHaveBeenCalledOnce();
  });
  it.each([new TypeError("network"), new ApiError("gateway", 504), null])("requires reread and new confirmation after unknown result %s", async failure => {
    const { controller, port } = setup(); await ready(controller);
    if (failure) port.submit.mockRejectedValue(failure); else port.submit.mockResolvedValue({ changed: true });
    await controller.submit(); controller.confirm(true); await controller.submit();
    expect(controller.snapshot().phase).toBe("unknown"); expect(port.submit).toHaveBeenCalledOnce();
    port.preview.mockResolvedValue(preview({ revision: "already-transferred", affectedClients: [{ ...preview().affectedClients[0], ownerUsername: "Bob" }] }));
    await controller.refresh(); expect(controller.snapshot().phase).toBe("review"); expect(controller.snapshot().confirmed).toBe(false); expect(port.submit).toHaveBeenCalledOnce();
    controller.confirm(true); port.submit.mockResolvedValue(result(preview(), false)); expect((await controller.submit())?.changed).toBe(false);
  });
  it("403 does not leave a confirmable dialog", async () => {
    const { controller, port } = setup(); await ready(controller); port.submit.mockRejectedValue(new ApiError("", 403)); await controller.submit();
    expect(controller.snapshot().phase).toBe("error"); expect(transferCanSubmit(controller.snapshot())).toBe(false);
  });
});
it("names management-only access retention and routes both kinds of owned resources safely", () => {
  expect(OWNER_TRANSFER_WARNING).toContain("持有密钥的人仍可接入"); expect(OWNER_TRANSFER_WARNING).toContain("不是安全交接");
  expect(countOwnedResources("ALIce", [], [{ ownerUsername: "alice" }])).toEqual({ clients: 0, credentials: 1 });
  expect(ownerResourcesHash("张三 & /?", "credentials")).toBe("#/clients?owner=%E5%BC%A0%E4%B8%89%20%26%20%2F%3F&section=credentials");
});
