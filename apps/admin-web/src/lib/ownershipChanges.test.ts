import { afterEach, expect, it, vi } from "vitest";
import { publishOwnershipChange, watchOwnershipChanges } from "./ownershipChanges";
afterEach(() => vi.unstubAllGlobals());
it("broadcasts invalidation without resource/private data and cleans local/storage/focus listeners", () => {
  const window = new EventTarget(), document = Object.assign(new EventTarget(), { visibilityState: "visible" });
  const save = vi.fn(); vi.stubGlobal("window", window); vi.stubGlobal("document", document); vi.stubGlobal("localStorage", { setItem: save });
  const local = vi.fn(), remote = vi.fn(); const stopLocal = watchOwnershipChanges(local), stopRemote = watchOwnershipChanges(remote, false);
  publishOwnershipChange(); expect(local).toHaveBeenCalledTimes(1); expect(remote).not.toHaveBeenCalled();
  expect(save.mock.calls[0][0]).toBe("specus:ownership-changed"); expect(save.mock.calls[0][1]).toMatch(/^[0-9a-f-]{36}$/);
  window.dispatchEvent(Object.assign(new Event("storage"), { key: "specus:ownership-changed" }));
  window.dispatchEvent(new Event("focus")); document.dispatchEvent(new Event("visibilitychange"));
  expect(local).toHaveBeenCalledTimes(4); expect(remote).toHaveBeenCalledTimes(3);
  stopLocal(); stopRemote(); window.dispatchEvent(new Event("focus")); publishOwnershipChange();
  expect(local).toHaveBeenCalledTimes(4); expect(remote).toHaveBeenCalledTimes(3);
});
