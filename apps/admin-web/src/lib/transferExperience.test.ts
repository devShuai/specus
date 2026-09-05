import { describe, expect, it } from "vitest";
import { clipboardQuickSendAllowed, collaborationPeers, keepUncompletedTransfers, transferCompletionLabel } from "./transferExperience";

describe("transfer experience boundaries", () => {
  const peers = [{ id: "member", sameRoom: true }, { id: "nearby", sameRoom: false }, { id: "legacy" }];
  it("does not treat nearby discovery as collaboration consent", () => {
    expect(collaborationPeers(peers, false)).toEqual([]);
    expect(collaborationPeers(peers, true)).toEqual([peers[0]]);
  });
  it("keeps failed and cancelled transfers available after clearing successes", () => {
    const tasks = ["completed", "failed", "cancelled", "queued", "connecting", "sending"].map((status) => ({ status }));
    expect(keepUncompletedTransfers(tasks).map((item) => item.status)).toEqual(["failed", "cancelled", "queued", "connecting", "sending"]);
  });
  it("requires explicit quick-send opt-in, write permission and an online recipient", () => {
    expect(clipboardQuickSendAllowed(false, true, "device")).toBe(false);
    expect(clipboardQuickSendAllowed(true, false, "device")).toBe(false);
    expect(clipboardQuickSendAllowed(true, true, "")).toBe(false);
    expect(clipboardQuickSendAllowed(true, true, "device")).toBe(true);
  });
  it("distinguishes upload completion from receipt", () => {
    expect(transferCompletionLabel(true)).toBe("文件链接已生成");
    expect(transferCompletionLabel(false)).toBe("对方已接收");
  });
});
