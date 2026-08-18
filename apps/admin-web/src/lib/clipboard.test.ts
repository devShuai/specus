import { afterEach, describe, expect, it, vi } from "vitest";

const { notify } = vi.hoisted(() => ({ notify: vi.fn() }));

vi.mock("../components/toast", () => ({ notify }));

import { copyTextToClipboard, copyTextWithFeedback } from "./clipboard";

afterEach(() => {
  notify.mockReset();
  vi.unstubAllGlobals();
});

describe("clipboard helpers", () => {
  it("uses the async clipboard API when it is available", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    await expect(copyTextToClipboard("specus")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("specus");
  });

  it("loads global feedback only after the copy action", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    await expect(copyTextWithFeedback("brew install", "安装命令已复制")).resolves.toBe(true);
    expect(notify).toHaveBeenCalledWith("安装命令已复制");
  });

  it("returns false and reports a manual-copy fallback when both strategies fail", async () => {
    vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    vi.stubGlobal("document", { createElement: vi.fn(() => { throw new Error("unavailable"); }) });

    await expect(copyTextWithFeedback("secret")).resolves.toBe(false);
    expect(notify).toHaveBeenCalledWith("复制失败，请手动选择文本复制", "error");
  });
});
