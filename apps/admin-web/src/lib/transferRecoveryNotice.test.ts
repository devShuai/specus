import { describe, expect, it } from "vitest";
import { transferRecoveryNotice } from "./transferRecoveryNotice";

describe("preflight recovery explanation", () => {
  it("conditions device resume on receiving consent and storage, with the original expiry and file reselection", () => {
    const notice = transferRecoveryNotice("device", true);
    expect(notice).toContain("文件草稿不会在刷新后恢复");
    expect(notice).toContain("对方确认写入本机浏览器存储");
    expect(notice).toContain("同意后 24 小时内续传");
    expect(notice).toContain("发送方刷新，需要重新选择同一文件");
    expect(notice).toContain("仅保存在内存中的接收，刷新后要重新发送");
  });

  it("does not promise device resume to an older sending page", () => {
    expect(transferRecoveryNotice("device", false)).toContain("不能恢复本次进度");
    expect(transferRecoveryNotice("device", false)).not.toContain("24 小时");
  });

  it("does not promise resumable cloud uploads just because the device transfer implementation supports resume", () => {
    expect(transferRecoveryNotice("link", true)).toContain("不能恢复本次进度");
    expect(transferRecoveryNotice("link", true)).not.toContain("24 小时");
  });
});
