import { describe, expect, it } from "vitest";
import { parseTransferCapabilities, cloudPreflightErrors, type TransferCapabilities } from "./transferCapabilities";
import { checkFilePreflight, type FilePreflightInput } from "./transferPreflight";

const snapshot: TransferCapabilities = {
  schemaVersion: 1, checkedAt: "2026-12-31T23:59:59Z", storageEnabled: true, maxAttachmentBytes: 100,
  retentionHours: 72, storageQuotaBytes: 200, storageUsedBytes: 50, storageRemainingBytes: 150,
  monthlyDownloadQuotaBytes: 100, monthlyDownloadUsedBytes: 120, monthlyDownloadRemainingBytes: 0,
  downloadUsageMonth: "2026-12", downloadResetsAt: "2027-01-01T00:00:00Z", downloadGrantSingleUse: true,
};

describe("transfer capability snapshot", () => {
  it("accepts a year rollover and zero remaining after a quota reduction", () => {
    expect(parseTransferCapabilities(snapshot)).toEqual(snapshot);
  });
  it.each([null, {}, "<html>", { ...snapshot, schemaVersion: 2 }, { ...snapshot, storageUsedBytes: -1 },
    { ...snapshot, maxAttachmentBytes: 1.2 }, { ...snapshot, storageRemainingBytes: 200 },
    { ...snapshot, checkedAt: "invalid" }, { ...snapshot, downloadUsageMonth: "2026-11" },
    { ...snapshot, downloadResetsAt: "2027-02-01T00:00:00Z" }, { ...snapshot, storageQuotaBytes: 2 ** 54 },
    { ...snapshot, monthlyDownloadRemainingBytes: null }, { ...snapshot, downloadGrantSingleUse: false }])("rejects malformed or unsupported snapshots", (value) => {
    expect(() => parseTransferCapabilities(value)).toThrow();
  });
  it("checks each file and batch storage, but not the sender's download quota", () => {
    expect(cloudPreflightErrors([{ size: 100 }, { size: 50 }], snapshot)).toEqual([]);
    expect(cloudPreflightErrors([{ size: 100 }, { size: 51 }], snapshot)).toHaveLength(1);
    expect(cloudPreflightErrors([{ size: 101 }], snapshot)).toHaveLength(1);
    expect(cloudPreflightErrors([{ size: 1 }], { ...snapshot, storageEnabled: false })).toHaveLength(1);
    expect(cloudPreflightErrors([{ size: 1 }], null)).toEqual([]);
  });
  it("blocks cloud while reading and on known quota errors without disabling direct-only delivery", () => {
    const input: FilePreflightInput = { files: [{ name: "test", size: 10 }], mode: "device", memoryLimitBytes: 100,
      queuedCount: 0, signedIn: true, rtcSupported: true, recipientOnline: true, discoveryOnline: true, writable: true, scopeCurrent: true };
    const disabled = { ...snapshot, storageEnabled: false };
    expect(checkFilePreflight({ ...input, cloudSnapshot: disabled }).canSend).toBe(true);
    expect(checkFilePreflight({ ...input, cloudRequested: true, cloudSnapshot: disabled }).canSend).toBe(false);
    expect(checkFilePreflight({ ...input, mode: "link", cloudLoading: true }).canSend).toBe(false);
    expect(checkFilePreflight({ ...input, mode: "link", cloudSnapshot: null }).canSend).toBe(true);
  });
});
