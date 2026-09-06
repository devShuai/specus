import { describe, expect, it } from "vitest";
import { checkFilePreflight, cloudFallbackPermitted, hasVolatileFileWork, retainVisibleFileActivities, type FilePreflightInput } from "./transferPreflight";

const limit = 128 * 1024 * 1024;
const valid: FilePreflightInput = {
  files: [{ name: "example.bin", size: limit }], mode: "device", memoryLimitBytes: limit, queuedCount: 0,
  signedIn: false, rtcSupported: true, recipientOnline: true, discoveryOnline: true, writable: true, scopeCurrent: true,
};
describe("file send preflight", () => {
  it("allows the exact device limit and rejects the first byte beyond it", () => {
    expect(checkFilePreflight(valid).canSend).toBe(true);
    const result = checkFilePreflight({ ...valid, files: [{ name: "large", size: limit + 1 }] });
    expect(result.canSend).toBe(false);
    expect(result.oversized).toHaveLength(1);
  });
  it("validates each file, not only the batch total", () => {
    expect(checkFilePreflight({ ...valid, files: [valid.files[0], valid.files[0]] })).toMatchObject({ canSend: true, totalBytes: limit * 2 });
  });
  it.each([0, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])("rejects invalid size %s before transfer", (size) => {
    expect(checkFilePreflight({ ...valid, files: [{ name: "invalid", size }] }).canSend).toBe(false);
  });
  it("keeps active tasks within the visible queue capacity", () => {
    expect(checkFilePreflight({ ...valid, queuedCount: 39 }).canSend).toBe(true);
    expect(checkFilePreflight({ ...valid, queuedCount: 40 }).canSend).toBe(false);
  });
  it.each(["rtcSupported", "recipientOnline", "discoveryOnline", "writable", "scopeCurrent"] as const)("blocks when %s is lost", (key) => {
    expect(checkFilePreflight({ ...valid, [key]: false }).canSend).toBe(false);
  });
  it("cloud mode requires login, not WebRTC or an online peer, and never promises quota", () => {
    const cloud = { ...valid, mode: "link" as const, files: [{ name: "large", size: limit + 1 }], rtcSupported: false, recipientOnline: false, discoveryOnline: false };
    expect(checkFilePreflight(cloud).canSend).toBe(false);
    expect(checkFilePreflight({ ...cloud, signedIn: true }).canSend).toBe(true);
  });
  it("requires explicit cloud consent even on retry and prevents same-LAN fallback", () => {
    expect(cloudFallbackPermitted(false, true, false)).toBe(false);
    expect(cloudFallbackPermitted(true, false, false)).toBe(false);
    expect(cloudFallbackPermitted(true, true, true)).toBe(false);
    expect(cloudFallbackPermitted(true, true, false)).toBe(true);
  });
  it("never hides in-flight tasks behind newer completed history", () => {
    const tasks = [{ id: "new", status: "queued" }, { id: "recent", status: "completed" }, { id: "old", status: "sending" }];
    expect(retainVisibleFileActivities(tasks, 2).map((item) => item.id)).toEqual(["new", "old"]);
    expect(retainVisibleFileActivities(tasks, 1).map((item) => item.id)).toEqual(["new", "old"]);
  });
  it("warns for drafts, active/queued sends, pending/active receives and unsaved files only", () => {
    const idle = { draftCount: 0, outgoingCount: 0, receivingCount: 0, pendingCount: 0, unsavedIncomingCount: 0 };
    expect(hasVolatileFileWork(idle)).toBe(false);
    for (const key of Object.keys(idle)) expect(hasVolatileFileWork({ ...idle, [key]: 1 })).toBe(true);
  });
});
