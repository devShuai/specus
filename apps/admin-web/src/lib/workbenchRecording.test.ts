import { describe, expect, it, vi } from "vitest";
import type { WorkbenchDocument } from "../api/types";
import {
  WORKBENCH_OPEN_ACTIONS,
  copyThenRecord,
  isLinkOpeningClick,
  recordWorkbenchOpen,
  recordsOpen,
} from "./workbenchRecording";

const documentBody: WorkbenchDocument = {
  schemaVersion: 1,
  limits: { maxFavorites: 50, maxRecents: 20, recentRetentionDays: 30 },
  favorites: [],
  recents: [{ kind: "http-route", id: 7, visitedAt: "2026-10-06T00:00:00.000Z" }],
};

function answer(status: number, body: unknown = documentBody): Response {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
}

describe("what counts as an open", () => {
  it("is a closed list of explicit actions", () => {
    expect(WORKBENCH_OPEN_ACTIONS).toEqual([
      "http-route.open-link",
      "http-route.copy-link",
      "tcp-mapping.copy-port",
      "peer-service.copy-address",
      "peer-service.open-link",
    ]);
    for (const action of WORKBENCH_OPEN_ACTIONS) expect(recordsOpen(action)).toBe(true);
  });

  it("excludes loading, polling, browsing and editing", () => {
    for (const action of ["page-load", "refresh", "poll", "render", "switch-tab", "expand", "hover", "focus",
      "create", "edit", "toggle", "delete", "favorite", "connectivity-check", "check-directory",
      "context-menu-copy", "tcp-mapping.open-link", "http-route.copy-port", ""]) {
      expect(recordsOpen(action), action).toBe(false);
    }
  });

  it("follows a link opened with the main or the middle button only", () => {
    expect(isLinkOpeningClick({ button: 0 })).toBe(true);
    expect(isLinkOpeningClick({ button: 1 })).toBe(true);
    expect(isLinkOpeningClick({ button: 2 })).toBe(false);
  });
});

describe("recording an open", () => {
  it("posts a keepalive request with the bearer token and no body", async () => {
    const fetchImpl = vi.fn(async () => answer(200));
    const result = await recordWorkbenchOpen("http-route.open-link", { kind: "http-route", id: 7 },
      { token: "token-1", fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toEqual(documentBody);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/admin/workbench/recents/http-route/7");
    expect(init.method).toBe("POST");
    expect(init.keepalive).toBe(true);
    expect(init.body).toBeUndefined();
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer token-1");
  });

  it("ignores every failure silently", async () => {
    for (const status of [429, 503, 404, 405, 500]) {
      const fetchImpl = vi.fn(async () => answer(status, { code: "WORKBENCH_RATE_LIMITED" }));
      await expect(recordWorkbenchOpen("tcp-mapping.copy-port", { kind: "tcp-mapping", id: 3 },
        { token: "t", fetchImpl: fetchImpl as unknown as typeof fetch })).resolves.toBeNull();
      expect(fetchImpl).toHaveBeenCalledTimes(1); // never retried
    }
    const offline = vi.fn(async () => { throw new TypeError("Failed to fetch"); });
    await expect(recordWorkbenchOpen("peer-service.copy-address", { kind: "peer-service", id: 9 },
      { token: "t", fetchImpl: offline as unknown as typeof fetch })).resolves.toBeNull();
    const garbled = vi.fn(async () => answer(200, "<html>"));
    await expect(recordWorkbenchOpen("peer-service.copy-address", { kind: "peer-service", id: 9 },
      { token: "t", fetchImpl: garbled as unknown as typeof fetch })).resolves.toBeNull();
  });

  it("sends nothing for an invalid reference, a mismatched kind or no session", async () => {
    const fetchImpl = vi.fn(async () => answer(200));
    const options = { token: "t", fetchImpl: fetchImpl as unknown as typeof fetch };
    await recordWorkbenchOpen("http-route.open-link", { kind: "http-route", id: 0 }, options);
    await recordWorkbenchOpen("http-route.open-link", { kind: "http-route", id: 2 ** 53 }, options);
    await recordWorkbenchOpen("http-route.open-link", { kind: "http-route", id: 1.5 }, options);
    await recordWorkbenchOpen("http-route.open-link", { kind: "tcp-mapping", id: 1 }, options);
    await recordWorkbenchOpen("refresh" as never, { kind: "http-route", id: 1 }, options);
    await recordWorkbenchOpen("http-route.open-link", { kind: "http-route", id: 1 }, { ...options, token: null });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("copy, then record", () => {
  it("records only after the copy happened", async () => {
    const order: string[] = [];
    const record = vi.fn(async () => { order.push("record"); });
    await copyThenRecord(async () => { order.push("copy"); return true; }, record);
    expect(order).toEqual(["copy", "record"]);
    expect(record).toHaveBeenCalledTimes(1);
  });

  it("does not record a copy that failed", async () => {
    const record = vi.fn(async () => undefined);
    await expect(copyThenRecord(async () => false, record)).resolves.toBe(false);
    expect(record).not.toHaveBeenCalled();
  });

  it("does not wait for the record", async () => {
    let finish: () => void = () => undefined;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    await expect(copyThenRecord(async () => true, () => pending)).resolves.toBe(true);
    finish();
  });
});
