import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.resetModules();
  vi.unstubAllGlobals();
});

describe("adminApi.uploadClientPackage", () => {
  it("sends browser-owned multipart boundaries and the shared catalog field names", async () => {
    vi.stubGlobal("sessionStorage", {
      getItem: () => null,
      setItem: () => undefined,
      removeItem: () => undefined,
    });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      text: async () => JSON.stringify({ id: 1 }),
    });
    vi.stubGlobal("fetch", fetchMock);
    const { adminApi } = await import("./client");
    const file = new File(["release"], "specus.apk", { type: "application/vnd.android.package-archive" });

    await adminApi.uploadClientPackage({
      file,
      implementation: "android",
      platform: "android",
      arch: "any",
      version: "1.4.0",
      displayName: "Android 1.4.0",
      minSupportedVersion: "1.2.0",
      enabled: true,
      isLatest: true,
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/admin/client-packages");
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).has("Content-Type")).toBe(false);
    const form = init.body as FormData;
    expect(form.get("file")).toBe(file);
    expect(Object.fromEntries(form.entries())).toMatchObject({
      implementation: "android",
      platform: "android",
      arch: "any",
      version: "1.4.0",
      displayName: "Android 1.4.0",
      minSupportedVersion: "1.2.0",
      enabled: "true",
      isLatest: "true",
    });
  });
});
