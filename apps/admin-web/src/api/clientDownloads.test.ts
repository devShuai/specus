import { afterEach, describe, expect, it, vi } from "vitest";
import type { ClientDownloadLink } from "./types";

const tagName = "v1.2.3";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.resetModules();
  vi.unstubAllGlobals();
});

function githubRelease(assetNames: string[]) {
  return {
    tag_name: tagName,
    published_at: "2026-08-18T00:00:00Z",
    assets: assetNames.map((name, index) => ({
      id: index + 100,
      name,
      browser_download_url: `https://github.com/devShuai/specus/releases/download/${tagName}/${name}`,
      created_at: "2026-08-18T00:00:00Z",
      updated_at: "2026-08-18T00:00:00Z",
    })),
  };
}

function completeRelease() {
  return githubRelease([
    `specus-client-java-${tagName}.jar`,
    ...["macos-arm64.tar.gz", "macos-x64.tar.gz", "windows-x64.zip", "windows-arm64.zip", "linux-x64.tar.gz", "linux-arm64.tar.gz"]
      .map((target) => `specus-client-go-${tagName}-${target}`),
    `specus-desktop-${tagName}-win-x64.zip`,
    `specus-client-csharp-${tagName}.tar.gz`,
  ]);
}

const configuredLinuxArm: ClientDownloadLink = {
  id: 900,
  implementation: "go",
  platform: "linux",
  arch: "arm64",
  displayName: "备用 Linux ARM64",
  downloadUrl: "https://downloads.example.test/specus-linux-arm64.tar.gz",
  description: null,
  displayOrder: 105,
  enabled: true,
  createdAt: "2026-08-18T00:00:00Z",
  updatedAt: "2026-08-18T00:00:00Z",
};

describe("fetchPublicClientDownloads", () => {
  it("uses a complete GitHub Release without requesting the configured fallback", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => completeRelease(),
    });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toHaveLength(9);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://api.github.com/repos/devShuai/specus/releases/latest");
  });

  it("fills targets missing from GitHub with configured links", async () => {
    const partial = completeRelease();
    partial.assets = partial.assets.filter((asset) => !asset.name.includes("linux-arm64"));
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => partial })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [configuredLinuxArm] });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    const links = await fetchPublicClientDownloads();
    expect(links).toContainEqual(configuredLinuxArm);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/public/client-downloads",
      expect.objectContaining({ signal: expect.any(Object) }),
    );
  });

  it("keeps partial GitHub assets when the configured fallback is unavailable", async () => {
    const partial = completeRelease();
    partial.assets = partial.assets.filter((asset) => !asset.name.includes("linux-arm64"));
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => partial })
      .mockRejectedValueOnce(new Error("fallback offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toHaveLength(8);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reports a failure when neither GitHub nor the configured fallback has a download", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [] });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).rejects.toThrow(
      "无法从 GitHub Releases 或备用接口获取客户端下载链接",
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("reports a failure when both download sources are unreachable", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockRejectedValueOnce(new Error("fallback offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).rejects.toThrow(
      "无法从 GitHub Releases 或备用接口获取客户端下载链接",
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("uses and short-caches a configured fallback when GitHub is unavailable", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [configuredLinuxArm] });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toEqual([configuredLinuxArm]);
    await expect(fetchPublicClientDownloads()).resolves.toEqual([configuredLinuxArm]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("prefers a freshly configured target over the same target in stale cache", async () => {
    const replacement = {
      ...configuredLinuxArm,
      id: 901,
      downloadUrl: "https://downloads.example.test/specus-linux-arm64-new.tar.gz",
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => completeRelease() })
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [replacement] });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await fetchPublicClientDownloads();
    const refreshed = await fetchPublicClientDownloads({ refresh: true });
    expect(refreshed).toHaveLength(9);
    expect(refreshed.find((link) => link.platform === "linux" && link.arch === "arm64"))
      .toEqual(replacement);
  });

  it("keeps a recent successful cache when both refresh sources fail", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => completeRelease() })
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockRejectedValueOnce(new Error("fallback offline"))
      .mockRejectedValueOnce(new Error("GitHub still offline"))
      .mockRejectedValueOnce(new Error("fallback offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    const cached = await fetchPublicClientDownloads();
    const recovered = await fetchPublicClientDownloads({ refresh: true });
    expect(recovered).toHaveLength(cached.length);
    expect(recovered).toEqual(expect.arrayContaining(cached));
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("does not reuse a successful cache beyond the maximum stale window", async () => {
    let now = 0;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => completeRelease() })
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockRejectedValueOnce(new Error("fallback offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await fetchPublicClientDownloads();
    now = 24 * 60 * 60_000 - 2 * 60_000;
    await expect(fetchPublicClientDownloads({ refresh: true })).resolves.toHaveLength(9);
    now = 24 * 60 * 60_000 + 1;
    await expect(fetchPublicClientDownloads({ refresh: true })).rejects.toThrow(
      "无法从 GitHub Releases 或备用接口获取客户端下载链接",
    );
  });

  it("filters unsafe or malformed configured download links", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [
          configuredLinuxArm,
          { ...configuredLinuxArm, id: 901, downloadUrl: "http://downloads.example.test/client.tar.gz" },
          { ...configuredLinuxArm, id: 902, downloadUrl: "javascript:alert(1)" },
          { ...configuredLinuxArm, id: 903, platform: "android" },
          { ...configuredLinuxArm, id: 904, displayName: "" },
        ],
      });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toEqual([configuredLinuxArm]);
  });

  it("times out a hanging configured fallback request", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error("GitHub offline"))
      .mockImplementationOnce((_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      }));
    vi.stubGlobal("fetch", fetchMock);
    const { CONFIGURED_DOWNLOAD_REQUEST_TIMEOUT_MS, fetchPublicClientDownloads } = await import("./client");

    const result = fetchPublicClientDownloads();
    const assertion = expect(result).rejects.toThrow(
      "无法从 GitHub Releases 或备用接口获取客户端下载链接",
    );
    await vi.advanceTimersByTimeAsync(CONFIGURED_DOWNLOAD_REQUEST_TIMEOUT_MS);
    await assertion;
  });

  it("deduplicates concurrent forced refreshes", async () => {
    let resolveFetch: ((value: unknown) => void) | undefined;
    const fetchMock = vi.fn().mockImplementation(() => new Promise((resolve) => {
      resolveFetch = resolve;
    }));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    const first = fetchPublicClientDownloads({ refresh: true });
    const second = fetchPublicClientDownloads({ refresh: true });
    resolveFetch?.({ ok: true, status: 200, json: async () => completeRelease() });

    await expect(Promise.all([first, second])).resolves.toEqual([
      expect.arrayContaining([expect.objectContaining({ displayName: "macOS Apple Silicon" })]),
      expect.arrayContaining([expect.objectContaining({ displayName: "macOS Apple Silicon" })]),
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
