import { afterEach, describe, expect, it, vi } from "vitest";
import type { ClientArch, ClientDownloadLink, ClientImplementation, ClientPlatform } from "./types";

const tagName = "v1.2.3";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.resetModules();
  vi.unstubAllGlobals();
});

function link(
  id: number,
  implementation: ClientImplementation,
  platform: ClientPlatform,
  arch: ClientArch,
  overrides: Partial<ClientDownloadLink> = {},
): ClientDownloadLink {
  return {
    id,
    implementation,
    platform,
    arch,
    displayName: `${implementation}-${platform}-${arch}`,
    downloadUrl: `https://downloads.example.test/${id}`,
    description: null,
    displayOrder: id,
    enabled: true,
    version: "1.2.3",
    isLatest: true,
    createdAt: "2026-08-18T00:00:00Z",
    updatedAt: "2026-08-18T00:00:00Z",
    ...overrides,
  };
}

function completeConfiguredRelease(): ClientDownloadLink[] {
  return [
    link(1, "java", "any", "any"),
    link(2, "go", "macos", "arm64"),
    link(3, "go", "macos", "x64"),
    link(4, "go", "windows", "x64"),
    link(5, "go", "windows", "arm64"),
    link(6, "go", "linux", "x64"),
    link(7, "go", "linux", "arm64"),
    link(8, "csharp", "windows", "x64"),
    link(9, "csharp", "any", "any"),
    link(10, "android", "android", "any", {
      hosted: true,
      packageId: 10,
      downloadUrl: "/api/public/client-packages/10/download",
    }),
  ];
}

function githubRelease(assetNames: string[]) {
  return {
    tag_name: tagName,
    published_at: "2026-08-18T00:00:00Z",
    assets: assetNames.map((name, index) => ({
      id: index + 100,
      name,
      size: 1024,
      browser_download_url: `https://github.com/devShuai/specus/releases/download/${tagName}/${name}`,
      created_at: "2026-08-18T00:00:00Z",
      updated_at: "2026-08-18T00:00:00Z",
    })),
  };
}

function completeGithubRelease() {
  return githubRelease([
    `specus-client-java-${tagName}.jar`,
    ...["macos-arm64.tar.gz", "macos-x64.tar.gz", "windows-x64.zip", "windows-arm64.zip", "linux-x64.tar.gz", "linux-arm64.tar.gz"]
      .map((target) => `specus-client-go-${tagName}-${target}`),
    `specus-desktop-${tagName}-win-x64.zip`,
    `specus-client-csharp-${tagName}.tar.gz`,
    `specus-client-android-${tagName}.apk`,
  ]);
}

describe("fetchPublicClientDownloads", () => {
  it("uses a complete server-hosted catalog without requesting GitHub", async () => {
    const configured = completeConfiguredRelease();
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => configured });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toEqual(configured);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/public/client-downloads");
  });

  it("lets a fresh server package override the same GitHub target and uses GitHub to fill gaps", async () => {
    const hosted = completeConfiguredRelease()[6];
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [hosted] })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => completeGithubRelease() });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    const links = await fetchPublicClientDownloads();
    expect(links).toHaveLength(10);
    expect(links.find((candidate) => candidate.implementation === "go"
      && candidate.platform === "linux" && candidate.arch === "arm64")).toEqual(hosted);
  });

  it("falls back to GitHub when the server catalog is unavailable", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new Error("catalog offline"))
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => completeGithubRelease() });
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toHaveLength(10);
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://api.github.com/repos/devShuai/specus/releases/latest",
      expect.objectContaining({ credentials: "omit" }),
    );
  });

  it("reports a useful failure when neither source has a download", async () => {
    vi.stubGlobal("fetch", vi.fn()
      .mockRejectedValueOnce(new Error("catalog offline"))
      .mockRejectedValueOnce(new Error("GitHub offline")));
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).rejects.toThrow(
      "无法从服务端版本编目或 GitHub Releases 获取客户端下载链接",
    );
  });

  it("accepts only the exact same-origin hosted package path and safe HTTPS external links", async () => {
    const hosted = link(42, "android", "android", "any", {
      downloadUrl: "/api/public/client-packages/42/download",
      hosted: true,
      packageId: 42,
    });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => [
          hosted,
          { ...hosted, id: 43, downloadUrl: "/api/public/client-packages/../secret" },
          { ...hosted, id: 44, downloadUrl: "http://downloads.example.test/client.apk" },
          { ...hosted, id: 45, downloadUrl: "javascript:alert(1)" },
        ],
      })
      .mockRejectedValueOnce(new Error("GitHub offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await expect(fetchPublicClientDownloads()).resolves.toEqual([hosted]);
  });

  it("keeps a recent successful cache when both refresh sources fail", async () => {
    const configured = completeConfiguredRelease();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => configured })
      .mockRejectedValueOnce(new Error("catalog offline"))
      .mockRejectedValueOnce(new Error("GitHub offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await fetchPublicClientDownloads();
    await expect(fetchPublicClientDownloads({ refresh: true })).resolves.toEqual(configured);
  });

  it("does not retain stale downloads beyond the bounded recovery window", async () => {
    let now = 0;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => completeConfiguredRelease() })
      .mockRejectedValue(new Error("offline"));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    await fetchPublicClientDownloads();
    now = 24 * 60 * 60_000 + 1;
    await expect(fetchPublicClientDownloads({ refresh: true })).rejects.toThrow(
      "无法从服务端版本编目或 GitHub Releases 获取客户端下载链接",
    );
  });

  it("deduplicates concurrent catalog refreshes", async () => {
    let resolveFetch: ((value: unknown) => void) | undefined;
    const fetchMock = vi.fn().mockImplementation(() => new Promise((resolve) => { resolveFetch = resolve; }));
    vi.stubGlobal("fetch", fetchMock);
    const { fetchPublicClientDownloads } = await import("./client");

    const first = fetchPublicClientDownloads({ refresh: true });
    const second = fetchPublicClientDownloads({ refresh: true });
    resolveFetch?.({ ok: true, status: 200, json: async () => completeConfiguredRelease() });

    await expect(Promise.all([first, second])).resolves.toEqual([
      expect.arrayContaining([expect.objectContaining({ implementation: "android" })]),
      expect.arrayContaining([expect.objectContaining({ implementation: "android" })]),
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
