import { afterEach, describe, expect, it, vi } from "vitest";
import type { ClientDownloadLink } from "./types";

const tagName = "v1.2.3";

afterEach(() => {
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
    expect(fetchMock).toHaveBeenNthCalledWith(2, "/api/public/client-downloads");
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
