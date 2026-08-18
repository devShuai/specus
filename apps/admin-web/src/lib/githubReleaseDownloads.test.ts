import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchLatestGithubClientDownloads,
  GITHUB_RELEASE_REQUEST_TIMEOUT_MS,
  hasCompleteGithubClientDownloadSet,
  mapGithubReleaseToClientDownloads,
  mergeGithubAndConfiguredDownloads,
  SPECUS_GITHUB_LATEST_RELEASE_API,
} from "./githubReleaseDownloads";

const tagName = "v1.2.3";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function asset(id: number, name: string, url = `https://github.com/devShuai/specus/releases/download/${tagName}/${name}`) {
  return {
    id,
    name,
    browser_download_url: url,
    created_at: "2026-08-18T01:00:00Z",
    updated_at: "2026-08-18T02:00:00Z",
  };
}

describe("mapGithubReleaseToClientDownloads", () => {
  it("maps only recognized client assets in stable display order", () => {
    const names = [
      `specus-client-go-${tagName}-linux-arm64.tar.gz`,
      `specus-client-java-${tagName}.jar`,
      `specus-server-java-${tagName}.jar`,
      `specus-client-go-${tagName}-macos-arm64.tar.gz`,
      `specus-client-go-${tagName}-windows-x64.zip`,
      `specus-desktop-${tagName}-win-x64.zip`,
      `specus-client-csharp-${tagName}.tar.gz`,
      `specus-client-android-${tagName}.apk`,
      "SHA256SUMS.txt",
    ];
    const links = mapGithubReleaseToClientDownloads({
      tag_name: tagName,
      published_at: "2026-08-18T00:00:00Z",
      assets: names.map((name, index) => asset(index + 1, name)),
    });

    expect(links.map((link) => link.displayName)).toEqual([
      "Java 21 可执行 JAR",
      "macOS Apple Silicon",
      "Windows x86_64",
      "Linux ARM64",
      "Windows 桌面版",
      ".NET 命令行客户端",
      "Android 应用",
    ]);
    expect(links.every((link) => link.enabled)).toBe(true);
    expect(links.every((link) => link.downloadUrl.includes("/devShuai/specus/releases/download/"))).toBe(true);
  });

  it("rejects foreign download URLs and malformed responses", () => {
    const name = `specus-client-go-${tagName}-macos-arm64.tar.gz`;
    expect(mapGithubReleaseToClientDownloads({
      tag_name: tagName,
      assets: [asset(1, name, `https://example.com/${name}`)],
    })).toEqual([]);
    expect(mapGithubReleaseToClientDownloads({ assets: [] })).toEqual([]);
    expect(mapGithubReleaseToClientDownloads(null)).toEqual([]);
  });

  it("detects a complete release and fills only missing targets from configured links", () => {
    const releaseNames = [
      `specus-client-java-${tagName}.jar`,
      ...["macos-arm64.tar.gz", "macos-x64.tar.gz", "windows-x64.zip", "windows-arm64.zip", "linux-x64.tar.gz", "linux-arm64.tar.gz"]
        .map((target) => `specus-client-go-${tagName}-${target}`),
      `specus-desktop-${tagName}-win-x64.zip`,
      `specus-client-csharp-${tagName}.tar.gz`,
      `specus-client-android-${tagName}.apk`,
    ];
    const githubLinks = mapGithubReleaseToClientDownloads({
      tag_name: tagName,
      assets: releaseNames.map((name, index) => asset(index + 1, name)),
    });
    expect(hasCompleteGithubClientDownloadSet(githubLinks)).toBe(true);

    const withoutLinuxArm = githubLinks.filter((link) => !(link.platform === "linux" && link.arch === "arm64"));
    const configuredLinuxArm: typeof githubLinks[number] = {
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
    const configuredDuplicate = { ...configuredLinuxArm, id: 901, platform: "macos" as const };
    const merged = mergeGithubAndConfiguredDownloads(withoutLinuxArm, [configuredLinuxArm, configuredDuplicate]);
    expect(hasCompleteGithubClientDownloadSet(withoutLinuxArm)).toBe(false);
    expect(merged).toContainEqual(configuredLinuxArm);
    expect(merged).not.toContainEqual(configuredDuplicate);
  });
});

describe("fetchLatestGithubClientDownloads", () => {
  it("loads the public latest-release API", async () => {
    const name = `specus-client-java-${tagName}.jar`;
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ tag_name: tagName, assets: [asset(9, name)] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchLatestGithubClientDownloads()).resolves.toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith(
      SPECUS_GITHUB_LATEST_RELEASE_API,
      expect.objectContaining({ credentials: "omit", referrerPolicy: "no-referrer" }),
    );
  });

  it("reports GitHub HTTP failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 403 }));
    await expect(fetchLatestGithubClientDownloads()).rejects.toThrow("HTTP 403");
  });

  it("aborts a stalled GitHub request", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn((_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    })));

    const request = fetchLatestGithubClientDownloads();
    const rejection = expect(request).rejects.toMatchObject({ name: "AbortError" });
    await vi.advanceTimersByTimeAsync(GITHUB_RELEASE_REQUEST_TIMEOUT_MS);
    await rejection;
  });
});
