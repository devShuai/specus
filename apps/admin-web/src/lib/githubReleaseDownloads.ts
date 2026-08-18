import type {
  ClientArch,
  ClientDownloadLink,
  ClientImplementation,
  ClientPlatform,
} from "../api/types";

export const SPECUS_GITHUB_LATEST_RELEASE_API =
  "https://api.github.com/repos/devShuai/specus/releases/latest";
export const GITHUB_RELEASE_REQUEST_TIMEOUT_MS = 8_000;

type AssetDescriptor = {
  assetName: string;
  implementation: ClientImplementation;
  platform: ClientPlatform;
  arch: ClientArch;
  displayName: string;
  description: string;
  displayOrder: number;
};

const GO_TARGETS: ReadonlyArray<{
  platform: Exclude<ClientPlatform, "any">;
  arch: Exclude<ClientArch, "any">;
  displayName: string;
}> = [
  { platform: "macos", arch: "arm64", displayName: "macOS Apple Silicon" },
  { platform: "macos", arch: "x64", displayName: "macOS Intel" },
  { platform: "windows", arch: "x64", displayName: "Windows x86_64" },
  { platform: "windows", arch: "arm64", displayName: "Windows ARM64" },
  { platform: "linux", arch: "x64", displayName: "Linux x86_64" },
  { platform: "linux", arch: "arm64", displayName: "Linux ARM64" },
];

function assetDescriptors(tagName: string): AssetDescriptor[] {
  const go = GO_TARGETS.map<AssetDescriptor>((target, index) => ({
    assetName: `specus-client-go-${tagName}-${target.platform}-${target.arch}.${target.platform === "windows" ? "zip" : "tar.gz"}`,
    implementation: "go",
    platform: target.platform,
    arch: target.arch,
    displayName: target.displayName,
    description: "静态单文件客户端，无需安装运行时。",
    displayOrder: 100 + index,
  }));

  return [
    {
      assetName: `specus-client-java-${tagName}.jar`,
      implementation: "java",
      platform: "any",
      arch: "any",
      displayName: "Java 21 可执行 JAR",
      description: "适用于已安装 JDK 21 或更高版本的系统。",
      displayOrder: 200,
    },
    ...go,
    {
      assetName: `specus-desktop-${tagName}-win-x64.zip`,
      implementation: "csharp",
      platform: "windows",
      arch: "x64",
      displayName: "Windows 桌面版",
      description: "自包含图形客户端，无需单独安装 .NET Runtime。",
      displayOrder: 300,
    },
    {
      assetName: `specus-client-csharp-${tagName}.tar.gz`,
      implementation: "csharp",
      platform: "any",
      arch: "any",
      displayName: ".NET 命令行客户端",
      description: "跨平台程序集，需要 .NET 10 Runtime。",
      displayOrder: 310,
    },
    {
      assetName: `specus-client-android-${tagName}.apk`,
      implementation: "android",
      platform: "android",
      arch: "any",
      displayName: "Android 应用",
      description: "适用于 Android 8.0 或更高版本。",
      displayOrder: 400,
    },
  ];
}

function targetKey(link: Pick<ClientDownloadLink, "implementation" | "platform" | "arch">): string {
  return `${link.implementation}:${link.platform}:${link.arch}`;
}

const EXPECTED_GITHUB_TARGETS = new Set(
  assetDescriptors("v0.0.0").map((descriptor) => targetKey(descriptor)),
);

export function hasCompleteGithubClientDownloadSet(links: ClientDownloadLink[]): boolean {
  const available = new Set(links.map((link) => targetKey(link)));
  return [...EXPECTED_GITHUB_TARGETS].every((key) => available.has(key));
}

/** GitHub wins for each target; configured links only fill missing implementation/platform/arch slots. */
export function mergeGithubAndConfiguredDownloads(
  githubLinks: ClientDownloadLink[],
  configuredLinks: ClientDownloadLink[],
): ClientDownloadLink[] {
  return mergePreferredClientDownloads(githubLinks, configuredLinks);
}

/** Preferred links replace the same target in fallback; fallback only fills missing slots. */
export function mergePreferredClientDownloads(
  preferredLinks: ClientDownloadLink[],
  fallbackLinks: ClientDownloadLink[],
): ClientDownloadLink[] {
  const preferred = preferredLinks.filter((link) => link.enabled);
  const preferredTargets = new Set(preferred.map((link) => targetKey(link)));
  return [
    ...preferred,
    ...fallbackLinks.filter((link) => link.enabled && !preferredTargets.has(targetKey(link))),
  ].sort((left, right) => left.displayOrder - right.displayOrder || left.id - right.id);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringField(record: Record<string, unknown>, name: string): string {
  const value = record[name];
  return typeof value === "string" ? value : "";
}

function isExpectedAssetUrl(rawUrl: string, tagName: string, assetName: string): boolean {
  try {
    const url = new URL(rawUrl);
    const expectedPath = `/devshuai/specus/releases/download/${tagName}/${assetName}`.toLowerCase();
    return url.protocol === "https:"
      && url.hostname.toLowerCase() === "github.com"
      && decodeURIComponent(url.pathname).toLowerCase() === expectedPath;
  } catch {
    return false;
  }
}

/** Converts the latest GitHub Release response into the download view model used by the site. */
export function mapGithubReleaseToClientDownloads(payload: unknown): ClientDownloadLink[] {
  const release = asRecord(payload);
  if (!release) {
    return [];
  }
  const tagName = stringField(release, "tag_name").trim();
  const assets = Array.isArray(release.assets) ? release.assets : [];
  if (!tagName || assets.length === 0) {
    return [];
  }

  const assetsByName = new Map<string, Record<string, unknown>>();
  for (const value of assets) {
    const asset = asRecord(value);
    if (asset) {
      const name = stringField(asset, "name");
      if (name) {
        assetsByName.set(name, asset);
      }
    }
  }

  const releaseTimestamp = stringField(release, "published_at") || stringField(release, "created_at");
  const links: ClientDownloadLink[] = [];
  for (const descriptor of assetDescriptors(tagName)) {
    const asset = assetsByName.get(descriptor.assetName);
    if (!asset) {
      continue;
    }
    const id = asset.id;
    const downloadUrl = stringField(asset, "browser_download_url");
    if (typeof id !== "number" || !Number.isSafeInteger(id)
      || !isExpectedAssetUrl(downloadUrl, tagName, descriptor.assetName)) {
      continue;
    }
    links.push({
      id,
      implementation: descriptor.implementation,
      platform: descriptor.platform,
      arch: descriptor.arch,
      displayName: descriptor.displayName,
      downloadUrl,
      description: descriptor.description,
      displayOrder: descriptor.displayOrder,
      enabled: true,
      version: tagName.replace(/^v/i, ""),
      sha256: stringField(asset, "digest").replace(/^sha256:/i, "") || null,
      fileSize: typeof asset.size === "number" && Number.isSafeInteger(asset.size) ? asset.size : null,
      isLatest: true,
      changelogUrl: null,
      minSupportedVersion: null,
      hosted: false,
      packageId: null,
      createdAt: stringField(asset, "created_at") || releaseTimestamp,
      updatedAt: stringField(asset, "updated_at") || releaseTimestamp,
    });
  }
  return links;
}

export async function fetchLatestGithubClientDownloads(): Promise<ClientDownloadLink[]> {
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), GITHUB_RELEASE_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(SPECUS_GITHUB_LATEST_RELEASE_API, {
      headers: { Accept: "application/vnd.github+json" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`GitHub Releases 请求失败（HTTP ${response.status}）`);
    }
    const links = mapGithubReleaseToClientDownloads(await response.json());
    if (links.length === 0) {
      throw new Error("最新 GitHub Release 中没有可识别的客户端产物");
    }
    return links;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}
