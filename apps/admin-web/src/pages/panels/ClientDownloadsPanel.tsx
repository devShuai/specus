import { useCallback, useEffect, useState } from "react";
import { Button, Card, Chip, Spinner, buttonVariants } from "@heroui/react";
import type { ClientDownloadLink, ClientImplementation } from "../../api/types";
import { fetchPublicClientDownloads } from "../../api/client";
import { MacosInstallGuide } from "../../components/MacosInstallGuide";
import { formatBytes, formatDateTime } from "../../lib/format";

const IMPLEMENTATION_LABELS: Record<ClientImplementation, string> = {
  java: "Java 客户端",
  go: "Go 客户端",
  csharp: ".NET 客户端",
  android: "Android 客户端",
};

const IMPLEMENTATION_DESCRIPTIONS: Record<ClientImplementation, string> = {
  java: "Spring Boot 实现，跨平台 jar。需要 JDK 21+。",
  go: "Go 实现，单二进制无依赖，启动最快。各操作系统/架构都有独立产物。",
  csharp: ".NET 实现，发布为自包含程序集或 dotnet 运行包。",
  android: "Android 8.0+ 通用 APK，客户端会主动检查新版本。",
};

const IMPLEMENTATION_ORDER: ClientImplementation[] = ["go", "csharp", "android", "java"];

/**
 * 客户端下载面板（只读）。优先读取服务端版本编目，按 implementation 分组展示；
 * 编目可直接指向 GitHub Release 或服务端托管包，GitHub API 只补齐缺少的目标。
 */
export function ClientDownloadsPanel() {
  const [links, setLinks] = useState<ClientDownloadLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (refresh = false) => {
    setLoading(true);
    setError(null);
    try {
      setLinks(await fetchPublicClientDownloads({ refresh }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "加载下载链接失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const grouped = IMPLEMENTATION_ORDER.map((impl) => ({
    implementation: impl,
    links: links.filter((link) => link.implementation === impl),
  }));

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-semibold">客户端下载</h2>
          <p className="text-small text-default-500">macOS 推荐 Homebrew；GitHub Releases 提供各平台手动下载包</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <a href="/download" rel="noopener noreferrer" target="_blank" className={buttonVariants({ variant: "outline", size: "sm" })}>
            打开公开下载页 ↗
          </a>
          <Button size="sm" variant="secondary" onPress={() => void load(true)} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
            刷新
          </Button>
        </div>
      </div>

      <MacosInstallGuide />

      {error ? (
        <div
          className="flex flex-col items-center gap-3 rounded-md border border-danger-200 bg-danger-50 px-4 py-8 text-center dark:border-danger-400/30 dark:bg-danger-500/10"
          role="alert"
        >
          <p className="text-small text-danger">下载链接加载失败：{error}</p>
          <Button size="sm" variant="danger-soft" onPress={() => void load()} isDisabled={loading}>{loading ? <Spinner size="sm" /> : null}
            重试
          </Button>
        </div>
      ) : loading && links.length === 0 ? (
        <span className="inline-flex items-center gap-2 my-8"><Spinner /><span className="text-sm text-default-500">加载中…</span></span>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-4">
          {grouped.map(({ implementation, links: implLinks }) => (
            <Card key={implementation} className="rounded-md border border-default-200">
              <Card.Header className="flex flex-col items-start gap-1 px-5 pb-2 pt-4">
                <h3 className="text-base font-semibold">{IMPLEMENTATION_LABELS[implementation]}</h3>
                <p className="text-tiny text-default-500">{IMPLEMENTATION_DESCRIPTIONS[implementation]}</p>
              </Card.Header>
              <Card.Content className="gap-3 px-5 pb-5 pt-2">
                {implLinks.length === 0 ? (
                  <p className="rounded-md border border-default-200 bg-default-50 p-3 text-tiny text-default-500">
                    当前未获取到对应产物，请稍后刷新
                  </p>
                ) : (
                  implLinks.map((link) => <DownloadCard key={link.id} link={link} />)
                )}
              </Card.Content>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function DownloadCard({ link }: { link: ClientDownloadLink }) {
  return (
    <a
      className="group block rounded-md border border-default-200 bg-content1 p-3 transition hover:border-primary hover:shadow-sm"
      href={link.downloadUrl}
      rel="noopener noreferrer"
      target="_blank"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium text-foreground group-hover:text-primary">{link.displayName}</div>
          {link.description ? (
            <p className="mt-1 text-tiny text-default-500">{link.description}</p>
          ) : null}
        </div>
        <span className="shrink-0 text-tiny text-default-400 group-hover:text-primary">↗</span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1">
        <Chip size="sm" variant="soft" color="accent">
          {platformLabel(link.platform)}
        </Chip>
        <Chip size="sm" variant="soft">
          {archLabel(link.arch)}
        </Chip>
        {link.version ? <Chip size="sm" color={link.isLatest ? "success" : "default"} variant="soft">v{link.version}</Chip> : null}
        {link.fileSize ? <span className="text-tiny text-default-400">{formatBytes(link.fileSize)}</span> : null}
        <span className="ml-auto text-tiny text-default-400">更新 {formatDateTime(link.updatedAt)}</span>
      </div>
    </a>
  );
}

export function platformLabel(platform: string): string {
  switch (platform) {
    case "windows":
      return "Windows";
    case "linux":
      return "Linux";
    case "macos":
      return "macOS";
    case "android":
      return "Android";
    case "any":
      return "跨平台";
    default:
      return platform;
  }
}

export function archLabel(arch: string): string {
  switch (arch) {
    case "x64":
      return "x86_64";
    case "arm64":
      return "ARM64";
    case "any":
      return "跨架构";
    default:
      return arch;
  }
}
