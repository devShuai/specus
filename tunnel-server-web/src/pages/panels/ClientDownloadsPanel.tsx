import { useCallback, useEffect, useState } from "react";
import { Button, Card, CardBody, CardHeader, Chip, Spinner } from "@heroui/react";
import type { ClientDownloadLink, ClientImplementation } from "../../api/types";
import { fetchPublicClientDownloads } from "../../api/client";

const IMPLEMENTATION_LABELS: Record<ClientImplementation, string> = {
  java: "Java 客户端",
  go: "Go 客户端",
  csharp: ".NET 客户端",
};

const IMPLEMENTATION_DESCRIPTIONS: Record<ClientImplementation, string> = {
  java: "Spring Boot 实现，跨平台 jar。需要 JDK 21+。",
  go: "Go 实现，单二进制无依赖，启动最快。各操作系统/架构都有独立产物。",
  csharp: ".NET 实现，发布为自包含程序集或 dotnet 运行包。",
};

const IMPLEMENTATION_ORDER: ClientImplementation[] = ["java", "go", "csharp"];

/**
 * 客户端下载面板（只读）。读公开接口 {@code /api/public/client-downloads}，按 implementation 分组展示。
 * 管理员维护入口在「系统管理」面板里。
 */
export function ClientDownloadsPanel() {
  const [links, setLinks] = useState<ClientDownloadLink[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setLinks(await fetchPublicClientDownloads());
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
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">客户端下载</h2>
          <p className="text-small text-default-500">按实现选择对应平台与架构的客户端</p>
        </div>
        <Button size="sm" variant="flat" isLoading={loading} onPress={() => void load()}>
          刷新
        </Button>
      </div>

      {loading && links.length === 0 ? (
        <Spinner className="my-8" label="加载中…" />
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          {grouped.map(({ implementation, links: implLinks }) => (
            <Card key={implementation} shadow="none" className="rounded-md border border-default-200">
              <CardHeader className="flex flex-col items-start gap-1 px-5 pb-2 pt-4">
                <h3 className="text-base font-semibold">{IMPLEMENTATION_LABELS[implementation]}</h3>
                <p className="text-tiny text-default-500">{IMPLEMENTATION_DESCRIPTIONS[implementation]}</p>
              </CardHeader>
              <CardBody className="gap-3 px-5 pb-5 pt-2">
                {implLinks.length === 0 ? (
                  <p className="rounded-md border border-default-200 bg-default-50 p-3 text-tiny text-default-500">
                    暂无下载链接，请管理员在「系统管理」配置
                  </p>
                ) : (
                  implLinks.map((link) => <DownloadCard key={link.id} link={link} />)
                )}
              </CardBody>
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
      <div className="mt-2 flex flex-wrap gap-1">
        <Chip size="sm" variant="flat" color="primary">
          {platformLabel(link.platform)}
        </Chip>
        <Chip size="sm" variant="flat">
          {archLabel(link.arch)}
        </Chip>
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
