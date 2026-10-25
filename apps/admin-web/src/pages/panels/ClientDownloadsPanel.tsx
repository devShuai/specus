import { useCallback, useEffect, useState } from "react";
import { Button } from "@heroui/react";
import type { ClientDownloadLink, ClientImplementation } from "../../api/types";
import { fetchPublicClientDownloads } from "../../api/client";
import { MacosInstallGuide } from "../../components/MacosInstallGuide";
import { formatBytes } from "../../lib/format";
import { PageHeader } from "../../components/PageHeader";
import { Alert, Icon, RelativeTime, Section, Tag } from "../../components/ui";
import { ListLoading } from "./accessUi";

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
  const latestVersion = links.find((link) => link.isLatest && link.version)?.version;

  return (
    <div className="acc-page">
      <PageHeader
        title="客户端下载"
        description="macOS 推荐 Homebrew；GitHub Releases 提供各平台手动下载包"
        actions={<>
          <Button as="a" href="/download" rel="noopener noreferrer" target="_blank" variant="bordered" endContent={<Icon name="external" size={14} />}>
            打开公开下载页
          </Button>
          <Button variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" />} onPress={() => void load(true)}>
            刷新
          </Button>
        </>}
      />

      <Alert tone="info" title="下载之后">
        先 <a className="jd-link" href="#/clients">创建接入凭证并保存配置</a>，再按 <a className="jd-link" href="#/help/quickstart">启动说明</a> 运行客户端。首次登录生成实例后即可选择它发布服务，建议先确认设备在线。
      </Alert>

      <Section title="macOS" description="Homebrew 一条命令安装和升级，Apple Silicon 与 Intel 通用。">
        <MacosInstallGuide />
      </Section>

      <Section
        title="全部下载"
        description="各平台的安装包来自服务端版本编目，缺少的目标从 GitHub Releases 补齐；在新窗口打开下载。"
        actions={latestVersion ? <Tag tone="success">最新 v{latestVersion.replace(/^v/, "")}</Tag> : null}
      >
        {error ? (
          <Alert
            tone="danger"
            role="alert"
            title="下载链接加载失败"
            actions={<Button size="sm" variant="flat" isLoading={loading} startContent={loading ? null : <Icon name="refresh" size={14} />} onPress={() => void load()}>重试</Button>}
          >
            {error}
          </Alert>
        ) : loading && links.length === 0 ? (
          <ListLoading label="正在读取下载链接…" rows={4} />
        ) : (
          <div className="acc-dl-grid">
            {grouped.map(({ implementation, links: implLinks }) => (
              <section key={implementation} className="bd-card acc-dl-card" aria-label={IMPLEMENTATION_LABELS[implementation]}>
                <div className="bd-card-header">
                  <div className="min-w-0">
                    <h3 className="bd-card-title">{IMPLEMENTATION_LABELS[implementation]}</h3>
                    <p className="app-card-desc">{IMPLEMENTATION_DESCRIPTIONS[implementation]}</p>
                  </div>
                  <span className="acc-head-count bd-num">{implLinks.length ? `${implLinks.length} 个` : ""}</span>
                </div>
                {implLinks.length === 0 ? (
                  <p className="acc-dl-empty">还没有读到这个客户端的下载包；过一会儿用右上角的“刷新”再取一次。</p>
                ) : (
                  <ul className="acc-dl-list">
                    {implLinks.map((link) => <DownloadRow key={link.id} link={link} />)}
                  </ul>
                )}
              </section>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function DownloadRow({ link }: { link: ClientDownloadLink }) {
  return (
    <li>
      <a className="acc-dl-row" href={link.downloadUrl} rel="noopener noreferrer" target="_blank">
        <span className="acc-dl-icon" aria-hidden="true"><Icon name="archive" size={16} /></span>
        <span className="acc-dl-main">
          <span className="acc-dl-name">{link.displayName}</span>
          <span className="acc-dl-meta">
            <span className="bd-tag bd-tag--plain">{platformLabel(link.platform)}</span>
            <span className="bd-tag bd-tag--plain">{archLabel(link.arch)}</span>
            {link.version ? <span className={`bd-tag ${link.isLatest ? "bd-tag--success" : ""}`}>v{link.version.replace(/^v/, "")}</span> : null}
            {link.fileSize ? <span className="bd-num">{formatBytes(link.fileSize)}</span> : null}
            <span className="acc-dl-time">更新 <RelativeTime value={link.updatedAt} /></span>
          </span>
        </span>
        <span className="acc-dl-go" aria-hidden="true"><Icon name="download" size={16} /></span>
      </a>
    </li>
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
