import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { fetchPublicClientDownloads } from "../api/client";
import type { ClientArch, ClientDownloadLink, ClientPlatform } from "../api/types";
import { PublicPage } from "../components/PublicTopBar";
import { Glyph } from "../components/PublicGlyph";
import { copyTextToClipboard } from "../lib/clipboard";
import { formatBytes } from "../lib/format";
import {
  MACOS_CLIENT_START_COMMAND,
  MACOS_HOMEBREW_INSTALL_COMMAND,
  MACOS_HOMEBREW_UPGRADE_COMMAND,
  SPECUS_HOMEBREW_TAP_URL,
} from "../lib/macosInstall";
import {
  detectVisitorDevice,
  recommendClientDownload,
  visitorDeviceDisplayName,
  type VisitorDevice,
  type VisitorUserAgentHints,
} from "../lib/platformDownloads";
import { usePageSeo } from "../lib/seo";

const GITHUB_RELEASES_URL = "https://github.com/devShuai/specus/releases/latest";
const USER_AGENT_HINT_TIMEOUT_MS = 1_500;

interface UserAgentDataLike {
  mobile?: boolean;
  platform?: string;
  getHighEntropyValues?: (hints: string[]) => Promise<Record<string, unknown>>;
}

type DownloadGroupKey = Exclude<ClientPlatform, "any"> | "any";

const MANUAL_DEVICES: Array<{ label: string; detail: string; device: VisitorDevice }> = [
  { label: "macOS", detail: "Homebrew 自动选架构", device: { platform: "macos", arch: "unknown" } },
  { label: "Windows", detail: "x86_64", device: { platform: "windows", arch: "x64" } },
  { label: "Windows", detail: "ARM64", device: { platform: "windows", arch: "arm64" } },
  { label: "Linux", detail: "x86_64", device: { platform: "linux", arch: "x64" } },
  { label: "Linux", detail: "ARM64", device: { platform: "linux", arch: "arm64" } },
  { label: "Android", detail: "Android 8.0+", device: { platform: "android", arch: "unknown" } },
];

const DOWNLOAD_GROUPS: Array<{
  key: DownloadGroupKey;
  title: string;
  description: string;
}> = [
  { key: "macos", title: "macOS", description: "Homebrew Cask 或对应架构的 Go 单文件客户端" },
  { key: "windows", title: "Windows", description: "图形桌面版或轻量 Go 命令行客户端" },
  { key: "linux", title: "Linux", description: "x86_64 与 ARM64 静态单文件客户端" },
  { key: "android", title: "Android", description: "通用 APK，安装时由 Android 确认应用来源与权限" },
  { key: "any", title: "跨平台 · 需要运行时", description: "适合已有 Java 或 .NET 运行环境的设备" },
];

const SETUP_STEPS = [
  { title: "安装客户端", description: "使用上方推荐方式，或在完整列表选择实现。" },
  { title: "准备配置", description: "将服务端地址与凭证写入 client.jsonc。" },
  { title: "启动连接", description: "运行客户端，让内网服务接入 specus。" },
];

export function PublicDownloadPage() {
  const [deviceDetectionPending, setDeviceDetectionPending] = useState(() => hasHighEntropyUserAgentData());
  const [detectedDevice, setDetectedDevice] = useState<VisitorDevice>(() => detectInitialDevice());
  const [manualDevice, setManualDevice] = useState<VisitorDevice | null>(null);
  const [chooserOpen, setChooserOpen] = useState(false);
  const [downloads, setDownloads] = useState<ClientDownloadLink[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const changeDeviceButtonRef = useRef<HTMLButtonElement>(null);
  const deviceChooserRef = useRef<HTMLDivElement>(null);
  const allDownloadsRef = useRef<HTMLDivElement>(null);

  usePageSeo({
    title: "Specus Client 下载 · Windows / macOS / Linux / Android · specus",
    description:
      "下载 Specus Client。页面会自动识别 macOS、Windows、Linux、Android 与 CPU 架构，优先推荐最合适的安装包。",
    canonical: "https://specus.devshuai.com/download",
    keywords: "Specus Client 下载,macOS Homebrew,Windows 客户端,Linux ARM64,内网穿透客户端",
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      name: "Specus Client",
      url: "https://specus.devshuai.com/download",
      downloadUrl: GITHUB_RELEASES_URL,
      applicationCategory: "DeveloperApplication",
      operatingSystem: "Windows, macOS, Linux, Android",
      description: "Specus 自托管内网穿透与对端互联客户端。",
      offers: { "@type": "Offer", price: "0", priceCurrency: "CNY" },
    },
  });

  useEffect(() => {
    let active = true;
    const userAgentData = readUserAgentData();
    if (!userAgentData?.getHighEntropyValues) {
      setDeviceDetectionPending(false);
      return;
    }
    const timeout = globalThis.setTimeout(() => {
      if (active) setDeviceDetectionPending(false);
    }, USER_AGENT_HINT_TIMEOUT_MS);
    void userAgentData.getHighEntropyValues(["architecture", "bitness", "platform", "wow64"])
      .then((values) => {
        if (!active) return;
        setDetectedDevice(detectFromNavigator({
          platform: stringValue(values.platform) || userAgentData.platform,
          architecture: stringValue(values.architecture) || "unavailable",
          bitness: stringValue(values.bitness),
          mobile: userAgentData.mobile,
          wow64: values.wow64 === true,
        }));
      })
      .catch(() => {
        // Low-entropy hints and the legacy UA already produced a safe fallback.
      })
      .finally(() => {
        if (active) setDeviceDetectionPending(false);
        globalThis.clearTimeout(timeout);
      });
    return () => {
      active = false;
      globalThis.clearTimeout(timeout);
    };
  }, []);

  const loadDownloads = useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      const links = await fetchPublicClientDownloads({ refresh });
      setDownloads(links);
      setLoadError(false);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDownloads();
  }, [loadDownloads]);

  const device = manualDevice ?? detectedDevice;
  const recommendation = useMemo(
    () => recommendClientDownload(device, downloads),
    [device, downloads],
  );
  const groups = useMemo(() => orderedDownloadGroups(device), [device]);

  const restoreChangeDeviceFocus = () => {
    globalThis.requestAnimationFrame(() => changeDeviceButtonRef.current?.focus());
  };

  const chooseDevice = (next: VisitorDevice) => {
    setManualDevice(next);
    setChooserOpen(false);
    restoreChangeDeviceFocus();
  };

  const openDeviceChooser = () => {
    setChooserOpen(true);
    globalThis.requestAnimationFrame(() => {
      deviceChooserRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
    });
  };

  const revealAllDownloads = () => {
    setShowAll(true);
    globalThis.requestAnimationFrame(() => {
      globalThis.requestAnimationFrame(() => {
        const target = allDownloadsRef.current;
        if (!target) return;
        const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        target.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "start" });
        target.focus({ preventScroll: true });
      });
    });
  };

  return (
    <PublicPage active="download">
      <div className="pub-container pub-container--narrow pub-download">
        <header className="bd-page-header pub-page-header">
          <div className="min-w-0">
            <p className="pub-eyebrow">Specus Client</p>
            <h1 className="bd-page-title">下载客户端</h1>
            <p className="bd-page-desc">识别这台设备的系统与处理器，先给出最合适的安装方式；其他平台和实现在下方完整列表里。</p>
          </div>
        </header>

        <section className="bd-card pub-recommend" aria-labelledby="recommended-download-title">
          <div className="pub-recommend-head">
            <span className="pub-device-mark" aria-hidden="true"><Glyph name="monitor" size={20} /></span>
            <div className="min-w-0 flex-1">
              <p className="pub-recommend-kicker">{manualDevice ? "手动选择" : "检测到这台设备"}</p>
              <h2 id="recommended-download-title" className="pub-recommend-device">
                {visitorDeviceDisplayName(device)}
              </h2>
            </div>
            <button
              ref={changeDeviceButtonRef}
              aria-expanded={chooserOpen}
              className="bd-btn bd-btn--secondary bd-btn--sm"
              type="button"
              onClick={() => setChooserOpen((value) => !value)}
            >
              <Glyph name="edit" />
              <span>不是你的设备？更改</span>
            </button>
          </div>

          {chooserOpen && (
            <DeviceChooser
              containerRef={deviceChooserRef}
              current={device}
              detected={detectedDevice}
              manual={manualDevice !== null}
              onChoose={chooseDevice}
              onReset={() => {
                setManualDevice(null);
                setChooserOpen(false);
                restoreChangeDeviceFocus();
              }}
            />
          )}

          <div className="pub-recommend-body" aria-live="polite">
            <RecommendedInstall
              device={device}
              detectingDevice={deviceDetectionPending && manualDevice === null}
              loading={loading}
              loadError={loadError}
              recommendation={recommendation}
              onChoose={chooseDevice}
              onRetry={() => void loadDownloads(true)}
              onOpenChooser={openDeviceChooser}
              onShowAll={revealAllDownloads}
            />
          </div>
        </section>

        <ol className="pub-setup-steps" aria-label="接入步骤">
          {SETUP_STEPS.map((step, index) => (
            <li key={step.title}>
              <span className="pub-stage-dot bd-num" aria-hidden="true">{index + 1}</span>
              <div className="min-w-0">
                <b>{step.title}</b>
                <p>{step.description}</p>
              </div>
            </li>
          ))}
        </ol>

        <section className="jd-section pub-all-downloads" aria-labelledby="all-downloads-title">
          <div className="jd-section-head">
            <div className="min-w-0">
              <h2 id="all-downloads-title">需要其他安装方式？</h2>
              <p>展开后可按 macOS、Windows、Linux 与跨平台运行时查看全部可用客户端产物、SHA-256 校验值与下载地址。</p>
            </div>
            <button
              aria-controls="all-download-methods"
              aria-expanded={showAll}
              className="bd-btn bd-btn--secondary"
              type="button"
              onClick={() => setShowAll((value) => !value)}
            >
              <span>{showAll ? "收起全部下载方式" : "查看全部平台与安装方式"}</span>
              <Glyph name="chevron-down" className={`pub-chevron${showAll ? " is-open" : ""}`} />
            </button>
          </div>

          {showAll && (
            <div
              ref={allDownloadsRef}
              id="all-download-methods"
              className="pub-download-groups"
              tabIndex={-1}
            >
              {loadError && (
                <Alert
                  tone="warning"
                  role="alert"
                  title="下载列表暂时无法更新"
                  actions={
                    <>
                      <button className="bd-btn bd-btn--secondary bd-btn--sm" type="button" onClick={() => void loadDownloads(true)}>
                        <Glyph name="refresh" />
                        <span>重试</span>
                      </button>
                      <a className="bd-btn bd-btn--ghost bd-btn--sm" href={GITHUB_RELEASES_URL} target="_blank" rel="noopener noreferrer">
                        <span>GitHub Releases</span>
                        <Glyph name="external" />
                      </a>
                    </>
                  }
                >
                  macOS Homebrew 仍可使用，也可以直接打开 GitHub Releases。
                </Alert>
              )}

              {groups.map((group) => (
                <DownloadGroup
                  key={group.key}
                  group={group}
                  links={downloads.filter((link) => link.platform === group.key)}
                  loading={loading}
                />
              ))}
            </div>
          )}
        </section>
      </div>
    </PublicPage>
  );
}

function RecommendedInstall({
  device,
  detectingDevice,
  loading,
  loadError,
  recommendation,
  onChoose,
  onOpenChooser,
  onRetry,
  onShowAll,
}: {
  device: VisitorDevice;
  detectingDevice: boolean;
  loading: boolean;
  loadError: boolean;
  recommendation: ReturnType<typeof recommendClientDownload>;
  onChoose: (device: VisitorDevice) => void;
  onOpenChooser: () => void;
  onRetry: () => void;
  onShowAll: () => void;
}) {
  if (recommendation.kind === "homebrew") {
    return <HomebrewGuide />;
  }

  if (device.platform === "android") {
    if (loading && recommendation.kind === "none") {
      return <DownloadLoading />;
    }
    if (recommendation.kind === "download") {
      return (
        <RecommendedDownload
          badge="Android 最佳匹配"
          link={recommendation.link}
          description="下载通用 APK 后，Android 会再次确认安装。后续版本可由客户端主动提示。"
          tags={["Android 8.0+", "APK"]}
          action="下载 Android 版"
          newTab={false}
        />
      );
    }
    return <DownloadUnavailable networkError={loadError} onRetry={onRetry} onShowAll={onShowAll} />;
  }

  if (device.platform === "windows" || device.platform === "linux") {
    if (device.arch === "unknown") {
      if (detectingDevice) {
        return <DeviceDetectionLoading />;
      }
      return (
        <div className="pub-recommend-block">
          <Tag tone="warning">还差一步</Tag>
          <h3 className="pub-recommend-title">选择这台设备的处理器架构</h3>
          <p className="pub-recommend-desc">
            浏览器没有提供可靠的架构信息。在系统设置里确认处理器类型，避免下载无法运行的版本。
          </p>
          <div className="pub-choice-grid pub-choice-grid--two">
            {(["x64", "arm64"] as const).map((arch) => (
              <button
                key={arch}
                className="pub-choice"
                type="button"
                onClick={() => onChoose({ platform: device.platform as "windows" | "linux", arch })}
              >
                <strong>{arch === "x64" ? "x86_64" : "ARM64"}</strong>
                <span>{arch === "x64" ? "Intel / AMD 64 位" : "ARM 64 位"}</span>
              </button>
            ))}
          </div>
        </div>
      );
    }

    if (loading && recommendation.kind === "none") {
      return <DownloadLoading />;
    }

    if (recommendation.kind === "download") {
      const desktop = recommendation.reason === "windows-desktop";
      return (
        <RecommendedDownload
          badge="最佳匹配"
          link={recommendation.link}
          description={desktop
            ? "自包含的 Windows 图形客户端，无需另外安装 .NET Runtime。下载压缩包并解压后即可使用。"
            : recommendation.link.description || "对应当前系统与处理器的静态单文件客户端，无需额外安装运行时。"}
          tags={[implementationLabel(recommendation.link), archLabel(recommendation.link.arch), "发布包"]}
          action="下载最佳匹配"
          newTab
        />
      );
    }

    return (
      <DownloadUnavailable
        networkError={loadError}
        onRetry={onRetry}
        onShowAll={onShowAll}
      />
    );
  }

  if (device.platform === "unsupported") {
    return (
      <div className="pub-recommend-block">
        <Tag plain>桌面客户端</Tag>
        <h3 className="pub-recommend-title">在电脑上打开下载页</h3>
        <p className="pub-recommend-desc">
          当前暂未提供 iOS、iPadOS 或 ChromeOS 安装包。用 Android、macOS、Windows 或 Linux 设备下载客户端。
        </p>
        <div className="bd-row pub-recommend-actions">
          <button className="bd-btn bd-btn--secondary" type="button" onClick={onShowAll}>
            <span>查看全部桌面平台</span>
            <Glyph name="arrow-right" />
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="pub-recommend-block">
      <Tag plain>未识别设备</Tag>
      <h3 className="pub-recommend-title">选择你的系统与处理器</h3>
      <p className="pub-recommend-desc">
        浏览器没有提供可确认的平台信息。用上方的设备选择器选定设备，或展开全部安装方式。
      </p>
      <div className="bd-row pub-recommend-actions">
        <button className="bd-btn bd-btn--primary" type="button" onClick={onOpenChooser}>
          <Glyph name="monitor" />
          <span>选择设备</span>
        </button>
        <button className="bd-btn bd-btn--secondary" type="button" onClick={onShowAll}>
          <span>查看全部平台与安装方式</span>
          <Glyph name="arrow-right" />
        </button>
      </div>
    </div>
  );
}

function RecommendedDownload({
  action,
  badge,
  description,
  link,
  newTab,
  tags,
}: {
  action: string;
  badge: string;
  description: string;
  link: ClientDownloadLink;
  newTab: boolean;
  tags: string[];
}) {
  const facts = [
    ...tags,
    link.version ? `v${link.version.replace(/^v/i, "")}` : null,
    link.fileSize ? formatBytes(link.fileSize) : null,
  ].filter((value): value is string => Boolean(value));
  return (
    <div className="pub-match">
      <div className="pub-recommend-block min-w-0">
        <Tag tone="success">{badge}</Tag>
        <h3 className="pub-recommend-title">{link.displayName}</h3>
        <p className="pub-recommend-desc">{description}</p>
        <div className="bd-row">
          {facts.map((fact) => <Tag key={fact} plain className="bd-num">{fact}</Tag>)}
        </div>
        {link.sha256 ? <Checksum value={link.sha256} name={link.displayName} /> : null}
      </div>
      <a
        className="bd-btn bd-btn--primary bd-btn--lg pub-match-action"
        href={link.downloadUrl}
        rel="noopener noreferrer"
        target={newTab ? "_blank" : undefined}
      >
        <Glyph name="download" />
        <span>{action}</span>
      </a>
    </div>
  );
}

/** The macOS install guide as a code card: the Homebrew commands with copy buttons. */
function HomebrewGuide() {
  return (
    <section className="pub-recommend-block" aria-label="macOS Homebrew 安装说明">
      <div className="bd-row">
        <Tag tone="info">macOS</Tag>
        <Tag tone="success">推荐安装方式</Tag>
        <a className="jd-link pub-inline-link" href={SPECUS_HOMEBREW_TAP_URL} rel="noopener noreferrer" target="_blank">
          <span>查看 Cask</span>
          <Glyph name="external" size={14} />
        </a>
      </div>
      <h3 className="pub-recommend-title">通过 Homebrew 安装 Specus Client</h3>
      <p className="pub-recommend-desc">同一条命令自动选择 Apple Silicon 或 Intel 版本，并可通过 Homebrew 直接升级。</p>
      <div className="pub-code-card">
        <CommandRow command={MACOS_HOMEBREW_INSTALL_COMMAND} label="安装" />
        <CommandRow command={MACOS_CLIENT_START_COMMAND} label="运行" />
      </div>
      <p className="pub-recommend-note">
        将运行命令中的配置路径替换为你的 <code>client.jsonc</code>；后续执行 <code>{MACOS_HOMEBREW_UPGRADE_COMMAND}</code> 即可升级。
        也可以使用 GitHub Release 中对应架构的 macOS 压缩包手动安装。
      </p>
    </section>
  );
}

function useCopyStatus() {
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const resetTimer = useRef<number | null>(null);
  useEffect(() => () => {
    if (resetTimer.current !== null) globalThis.clearTimeout(resetTimer.current);
  }, []);
  const copy = async (text: string) => {
    const copied = await copyTextToClipboard(text);
    setStatus(copied ? "success" : "error");
    if (resetTimer.current !== null) globalThis.clearTimeout(resetTimer.current);
    resetTimer.current = globalThis.setTimeout(() => setStatus("idle"), 2_500);
  };
  return { status, copy };
}

function CommandRow({ command, label }: { command: string; label: string }) {
  const { status, copy } = useCopyStatus();
  return (
    <div className="pub-code">
      <span className="pub-code-label">{label}</span>
      <code><span className="pub-code-prompt" aria-hidden="true">$ </span>{command}</code>
      <button
        aria-label={`复制${label}命令`}
        className="bd-btn bd-btn--ghost bd-btn--sm"
        type="button"
        onClick={() => void copy(command)}
      >
        <Glyph name={status === "success" ? "check" : "copy"} />
        <span>{status === "success" ? "已复制" : status === "error" ? "复制失败" : "复制"}</span>
      </button>
      <span aria-live="polite" className="jd-sr-only">
        {status === "success" ? `${label}命令已复制` : status === "error" ? "复制失败，手动选中文本复制" : ""}
      </span>
    </div>
  );
}

/** A SHA-256 value, shortened on screen with the full value on hover, and a copy button. */
function Checksum({ value, name, compact = false }: { value: string; name: string; compact?: boolean }) {
  const { status, copy } = useCopyStatus();
  return (
    <span className={`pub-checksum${compact ? " pub-checksum--compact" : ""}`}>
      {compact ? null : <span className="pub-checksum-label">SHA-256</span>}
      <code title={value}>{compact ? `${value.slice(0, 10)}…` : `${value.slice(0, 16)}…${value.slice(-8)}`}</code>
      <button
        type="button"
        className="bd-btn bd-btn--ghost bd-btn--sm pub-checksum-copy"
        aria-label={`复制 ${name} 的 SHA-256`}
        title={status === "success" ? "已复制" : status === "error" ? "复制失败" : "复制 SHA-256"}
        onClick={() => void copy(value)}
      >
        <Glyph name={status === "success" ? "check" : "copy"} />
        <span />
      </button>
      <span aria-live="polite" className="jd-sr-only">
        {status === "success" ? `${name} 的 SHA-256 已复制` : status === "error" ? "复制失败，手动选中文本复制" : ""}
      </span>
    </span>
  );
}

function DeviceChooser({
  containerRef,
  current,
  detected,
  manual,
  onChoose,
  onReset,
}: {
  containerRef: RefObject<HTMLDivElement | null>;
  current: VisitorDevice;
  detected: VisitorDevice;
  manual: boolean;
  onChoose: (device: VisitorDevice) => void;
  onReset: () => void;
}) {
  return (
    <div ref={containerRef} className="pub-device-chooser">
      <p className="pub-recommend-kicker">选择要下载到的设备</p>
      <div className="pub-choice-grid">
        {MANUAL_DEVICES.map((option) => {
          const selected = current.platform === option.device.platform && current.arch === option.device.arch;
          return (
            <button
              key={`${option.device.platform}-${option.device.arch}`}
              aria-pressed={selected}
              className="pub-choice"
              type="button"
              onClick={() => onChoose(option.device)}
            >
              <strong>{option.label}</strong>
              <span>{option.detail}</span>
            </button>
          );
        })}
      </div>
      {manual && (
        <button className="bd-btn bd-btn--ghost bd-btn--sm pub-device-reset" type="button" onClick={onReset}>
          <Glyph name="refresh" />
          <span>恢复自动识别 · {visitorDeviceDisplayName(detected)}</span>
        </button>
      )}
    </div>
  );
}

function DownloadUnavailable({
  networkError,
  onRetry,
  onShowAll,
}: {
  networkError: boolean;
  onRetry: () => void;
  onShowAll: () => void;
}) {
  return (
    <Alert
      tone={networkError ? "danger" : "warning"}
      role={networkError ? "alert" : "status"}
      title={networkError ? "暂时无法获取下载链接" : "当前发布暂无匹配原生包"}
      className="pub-unavailable"
    >
      <span className="block">我们不会自动改用其他处理器架构，以免下载后无法运行。</span>
      <span className="bd-row pub-unavailable-actions">
        {networkError && (
          <button className="bd-btn bd-btn--secondary bd-btn--sm" type="button" onClick={onRetry}>
            <Glyph name="refresh" />
            <span>重新获取</span>
          </button>
        )}
        <button className="bd-btn bd-btn--secondary bd-btn--sm" type="button" onClick={onShowAll}>
          <Glyph name="list" />
          <span>查看全部方式</span>
        </button>
        <a className="bd-btn bd-btn--ghost bd-btn--sm" href={GITHUB_RELEASES_URL} target="_blank" rel="noopener noreferrer">
          <span>GitHub Releases</span>
          <Glyph name="external" />
        </a>
      </span>
    </Alert>
  );
}

function DownloadLoading() {
  return (
    <div className="pub-loading" role="status">
      <Glyph name="loader" size={18} className="animate-spin" />
      <span>正在为这台设备查找最新客户端…</span>
    </div>
  );
}

function DeviceDetectionLoading() {
  return (
    <div className="pub-loading" role="status">
      <Glyph name="loader" size={18} className="animate-spin" />
      <span>正在确认这台设备的处理器架构…</span>
    </div>
  );
}

function DownloadGroup({
  group,
  links,
  loading,
}: {
  group: (typeof DOWNLOAD_GROUPS)[number];
  links: ClientDownloadLink[];
  loading: boolean;
}) {
  const sorted = [...links]
    .filter((link) => link.enabled)
    .sort((left, right) => left.displayOrder - right.displayOrder || left.id - right.id);
  const count = sorted.length + (group.key === "macos" ? 1 : 0);
  return (
    <section className="bd-card pub-download-group" aria-labelledby={`download-group-${group.key}`}>
      <div className="bd-card-header">
        <div className="min-w-0">
          <h3 id={`download-group-${group.key}`} className="bd-card-title">{group.title}</h3>
          <p className="app-card-desc">{group.description}</p>
        </div>
        {count > 0 ? <Tag plain className="bd-num">{count} 个</Tag> : null}
      </div>
      {count === 0 ? (
        <p className="pub-download-empty" role={loading ? "status" : undefined}>
          {loading ? "正在加载可用产物…" : "当前发布暂未提供此分组的产物。"}
        </p>
      ) : (
        <table className="bd-table jd-stack pub-download-table">
          <thead>
            <tr>
              <th scope="col">安装包</th>
              <th scope="col">架构</th>
              <th scope="col">版本</th>
              <th scope="col" className="bd-col-num">大小</th>
              <th scope="col">SHA-256</th>
              <th scope="col"><span className="jd-sr-only">操作</span></th>
            </tr>
          </thead>
          <tbody>
            {group.key === "macos" && <HomebrewDownloadRow />}
            {sorted.map((link) => <ReleaseDownloadRow key={`${link.implementation}-${link.platform}-${link.arch}-${link.id}`} link={link} />)}
          </tbody>
        </table>
      )}
    </section>
  );
}

function HomebrewDownloadRow() {
  return (
    <tr>
      <td>
        <div className="pub-download-name">
          <b>Homebrew Cask</b>
          <span>推荐 · 自动选择 Apple Silicon 或 Intel，并支持直接升级</span>
        </div>
      </td>
      <td data-label="架构">自动选择</td>
      <td className="is-empty" />
      <td className="bd-col-num is-empty" />
      <td className="is-empty" />
      <td className="jd-cell-actions">
        <a className="bd-btn bd-btn--secondary bd-btn--sm" href={SPECUS_HOMEBREW_TAP_URL} rel="noopener noreferrer" target="_blank">
          <span>查看 Cask</span>
          <Glyph name="external" />
        </a>
      </td>
    </tr>
  );
}

function ReleaseDownloadRow({ link }: { link: ClientDownloadLink }) {
  return (
    <tr>
      <td>
        <div className="pub-download-name">
          <b>{link.displayName}</b>
          <span>{implementationLabel(link)}{link.description ? ` · ${link.description}` : ""}</span>
        </div>
      </td>
      <td data-label="架构">{archLabel(link.arch)}</td>
      <td data-label="版本" className={`bd-num${link.version ? "" : " is-empty"}`}>
        {link.version ? `v${link.version.replace(/^v/i, "")}` : null}
      </td>
      <td data-label="大小" className={`bd-col-num${link.fileSize ? "" : " is-empty"}`}>
        {link.fileSize ? formatBytes(link.fileSize) : null}
      </td>
      <td className={link.sha256 ? "" : "is-empty"}>
        {link.sha256 ? <Checksum value={link.sha256} name={link.displayName} compact /> : null}
      </td>
      <td className="jd-cell-actions">
        <a
          className="bd-btn bd-btn--secondary bd-btn--sm"
          href={link.downloadUrl}
          rel="noopener noreferrer"
          target="_blank"
          aria-label={`下载 ${link.displayName}`}
        >
          <Glyph name="download" />
          <span>下载</span>
        </a>
      </td>
    </tr>
  );
}

function orderedDownloadGroups(device: VisitorDevice) {
  const preferred = device.platform === "macos" || device.platform === "windows" || device.platform === "linux" || device.platform === "android"
    ? device.platform
    : null;
  return [...DOWNLOAD_GROUPS].sort((left, right) => {
    if (left.key === preferred) return -1;
    if (right.key === preferred) return 1;
    return DOWNLOAD_GROUPS.indexOf(left) - DOWNLOAD_GROUPS.indexOf(right);
  });
}

function readUserAgentData(): UserAgentDataLike | undefined {
  return (navigator as Navigator & { userAgentData?: UserAgentDataLike }).userAgentData;
}

function detectFromNavigator(userAgentData?: VisitorUserAgentHints): VisitorDevice {
  const lowEntropy = readUserAgentData();
  return detectVisitorDevice({
    userAgent: navigator.userAgent,
    navigatorPlatform: navigator.platform,
    maxTouchPoints: navigator.maxTouchPoints,
    userAgentData: userAgentData ?? {
      platform: lowEntropy?.platform,
      mobile: lowEntropy?.mobile,
    },
  });
}

function detectInitialDevice(): VisitorDevice {
  const userAgentData = readUserAgentData();
  if (!userAgentData?.getHighEntropyValues) return detectFromNavigator();
  return detectFromNavigator({
    platform: userAgentData.platform,
    mobile: userAgentData.mobile,
    // A non-empty unresolved marker prevents a legacy x64 UA from being trusted
    // while the authoritative architecture hint is still in flight.
    architecture: "unresolved",
  });
}

function hasHighEntropyUserAgentData(): boolean {
  return typeof readUserAgentData()?.getHighEntropyValues === "function";
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function implementationLabel(link: Pick<ClientDownloadLink, "implementation">): string {
  if (link.implementation === "go") return "Go 单文件客户端";
  if (link.implementation === "csharp") return ".NET 客户端";
  if (link.implementation === "android") return "Android 客户端";
  return "Java 客户端";
}

function archLabel(arch: ClientArch): string {
  if (arch === "x64") return "x86_64";
  if (arch === "arm64") return "ARM64";
  return "跨架构";
}

// Tag and Alert of the design, written out here rather than imported from components/ui: that
// module pulls in the full icon set, which would push this route over its static budget.
function Tag({ tone, plain, className, children }: {
  tone?: "success" | "info" | "warning"; plain?: boolean; className?: string; children: ReactNode;
}) {
  return (
    <span className={["bd-tag", tone && `bd-tag--${tone}`, plain && "bd-tag--plain", className].filter(Boolean).join(" ")}>
      {children}
    </span>
  );
}

function Alert({ tone, role, title, actions, className, children }: {
  tone: "warning" | "danger"; role: "alert" | "status"; title: ReactNode; actions?: ReactNode; className?: string; children?: ReactNode;
}) {
  return (
    <div className={["bd-alert", `bd-alert--${tone}`, className].filter(Boolean).join(" ")} role={role}>
      <Glyph name={tone === "danger" ? "circle-alert" : "alert"} />
      <div className="min-w-0 flex-1">
        <div className="bd-alert-title">{title}</div>
        {children ? <div className="bd-alert-body">{children}</div> : null}
      </div>
      {actions ? <div className="flex flex-none flex-wrap items-center gap-2 self-center">{actions}</div> : null}
    </div>
  );
}
