import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { fetchPublicClientDownloads } from "../api/client";
import type { ClientArch, ClientDownloadLink, ClientPlatform } from "../api/types";
import { AppLogo } from "../components/AppLogo";
import { MacosInstallGuide } from "../components/MacosInstallGuide";
import { PublicToolsMenu } from "../components/PublicToolsMenu";
import { UserMenuButton } from "../components/UserMenuButton";
import { SPECUS_HOMEBREW_TAP_URL } from "../lib/macosInstall";
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
];

const DOWNLOAD_GROUPS: Array<{
  key: DownloadGroupKey;
  title: string;
  description: string;
}> = [
  { key: "macos", title: "macOS", description: "Homebrew Cask 或对应架构的 Go 单文件客户端" },
  { key: "windows", title: "Windows", description: "图形桌面版或轻量 Go 命令行客户端" },
  { key: "linux", title: "Linux", description: "x86_64 与 ARM64 静态单文件客户端" },
  { key: "any", title: "跨平台 · 需要运行时", description: "适合已有 Java 或 .NET 运行环境的设备" },
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
    title: "Specus Client 下载 · Windows / macOS / Linux · specus",
    description:
      "下载 Specus Client。页面会自动识别 macOS、Windows、Linux 与 CPU 架构，优先推荐 Homebrew、Windows 桌面版或对应架构的 Go 客户端。",
    canonical: "https://specus.devshuai.com/download",
    keywords: "Specus Client 下载,macOS Homebrew,Windows 客户端,Linux ARM64,内网穿透客户端",
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      name: "Specus Client",
      url: "https://specus.devshuai.com/download",
      downloadUrl: GITHUB_RELEASES_URL,
      applicationCategory: "DeveloperApplication",
      operatingSystem: "Windows, macOS, Linux",
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
    <main className="app-apple landing-shell landing-apple download-page min-h-screen text-zinc-950 dark:text-white">
      <section className="download-hero relative overflow-hidden pb-14 pt-5 sm:pb-20">
        <div className="download-channel-lines" aria-hidden="true" />
        <header className="landing-apple-header relative z-40 mx-auto flex w-full max-w-[1120px] items-center justify-between gap-3 px-5 sm:px-8">
          <a className="rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary" href="/" aria-label="返回 specus 首页">
            <AppLogo className="min-w-0" label="specus" subtitle="客户端下载" />
          </a>
          <div className="public-header-actions flex shrink-0 items-center gap-2">
            <PublicToolsMenu active="download" />
            <UserMenuButton className="public-header-theme-button" />
          </div>
        </header>

        <div className="relative z-10 mx-auto mt-14 w-full max-w-[1120px] px-5 sm:mt-20 sm:px-8">
          <div className="mx-auto max-w-3xl text-center">
            <span className="landing-apple-eyebrow text-small font-semibold">SPECUS CLIENT</span>
            <h1 className="download-title mt-4 font-semibold text-zinc-950 dark:text-white">
              把正确的客户端，交给这台设备。
            </h1>
            <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-zinc-600 dark:text-zinc-300 sm:text-lg">
              我们先识别操作系统与处理器，只突出最合适的安装方式。需要其他平台、架构或实现时，再展开完整列表。
            </p>
          </div>

          <section className="download-recommendation mx-auto mt-10 max-w-4xl" aria-labelledby="recommended-download-title">
            <div className="download-recommendation-head flex flex-col gap-4 px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
              <div className="flex min-w-0 items-center gap-3">
                <span className="download-device-mark" aria-hidden="true"><DeviceIcon device={device} /></span>
                <div className="min-w-0">
                  <p className="text-tiny font-semibold uppercase tracking-[0.14em] text-zinc-500 dark:text-zinc-400">
                    {manualDevice ? "手动选择" : "检测到这台设备"}
                  </p>
                  <h2 id="recommended-download-title" className="mt-0.5 truncate text-lg font-semibold">
                    {visitorDeviceDisplayName(device)}
                  </h2>
                </div>
              </div>
              <button
                ref={changeDeviceButtonRef}
                aria-expanded={chooserOpen}
                className="download-change-device"
                type="button"
                onClick={() => setChooserOpen((value) => !value)}
              >
                不是你的设备？更改
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

            <div className="download-recommendation-body p-5 sm:p-6" aria-live="polite">
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

          <div className="download-steps mx-auto mt-5 grid max-w-4xl sm:grid-cols-3">
            {[
              ["01", "安装客户端", "使用上方推荐方式，或在完整列表选择实现。"],
              ["02", "准备配置", "将服务端地址与凭证写入 client.jsonc。"],
              ["03", "启动连接", "运行客户端，让内网服务接入 specus。"],
            ].map(([number, title, description]) => (
              <div key={number} className="download-step px-5 py-4">
                <span className="font-mono text-tiny text-primary">{number}</span>
                <strong className="ml-3 text-small font-semibold">{title}</strong>
                <p className="mt-2 text-tiny leading-5 text-zinc-600 dark:text-zinc-400">{description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="landing-apple-content px-5 py-14 sm:px-8 sm:py-20">
        <div className="mx-auto max-w-[1120px]">
          <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
            <div className="max-w-2xl">
              <span className="landing-apple-kicker text-tiny font-semibold">ALL OPTIONS</span>
              <h2 className="mt-2">需要其他安装方式？</h2>
              <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
                展开后可按 macOS、Windows、Linux 与跨平台运行时查看全部可用客户端产物。
              </p>
            </div>
            <button
              aria-controls="all-download-methods"
              aria-expanded={showAll}
              className="landing-secondary-button shrink-0 px-6"
              type="button"
              onClick={() => setShowAll((value) => !value)}
            >
              {showAll ? "收起全部下载方式" : "查看全部平台与安装方式"}
              <ChevronIcon expanded={showAll} />
            </button>
          </div>

          {showAll && (
            <div
              ref={allDownloadsRef}
              id="all-download-methods"
              className="download-all mt-8 scroll-mt-6 focus:outline-none"
              tabIndex={-1}
            >
              {loadError && (
                <div className="download-inline-alert mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" role="alert">
                  <span>下载列表暂时无法更新；macOS Homebrew 仍可使用，也可以直接打开 GitHub Releases。</span>
                  <span className="flex flex-wrap gap-3">
                    <button className="font-medium text-primary hover:underline" type="button" onClick={() => void loadDownloads(true)}>重试</button>
                    <a className="font-medium text-primary hover:underline" href={GITHUB_RELEASES_URL} target="_blank" rel="noopener noreferrer">GitHub Releases ↗</a>
                  </span>
                </div>
              )}

              <div className="grid gap-5 lg:grid-cols-2">
                {groups.map((group) => (
                  <DownloadGroup
                    key={group.key}
                    group={group}
                    links={downloads.filter((link) => link.platform === group.key)}
                    loading={loading}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      </section>
    </main>
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
    return <MacosInstallGuide landing />;
  }

  if (device.platform === "windows" || device.platform === "linux") {
    if (device.arch === "unknown") {
      if (detectingDevice) {
        return <DeviceDetectionLoading />;
      }
      return (
        <div>
          <span className="download-match-badge">还差一步</span>
          <h3 className="mt-3 text-xl font-semibold">选择这台设备的处理器架构</h3>
          <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
            浏览器没有提供可靠的架构信息。请在系统设置中确认，避免下载无法运行的版本。
          </p>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            {(["x64", "arm64"] as const).map((arch) => (
              <button
                key={arch}
                className="download-arch-choice"
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
        <div className="grid gap-6 md:grid-cols-[1fr_auto] md:items-end">
          <div>
            <span className="download-match-badge">最佳匹配</span>
            <h3 className="mt-3 text-2xl font-semibold">{recommendation.link.displayName}</h3>
            <p className="mt-2 max-w-2xl text-small leading-6 text-zinc-600 dark:text-zinc-400">
              {desktop
                ? "自包含的 Windows 图形客户端，无需另外安装 .NET Runtime。下载压缩包并解压后即可使用。"
                : recommendation.link.description || "对应当前系统与处理器的静态单文件客户端，无需额外安装运行时。"}
            </p>
            <div className="mt-4 flex flex-wrap gap-2 text-tiny text-zinc-600 dark:text-zinc-400">
              <span className="download-meta-chip">{implementationLabel(recommendation.link)}</span>
              <span className="download-meta-chip">{archLabel(recommendation.link.arch)}</span>
              <span className="download-meta-chip">发布包</span>
            </div>
          </div>
          <a
            className="landing-primary-button px-6"
            href={recommendation.link.downloadUrl}
            rel="noopener noreferrer"
            target="_blank"
          >
            下载最佳匹配
            <DownloadArrowIcon />
          </a>
        </div>
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
      <div>
        <span className="download-match-badge download-match-badge-neutral">桌面客户端</span>
        <h3 className="mt-3 text-xl font-semibold">请在电脑上打开下载页</h3>
        <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
          当前暂未提供 iOS、iPadOS、Android 或 ChromeOS 安装包。请使用 macOS、Windows 或 Linux 设备下载客户端。
        </p>
        <button className="mt-5 font-medium text-primary hover:underline" type="button" onClick={onShowAll}>
          仍然查看全部桌面平台 →
        </button>
      </div>
    );
  }

  return (
    <div>
      <span className="download-match-badge download-match-badge-neutral">未识别设备</span>
      <h3 className="mt-3 text-xl font-semibold">选择你的系统与处理器</h3>
      <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
        浏览器没有提供可确认的平台信息。请使用上方设备选择器，或展开全部安装方式。
      </p>
      <div className="mt-5 flex flex-wrap gap-4 text-small">
        <button className="font-medium text-primary hover:underline" type="button" onClick={onOpenChooser}>选择设备</button>
        <button className="font-medium text-primary hover:underline" type="button" onClick={onShowAll}>查看全部平台与安装方式 →</button>
      </div>
    </div>
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
  containerRef: RefObject<HTMLDivElement>;
  current: VisitorDevice;
  detected: VisitorDevice;
  manual: boolean;
  onChoose: (device: VisitorDevice) => void;
  onReset: () => void;
}) {
  return (
    <div ref={containerRef} className="download-device-chooser border-y border-default-200 px-5 py-4 sm:px-6">
      <p className="text-tiny font-medium text-zinc-600 dark:text-zinc-400">选择要下载到的设备</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {MANUAL_DEVICES.map((option) => {
          const selected = current.platform === option.device.platform && current.arch === option.device.arch;
          return (
            <button
              key={`${option.device.platform}-${option.device.arch}`}
              aria-pressed={selected}
              className="download-device-choice"
              type="button"
              onClick={() => onChoose(option.device)}
            >
              <strong>{option.label}</strong>
              <span>{option.detail}</span>
            </button>
          );
        })}
        {manual && (
          <button className="download-device-reset" type="button" onClick={onReset}>
            恢复自动识别 · {visitorDeviceDisplayName(detected)}
          </button>
        )}
      </div>
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
    <div role={networkError ? "alert" : "status"}>
      <span className="download-match-badge download-match-badge-neutral">暂未匹配</span>
      <h3 className="mt-3 text-xl font-semibold">
        {networkError ? "暂时无法获取下载链接" : "当前发布暂无匹配原生包"}
      </h3>
      <p className="mt-2 text-small leading-6 text-zinc-600 dark:text-zinc-400">
        我们不会自动改用其他处理器架构，以免下载后无法运行。
      </p>
      <div className="mt-5 flex flex-wrap gap-4 text-small">
        {networkError && <button className="font-medium text-primary hover:underline" type="button" onClick={onRetry}>重新获取</button>}
        <button className="font-medium text-primary hover:underline" type="button" onClick={onShowAll}>查看全部方式</button>
        <a className="font-medium text-primary hover:underline" href={GITHUB_RELEASES_URL} target="_blank" rel="noopener noreferrer">GitHub Releases ↗</a>
      </div>
    </div>
  );
}

function DownloadLoading() {
  return (
    <div className="flex items-center gap-3 py-8" role="status">
      <span className="h-5 w-5 animate-spin rounded-full border-2 border-default-300 border-t-primary" />
      <span className="text-small text-zinc-600 dark:text-zinc-400">正在为这台设备查找最新客户端…</span>
    </div>
  );
}

function DeviceDetectionLoading() {
  return (
    <div className="flex items-center gap-3 py-8" role="status">
      <span className="h-5 w-5 animate-spin rounded-full border-2 border-default-300 border-t-primary" />
      <span className="text-small text-zinc-600 dark:text-zinc-400">正在确认这台设备的处理器架构…</span>
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
  return (
    <section className="download-group app-apple-landing-surface overflow-hidden" aria-labelledby={`download-group-${group.key}`}>
      <div className="border-b border-default-200 px-5 py-4">
        <h3 id={`download-group-${group.key}`} className="text-lg font-semibold">{group.title}</h3>
        <p className="mt-1 text-tiny leading-5 text-zinc-600 dark:text-zinc-400">{group.description}</p>
      </div>
      <div className="grid gap-2 p-3">
        {group.key === "macos" && <HomebrewDownloadRow />}
        {sorted.map((link) => <ReleaseDownloadRow key={`${link.implementation}-${link.platform}-${link.arch}-${link.id}`} link={link} />)}
        {sorted.length === 0 && group.key !== "macos" && (
          <p className="px-2 py-5 text-small text-zinc-600 dark:text-zinc-400" role={loading ? "status" : undefined}>
            {loading ? "正在加载可用产物…" : "当前发布暂未提供此分组的产物。"}
          </p>
        )}
      </div>
    </section>
  );
}

function HomebrewDownloadRow() {
  return (
    <a className="download-release-row" href={SPECUS_HOMEBREW_TAP_URL} rel="noopener noreferrer" target="_blank">
      <span className="download-release-icon" aria-hidden="true"><PackageIcon /></span>
      <span className="min-w-0 flex-1">
        <strong className="block text-small font-semibold">Homebrew Cask</strong>
        <span className="mt-1 block text-tiny leading-5 text-zinc-600 dark:text-zinc-400">推荐 · 自动选择 Apple Silicon 或 Intel，并支持直接升级</span>
      </span>
      <span className="text-small text-primary" aria-hidden="true">↗</span>
    </a>
  );
}

function ReleaseDownloadRow({ link }: { link: ClientDownloadLink }) {
  return (
    <a className="download-release-row" href={link.downloadUrl} rel="noopener noreferrer" target="_blank">
      <span className="download-release-icon" aria-hidden="true"><PackageIcon /></span>
      <span className="min-w-0 flex-1">
        <strong className="block text-small font-semibold">{link.displayName}</strong>
        <span className="mt-1 block text-tiny leading-5 text-zinc-600 dark:text-zinc-400">
          {implementationLabel(link)} · {archLabel(link.arch)}{link.description ? ` · ${link.description}` : ""}
        </span>
      </span>
      <DownloadArrowIcon />
    </a>
  );
}

function orderedDownloadGroups(device: VisitorDevice) {
  const preferred = device.platform === "macos" || device.platform === "windows" || device.platform === "linux"
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
  return "Java 客户端";
}

function archLabel(arch: ClientArch): string {
  if (arch === "x64") return "x86_64";
  if (arch === "arm64") return "ARM64";
  return "跨架构";
}

function DeviceIcon({ device }: { device: VisitorDevice }) {
  if (device.platform === "unsupported") {
    return <svg viewBox="0 0 24 24"><rect x="7" y="2.5" width="10" height="19" rx="2.5" /><path d="M10.5 18.5h3" /></svg>;
  }
  return <svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></svg>;
}

function PackageIcon() {
  return <svg viewBox="0 0 24 24"><path d="m4 7 8-4 8 4-8 4-8-4Z" /><path d="M4 7v10l8 4 8-4V7M12 11v10" /></svg>;
}

function DownloadArrowIcon() {
  return (
    <svg aria-hidden="true" className="ml-2 h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 24 24">
      <path d="M12 3v12M8.5 11.5 12 15l3.5-3.5M5 20h14" />
    </svg>
  );
}

function ChevronIcon({ expanded }: { expanded: boolean }) {
  return (
    <svg aria-hidden="true" className={`ml-2 h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`} fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 20 20">
      <path d="m5 7.5 5 5 5-5" />
    </svg>
  );
}
