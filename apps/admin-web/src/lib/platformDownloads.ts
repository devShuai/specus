import type { ClientDownloadLink } from "../api/types";

export type VisitorPlatform = "windows" | "linux" | "macos" | "android" | "unsupported" | "unknown";
export type VisitorArch = "x64" | "arm64" | "unknown";
export type UnsupportedVisitorPlatform = "ios" | "ipados" | "chromeos" | "mobile";

/**
 * Browser-provided User-Agent Client Hints after any high-entropy values have
 * been resolved by the caller. Keeping this as input makes detection pure and
 * independently testable.
 */
export interface VisitorUserAgentHints {
  platform?: string | null;
  architecture?: string | null;
  bitness?: string | null;
  mobile?: boolean | null;
  wow64?: boolean | null;
}

export interface VisitorDeviceInput {
  userAgent?: string | null;
  navigatorPlatform?: string | null;
  maxTouchPoints?: number | null;
  userAgentData?: VisitorUserAgentHints | null;
}

export interface VisitorDevice {
  platform: VisitorPlatform;
  arch: VisitorArch;
  unsupportedPlatform?: UnsupportedVisitorPlatform;
}

export type ClientDownloadRecommendation =
  | {
    kind: "homebrew";
    reason: "macos-homebrew";
  }
  | {
    kind: "download";
    reason: "windows-desktop" | "native-go" | "android-app";
    link: ClientDownloadLink;
  }
  | {
    kind: "none";
    reason:
      | "unsupported-platform"
      | "unknown-platform"
      | "unknown-architecture"
      | "download-unavailable";
  };

function normalized(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? "";
}

function unsupportedFromPlatformName(value: string): UnsupportedVisitorPlatform | null {
  const platform = normalized(value).replace(/[\s_-]+/g, "");
  if (platform === "ipados" || platform === "ipad") {
    return "ipados";
  }
  if (platform === "ios" || platform === "iphone" || platform === "ipod") {
    return "ios";
  }
  if (platform === "chromeos" || platform === "cros") {
    return "chromeos";
  }
  return null;
}

function unsupportedFromLegacySignals(
  userAgent: string,
  navigatorPlatform: string,
  maxTouchPoints: number,
): UnsupportedVisitorPlatform | null {
  if (/\bipad\b/.test(userAgent)
    || (/\bmacintosh\b/.test(userAgent) || navigatorPlatform === "macintel")
      && maxTouchPoints > 1) {
    return "ipados";
  }
  if (/\b(?:iphone|ipod)\b/.test(userAgent)) {
    return "ios";
  }
  if (/\bcros\b/.test(userAgent) || /\bchrome\s*os\b/.test(userAgent)) {
    return "chromeos";
  }
  if (/\bmobile\b/.test(userAgent) && !/\bandroid\b/.test(userAgent)) {
    return "mobile";
  }
  return null;
}

function platformFromUserAgentHints(value: string): Exclude<VisitorPlatform, "unsupported"> | null {
  const platform = normalized(value).replace(/[\s_-]+/g, "");
  if (platform === "windows" || platform === "win") {
    return "windows";
  }
  if (platform === "macos" || platform === "mac") {
    return "macos";
  }
  if (platform === "linux") {
    return "linux";
  }
  if (platform === "android") {
    return "android";
  }
  return null;
}

function platformFromLegacySignals(userAgent: string, navigatorPlatform: string): VisitorPlatform {
  const combined = `${userAgent} ${navigatorPlatform}`;
  if (/\bandroid\b/.test(combined)) {
    return "android";
  }
  if (/\b(?:windows|win32|win64)\b/.test(combined)) {
    return "windows";
  }
  if (/\b(?:macintosh|macintel|macppc)\b/.test(combined) || /\bmac os x\b/.test(combined)) {
    return "macos";
  }
  if (/\b(?:linux|x11)\b/.test(combined)) {
    return "linux";
  }
  return "unknown";
}

function architectureFromUserAgentHints(
  architectureValue: string | null | undefined,
  bitnessValue: string | null | undefined,
  wow64: boolean | null | undefined,
): VisitorArch {
  const architecture = normalized(architectureValue).replace(/[\s_-]+/g, "");
  const bitness = normalized(bitnessValue);
  if (architecture === "arm64" || architecture === "aarch64"
    || architecture === "arm" && bitness === "64") {
    return "arm64";
  }
  if (wow64 === true || architecture === "x64" || architecture === "x8664" || architecture === "amd64"
    || architecture === "x86" && bitness === "64") {
    return "x64";
  }
  return "unknown";
}

function architectureFromLegacySignals(userAgent: string, navigatorPlatform: string): VisitorArch {
  const combined = `${userAgent} ${navigatorPlatform}`;
  if (/\b(?:arm64|aarch64)\b/.test(combined)) {
    return "arm64";
  }
  if (/\b(?:x86_64|x86-64|amd64|win64|x64|wow64)\b/.test(combined)) {
    return "x64";
  }
  return "unknown";
}

/** Detects the visitor without reading browser globals. UA-CH wins when available. */
export function detectVisitorDevice(input: VisitorDeviceInput): VisitorDevice {
  const userAgent = normalized(input.userAgent);
  const navigatorPlatform = normalized(input.navigatorPlatform);
  const hints = input.userAgentData;

  const unsupported = unsupportedFromPlatformName(hints?.platform ?? "")
    ?? unsupportedFromLegacySignals(userAgent, navigatorPlatform, input.maxTouchPoints ?? 0)
    ?? (hints?.mobile === true && normalized(hints?.platform) !== "android" ? "mobile" : null);
  if (unsupported) {
    return { platform: "unsupported", arch: "unknown", unsupportedPlatform: unsupported };
  }

  const hintedPlatform = platformFromUserAgentHints(hints?.platform ?? "");
  const platform = hintedPlatform ?? platformFromLegacySignals(userAgent, navigatorPlatform);
  if (platform === "unknown") {
    return { platform, arch: "unknown" };
  }

  const hintedArchitecture = architectureFromUserAgentHints(hints?.architecture, hints?.bitness, hints?.wow64);
  const hasArchitectureHints = normalized(hints?.architecture) !== ""
    || normalized(hints?.bitness) !== ""
    || hints?.wow64 === true;
  const arch = hintedArchitecture !== "unknown" || hasArchitectureHints
    ? hintedArchitecture
    : architectureFromLegacySignals(userAgent, navigatorPlatform);
  return { platform, arch };
}

function firstAvailable(
  links: readonly ClientDownloadLink[],
  predicate: (link: ClientDownloadLink) => boolean,
): ClientDownloadLink | undefined {
  return links
    .filter((link) => link.enabled && predicate(link))
    .sort((left, right) => left.displayOrder - right.displayOrder || left.id - right.id)[0];
}

/** Returns one safe primary install choice. Unknown architectures are never guessed. */
export function recommendClientDownload(
  device: VisitorDevice,
  links: readonly ClientDownloadLink[],
): ClientDownloadRecommendation {
  if (device.platform === "unsupported") {
    return { kind: "none", reason: "unsupported-platform" };
  }
  if (device.platform === "unknown") {
    return { kind: "none", reason: "unknown-platform" };
  }
  if (device.platform === "macos") {
    return { kind: "homebrew", reason: "macos-homebrew" };
  }
  if (device.platform === "android") {
    const android = firstAvailable(links, (link) => link.implementation === "android"
      && link.platform === "android" && link.arch === "any");
    return android
      ? { kind: "download", reason: "android-app", link: android }
      : { kind: "none", reason: "download-unavailable" };
  }
  if (device.arch === "unknown") {
    return { kind: "none", reason: "unknown-architecture" };
  }

  if (device.platform === "windows" && device.arch === "x64") {
    const desktop = firstAvailable(links, (link) => link.implementation === "csharp"
      && link.platform === "windows" && link.arch === "x64");
    if (desktop) {
      return { kind: "download", reason: "windows-desktop", link: desktop };
    }
  }

  const nativeGo = firstAvailable(links, (link) => link.implementation === "go"
    && link.platform === device.platform && link.arch === device.arch);
  return nativeGo
    ? { kind: "download", reason: "native-go", link: nativeGo }
    : { kind: "none", reason: "download-unavailable" };
}

export function visitorPlatformDisplayName(device: VisitorDevice): string {
  if (device.platform === "windows") return "Windows";
  if (device.platform === "macos") return "macOS";
  if (device.platform === "linux") return "Linux";
  if (device.platform === "android") return "Android";
  if (device.platform === "unknown") return "未识别设备";
  if (device.unsupportedPlatform === "ios") return "iPhone / iOS";
  if (device.unsupportedPlatform === "ipados") return "iPad / iPadOS";
  if (device.unsupportedPlatform === "chromeos") return "ChromeOS";
  return "移动设备";
}

export function visitorArchDisplayName(arch: VisitorArch): string {
  if (arch === "x64") return "x86_64";
  if (arch === "arm64") return "ARM64";
  return "未知架构";
}

export function visitorDeviceDisplayName(device: VisitorDevice): string {
  const platform = visitorPlatformDisplayName(device);
  return device.arch === "unknown" ? platform : `${platform} · ${visitorArchDisplayName(device.arch)}`;
}
