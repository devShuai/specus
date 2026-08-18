import { describe, expect, it } from "vitest";
import type { ClientDownloadLink } from "../api/types";
import {
  detectVisitorDevice,
  recommendClientDownload,
  visitorDeviceDisplayName,
} from "./platformDownloads";

function link(
  id: number,
  implementation: ClientDownloadLink["implementation"],
  platform: ClientDownloadLink["platform"],
  arch: ClientDownloadLink["arch"],
  overrides: Partial<ClientDownloadLink> = {},
): ClientDownloadLink {
  return {
    id,
    implementation,
    platform,
    arch,
    displayName: `download-${id}`,
    downloadUrl: `https://example.test/download-${id}`,
    description: null,
    displayOrder: id,
    enabled: true,
    createdAt: "2026-08-18T00:00:00Z",
    updatedAt: "2026-08-18T00:00:00Z",
    ...overrides,
  };
}

describe("detectVisitorDevice", () => {
  it("prefers UA-CH platform and architecture over conflicting legacy UA values", () => {
    expect(detectVisitorDevice({
      userAgent: "Mozilla/5.0 (X11; Linux x86_64)",
      navigatorPlatform: "Linux x86_64",
      userAgentData: { platform: "Windows", architecture: "arm", bitness: "64" },
    })).toEqual({ platform: "windows", arch: "arm64" });
  });

  it("detects supported desktop systems from legacy browser signals", () => {
    expect(detectVisitorDevice({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      navigatorPlatform: "Win32",
    })).toEqual({ platform: "windows", arch: "x64" });
    expect(detectVisitorDevice({
      userAgent: "Mozilla/5.0 (X11; Linux aarch64)",
      navigatorPlatform: "Linux aarch64",
    })).toEqual({ platform: "linux", arch: "arm64" });
  });

  it("does not infer Intel architecture from Safari's MacIntel compatibility value", () => {
    const device = detectVisitorDevice({
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
      navigatorPlatform: "MacIntel",
      maxTouchPoints: 0,
    });
    expect(device).toEqual({ platform: "macos", arch: "unknown" });
    expect(visitorDeviceDisplayName(device)).toBe("macOS");
  });

  it.each([
    ["Android", { userAgentData: { platform: "Android", mobile: true } }, "android"],
    ["ChromeOS", { userAgent: "Mozilla/5.0 (X11; CrOS x86_64 15917.0.0)" }, "chromeos"],
    ["iOS", { userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile" }, "ios"],
    ["iPadOS UA", { userAgent: "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) Mobile" }, "ipados"],
    ["iPadOS desktop mode", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)",
      navigatorPlatform: "MacIntel",
      maxTouchPoints: 5,
    }, "ipados"],
    ["unknown mobile", { userAgentData: { platform: "Unknown", mobile: true } }, "mobile"],
  ])("intercepts unsupported %s visitors", (_name, input, unsupportedPlatform) => {
    expect(detectVisitorDevice(input)).toEqual({
      platform: "unsupported",
      arch: "unknown",
      unsupportedPlatform,
    });
  });

  it("keeps unsupported or ambiguous architectures unknown", () => {
    expect(detectVisitorDevice({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      userAgentData: { platform: "Windows", architecture: "x86", bitness: "32" },
    })).toEqual({ platform: "windows", arch: "unknown" });
    expect(detectVisitorDevice({ userAgent: "custom browser" })).toEqual({
      platform: "unknown",
      arch: "unknown",
    });
  });

  it("uses the UA-CH WOW64 signal for a 32-bit browser on 64-bit Windows", () => {
    expect(detectVisitorDevice({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win32; x86)",
      userAgentData: { platform: "Windows", architecture: "x86", bitness: "32", wow64: true },
    })).toEqual({ platform: "windows", arch: "x64" });
  });
});

describe("recommendClientDownload", () => {
  const windowsDesktop = link(30, "csharp", "windows", "x64");
  const windowsX64Go = link(10, "go", "windows", "x64");
  const windowsArmGo = link(11, "go", "windows", "arm64");
  const linuxX64Go = link(12, "go", "linux", "x64");
  const linuxArmGo = link(13, "go", "linux", "arm64");
  const universalJava = link(20, "java", "any", "any");
  const links = [windowsX64Go, windowsArmGo, linuxX64Go, linuxArmGo, universalJava, windowsDesktop];

  it("recommends Homebrew on macOS without guessing architecture", () => {
    expect(recommendClientDownload({ platform: "macos", arch: "unknown" }, links)).toEqual({
      kind: "homebrew",
      reason: "macos-homebrew",
    });
  });

  it("prefers the Windows x64 desktop build, then falls back to the exact Go build", () => {
    expect(recommendClientDownload({ platform: "windows", arch: "x64" }, links)).toEqual({
      kind: "download",
      reason: "windows-desktop",
      link: windowsDesktop,
    });
    expect(recommendClientDownload(
      { platform: "windows", arch: "x64" },
      links.filter((candidate) => candidate !== windowsDesktop),
    )).toEqual({ kind: "download", reason: "native-go", link: windowsX64Go });
  });

  it("selects exact native Go builds for Windows ARM64 and Linux", () => {
    expect(recommendClientDownload({ platform: "windows", arch: "arm64" }, links)).toEqual({
      kind: "download",
      reason: "native-go",
      link: windowsArmGo,
    });
    expect(recommendClientDownload({ platform: "linux", arch: "x64" }, links)).toEqual({
      kind: "download",
      reason: "native-go",
      link: linuxX64Go,
    });
    expect(recommendClientDownload({ platform: "linux", arch: "arm64" }, links)).toEqual({
      kind: "download",
      reason: "native-go",
      link: linuxArmGo,
    });
  });

  it("ignores disabled matches and never substitutes a universal or wrong-architecture build", () => {
    expect(recommendClientDownload(
      { platform: "linux", arch: "arm64" },
      [universalJava, { ...linuxArmGo, enabled: false }, linuxX64Go],
    )).toEqual({ kind: "none", reason: "download-unavailable" });
  });

  it("does not guess when architecture or platform is unavailable", () => {
    expect(recommendClientDownload({ platform: "windows", arch: "unknown" }, links)).toEqual({
      kind: "none",
      reason: "unknown-architecture",
    });
    expect(recommendClientDownload({ platform: "unknown", arch: "unknown" }, links)).toEqual({
      kind: "none",
      reason: "unknown-platform",
    });
    expect(recommendClientDownload({
      platform: "unsupported",
      arch: "unknown",
      unsupportedPlatform: "android",
    }, links)).toEqual({ kind: "none", reason: "unsupported-platform" });
  });
});
