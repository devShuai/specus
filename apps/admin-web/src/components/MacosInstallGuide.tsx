import { useEffect, useRef, useState } from "react";
import { copyTextToClipboard } from "../lib/clipboard";
import {
  MACOS_CLIENT_START_COMMAND,
  MACOS_HOMEBREW_INSTALL_COMMAND,
  MACOS_HOMEBREW_UPGRADE_COMMAND,
  SPECUS_HOMEBREW_TAP_URL,
} from "../lib/macosInstall";

// Three icons of the design's set (components/ui/Icon.tsx), inline: the public download page renders
// this guide and has a static JavaScript budget that the whole icon module would exceed.
const GUIDE_ICONS = {
  copy: <><rect width="14" height="14" x="8" y="8" rx="2" /><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" /></>,
  check: <polyline points="20 6 9 17 4 12" />,
  external: <><path d="M15 3h6v6" /><path d="M10 14 21 3" /><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /></>,
};

function Icon({ name, size }: { name: keyof typeof GUIDE_ICONS; size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {GUIDE_ICONS[name]}
    </svg>
  );
}

/**
 * The macOS Homebrew guide: a card with the install and run commands as a code block, each line with
 * its own copy button. On the public download page (landing) it keeps that page's glass surface.
 */
export function MacosInstallGuide({ landing = false }: { landing?: boolean }) {
  return (
    <section
      aria-label="macOS Homebrew 安装说明"
      className={landing
        ? "app-apple-landing-surface glass glass-border acc-mac is-landing rounded-md border text-zinc-950 shadow-xs dark:text-white dark:shadow-none"
        : "bd-card acc-mac"
      }
    >
      <div className="acc-mac-head">
        <div className="min-w-0">
          <div className="acc-mac-tags">
            <span className="bd-tag bd-tag--plain">macOS</span>
            <span className="bd-tag bd-tag--success">推荐安装方式</span>
          </div>
          <h3 className="acc-mac-title">通过 Homebrew 安装 Specus Client</h3>
          <p className="acc-mac-desc">
            同一条命令自动选择 Apple Silicon 或 Intel 版本，并可通过 Homebrew 直接升级。
          </p>
        </div>
        <a
          className="jd-link acc-mac-cask"
          href={SPECUS_HOMEBREW_TAP_URL}
          rel="noopener noreferrer"
          target="_blank"
        >
          查看 Cask
          <Icon name="external" size={14} />
        </a>
      </div>

      <div className="acc-code">
        <CommandRow command={MACOS_HOMEBREW_INSTALL_COMMAND} label="安装" />
        <CommandRow command={MACOS_CLIENT_START_COMMAND} label="运行" />
      </div>

      <p className="acc-mac-foot">
        将运行命令中的配置路径替换为你的 <code className="font-mono">client.jsonc</code>；
        后续执行 <code className="font-mono">{MACOS_HOMEBREW_UPGRADE_COMMAND}</code> 即可升级。
        也可以使用 GitHub Release 中对应架构的 macOS 压缩包手动安装。
      </p>
    </section>
  );
}

function CommandRow({ command, label }: { command: string; label: string }) {
  const [copyStatus, setCopyStatus] = useState<"idle" | "success" | "error">("idle");
  const resetTimer = useRef<number | null>(null);

  useEffect(() => () => {
    if (resetTimer.current !== null) {
      globalThis.clearTimeout(resetTimer.current);
    }
  }, []);

  const copyCommand = async () => {
    const copied = await copyTextToClipboard(command);
    setCopyStatus(copied ? "success" : "error");
    if (resetTimer.current !== null) {
      globalThis.clearTimeout(resetTimer.current);
    }
    resetTimer.current = globalThis.setTimeout(() => setCopyStatus("idle"), 2_500);
  };

  return (
    <div className="acc-code-row">
      <span className="acc-code-label">{label}</span>
      <code className="acc-code-text font-mono">
        <span className="acc-code-prompt" aria-hidden="true">$ </span>{command}
      </code>
      <button
        aria-label={`复制${label}命令`}
        className={`bd-btn bd-btn--ghost bd-btn--sm acc-code-copy${copyStatus === "success" ? " is-done" : copyStatus === "error" ? " is-error" : ""}`}
        type="button"
        onClick={() => void copyCommand()}
      >
        <Icon name={copyStatus === "success" ? "check" : "copy"} size={14} />
        <span>{copyStatus === "success" ? "已复制" : copyStatus === "error" ? "复制失败" : "复制"}</span>
      </button>
      <span aria-live="polite" className="sr-only">
        {copyStatus === "success"
          ? `${label}命令已复制`
          : copyStatus === "error"
            ? "复制失败，请手动选择文本复制"
            : ""}
      </span>
    </div>
  );
}
