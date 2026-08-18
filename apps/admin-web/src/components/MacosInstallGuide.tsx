import { copyTextWithFeedback } from "../lib/clipboard";
import {
  MACOS_CLIENT_START_COMMAND,
  MACOS_HOMEBREW_INSTALL_COMMAND,
  MACOS_HOMEBREW_UPGRADE_COMMAND,
  SPECUS_HOMEBREW_TAP_URL,
} from "../lib/macosInstall";

export function MacosInstallGuide({ landing = false }: { landing?: boolean }) {
  return (
    <section
      aria-label="macOS Homebrew 安装说明"
      className={landing
        ? "app-apple-landing-surface glass glass-border rounded-md border p-4 text-zinc-950 shadow-sm dark:text-white dark:shadow-none"
        : "rounded-md border border-default-200 bg-content1 p-4 shadow-sm"
      }
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-primary-100 px-2 py-1 text-tiny font-medium text-primary-700 dark:bg-primary-500/15 dark:text-primary-300">
              macOS
            </span>
            <span className="text-tiny font-medium text-emerald-700 dark:text-emerald-300">推荐安装方式</span>
          </div>
          <h3 className="mt-2 text-base font-semibold">通过 Homebrew 安装 Specus Client</h3>
          <p className="mt-1 text-small leading-6 text-default-500">
            同一条命令自动选择 Apple Silicon 或 Intel 版本，并可通过 Homebrew 直接升级。
          </p>
        </div>
        <a
          className="shrink-0 text-small font-medium text-primary hover:underline"
          href={SPECUS_HOMEBREW_TAP_URL}
          rel="noopener noreferrer"
          target="_blank"
        >
          查看 Cask ↗
        </a>
      </div>

      <div className="mt-4 grid gap-2">
        <CommandRow command={MACOS_HOMEBREW_INSTALL_COMMAND} label="安装" />
        <CommandRow command={MACOS_CLIENT_START_COMMAND} label="运行" />
      </div>

      <p className="mt-3 text-tiny leading-5 text-default-500">
        将运行命令中的配置路径替换为你的 <code className="font-mono text-foreground">client.jsonc</code>；
        后续执行 <code className="font-mono text-foreground">{MACOS_HOMEBREW_UPGRADE_COMMAND}</code> 即可升级。
        也可以使用 GitHub Release 中对应架构的 macOS 压缩包手动安装。
      </p>
    </section>
  );
}

function CommandRow({ command, label }: { command: string; label: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2 rounded-md border border-default-200 bg-default-50 p-2 dark:bg-default-100/10">
      <span className="w-8 shrink-0 text-center text-tiny font-medium text-default-500">{label}</span>
      <code className="min-w-0 flex-1 break-all font-mono text-tiny text-foreground sm:overflow-x-auto sm:whitespace-nowrap">
        <span className="select-none text-default-400" aria-hidden="true">$ </span>{command}
      </code>
      <button
        aria-label={`复制${label}命令`}
        className="shrink-0 rounded-md px-2 py-1 text-tiny font-medium text-primary transition hover:bg-primary-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary dark:hover:bg-primary-500/10"
        type="button"
        onClick={() => void copyTextWithFeedback(command, `${label}命令已复制`)}
      >
        复制
      </button>
    </div>
  );
}
