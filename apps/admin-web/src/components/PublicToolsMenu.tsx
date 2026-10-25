import { HeaderMenu } from "./HeaderMenu";
import { Glyph, type GlyphName } from "./PublicGlyph";

export type PublicToolKey = "transfer" | "diagram" | "nat-detect" | "download";

type PublicToolEntryKey = PublicToolKey | "console";

/** The public tools, in menu order. `short` is the label in the top bar's link row. */
export const PUBLIC_TOOLS: Array<{ key: PublicToolEntryKey; label: string; short: string; detail: string; icon: GlyphName }> = [
  { key: "transfer", label: "互传", short: "互传", detail: "文件、剪贴板与白板", icon: "send" },
  { key: "diagram", label: "专业流程图", short: "流程图", detail: "独立协作编辑器", icon: "share" },
  { key: "nat-detect", label: "NAT 检测", short: "NAT 检测", detail: "检测网络连通类型", icon: "globe" },
  { key: "download", label: "客户端下载", short: "客户端下载", detail: "自动匹配当前平台", icon: "download" },
  { key: "console", label: "控制台", short: "控制台", detail: "登录并管理隧道服务", icon: "server" },
];

/**
 * The tools menu of the public pages (Menu component of the design). The default trigger keeps the
 * classes the transfer page and the diagram editor style; `topbar` renders the design's round icon
 * button for the public top bar.
 */
export function PublicToolsMenu({ active, className = "", variant = "header" }: {
  active?: PublicToolKey; className?: string; variant?: "header" | "topbar";
}) {
  return (
    <HeaderMenu
      label="打开工具菜单"
      menuClassName="public-header-menu public-tools-menu"
      title="工具"
      trigger={<Glyph name="grid" size={18} />}
      triggerClassName={variant === "topbar"
        ? `pub-icon-btn pub-tools-trigger ${className}`
        : `public-header-button public-tools-trigger ${className}`}
    >
      {PUBLIC_TOOLS.map((tool) => {
        const current = active === tool.key;
        return (
          <a
            key={tool.key}
            aria-current={current ? "page" : undefined}
            className={`header-menu-item public-tools-menu-item ${current ? "public-tools-menu-item-active" : ""}`}
            href={tool.key === "console" ? "/" : `/${tool.key}`}
            role="menuitem"
          >
            <span className="public-tools-menu-icon" aria-hidden="true">
              <Glyph name={tool.icon} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="public-tools-menu-label">{tool.label}</span>
              <span className="public-tools-menu-detail">{tool.detail}</span>
            </span>
            <Glyph name={current ? "check" : "chevron-right"} size={14} className="public-tools-menu-end" />
          </a>
        );
      })}
    </HeaderMenu>
  );
}
