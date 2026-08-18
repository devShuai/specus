import { HeaderMenu } from "./HeaderMenu";

export type PublicToolKey = "transfer" | "diagram" | "nat-detect" | "download";

type PublicToolIconName = PublicToolKey | "console";

const PUBLIC_TOOLS: Array<{ key: PublicToolIconName; label: string; detail: string }> = [
  { key: "transfer", label: "互传", detail: "文件、剪贴板与白板" },
  { key: "diagram", label: "专业流程图", detail: "独立协作编辑器" },
  { key: "nat-detect", label: "NAT 检测", detail: "检测网络连通类型" },
  { key: "download", label: "客户端下载", detail: "自动匹配当前平台" },
  { key: "console", label: "控制台", detail: "登录并管理隧道服务" },
];

export function PublicToolsMenu({ active, className = "" }: { active?: PublicToolKey; className?: string }) {
  return (
    <HeaderMenu
      label="打开工具菜单"
      menuClassName="public-header-menu public-tools-menu"
      title="工具"
      trigger={<ToolsLauncherIcon />}
      triggerClassName={`public-header-button public-tools-trigger ${className}`}
    >
      {PUBLIC_TOOLS.map((tool) => (
        <a
          key={tool.key}
          aria-current={active === tool.key ? "page" : undefined}
          className={`header-menu-item public-tools-menu-item ${active === tool.key ? "public-tools-menu-item-active" : ""}`}
          href={tool.key === "console" ? "/" : `/${tool.key}`}
          role="menuitem"
        >
          <span className="public-tools-menu-icon" aria-hidden="true">
            <PublicToolIcon name={tool.key} />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-[13px] font-semibold leading-5">{tool.label}</span>
            <span className="block text-tiny leading-4 text-zinc-500 dark:text-zinc-400">{tool.detail}</span>
          </span>
          {active === tool.key ? <CurrentIcon /> : <NavigateIcon />}
        </a>
      ))}
    </HeaderMenu>
  );
}

function ToolsLauncherIcon() {
  return (
    <svg aria-hidden="true" className="h-[18px] w-[18px] shrink-0" fill="none" stroke="currentColor" strokeWidth="1.7" viewBox="0 0 24 24">
      <rect x="3.5" y="3.5" width="6.5" height="6.5" rx="1.5" />
      <rect x="14" y="3.5" width="6.5" height="6.5" rx="1.5" />
      <rect x="3.5" y="14" width="6.5" height="6.5" rx="1.5" />
      <rect x="14" y="14" width="6.5" height="6.5" rx="1.5" />
    </svg>
  );
}

function PublicToolIcon({ name }: { name: PublicToolIconName }) {
  let paths;
  if (name === "transfer") {
    paths = <><path d="M4 7.5h13M14 4.5l3 3-3 3M20 16.5H7M10 13.5l-3 3 3 3" /></>;
  } else if (name === "diagram") {
    paths = <><rect x="3.5" y="4" width="6" height="5" rx="1" /><rect x="14.5" y="15" width="6" height="5" rx="1" /><path d="M9.5 6.5h3a4 4 0 0 1 4 4V15" /></>;
  } else if (name === "nat-detect") {
    paths = <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.3 2.4 3.5 5.2 3.5 8.5S14.3 18.1 12 20.5M12 3.5C9.7 5.9 8.5 8.7 8.5 12s1.2 6.1 3.5 8.5" /></>;
  } else if (name === "download") {
    paths = <><path d="M12 3.5v11M8.5 11l3.5 3.5 3.5-3.5" /><path d="M4.5 16.5v2a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-2" /></>;
  } else {
    paths = <><rect x="3.5" y="3.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="3.5" width="7" height="4.5" rx="1.5" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.5" /><rect x="13.5" y="10.5" width="7" height="10" rx="1.5" /></>;
  }
  return (
    <svg className="h-[17px] w-[17px]" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.65" viewBox="0 0 24 24">
      {paths}
    </svg>
  );
}

function NavigateIcon() {
  return (
    <svg aria-hidden="true" className="h-3.5 w-3.5 text-zinc-400" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" viewBox="0 0 16 16">
      <path d="m6 3.5 4.5 4.5L6 12.5" />
    </svg>
  );
}

function CurrentIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4 text-primary" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 16 16">
      <path d="m3.5 8 3 3 6-6" />
    </svg>
  );
}
