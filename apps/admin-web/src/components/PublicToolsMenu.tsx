import { Button, Dropdown, DropdownItem, DropdownMenu, DropdownTrigger } from "@heroui/react";

export type PublicToolKey = "transfer" | "diagram" | "nat-detect";

type PublicToolIconName = PublicToolKey | "console";

const PUBLIC_TOOLS: Array<{ key: PublicToolIconName; label: string; detail: string }> = [
  { key: "transfer", label: "互传", detail: "文件、剪贴板与白板" },
  { key: "diagram", label: "专业流程图", detail: "独立协作编辑器" },
  { key: "nat-detect", label: "NAT 检测", detail: "检测网络连通类型" },
  { key: "console", label: "控制台", detail: "登录并管理隧道服务" },
];

export function PublicToolsMenu({ active, className = "" }: { active?: PublicToolKey; className?: string }) {
  return (
    <Dropdown placement="bottom-end" shouldBlockScroll={false}>
      <DropdownTrigger>
        <Button
          isIconOnly
          aria-label="打开工具菜单"
          className={`public-header-button public-tools-trigger ${className}`}
          radius="full"
          size="sm"
          title="工具"
          variant="light"
        >
          <ToolsLauncherIcon />
        </Button>
      </DropdownTrigger>
      <DropdownMenu aria-label="公共工具" className="public-header-menu public-tools-menu">
        {PUBLIC_TOOLS.map((tool) => (
          <DropdownItem
            key={tool.key}
            href={tool.key === "console" ? "/" : `/${tool.key}`}
            aria-current={active === tool.key ? "page" : undefined}
            className={`public-tools-menu-item ${active === tool.key ? "public-tools-menu-item-active" : ""}`}
            startContent={
              <span className="public-tools-menu-icon" aria-hidden="true">
                <PublicToolIcon name={tool.key} />
              </span>
            }
            endContent={active === tool.key ? <CurrentIcon /> : <NavigateIcon />}
            textValue={`${tool.label}，${tool.detail}`}
          >
            <span className="block text-[13px] font-semibold leading-5">{tool.label}</span>
            <span className="block text-[10px] leading-4 text-zinc-500 dark:text-zinc-400">{tool.detail}</span>
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
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
