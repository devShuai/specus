import { Button, Dropdown, DropdownItem, DropdownMenu, DropdownTrigger } from "@heroui/react";

export type PublicToolKey = "transfer" | "diagram" | "nat-detect";

const PUBLIC_TOOLS: Array<{ key: PublicToolKey; label: string; detail: string }> = [
  { key: "transfer", label: "互传", detail: "文件、剪贴板与白板" },
  { key: "diagram", label: "专业流程图", detail: "独立协作编辑器" },
  { key: "nat-detect", label: "NAT 检测", detail: "检测网络连通类型" },
];

export function PublicToolsMenu({ active, className = "" }: { active?: PublicToolKey; className?: string }) {
  return (
    <Dropdown placement="bottom-end" shouldBlockScroll={false}>
      <DropdownTrigger>
        <Button
          className={`public-header-button ${className}`}
          endContent={<ChevronIcon />}
          radius="full"
          size="sm"
          variant="light"
        >
          工具
        </Button>
      </DropdownTrigger>
      <DropdownMenu aria-label="公共工具" className="public-header-menu">
        {PUBLIC_TOOLS.map((tool) => (
          <DropdownItem
            key={tool.key}
            href={`/${tool.key}`}
            aria-current={active === tool.key ? "page" : undefined}
            className={active === tool.key ? "text-primary" : ""}
          >
            <span className="block text-small font-semibold">{tool.label}</span>
            <span className="mt-0.5 block text-[10px] text-zinc-500 dark:text-zinc-400">{tool.detail}</span>
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
  );
}

function ChevronIcon() {
  return (
    <svg aria-hidden="true" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 16 16">
      <path d="m4 6 4 4 4-4" />
    </svg>
  );
}
