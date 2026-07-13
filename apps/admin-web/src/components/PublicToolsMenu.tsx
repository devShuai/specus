export type PublicToolKey = "transfer" | "diagram" | "nat-detect";

const PUBLIC_TOOLS: Array<{ key: PublicToolKey; label: string; detail: string }> = [
  { key: "transfer", label: "互传", detail: "文件、剪贴板与白板" },
  { key: "diagram", label: "专业流程图", detail: "独立协作编辑器" },
  { key: "nat-detect", label: "NAT 检测", detail: "检测网络连通类型" },
];

export function PublicToolsMenu({ active, className = "" }: { active?: PublicToolKey; className?: string }) {
  return (
    <details className={`group relative ${className}`}>
      <summary className="landing-ghost-button landing-nav-button flex cursor-pointer list-none items-center justify-center gap-1.5 marker:hidden [&::-webkit-details-marker]:hidden">
        工具
        <svg className="h-3.5 w-3.5 transition-transform group-open:rotate-180" fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 16 16" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
      </summary>
      <div className="absolute right-0 top-[calc(100%+0.5rem)] z-50 w-52 overflow-hidden rounded-xl border border-black/10 bg-white/95 p-1.5 text-left shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-zinc-950/95">
        {PUBLIC_TOOLS.map((tool) => (
          <a
            key={tool.key}
            href={`#/${tool.key}`}
            aria-current={active === tool.key ? "page" : undefined}
            className={`block rounded-lg px-3 py-2 transition-colors ${active === tool.key
              ? "bg-cyan-50 text-cyan-900 dark:bg-cyan-300/10 dark:text-cyan-100"
              : "text-zinc-700 hover:bg-zinc-100 dark:text-zinc-200 dark:hover:bg-white/[0.07]"}`}
          >
            <span className="block text-small font-semibold">{tool.label}</span>
            <span className="mt-0.5 block text-[10px] text-zinc-500 dark:text-zinc-400">{tool.detail}</span>
          </a>
        ))}
      </div>
    </details>
  );
}
