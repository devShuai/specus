import type { ReactNode } from "react";
import { AppLogo } from "./AppLogo";

export interface NavItem { key: string; title: string; /** true 表示点击会离开管理外壳（整页跳转公开工具页），侧栏显示外链图标区分 */ external?: boolean; }
export interface NavGroup { label: string; items: NavItem[]; }
export interface SidebarProps { groups: NavGroup[]; active: string; onSelect: (k: string) => void; variant?: "desktop" | "mobile"; onClose?: () => void; footer?: ReactNode; }

export function Sidebar({ groups, active, onSelect, variant = "desktop", onClose, footer }: SidebarProps) {
  return <nav aria-label="主导航" className="app-apple-nav flex h-full flex-col">
    {variant === "desktop" && <div className="app-apple-nav-brand flex h-14 shrink-0 items-center px-3"><AppLogo className="min-w-0" label="specus" markClassName="h-8 w-8" subtitle="管理后台" /></div>}
    <div className="app-apple-nav-scroll flex-1 overflow-y-auto px-2.5 py-2.5">
      {groups.map((g) => <div key={g.label} className="app-apple-nav-group mb-2.5">
        <div className="app-apple-nav-heading mb-1 px-2 text-small font-semibold text-default-400">{g.label}</div>
        <ul className="flex flex-col gap-0.5">{g.items.map(item => { const isActive = item.key === active; return <li key={item.key}>
          <button
            aria-current={isActive ? "page" : undefined}
            className={["app-apple-nav-item flex w-full items-center gap-2 px-2 py-1.5 text-left text-small transition-colors", isActive ? "app-apple-nav-item-active" : ""].join(" ")}
            title={item.external ? `${item.title}（新页面，离开控制台）` : undefined}
            type="button"
            onClick={() => { onSelect(item.key); onClose?.(); }}
          >
            <span className="app-apple-nav-icon">{Icon(item.key)}</span>
            <span className="min-w-0 flex-1 truncate">{item.title}</span>
            {item.external ? <span aria-hidden="true" className="app-apple-nav-external"><ExternalIcon /></span> : null}
          </button>
        </li>})}</ul>
      </div>)}
    </div>
    {variant === "desktop" && <div className="app-apple-nav-footer shrink-0 px-2.5 py-2.5">{footer}</div>}
  </nav>;
}

const C = "h-4 w-4";
const A = { fill:"none",stroke:"currentColor",strokeWidth:"1.6",strokeLinecap:"round" as const,strokeLinejoin:"round" as const };
function ExternalIcon() {
  return <svg className="h-3.5 w-3.5" {...A} viewBox="0 0 24 24"><path d="M14 4h6v6"/><path d="M20 4 11 13"/><path d="M19 13.5V18a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h4.5"/></svg>;
}
function Icon(k: string) {
  switch(k){
    case "overview": return <svg className={C} {...A} viewBox="0 0 24 24"><rect height="7" rx="1" width="7" x="3" y="3"/><rect height="7" rx="1" width="7" x="14" y="3"/><rect height="7" rx="1" width="7" x="3" y="14"/><rect height="7" rx="1" width="7" x="14" y="14"/></svg>;
    case "clients": return <svg className={C} {...A} viewBox="0 0 24 24"><rect height="13" rx="2" width="18" x="3" y="3"/><line x1="12" x2="12" y1="16" y2="20"/><line x1="8" x2="16" y1="20" y2="20"/></svg>;
    case "messages": return <svg className={C} {...A} viewBox="0 0 24 24"><path d="M4 5.5A2.5 2.5 0 016.5 3h11A2.5 2.5 0 0120 5.5v7A2.5 2.5 0 0117.5 15H10l-4 4v-4.2A2.5 2.5 0 014 12.5z"/><path d="M8 8h8M8 11h5"/></svg>;
    case "transfer": return <svg className={C} {...A} viewBox="0 0 24 24"><path d="M4 7.5A2.5 2.5 0 016.5 5h3l2 2h6A2.5 2.5 0 0120 9.5v7A2.5 2.5 0 0117.5 19h-11A2.5 2.5 0 014 16.5z"/><path d="M12 10v5"/><path d="M9.5 12.5 12 10l2.5 2.5"/></svg>;
    case "diagram": return <svg className={C} {...A} viewBox="0 0 24 24"><rect x="3" y="4" width="7" height="6" rx="1.5"/><rect x="14" y="14" width="7" height="6" rx="1.5"/><path d="M10 7h2a5 5 0 015 5v2M7 10v3a4 4 0 004 4h3"/></svg>;
    case "specusMappings": return <svg className={C} {...A} viewBox="0 0 24 24"><path d="M7 7h10M7 10v7a2 2 0 002 2h6a2 2 0 002-2v-7M12 3v7M16 17v3a1 1 0 01-1 1h-6a1 1 0 01-1-1v-3"/></svg>;
    case "http-routes": return <svg className={C} {...A} viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><line x1="3" x2="21" y1="12" y2="12"/></svg>;
    case "downloads": return <svg className={C} {...A} viewBox="0 0 24 24"><path d="M12 3v12"/><polyline points="8,11 12,15 16,11"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/></svg>;
    case "traffic": return <svg className={C} {...A} viewBox="0 0 24 24"><line x1="4" x2="4" y1="20" y2="8"/><line x1="10" x2="10" y1="20" y2="4"/><line x1="16" x2="16" y1="20" y2="12"/></svg>;
    case "connections": return <svg className={C} {...A} viewBox="0 0 24 24"><line x1="8" x2="16" y1="6" y2="6"/><line x1="8" x2="16" y1="12" y2="12"/><line x1="8" x2="16" y1="18" y2="18"/></svg>;
    case "peer-mesh": return <svg className={C} {...A} viewBox="0 0 24 24"><circle cx="7" cy="7" r="3"/><circle cx="17" cy="17" r="3"/><line x1="9.5" x2="14.5" y1="9.5" y2="14.5"/></svg>;
    case "system": return <svg className={C} {...A} viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 1v3M12 20v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M1 12h3M20 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/></svg>;
    case "help": return <svg className={C} {...A} viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/><line x1="8" x2="16" y1="7" y2="7"/><line x1="8" x2="12" y1="11" y2="11"/></svg>;
    default: return <svg className={C} {...A} viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>;
  }
}
