import type { ReactNode } from "react";
import { useTheme } from "../theme/ThemeContext";
import { AppLogo } from "./AppLogo";
import { Icon, type IconName } from "./ui/Icon";

export interface NavItem { key: string; title: string; /** true 表示点击会离开管理外壳（整页跳转公开工具页），侧栏显示外链图标区分 */ external?: boolean; }
export interface NavGroup { label: string; items: NavItem[]; }
export interface SidebarProps {
  groups: NavGroup[];
  active: string;
  onSelect: (k: string) => void;
  collapsed?: boolean;
  onToggleCollapsed?: () => void;
  /** Closes the drawer on phones. */
  onClose?: () => void;
  footer?: ReactNode;
}

const NAV_ICON: Record<string, IconName> = {
  workbench: "home",
  overview: "grid",
  clients: "monitor",
  messages: "message",
  specusMappings: "shuffle",
  "http-routes": "globe",
  downloads: "download",
  transfer: "send",
  diagram: "layers",
  traffic: "bar-chart",
  connections: "history",
  "peer-mesh": "wifi",
  system: "settings",
  metrics: "activity",
  help: "info-circle",
};

export function navIcon(key: string): IconName {
  return NAV_ICON[key] ?? "circle-alert";
}

/**
 * The floating glass sidebar of the design (Sidebar component): brand, grouped navigation with the
 * current page as a raised glass chip, and the appearance switch at the foot. On phones the same
 * panel is the drawer (see Dashboard).
 */
export function Sidebar({ groups, active, onSelect, collapsed = false, onToggleCollapsed, onClose, footer }: SidebarProps) {
  return (
    <>
      <div className="jd-sidebar-head">
        <a className="jd-brand" href="#/workbench" onClick={(event) => { event.preventDefault(); onSelect("workbench"); onClose?.(); }}>
          <AppLogo className="min-w-0" label="specus" subtitle="管理后台" />
        </a>
        {onToggleCollapsed ? (
          <button
            type="button"
            className="bd-icon-btn jd-collapse"
            aria-label={collapsed ? "展开侧栏" : "收起侧栏"}
            aria-expanded={!collapsed}
            title={collapsed ? "展开侧栏" : "收起侧栏"}
            onClick={onToggleCollapsed}
          >
            <Icon name="panel-left" size={18} />
          </button>
        ) : null}
        {onClose ? (
          <button type="button" className="bd-icon-btn jd-drawer-close" aria-label="关闭" onClick={onClose}>
            <Icon name="x" size={18} />
          </button>
        ) : null}
      </div>
      <nav aria-label="主导航" className="bd-nav">
        {groups.map((group) => (
          <div key={group.label} role="group" aria-label={group.label} className="flex flex-col gap-0.5">
            <div className="bd-nav-group" aria-hidden="true">{group.label}</div>
            {group.items.map((item) => {
              const isActive = item.key === active;
              return (
                <a
                  key={item.key}
                  href={"#/" + item.key}
                  aria-current={isActive ? "page" : undefined}
                  aria-label={collapsed ? item.title : undefined}
                  className="bd-nav-item"
                  title={item.external ? `${item.title}（新页面，离开控制台）` : collapsed ? item.title : undefined}
                  onClick={(event) => { event.preventDefault(); onSelect(item.key); onClose?.(); }}
                >
                  <Icon name={navIcon(item.key)} size={18} />
                  <span className="bd-nav-label min-w-0 flex-1 truncate">{item.title}</span>
                  {item.external ? <span aria-hidden="true" className="bd-nav-count app-nav-external"><Icon name="external" size={14} /></span> : null}
                </a>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="jd-sidebar-foot">
        {footer}
        <div className="jd-foot-row">
          <ThemeSwitch />
        </div>
      </div>
    </>
  );
}

/** The appearance switch at the sidebar foot: follow the system, light or dark. */
function ThemeSwitch() {
  const { theme, setTheme, resetToSystem, userOverride } = useTheme();
  const mode = userOverride ? theme : "system";
  const options: Array<{ key: "system" | "light" | "dark"; label: string; icon: IconName }> = [
    { key: "system", label: "跟随系统", icon: "monitor" },
    { key: "light", label: "浅色", icon: "sun" },
    { key: "dark", label: "深色", icon: "moon" },
  ];
  const cycle = () => {
    if (mode === "system") setTheme("light");
    else if (mode === "light") setTheme("dark");
    else resetToSystem();
  };
  const current = options.find((option) => option.key === mode) ?? options[0];
  return (
    <>
      <div className="jd-theme-seg" role="radiogroup" aria-label="外观">
        {options.map((option) => (
          <button
            key={option.key}
            type="button"
            role="radio"
            aria-checked={mode === option.key}
            aria-label={option.label}
            title={option.label}
            onClick={() => (option.key === "system" ? resetToSystem() : setTheme(option.key))}
          >
            <Icon name={option.icon} size={15} />
          </button>
        ))}
      </div>
      <button type="button" className="bd-icon-btn jd-theme-cycle" aria-label={`外观：${current.label}`} title={`外观：${current.label}`} onClick={cycle}>
        <Icon name={current.icon} size={18} />
      </button>
    </>
  );
}
