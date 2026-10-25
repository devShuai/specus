import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  Dropdown, DropdownItem, DropdownMenu,
  DropdownSection, DropdownTrigger, Spinner,
} from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { adminApi } from "../api/client";
import { notify, notifyError } from "../components/toast";
import { ConfirmModal } from "../components/ConfirmModal";
import { HeroRuntime } from "../components/HeroRuntime";
import { Sidebar, navIcon, type NavGroup } from "../components/Sidebar";
import { GlobalSearch, type SearchEntry } from "../components/GlobalSearch";
import { Icon, Tabs } from "../components/ui";
import { ProductMetricsMemberNotice } from "../components/ProductMetricsDisclosure";
import { useProductMetricsCollecting } from "../hooks/useProductMetricsCollecting";

const LazyWorkbenchPanel = lazy(() => import("./panels/WorkbenchPanel").then(m => ({ default: m.WorkbenchPanel })));
const LazyOverviewPanel = lazy(() => import("./panels/OverviewPanel").then(m => ({ default: m.OverviewPanel })));
const LazyClientsPanel = lazy(() => import("./panels/ClientsPanel").then(m => ({ default: m.ClientsPanel })));
const LazyAdminMessagesPanel = lazy(() => import("./panels/AdminMessagesPanel").then(m => ({ default: m.AdminMessagesPanel })));
const LazySpecusMappingsPanel = lazy(() => import("./panels/SpecusMappingsPanel").then(m => ({ default: m.SpecusMappingsPanel })));
const LazyHttpRoutesPanel = lazy(() => import("./panels/HttpRoutesPanel").then(m => ({ default: m.HttpRoutesPanel })));
const LazyConnectionsPanel = lazy(() => import("./panels/ConnectionsPanel").then(m => ({ default: m.ConnectionsPanel })));
const LazyTrafficPanel = lazy(() => import("./panels/TrafficPanel").then(m => ({ default: m.TrafficPanel })));
const LazyPeerMeshPanel = lazy(() => import("./panels/PeerMeshPanel").then(m => ({ default: m.PeerMeshPanel })));
const LazyClientDownloadsPanel = lazy(() => import("./panels/ClientDownloadsPanel").then(m => ({ default: m.ClientDownloadsPanel })));
const LazyHelpPanel = lazy(() => import("./panels/HelpPanel").then(m => ({ default: m.HelpPanel })));
const LazySystemPanel = lazy(() => import("./panels/SystemPanel").then(m => ({ default: m.SystemPanel })));
const LazyProductMetricsPanel = lazy(() => import("./panels/ProductMetricsPanel").then(m => ({ default: m.ProductMetricsPanel })));

const navGroups: NavGroup[] = [
  { label: "概览", items: [
    { key: "workbench" as const, title: "工作台" },
    { key: "overview" as const, title: "概览" },
  ]},
  { label: "接入", items: [
    { key: "clients" as const, title: "客户端" },
    { key: "messages" as const, title: "消息" },
    { key: "specusMappings" as const, title: "端口映射" },
    { key: "http-routes" as const, title: "HTTP 路由" },
    { key: "downloads" as const, title: "客户端下载" },
  ]},
  { label: "工具", items: [
    // E-1: 这两项会离开管理外壳（整页跳转到公开工具页），标记 external 让侧栏加外链图标。
    { key: "transfer" as const, title: "互传", external: true },
    { key: "diagram" as const, title: "专业流程图", external: true },
  ]},
  { label: "流量", items: [
    { key: "traffic" as const, title: "流量使用" },
    { key: "connections" as const, title: "连接记录" },
  ]},
  { label: "组网", items: [{ key: "peer-mesh" as const, title: "私有组网" }] },
  { label: "系统", items: [
    { key: "system" as const, title: "系统管理" },
    { key: "metrics" as const, title: "产品指标" },
    { key: "help" as const, title: "帮助文档" },
  ]},
];

const panels = navGroups.flatMap(g => g.items);
type PanelKey = typeof panels[number]["key"];
// The service workbench is where everyone lands; 概览 stays one click away in the navigation.
const defaultPanel: PanelKey = "workbench";
const panelKeys = new Set<PanelKey>(panels.map(p => p.key));
// System management and product metrics are for the tenant's administrators only.
const adminOnly = (key: PanelKey) => key === "system" || key === "metrics";

function readPanelFromLocation(): PanelKey {
  const h = window.location.hash.replace(/^#\/?/, "").split(/[/?#]/, 1)[0].trim();
  return panelKeys.has(h as PanelKey) ? h as PanelKey : defaultPanel;
}

export function Dashboard() { return <HeroRuntime><DashboardContent /></HeroRuntime>; }

const SIDEBAR_COLLAPSED_KEY = "specus_sidebar_collapsed";
const PHONE_QUERY = "(max-width: 767px)";

// What the topbar search finds besides the page names.
const PANEL_KEYWORDS: Partial<Record<PanelKey, string>> = {
  workbench: "首页 服务 收藏 最近 问题",
  overview: "统计 运行 状态",
  clients: "设备 接入 凭证 apiKey secret 实例 上线",
  messages: "聊天 文件",
  specusMappings: "tcp 端口 公网",
  "http-routes": "web 发布 分享 认证 域名",
  downloads: "安装 下载 homebrew release",
  transfer: "互传 文件 发送 剪贴板 白板",
  diagram: "流程图 绘图 drawio",
  traffic: "流量 http tcp 记录 排行",
  connections: "连接 日志 登录",
  "peer-mesh": "组网 虚拟 ip 出口 nat turn 服务",
  system: "用户 数据库 发布 客户端版本",
  metrics: "指标 统计",
  help: "文档 帮助 启动 配置",
};

function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const onChange = () => setMatches(mq.matches);
    onChange();
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

function DashboardContent() {
  const { logout, profile } = useAuth();
  const [initializing, setInitializing] = useState(false);
  const [initConfirmOpen, setInitConfirmOpen] = useState(false);
  const [activePanel, setActivePanel] = useState<PanelKey>(() => readPanelFromLocation());
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [searching, setSearching] = useState(false);
  const [collapsed, setCollapsed] = useState(() => {
    try { return window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1"; } catch { return false; }
  });
  const phone = useMediaQuery(PHONE_QUERY);
  const drawerButtonRef = useRef<HTMLButtonElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);

  const activatePanel = useCallback((panel: PanelKey) => {
    setActivePanel(panel); setDrawerOpen(false);
    if (panel === "transfer" || panel === "diagram") {
      window.location.hash = "/" + panel;
      return;
    }
    if (window.location.hash !== "#/" + panel) window.location.hash = "/" + panel;
  }, []);

  const toggleCollapsed = useCallback(() => {
    setCollapsed((value) => {
      try { window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, value ? "0" : "1"); } catch { /* per-viewer convenience only */ }
      return !value;
    });
  }, []);

  const visibleGroups = navGroups.map(g => ({
    ...g, items: g.items.filter(i => !adminOnly(i.key) || profile?.admin)
  })).filter(g => g.items.length > 0);

  const renderedPanel = adminOnly(activePanel) && !profile?.admin ? defaultPanel : activePanel;
  // Hub tabs (the design's area tabs): the sibling pages of the current page's group.
  const activeGroup = visibleGroups.find(g => g.items.some(i => i.key === renderedPanel));
  const hubItems = (activeGroup?.items ?? []).filter(i => !i.external);

  const searchEntries = useMemo<SearchEntry[]>(() => visibleGroups.flatMap(group => group.items.map(item => ({
    key: item.key,
    title: item.title,
    subtitle: item.external ? `${group.label} · 新页面` : group.label,
    icon: navIcon(item.key),
    keywords: PANEL_KEYWORDS[item.key],
    run: () => activatePanel(item.key),
  }))), [visibleGroups, activatePanel]);

  useEffect(() => {
    const sync = () => setActivePanel(readPanelFromLocation());
    window.addEventListener("hashchange", sync);
    window.addEventListener("popstate", sync);
    return () => { window.removeEventListener("hashchange", sync); window.removeEventListener("popstate", sync); };
  }, []);

  // E-17: 非管理员停在 #/system 时纠偏回默认面板，让 URL 与实际渲染一致；补齐依赖避免闭包过期。
  useEffect(() => {
    if (adminOnly(activePanel) && !profile?.admin) activatePanel(defaultPanel);
  }, [activePanel, profile?.admin, activatePanel]);

  // E-5: 切换面板后回到页面顶部，避免沿用上一个面板的滚动位置。
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [renderedPanel]);

  useEffect(() => {
    if (!phone) setDrawerOpen(false);
  }, [phone]);

  useEffect(() => {
    if (!drawerOpen) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setDrawerOpen(false); };
    window.addEventListener("keydown", esc);
    return () => { document.body.style.overflow = prev; window.removeEventListener("keydown", esc); };
  }, [drawerOpen]);

  // H-8: on phones the closed drawer leaves the tab order and the accessibility tree; opening it
  // moves focus to the first link, closing it (Esc, scrim, a choice) returns focus to the menu button.
  useLayoutEffect(() => {
    const panel = sidebarRef.current;
    if (!panel) return;
    if (!phone || drawerOpen) {
      panel.removeAttribute("inert");
      if (phone && drawerOpen) {
        const focusTimer = window.setTimeout(() => panel.querySelector<HTMLElement>(".bd-nav [href]")?.focus(), 50);
        return () => window.clearTimeout(focusTimer);
      }
      return;
    }
    panel.setAttribute("inert", "");
    if (panel.contains(window.document.activeElement)) drawerButtonRef.current?.focus();
  }, [phone, drawerOpen]);

  // S-1: 原生 confirm 换成共享 ConfirmModal；SystemPanel 的入口先打开确认框，确认后才真正执行。
  const requestInitializeDatabase = useCallback(async () => {
    setInitConfirmOpen(true);
  }, []);

  const initializeDatabase = async () => {
    setInitializing(true);
    try { const r = await adminApi.initializeDatabase(); notify(`初始化完成: ${r.dialect}, ${r.clients} 个客户端`); }
    catch (e) { notifyError(e, "初始化失败"); }
    finally { setInitializing(false); }
  };

  const shellClass = ["app-apple-dashboard jd-shell", collapsed && !phone ? "bd-shell--collapsed" : "", drawerOpen ? "jd-drawer-open" : ""].filter(Boolean).join(" ");
  return (
    <div className={shellClass}>
      <a className="app-skip-link" href="#app-main-content">跳到主内容</a>
      <aside
        ref={sidebarRef}
        className="bd-sidebar"
        aria-label={phone ? "导航菜单" : undefined}
        role={phone && drawerOpen ? "dialog" : undefined}
        aria-modal={phone && drawerOpen ? true : undefined}
      >
        <Sidebar
          groups={visibleGroups}
          active={renderedPanel}
          onSelect={(key) => activatePanel(key as PanelKey)}
          collapsed={collapsed && !phone}
          onToggleCollapsed={phone ? undefined : toggleCollapsed}
          onClose={phone ? () => setDrawerOpen(false) : undefined}
          footer={<UserMenu profile={profile} onLogout={logout} variant={collapsed && !phone ? "compact" : "block"} />}
        />
      </aside>
      <div className="jd-drawer-scrim" aria-hidden="true" onClick={() => setDrawerOpen(false)} />
      <header className={`bd-topbar jd-topbar${searching ? " is-searching" : ""}`}>
        <button ref={drawerButtonRef} type="button" className="bd-icon-btn jd-glass-btn jd-drawer-btn" aria-label="打开菜单" aria-expanded={drawerOpen} onClick={() => setDrawerOpen(true)}>
          <Icon name="menu" size={19} />
        </button>
        <GlobalSearch entries={searchEntries} searching={searching} onSearchingChange={setSearching} />
        <div className="jd-topbar-tools">
          <button type="button" className="bd-icon-btn jd-glass-btn jd-search-open" aria-label="搜索" onClick={() => setSearching(true)}>
            <Icon name="search" size={19} />
          </button>
          <a className="bd-icon-btn jd-glass-btn" href="#/help" aria-label="帮助文档" title="帮助文档" onClick={(event) => { event.preventDefault(); activatePanel("help"); }}>
            <Icon name="info-circle" size={19} />
          </a>
          <UserMenu profile={profile} onLogout={logout} variant="icon" />
        </div>
      </header>
      <main id="app-main-content" tabIndex={-1} className="bd-main outline-hidden">
        <div className="mx-auto w-full min-w-0 max-w-[1680px]">
          {hubItems.length > 1 ? (
            <Tabs
              variant="hub"
              label={activeGroup?.label ?? "页面"}
              value={renderedPanel}
              items={hubItems.map(item => ({ key: item.key, label: item.title, icon: navIcon(item.key), href: "#/" + item.key }))}
            />
          ) : null}
          <section className="min-w-0" key={renderedPanel}>
            <Suspense fallback={<PanelLoading />}>
              <ActivePanel panel={renderedPanel} initializing={initializing} onInitializeDatabase={requestInitializeDatabase} />
            </Suspense>
          </section>
        </div>
      </main>
      <ConfirmModal
        isOpen={initConfirmOpen}
        onClose={() => setInitConfirmOpen(false)}
        onConfirm={initializeDatabase}
        title="初始化数据库？"
        description="将按当前配置重建并初始化数据库结构，可能影响现有数据，执行后无法撤销。"
        confirmLabel="执行初始化"
        danger
      />
    </div>
  );
}

function UserMenu({ profile, onLogout, variant = "icon" }: { profile: ReturnType<typeof useAuth>["profile"]; onLogout: () => void; variant?: "icon" | "block" | "compact" }) {
  const name = profile?.username || "user";
  const initials = name.slice(0, 1).toUpperCase();
  // The standing member notice of product metrics (protocol/spec/product-metrics.md section 3.1).
  const metricsCollecting = useProductMetricsCollecting(Boolean(profile));
  const role = profile?.admin ? "管理员" : "普通用户";
  return (
    <Dropdown placement={variant === "icon" ? "bottom-end" : "top-start"} shouldBlockScroll={false}>
      <DropdownTrigger>
        {variant === "block" ? (
          <button type="button" aria-label="个人菜单" className="bd-nav-item app-user-block">
            <span className="bd-avatar" aria-hidden="true">{initials}</span>
            <span className="flex min-w-0 flex-1 flex-col text-left leading-tight">
              <span className="truncate text-[13px] font-semibold text-[var(--text)]">{name}</span>
              <span className="truncate text-[12px] text-[var(--text-subtle)]">{role}</span>
            </span>
          </button>
        ) : variant === "compact" ? (
          <button type="button" aria-label="个人菜单" title={name} className="bd-nav-item app-user-block">
            <span className="bd-avatar" aria-hidden="true">{initials}</span>
          </button>
        ) : (
          <button type="button" aria-label="个人菜单" className="bd-icon-btn jd-glass-btn">
            <span className="bd-avatar bd-avatar--sm" aria-hidden="true">{initials}</span>
          </button>
        )}
      </DropdownTrigger>
      <DropdownMenu aria-label="个人菜单" onAction={(key) => {
        if (key === "logout") onLogout();
        else if (key === "docs") window.location.hash = "/help";
      }}>
        <DropdownSection aria-label="账户" showDivider>
          <DropdownItem key="profile" textValue="信息" isReadOnly>
            <div className="min-w-48 space-y-1 py-1">
              <div className="text-small font-semibold text-foreground">{name}</div>
              <div className="text-tiny text-default-500">租户：{profile?.tenantId || "default"} · {role}</div>
              {metricsCollecting ? <ProductMetricsMemberNotice className="max-w-64 whitespace-normal pt-1" /> : null}
            </div>
          </DropdownItem>
        </DropdownSection>
        <DropdownSection aria-label="操作">
          <DropdownItem key="docs" textValue="帮助" startContent={<Icon name="info-circle" />}>帮助文档</DropdownItem>
          <DropdownItem key="logout" className="text-danger" color="danger" textValue="退出" startContent={<Icon name="logout" />}>退出登录</DropdownItem>
        </DropdownSection>
      </DropdownMenu>
    </Dropdown>
  );
}

function ActivePanel({ panel, initializing, onInitializeDatabase }: { panel: PanelKey; initializing: boolean; onInitializeDatabase: () => Promise<void> }) {
  switch (panel) {
    case "clients": return <LazyClientsPanel />;
    case "messages": return <LazyAdminMessagesPanel />;
    case "specusMappings": return <LazySpecusMappingsPanel />;
    case "http-routes": return <LazyHttpRoutesPanel />;
    case "peer-mesh": return <LazyPeerMeshPanel />;
    case "connections": return <LazyConnectionsPanel />;
    case "traffic": return <LazyTrafficPanel />;
    case "downloads": return <LazyClientDownloadsPanel />;
    case "help": return <LazyHelpPanel />;
    case "system": return <LazySystemPanel initializing={initializing} onInitializeDatabase={onInitializeDatabase} />;
    case "metrics": return <LazyProductMetricsPanel />;
    case "overview": return <LazyOverviewPanel />;
    default: return <LazyWorkbenchPanel />;
  }
}
function PanelLoading() {
  return (
    <div className="bd-card flex min-h-[240px] items-center justify-center" role="status">
      <Spinner label="加载页面…" />
    </div>
  );
}
