import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import {
  Avatar, Button, Dropdown, DropdownItem, DropdownMenu,
  DropdownSection, DropdownTrigger, Spinner,
} from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { useTheme } from "../theme/ThemeContext";
import { adminApi } from "../api/client";
import { notify, notifyError } from "../components/toast";
import { AppLogo } from "../components/AppLogo";
import { HeroRuntime } from "../components/HeroRuntime";
import { Sidebar, type NavGroup } from "../components/Sidebar";

const LazyOverviewPanel = lazy(() => import("./panels/OverviewPanel").then(m => ({ default: m.OverviewPanel })));
const LazyClientsPanel = lazy(() => import("./panels/ClientsPanel").then(m => ({ default: m.ClientsPanel })));
const LazyAdminMessagesPanel = lazy(() => import("./panels/AdminMessagesPanel").then(m => ({ default: m.AdminMessagesPanel })));
const LazyTunnelsPanel = lazy(() => import("./panels/TunnelsPanel").then(m => ({ default: m.TunnelsPanel })));
const LazyHttpRoutesPanel = lazy(() => import("./panels/HttpRoutesPanel").then(m => ({ default: m.HttpRoutesPanel })));
const LazyConnectionsPanel = lazy(() => import("./panels/ConnectionsPanel").then(m => ({ default: m.ConnectionsPanel })));
const LazyTrafficPanel = lazy(() => import("./panels/TrafficPanel").then(m => ({ default: m.TrafficPanel })));
const LazyPeerMeshPanel = lazy(() => import("./panels/PeerMeshPanel").then(m => ({ default: m.PeerMeshPanel })));
const LazyClientDownloadsPanel = lazy(() => import("./panels/ClientDownloadsPanel").then(m => ({ default: m.ClientDownloadsPanel })));
const LazyHelpPanel = lazy(() => import("./panels/HelpPanel").then(m => ({ default: m.HelpPanel })));
const LazySystemPanel = lazy(() => import("./panels/SystemPanel").then(m => ({ default: m.SystemPanel })));

const navGroups: NavGroup[] = [
  { label: "概览", items: [{ key: "overview" as const, title: "概览" }] },
  { label: "接入", items: [
    { key: "clients" as const, title: "客户端" },
    { key: "messages" as const, title: "消息" },
    { key: "tunnels" as const, title: "端口映射" },
    { key: "http-routes" as const, title: "HTTP 路由" },
    { key: "downloads" as const, title: "客户端下载" },
  ]},
  { label: "流量", items: [
    { key: "traffic" as const, title: "流量使用" },
    { key: "connections" as const, title: "连接记录" },
  ]},
  { label: "组网", items: [{ key: "peer-mesh" as const, title: "私有组网" }] },
  { label: "系统", items: [
    { key: "system" as const, title: "系统管理" },
    { key: "help" as const, title: "帮助文档" },
  ]},
];

const panels = navGroups.flatMap(g => g.items);
type PanelKey = typeof panels[number]["key"];
const defaultPanel: PanelKey = "overview";
const panelKeys = new Set<PanelKey>(panels.map(p => p.key));

function readPanelFromLocation(): PanelKey {
  const h = window.location.hash.replace(/^#\/?/, "").split(/[/?#]/, 1)[0].trim();
  return panelKeys.has(h as PanelKey) ? h as PanelKey : defaultPanel;
}

export function Dashboard() { return <HeroRuntime><DashboardContent /></HeroRuntime>; }

function DashboardContent() {
  const { logout, profile } = useAuth();
  const [initializing, setInitializing] = useState(false);
  const [activePanel, setActivePanel] = useState<PanelKey>(() => readPanelFromLocation());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const activatePanel = useCallback((panel: PanelKey) => {
    setActivePanel(panel); setMobileNavOpen(false);
    if (window.location.hash !== "#/" + panel) window.location.hash = "/" + panel;
  }, []);

  const visibleGroups = navGroups.map(g => ({
    ...g, items: g.items.filter(i => i.key !== "system" || profile?.admin)
  })).filter(g => g.items.length > 0);

  const renderedPanel = activePanel === "system" && !profile?.admin ? defaultPanel : activePanel;
  const activeTitle = panels.find(p => p.key === renderedPanel)?.title ?? "概览";

  useEffect(() => {
    const sync = () => setActivePanel(readPanelFromLocation());
    window.addEventListener("hashchange", sync);
    window.addEventListener("popstate", sync);
    return () => { window.removeEventListener("hashchange", sync); window.removeEventListener("popstate", sync); };
  }, []);

  useEffect(() => {
    if (activePanel === "system" && !profile?.admin) activatePanel(defaultPanel);
  }, [activePanel]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") setMobileNavOpen(false); };
    window.addEventListener("keydown", esc);
    return () => { document.body.style.overflow = prev; window.removeEventListener("keydown", esc); };
  }, [mobileNavOpen]);

  const initializeDatabase = async () => {
    if (!window.confirm("确定执行数据库初始化吗？")) return;
    setInitializing(true);
    try { const r = await adminApi.initializeDatabase(); notify(`初始化完成: ${r.dialect}, ${r.clients} 个客户端`); }
    catch (e) { notifyError(e, "初始化失败"); }
    finally { setInitializing(false); }
  };

  const renderActions = (cls: string) => <div className={cls}><UserMenu profile={profile} onLogout={logout} /></div>;

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 bg-background shadow-[1px_0_3px_rgba(0,0,0,0.04)] lg:fixed lg:inset-y-0 lg:left-0 lg:z-30 lg:flex lg:flex-col">
        <Sidebar groups={visibleGroups} active={renderedPanel} onSelect={activatePanel} variant="desktop" />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col lg:ml-60">
        <header className="bg-background/80 backdrop-blur">
          <div className="flex items-center gap-2 px-3 py-2 sm:px-4 lg:hidden">
            <Button isIconOnly aria-label="打开菜单" className="h-10 w-10 min-w-10" radius="sm" variant="flat" onPress={() => setMobileNavOpen(true)}><HamburgerIcon /></Button>
            <AppLogo className="min-w-0 shrink" label="shuai-tunnel" markClassName="h-8 w-8" />
            <span className="ml-auto truncate text-tiny font-medium text-default-500">{activeTitle}</span>
            {renderActions("flex shrink-0 items-center gap-1.5")}
          </div>
          <div className="hidden h-16 w-full px-4 py-3 sm:px-6 lg:flex lg:items-center lg:justify-between lg:py-0">
            <h2 className="text-lg font-semibold text-foreground">{activeTitle}</h2>
            {renderActions("flex shrink-0 items-center gap-3")}
          </div>
        </header>
        <main className="mx-auto w-full min-w-0 max-w-[1440px] flex-1 p-3 sm:p-4">
          <section className="min-w-0" key={renderedPanel}>
            <Suspense fallback={<PanelLoading />}>
              <ActivePanel panel={renderedPanel} initializing={initializing} onInitializeDatabase={initializeDatabase} />
            </Suspense>
          </section>
        </main>
      </div>
      <MobileNav open={mobileNavOpen} groups={visibleGroups} active={renderedPanel} onSelect={activatePanel} onClose={() => setMobileNavOpen(false)} />
    </div>
  );
}

function MobileNav({ open, groups, active, onSelect, onClose }: { open: boolean; groups: NavGroup[]; active: PanelKey; onSelect: (p: PanelKey) => void; onClose: () => void }) {
  return (<>
    <div aria-hidden="true" className={`fixed inset-0 z-40 bg-black/40 backdrop-blur-sm transition-opacity duration-200 lg:hidden ${open ? "opacity-100" : "pointer-events-none opacity-0"}`} onClick={onClose} />
    <aside className={`fixed inset-y-0 left-0 z-50 flex w-72 max-w-[82vw] flex-col bg-background shadow-2xl transition-transform duration-200 lg:hidden ${open ? "translate-x-0" : "-translate-x-full"}`}>
      <div className="flex items-center justify-between gap-2 px-4 py-3">
        <AppLogo className="min-w-0 shrink" label="shuai-tunnel" markClassName="h-8 w-8" />
        <Button isIconOnly aria-label="关闭" className="h-9 w-9 min-w-9" radius="sm" variant="light" onPress={onClose}><CloseIcon /></Button>
      </div>
      <Sidebar groups={groups} active={active} onSelect={onSelect} variant="mobile" onClose={onClose} />
    </aside>
  </>);
}

function HamburgerIcon() { return <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" /></svg>; }
function CloseIcon() { return <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M6 6l12 12M6 18L18 6" /></svg>; }

function UserMenu({ profile, onLogout }: { profile: ReturnType<typeof useAuth>["profile"]; onLogout: () => void }) {
  const name = profile?.username || "user";
  const initials = name.slice(0, 1).toUpperCase();
  const { theme, setTheme, resetToSystem, userOverride } = useTheme();
  return (
    <Dropdown placement="bottom-end" shouldBlockScroll={false}>
      <DropdownTrigger>
        <Button isIconOnly aria-label="个人菜单" className="h-10 w-10 min-w-10 rounded-full" radius="full" variant="flat">
          <Avatar className="h-7 w-7 bg-primary-500 text-primary-foreground" name={initials} size="sm" />
        </Button>
      </DropdownTrigger>
      <DropdownMenu aria-label="个人菜单" onAction={(key) => {
        if (key === "logout") onLogout();
        else if (key === "theme-dark") setTheme("dark");
        else if (key === "theme-light") setTheme("light");
        else if (key === "theme-system") resetToSystem();
        else if (key === "docs") window.location.hash = "/help";
      }}>
        <DropdownSection aria-label="主题" showDivider>
          <DropdownItem key="theme-dark" textValue="深色" endContent={theme === "dark" ? <CheckIcon /> : null}>{"\uD83C\uDF19"} 深色模式</DropdownItem>
          <DropdownItem key="theme-light" textValue="浅色" endContent={theme === "light" ? <CheckIcon /> : null}>{"\u2600\uFE0F"} 浅色模式</DropdownItem>
          <DropdownItem key="theme-system" textValue="系统" endContent={!userOverride ? <CheckIcon /> : null}>{"\uD83D\uDDA5\uFE0F"} 跟随系统</DropdownItem>
        </DropdownSection>
        <DropdownSection aria-label="快捷" showDivider>
          <DropdownItem key="docs" textValue="帮助">{"\uD83D\uDCD6"} 帮助文档</DropdownItem>
        </DropdownSection>
        <DropdownSection aria-label="账户">
          <DropdownItem key="profile" textValue="信息" isReadOnly>
            <div className="min-w-48 space-y-1 py-1">
              <div className="text-small font-semibold text-foreground">{name}</div>
              <div className="text-tiny text-default-500">租户: {profile?.tenantId || "-"}</div>
              <div className="text-tiny text-default-500">角色: {profile?.admin ? "管理员" : "普通用户"}</div>
            </div>
          </DropdownItem>
          <DropdownItem key="logout" className="text-danger" color="danger" textValue="退出">退出登录</DropdownItem>
        </DropdownSection>
      </DropdownMenu>
    </Dropdown>
  );
}
function CheckIcon() { return <svg className="h-4 w-4 text-primary" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>; }

function ActivePanel({ panel, initializing, onInitializeDatabase }: { panel: PanelKey; initializing: boolean; onInitializeDatabase: () => Promise<void> }) {
  switch (panel) {
    case "clients": return <LazyClientsPanel />;
    case "messages": return <LazyAdminMessagesPanel />;
    case "tunnels": return <LazyTunnelsPanel />;
    case "http-routes": return <LazyHttpRoutesPanel />;
    case "peer-mesh": return <LazyPeerMeshPanel />;
    case "connections": return <LazyConnectionsPanel />;
    case "traffic": return <LazyTrafficPanel />;
    case "downloads": return <LazyClientDownloadsPanel />;
    case "help": return <LazyHelpPanel />;
    case "system": return <LazySystemPanel initializing={initializing} onInitializeDatabase={onInitializeDatabase} />;
    default: return <LazyOverviewPanel />;
  }
}
function PanelLoading() { return <div className="flex min-h-[240px] items-center justify-center rounded-md border border-default-200 bg-content1"><Spinner label="加载页面…" /></div>; }
