import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import {
  Avatar,
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Spinner,
} from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { adminApi } from "../api/client";
import { notify, notifyError } from "../components/toast";
import { ThemeToggleButton } from "../components/ThemeToggleButton";
import { AppLogo } from "../components/AppLogo";

const LazyOverviewPanel = lazy(() => import("./panels/OverviewPanel").then((module) => ({ default: module.OverviewPanel })));
const LazyClientsPanel = lazy(() => import("./panels/ClientsPanel").then((module) => ({ default: module.ClientsPanel })));
const LazyTunnelsPanel = lazy(() => import("./panels/TunnelsPanel").then((module) => ({ default: module.TunnelsPanel })));
const LazyHttpRoutesPanel = lazy(() => import("./panels/HttpRoutesPanel").then((module) => ({ default: module.HttpRoutesPanel })));
const LazyConnectionsPanel = lazy(() => import("./panels/ConnectionsPanel").then((module) => ({ default: module.ConnectionsPanel })));
const LazyTrafficPanel = lazy(() => import("./panels/TrafficPanel").then((module) => ({ default: module.TrafficPanel })));
const LazyPeerMeshPanel = lazy(() => import("./panels/PeerMeshPanel").then((module) => ({ default: module.PeerMeshPanel })));
const LazyClientDownloadsPanel = lazy(() => import("./panels/ClientDownloadsPanel").then((module) => ({ default: module.ClientDownloadsPanel })));
const LazyHelpPanel = lazy(() => import("./panels/HelpPanel").then((module) => ({ default: module.HelpPanel })));
const LazySystemPanel = lazy(() => import("./panels/SystemPanel").then((module) => ({ default: module.SystemPanel })));

const panels = [
  { key: "overview", title: "概览" },
  { key: "clients", title: "客户端" },
  { key: "tunnels", title: "端口映射" },
  { key: "http-routes", title: "HTTP 路由" },
  { key: "peer-mesh", title: "私有组网" },
  { key: "connections", title: "连接记录" },
  { key: "traffic", title: "流量使用" },
  { key: "downloads", title: "客户端下载" },
  { key: "help", title: "帮助文档" },
  { key: "system", title: "系统管理" },
] as const;

type PanelKey = (typeof panels)[number]["key"];

const defaultPanel: PanelKey = "overview";
const panelKeys = new Set<PanelKey>(panels.map((panel) => panel.key));

function readPanelFromLocation(): PanelKey {
  const hashPanel = normalizePanelKey(window.location.hash.replace(/^#\/?/, ""));
  if (hashPanel) {
    return hashPanel;
  }

  const queryPanel = normalizePanelKey(new URLSearchParams(window.location.search).get("panel") ?? "");
  return queryPanel ?? defaultPanel;
}

function normalizePanelKey(value: string): PanelKey | null {
  const panel = value.split(/[/?#]/, 1)[0].trim();
  return panelKeys.has(panel as PanelKey) ? (panel as PanelKey) : null;
}

function panelHash(panel: PanelKey) {
  return `#/${panel}`;
}

export function Dashboard() {
  const { logout, profile } = useAuth();
  const [initializing, setInitializing] = useState(false);
  const [activePanel, setActivePanel] = useState<PanelKey>(() => readPanelFromLocation());
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const activatePanel = useCallback((panel: PanelKey) => {
    setActivePanel(panel);
    setMobileNavOpen(false);
    const nextHash = panelHash(panel);
    if (window.location.hash !== nextHash) {
      window.location.hash = `/${panel}`;
    }
  }, []);

  const visiblePanels = panels.filter((panel) => panel.key !== "system" || profile?.admin);
  const renderedPanel = activePanel === "system" && !profile?.admin ? defaultPanel : activePanel;
  const activeTitle = visiblePanels.find((p) => p.key === renderedPanel)?.title ?? "概览";

  useEffect(() => {
    const syncPanelFromLocation = () => {
      setActivePanel(readPanelFromLocation());
    };

    window.addEventListener("hashchange", syncPanelFromLocation);
    window.addEventListener("popstate", syncPanelFromLocation);
    return () => {
      window.removeEventListener("hashchange", syncPanelFromLocation);
      window.removeEventListener("popstate", syncPanelFromLocation);
    };
  }, []);

  useEffect(() => {
    if (activePanel === "system" && !profile?.admin) {
      activatePanel(defaultPanel);
    }
  }, [activePanel, activatePanel, profile?.admin]);

  // 抽屉打开期间锁定 body 滚动
  useEffect(() => {
    if (!mobileNavOpen) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    window.addEventListener("keydown", handleEscape);
    return () => {
      document.body.style.overflow = previous;
      window.removeEventListener("keydown", handleEscape);
    };
  }, [mobileNavOpen]);

  const initializeDatabase = async () => {
    if (!window.confirm("确定执行数据库初始化吗？该操作幂等，可重复执行。")) {
      return;
    }
    setInitializing(true);
    try {
      const result = await adminApi.initializeDatabase();
      notify(`数据库初始化完成：${result.dialect}，客户端 ${result.clients} 个`);
    } catch (error) {
      notifyError(error, "初始化失败");
    } finally {
      setInitializing(false);
    }
  };

  const renderActions = (className: string) => (
    <div className={className}>
      <ThemeToggleButton />
      <UserMenu profile={profile} onLogout={logout} />
    </div>
  );

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-divider bg-background/80 backdrop-blur">
        {/* mobile (< lg) header: 汉堡 + Logo + 当前 panel 标题 + 主题/用户 */}
        <div className="flex items-center gap-2 px-3 py-2 sm:px-4 lg:hidden">
          <Button
            isIconOnly
            aria-label="打开菜单"
            className="h-10 w-10 min-w-10"
            radius="sm"
            variant="flat"
            onPress={() => setMobileNavOpen(true)}
          >
            <HamburgerIcon />
          </Button>
          <AppLogo className="min-w-0 shrink" label="shuai-tunnel" markClassName="h-8 w-8" />
          <span className="ml-auto truncate text-tiny font-medium text-default-500">{activeTitle}</span>
          {renderActions("flex shrink-0 items-center gap-1.5")}
        </div>

        {/* desktop (≥ lg) header: 原 tab strip 布局保持不变 */}
        <div className="hidden w-full px-4 py-3 sm:px-6 lg:flex lg:min-h-20 lg:items-center lg:gap-4 lg:py-0">
          <AppLogo className="min-w-0 shrink" label="shuai-tunnel 管理后台" markClassName="h-9 w-9" />
          <nav className="relative min-w-0 flex-1" aria-label="管理面板">
            <div className="flex min-w-max items-center gap-1" role="tablist" aria-label="管理面板">
              {visiblePanels.map((panel) => (
                <button
                  key={panel.key}
                  aria-selected={panel.key === renderedPanel}
                  className={`h-12 shrink-0 whitespace-nowrap border-b-2 px-3 text-small transition-colors ${
                    panel.key === renderedPanel
                      ? "border-foreground text-foreground"
                      : "border-transparent text-default-500 hover:text-foreground"
                  }`}
                  role="tab"
                  type="button"
                  onClick={() => activatePanel(panel.key)}
                >
                  {panel.title}
                </button>
              ))}
            </div>
          </nav>
          {renderActions("flex shrink-0 items-center gap-3")}
        </div>
      </header>

      <main className="mx-auto w-full min-w-0 max-w-[1440px] flex-1 p-3 sm:p-4">
        <section className="min-w-0" key={renderedPanel}>
          <Suspense fallback={<PanelLoading />}>
            <ActivePanel
              panel={renderedPanel}
              initializing={initializing}
              onInitializeDatabase={initializeDatabase}
            />
          </Suspense>
        </section>
      </main>

      <MobileNav
        open={mobileNavOpen}
        panels={visiblePanels}
        active={renderedPanel}
        onSelect={activatePanel}
        onClose={() => setMobileNavOpen(false)}
      />
    </div>
  );
}

/**
 * Mobile 抽屉式导航。固定定位 + 半透明遮罩，点击遮罩或选项关闭。
 * 仅在 < lg 出现，桌面端不渲染（由父组件的 mobileNavOpen 只在 mobile 触发）。
 */
function MobileNav({
  open,
  panels,
  active,
  onSelect,
  onClose,
}: {
  open: boolean;
  panels: ReadonlyArray<{ key: PanelKey; title: string }>;
  active: PanelKey;
  onSelect: (panel: PanelKey) => void;
  onClose: () => void;
}) {
  return (
    <>
      {/* 遮罩 */}
      <div
        aria-hidden="true"
        className={`fixed inset-0 z-40 bg-black/40 backdrop-blur-sm transition-opacity duration-200 lg:hidden ${
          open ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
        onClick={onClose}
      />
      {/* 抽屉 */}
      <aside
        aria-label="主导航"
        className={`fixed inset-y-0 left-0 z-50 flex w-72 max-w-[82vw] flex-col border-r border-divider bg-background shadow-2xl transition-transform duration-200 lg:hidden ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between gap-2 border-b border-divider px-4 py-3">
          <AppLogo className="min-w-0 shrink" label="shuai-tunnel" markClassName="h-8 w-8" />
          <Button
            isIconOnly
            aria-label="关闭菜单"
            className="h-9 w-9 min-w-9"
            radius="sm"
            variant="light"
            onPress={onClose}
          >
            <CloseIcon />
          </Button>
        </div>
        <nav className="flex-1 overflow-y-auto p-2">
          <ul className="flex flex-col gap-1">
            {panels.map((panel) => (
              <li key={panel.key}>
                <button
                  className={`flex w-full items-center justify-between rounded-md px-3 py-3 text-left text-small transition-colors ${
                    panel.key === active
                      ? "bg-default-100 font-semibold text-foreground"
                      : "text-default-600 hover:bg-default-50 hover:text-foreground"
                  }`}
                  type="button"
                  onClick={() => onSelect(panel.key)}
                >
                  <span>{panel.title}</span>
                  {panel.key === active ? <span className="text-tiny text-primary">●</span> : null}
                </button>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
    </>
  );
}

function HamburgerIcon() {
  return (
    <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 6l12 12M6 18L18 6" />
    </svg>
  );
}

function UserMenu({
  profile,
  onLogout,
}: {
  profile: ReturnType<typeof useAuth>["profile"];
  onLogout: () => void;
}) {
  const name = profile?.username || "user";
  const initials = name.slice(0, 1).toUpperCase();

  return (
    <Dropdown placement="bottom-end">
      <DropdownTrigger>
        <Button
          isIconOnly
          aria-label="个人菜单"
          className="h-10 w-10 min-w-10 rounded-full"
          radius="full"
          variant="flat"
        >
          <Avatar
            className="h-7 w-7 bg-primary-500 text-primary-foreground"
            name={initials}
            size="sm"
          />
        </Button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label="个人菜单"
        onAction={(key) => {
          if (key === "logout") {
            onLogout();
          }
        }}
      >
        <DropdownItem key="profile" textValue="个人信息" isReadOnly>
          <div className="min-w-48 space-y-1 py-1">
            <div className="text-small font-semibold text-foreground">{name}</div>
            <div className="text-tiny text-default-500">租户：{profile?.tenantId || "-"}</div>
            <div className="text-tiny text-default-500">
              角色：{profile?.admin ? "管理员" : "普通用户"}
            </div>
          </div>
        </DropdownItem>
        <DropdownItem key="logout" className="text-danger" color="danger" textValue="退出登录">
          退出登录
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
}

function ActivePanel({
  panel,
  initializing,
  onInitializeDatabase,
}: {
  panel: PanelKey;
  initializing: boolean;
  onInitializeDatabase: () => Promise<void>;
}) {
  switch (panel) {
    case "clients":
      return <LazyClientsPanel />;
    case "tunnels":
      return <LazyTunnelsPanel />;
    case "http-routes":
      return <LazyHttpRoutesPanel />;
    case "peer-mesh":
      return <LazyPeerMeshPanel />;
    case "connections":
      return <LazyConnectionsPanel />;
    case "traffic":
      return <LazyTrafficPanel />;
    case "downloads":
      return <LazyClientDownloadsPanel />;
    case "help":
      return <LazyHelpPanel />;
    case "system":
      return <LazySystemPanel initializing={initializing} onInitializeDatabase={onInitializeDatabase} />;
    case "overview":
    default:
      return <LazyOverviewPanel />;
  }
}

function PanelLoading() {
  return (
    <div className="flex min-h-[240px] items-center justify-center rounded-md border border-default-200 bg-content1">
      <Spinner label="加载页面…" />
    </div>
  );
}
