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
const LazySystemPanel = lazy(() => import("./panels/SystemPanel").then((module) => ({ default: module.SystemPanel })));

const panels = [
  { key: "overview", title: "概览" },
  { key: "clients", title: "客户端" },
  { key: "tunnels", title: "端口映射" },
  { key: "http-routes", title: "HTTP 路由" },
  { key: "connections", title: "连接记录" },
  { key: "traffic", title: "流量使用" },
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

  const activatePanel = useCallback((panel: PanelKey) => {
    setActivePanel(panel);
    const nextHash = panelHash(panel);
    if (window.location.hash !== nextHash) {
      window.location.hash = `/${panel}`;
    }
  }, []);

  const visiblePanels = panels.filter((panel) => panel.key !== "system" || profile?.admin);
  const renderedPanel = activePanel === "system" && !profile?.admin ? defaultPanel : activePanel;

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
        <div className="flex w-full flex-col gap-2 px-4 py-3 sm:px-6 lg:min-h-20 lg:flex-row lg:items-center lg:gap-4 lg:py-0">
          <div className="flex min-w-0 items-center justify-between gap-3 lg:contents">
            <AppLogo className="min-w-0 shrink" label="shuai-tunnel 管理后台" markClassName="h-9 w-9" />
            {renderActions("flex shrink-0 items-center gap-2 lg:hidden")}
          </div>
          <nav className="relative -mx-4 overflow-hidden border-t border-divider/70 pt-2 sm:-mx-6 lg:mx-0 lg:min-w-0 lg:flex-1 lg:border-t-0 lg:pt-0" aria-label="管理面板">
            <div className="pointer-events-none absolute inset-y-2 left-0 z-10 w-5 bg-gradient-to-r from-background to-transparent lg:hidden" />
            <div className="pointer-events-none absolute inset-y-2 right-0 z-10 w-8 bg-gradient-to-l from-background to-transparent lg:hidden" />
            <div className="flex min-w-0 items-center gap-1 overflow-x-auto px-4 pb-1 sm:px-6 lg:min-w-max lg:px-0 lg:pb-0" role="tablist" aria-label="管理面板">
              {visiblePanels.map((panel) => (
                <button
                  key={panel.key}
                  aria-selected={panel.key === renderedPanel}
                  className={`h-11 shrink-0 whitespace-nowrap border-b-2 px-3 text-small transition-colors lg:h-12 ${
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
          {renderActions("hidden shrink-0 items-center gap-3 lg:flex")}
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1440px] flex-1 p-3 sm:p-4">
        <section key={renderedPanel}>
          <Suspense fallback={<PanelLoading />}>
            <ActivePanel
              panel={renderedPanel}
              initializing={initializing}
              onInitializeDatabase={initializeDatabase}
            />
          </Suspense>
        </section>
      </main>
    </div>
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
    case "connections":
      return <LazyConnectionsPanel />;
    case "traffic":
      return <LazyTrafficPanel />;
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
