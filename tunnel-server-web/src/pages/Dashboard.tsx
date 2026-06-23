import { useMemo, useState } from "react";
import {
  Button,
} from "@heroui/react";
import { useAuth } from "../auth/AuthContext";
import { adminApi } from "../api/client";
import { notify, notifyError } from "../components/toast";
import { OverviewPanel } from "./panels/OverviewPanel";
import { ClientsPanel } from "./panels/ClientsPanel";
import { ClientCredentialsPanel } from "./panels/ClientCredentialsPanel";
import { TunnelsPanel } from "./panels/TunnelsPanel";
import { HttpRoutesPanel } from "./panels/HttpRoutesPanel";
import { ConnectionsPanel } from "./panels/ConnectionsPanel";
import { TrafficPanel } from "./panels/TrafficPanel";
import { ThemeToggleButton } from "../components/ThemeToggleButton";
import { AppLogo } from "../components/AppLogo";

export function Dashboard() {
  const { logout } = useAuth();
  const [initializing, setInitializing] = useState(false);
  const [activePanel, setActivePanel] = useState("overview");
  const panels = useMemo(
    () => [
      { key: "overview", title: "概览", content: <OverviewPanel /> },
      { key: "clients", title: "客户端", content: <ClientsPanel /> },
      { key: "client-credentials", title: "客户端凭证", content: <ClientCredentialsPanel /> },
      { key: "tunnels", title: "端口映射", content: <TunnelsPanel /> },
      { key: "http-routes", title: "HTTP 路由", content: <HttpRoutesPanel /> },
      { key: "connections", title: "连接记录", content: <ConnectionsPanel /> },
      { key: "traffic", title: "流量使用", content: <TrafficPanel /> },
    ],
    [],
  );

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

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-divider bg-background/80 backdrop-blur">
        <div className="flex min-h-20 w-full items-center gap-4 px-6">
          <AppLogo className="shrink-0" label="shuai-tunnel 管理后台" markClassName="h-9 w-9" />
          <nav className="min-w-0 flex-1 overflow-x-auto" aria-label="管理面板">
            <div className="flex min-w-max items-center gap-1" role="tablist" aria-label="管理面板">
              {panels.map((panel) => (
                <button
                  key={panel.key}
                  aria-selected={panel.key === activePanel}
                  className={`h-12 border-b-2 px-3 text-small transition-colors ${
                    panel.key === activePanel
                      ? "border-foreground text-foreground"
                      : "border-transparent text-default-500 hover:text-foreground"
                  }`}
                  role="tab"
                  type="button"
                  onClick={() => setActivePanel(panel.key)}
                >
                  {panel.title}
                </button>
              ))}
            </div>
          </nav>
          <div className="flex shrink-0 items-center gap-3">
            <ThemeToggleButton />
            <Button size="sm" variant="flat" isLoading={initializing} onPress={() => void initializeDatabase()}>
              初始化数据库
            </Button>
            <Button size="sm" color="danger" variant="flat" onPress={logout}>
              退出登录
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1440px] flex-1 p-4">
        {panels.map((panel) => (
          <section key={panel.key} className={panel.key === activePanel ? "block" : "hidden"}>
            {panel.content}
          </section>
        ))}
      </main>
    </div>
  );
}
