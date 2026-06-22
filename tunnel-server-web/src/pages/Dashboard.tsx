import { useState } from "react";
import {
  Button,
  Navbar,
  NavbarBrand,
  NavbarContent,
  Tab,
  Tabs,
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

export function Dashboard() {
  const { logout } = useAuth();
  const [initializing, setInitializing] = useState(false);

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
      <Navbar maxWidth="full" isBordered>
        <NavbarBrand>
          <span className="font-semibold">shuai-tunnel 管理后台</span>
        </NavbarBrand>
        <NavbarContent justify="end">
          <Button size="sm" variant="flat" isLoading={initializing} onPress={() => void initializeDatabase()}>
            初始化数据库
          </Button>
          <Button size="sm" color="danger" variant="flat" onPress={logout}>
            退出登录
          </Button>
        </NavbarContent>
      </Navbar>

      <main className="mx-auto w-full max-w-[1440px] flex-1 p-4">
        <Tabs aria-label="管理面板" variant="underlined" destroyInactiveTabPanel={false}>
          <Tab key="overview" title="概览">
            <OverviewPanel />
          </Tab>
          <Tab key="clients" title="客户端">
            <ClientsPanel />
          </Tab>
          <Tab key="client-credentials" title="客户端凭证">
            <ClientCredentialsPanel />
          </Tab>
          <Tab key="tunnels" title="端口映射">
            <TunnelsPanel />
          </Tab>
          <Tab key="http-routes" title="HTTP 路由">
            <HttpRoutesPanel />
          </Tab>
          <Tab key="connections" title="连接记录">
            <ConnectionsPanel />
          </Tab>
          <Tab key="traffic" title="流量使用">
            <TrafficPanel />
          </Tab>
        </Tabs>
      </main>
    </div>
  );
}
