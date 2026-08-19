import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Input,
  Pagination,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Select,
  SelectItem,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tabs,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { PeerMeshAcl, PeerMeshDevice, PeerMeshPathStats, PeerMeshSession, PeerMeshStatus } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { ConfirmModal } from "../../components/ConfirmModal";
import { formatBytes, formatDateTime } from "../../lib/format";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { EmptyState } from "../../components/EmptyState";
import { useNowTick } from "../../hooks/useNowTick";
import { PeerMeshServicesTab } from "./PeerMeshServicesTab";
import {
  NAT_BEHAVIOR_AXES,
  natBehaviorDiscoveryLabel,
  natClassificationProfile,
  natFilteringBehaviorLabel,
  natMappingBehaviorLabel,
  natTypeColor,
  natTypeLabel,
} from "../../lib/nat";

const peerNatFilterOptions = [
  { key: "all", label: "全部设备" },
  { key: "online", label: "仅在线" },
  { key: "direct", label: "直连友好" },
  { key: "relay", label: "建议 Relay" },
  { key: "unknown", label: "未检测" },
] as const;

type PeerNatFilterKey = (typeof peerNatFilterOptions)[number]["key"];
type PeerMeshViewKey = "devices" | "sessions" | "acl" | "nat" | "services";
const SESSION_PAGE_SIZE = 20;
const PEER_SESSION_FRESH_MILLIS = 120_000;

export function PeerMeshPanel() {
  const [status, setStatus] = useState<PeerMeshStatus | null>(null);
  const [pathStats, setPathStats] = useState<PeerMeshPathStats | null>(null);
  const [devices, setDevices] = useState<PeerMeshDevice[]>([]);
  const [acls, setAcls] = useState<PeerMeshAcl[]>([]);
  const [sessions, setSessions] = useState<PeerMeshSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<PeerMeshSession | null>(null);
  const [mobileDetailOpen, setMobileDetailOpen] = useState(false);
  const [aclDirection, setAclDirection] = useState<"OUTBOUND" | "INBOUND" | "BOTH">("OUTBOUND");
  // 设备/会话加载态分开，局部操作不再整页闪烁。
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [clearingSessions, setClearingSessions] = useState(false);
  const [updatingDeviceIds, setUpdatingDeviceIds] = useState<ReadonlySet<number>>(new Set());
  const [confirmState, setConfirmState] = useState<{
    title: string;
    description: ReactNode;
    confirmLabel: string;
    action: () => Promise<void>;
  } | null>(null);
  const [sourceClientId, setSourceClientId] = useState("");
  const [targetClientId, setTargetClientId] = useState("");
  const [natFilter, setNatFilter] = useState<PeerNatFilterKey>("all");
  const [natKeyword, setNatKeyword] = useState("");
  const [peerView, setPeerView] = useState<PeerMeshViewKey>("devices");
  const [sessionPage, setSessionPage] = useState(0);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [sessionTotalPages, setSessionTotalPages] = useState(1);
  const sessionRequestId = useRef(0);
  // 新鲜度窗口 120s，30s tick 足够驱动过期判定，避免每秒整面板重渲染。
  const now = useNowTick(30_000);

  const loadOverview = useCallback(async () => {
    try {
      const [nextStatus, nextDevices, nextAcls, nextPathStats] = await Promise.all([
        adminApi.peerMeshStatus(),
        adminApi.listPeerMeshDevices(),
        adminApi.listPeerMeshAcls(),
        // stats 暂不可用时降级为 null，不影响面板其余部分。
        adminApi.peerMeshStats().catch(() => null),
      ]);
      setStatus(nextStatus);
      setPathStats(nextPathStats);
      setDevices(nextDevices);
      setAcls(nextAcls);
    } catch (error) {
      notifyError(error, "加载私有组网失败");
    } finally {
      setDevicesLoading(false);
    }
  }, []);

  const loadSessions = useCallback(async (page: number, showSpinner = false) => {
    const requestId = sessionRequestId.current + 1;
    sessionRequestId.current = requestId;
    if (showSpinner) {
      setSessionsLoading(true);
    }
    try {
      const nextSessions = await adminApi.listPeerMeshSessionsPage({
        page,
        size: SESSION_PAGE_SIZE,
        openOnly: true,
      });
      if (requestId !== sessionRequestId.current) {
        return;
      }
      setSessions(nextSessions.items);
      setSessionTotal(nextSessions.total);
      setSessionTotalPages(Math.max(1, nextSessions.totalPages));
    } catch (error) {
      if (requestId === sessionRequestId.current) {
        notifyError(error, "加载 peer 会话失败");
      }
    } finally {
      if (requestId === sessionRequestId.current) {
        setSessionsLoading(false);
      }
    }
  }, []);

  // 刷新保留旧数据，只给按钮 loading。
  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([loadOverview(), loadSessions(sessionPage)]);
    } finally {
      setRefreshing(false);
    }
  }, [loadOverview, loadSessions, sessionPage]);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  // 翻页只刷新会话区。
  useEffect(() => {
    void loadSessions(sessionPage, true);
  }, [loadSessions, sessionPage]);

  const enabledDevices = useMemo(() => devices.filter((device) => device.enabled), [devices]);
  const onlineDevices = useMemo(() => devices.filter((device) => device.online), [devices]);
  const deviceById = useMemo(() => new Map(devices.map((device) => [device.clientId, device])), [devices]);
  const openSessions = useMemo(() => sessions.filter((session) => session.status !== "CLOSED"), [sessions]);
  const activeSessions = useMemo(
    () => sessions.filter((session) => isPeerSessionEffectivelyActive(session, deviceById, now)),
    [sessions, deviceById, now],
  );
  // 指标卡使用 pathStats 全局字段 / sessionTotal，不用当前页 20 条数据冒充全局总量。
  const globalActiveSessions = pathStats?.activeSessions ?? sessionTotal;
  const globalDirectSessions = pathStats?.activeDirectSessions ?? null;
  const globalRelaySessions = pathStats?.activeRelaySessions ?? null;
  const peerTrafficBytes = useMemo(
    () => (pathStats
      ? pathStats.pathTypes.reduce((total, row) => total + (row.directBytes || 0) + (row.relayBytes || 0), 0)
      : null),
    [pathStats],
  );
  const natStats = useMemo(() => buildPeerNatStats(devices), [devices]);
  const natDevices = useMemo(() => {
    const normalizedKeyword = natKeyword.trim().toLowerCase();
    return devices
      .filter((device) => matchPeerNatFilter(device, natFilter))
      .filter((device) => {
        if (!normalizedKeyword) {
          return true;
        }
        return [
          device.clientName,
          device.ownerUsername,
          device.virtualIp,
          device.lastEndpoint,
          device.natType,
          device.natMappingBehavior,
          device.natFilteringBehavior,
          device.natBehaviorDiscovery,
          device.virtualDeviceName,
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedKeyword));
      })
      .sort(comparePeerNatDevice);
  }, [devices, natFilter, natKeyword]);

  // 设备开关乐观更新单行，失败回滚；不再整表重载。
  const updateDevice = async (device: PeerMeshDevice, enabled: boolean) => {
    setUpdatingDeviceIds((ids) => new Set(ids).add(device.clientId));
    setDevices((items) => items.map((item) => (item.clientId === device.clientId ? { ...item, enabled } : item)));
    try {
      const updated = await adminApi.updatePeerMeshDevice(device.clientId, { enabled });
      setDevices((items) => items.map((item) => (item.clientId === updated.clientId ? updated : item)));
      notify(enabled ? "已启用私有组网设备" : "已停用私有组网设备");
    } catch (error) {
      setDevices((items) => items.map((item) => (item.clientId === device.clientId ? device : item)));
      notifyError(error, "更新设备失败");
    } finally {
      setUpdatingDeviceIds((ids) => {
        const next = new Set(ids);
        next.delete(device.clientId);
        return next;
      });
    }
  };

  const createAcl = async () => {
    const source = Number(sourceClientId);
    const target = Number(targetClientId);
    if (!source || !target || source === target) {
      notifyError(new Error("请选择两个不同的客户端"), "创建 ACL 失败");
      return;
    }
    try {
      const acl = await adminApi.createPeerMeshAcl({ sourceClientId: source, targetClientId: target, allowed: true, direction: aclDirection });
      setAcls((items) => [acl, ...items.filter((item) => item.id !== acl.id)]);
      notify("Peer ACL 已创建");
    } catch (error) {
      notifyError(error, "创建 ACL 失败");
    }
  };

  const deleteAcl = (acl: PeerMeshAcl) => {
    setConfirmState({
      title: "删除 ACL",
      description: `将删除 ${acl.sourceClientName} → ${acl.targetClientName} 的放行规则，删除后跨用户互访会立即失效且不可恢复。`,
      confirmLabel: "删除",
      action: async () => {
        try {
          await adminApi.deletePeerMeshAcl(acl.id);
          setAcls((items) => items.filter((item) => item.id !== acl.id));
          notify("Peer ACL 已删除");
        } catch (error) {
          notifyError(error, "删除 ACL 失败");
        }
      },
    });
  };

  const closeSession = (session: PeerMeshSession) => {
    setConfirmState({
      title: "断开 peer session",
      description: `将立即断开 ${session.sourceClientName} → ${session.targetClientName} 的 peer session，进行中的直连/relay 传输会中断。`,
      confirmLabel: "断开",
      action: async () => {
        try {
          const closed = await adminApi.closePeerMeshSession(session.id);
          setSessions((items) => items.map((item) => (item.id === closed.id ? closed : item)));
          if (selectedSession?.id === session.id) setSelectedSession(null);
          notify("Peer session 已断开");
          await loadSessions(sessionPage);
        } catch (error) {
          notifyError(error, "断开 peer session 失败");
        }
      },
    });
  };

  const closeOpenSessions = () => {
    if (sessionTotal === 0 && openSessions.length === 0) {
      notify("当前没有未关闭 peer 链路");
      return;
    }
    setConfirmState({
      title: "清理未关闭 peer 链路",
      description: `将关闭当前权限范围内全部 ${sessionTotal} 条未关闭 peer 链路（当前页有效活跃 ${activeSessions.length} 条），进行中的传输会全部中断。`,
      confirmLabel: "全部清理",
      action: async () => {
        setClearingSessions(true);
        try {
          const closedSessions = await adminApi.closeOpenPeerMeshSessions();
          notify(`已清理 ${closedSessions.length} 条 peer 链路`);
          // 统一从服务端收敛列表与计数，不手工重置。
          setSessionPage(0);
          await Promise.all([loadOverview(), loadSessions(0)]);
        } catch (error) {
          notifyError(error, "清理 peer 链路失败");
        } finally {
          setClearingSessions(false);
        }
      },
    });
  };

  return (
    <div className="mt-4 flex min-w-0 flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-foreground">私有组网</h2>
          <p className="text-small text-default-500">
            设备通过虚拟 IP 互联；RFC 5780 双轴结果辅助选路，直连失败后切换认证 TURN。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            color="danger"
            variant="flat"
            isDisabled={sessionTotal === 0 && openSessions.length === 0}
            isLoading={clearingSessions}
            onPress={closeOpenSessions}
          >
            清理未关闭链路
          </Button>
          <Button variant="flat" isLoading={refreshing} onPress={() => void refresh()}>
            刷新
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard
          label="全局开关"
          value={status ? (status.enabled ? "已开启" : "默认关闭") : "-"}
          tone={status?.enabled ? "success" : "default"}
        />
        <MetricCard label="已启用设备" value={`${enabledDevices.length} / ${devices.length}`} />
        <MetricCard label="在线设备" value={String(onlineDevices.length)} tone={onlineDevices.length > 0 ? "success" : "default"} />
        <MetricCard
          label="活跃 Direct / Relay"
          value={globalDirectSessions == null || globalRelaySessions == null ? "-" : `${globalDirectSessions} / ${globalRelaySessions}`}
        />
        <MetricCard
          label="直连占比"
          value={pathStats?.activeDirectRatio == null ? "-" : `${Math.round(pathStats.activeDirectRatio * 100)}%`}
          tone={pathStats?.activeDirectRatio != null && pathStats.activeDirectRatio >= 0.5 ? "success" : "default"}
        />
        <MetricCard label="Peer 流量" value={peerTrafficBytes == null ? "-" : formatBytes(peerTrafficBytes)} tone={peerTrafficBytes != null && peerTrafficBytes > 0 ? "success" : "default"} />
      </div>

      {!status?.enabled && (
        <Card shadow="none" className="rounded-md border border-warning-200 bg-warning-50 dark:border-warning-400/30 dark:bg-warning-500/10">
          <CardBody className="p-3 text-small text-warning-700 dark:text-warning-200">
            server 当前未启用 peer mesh。设置 SPECUS_PEER_MESH_ENABLED=true 后，客户端下次登录会收到虚拟 IP、独立 STUN 拓扑和 TURN/ICE 凭证。
          </CardBody>
        </Card>
      )}

      <Tabs
        aria-label="私有组网视图"
        selectedKey={peerView}
        variant="underlined"
        onSelectionChange={(key) => setPeerView(String(key) as PeerMeshViewKey)}
      >
        <Tab key="devices" title="设备拓扑" />
        <Tab key="services" title="服务" />
        <Tab key="sessions" title={`活跃会话 ${globalActiveSessions}`} />
        <Tab key="acl" title={`ACL ${acls.length}`} />
        <Tab key="nat" title="NAT 诊断" />
      </Tabs>

      {peerView === "services" && (
        <PeerMeshServicesTab deploymentEnabled={Boolean(status?.enabled)} devices={devices} />
      )}

      {peerView === "nat" && (
      <PeerNatInsight
        devices={natDevices}
        devicesTotal={devices.length}
        filter={natFilter}
        keyword={natKeyword}
        loading={devicesLoading}
        onFilterChange={setNatFilter}
        onKeywordChange={setNatKeyword}
        stats={natStats}
      />
      )}

      {peerView === "devices" && (
      <>
      <TopologyView devices={devices} sessions={activeSessions} />

      <section className="min-w-0 space-y-2">
        <h3 className="text-base font-semibold">设备与虚拟 IP</h3>

        {/* mobile: 卡片 */}
        <div className="lg:hidden">
          <MobileListCardList
            items={devices}
            isLoading={devicesLoading}
            emptyContent="暂无 peer mesh 设备"
            renderCard={(raw) => {
              const device = raw as PeerMeshDevice;
              return (
                <MobileListCard
                  key={device.clientId}
                  title={
                    <div className="flex flex-col gap-0.5">
                      <span className="break-all">{device.clientName}</span>
                      <span className="text-tiny font-normal text-default-400">{device.clientId}</span>
                    </div>
                  }
                  subtitle={device.ownerUsername || "-"}
                  badges={
                    <>
                      <Chip size="sm" color={device.online ? "success" : "default"} variant="flat">
                        {device.online ? "在线" : "离线"}
                      </Chip>
                      <Chip size="sm" color={device.enabled ? "primary" : "default"} variant="flat">
                        {device.enabled ? "组网启用" : "未启用"}
                      </Chip>
                      <Chip size="sm" color={virtualDeviceColor(device.virtualDeviceStatus)} variant="flat">
                        {virtualDeviceLabel(device.virtualDeviceStatus)}
                      </Chip>
                    </>
                  }
                  fields={[
                    {
                      label: "虚拟 IP",
                      value: (
                        <div className="flex flex-col">
                          <span className="font-mono">{device.virtualIp || "-"}</span>
                          <span className="text-tiny text-default-400">{device.cidr}</span>
                        </div>
                      ),
                    },
                    {
                      label: "虚拟网卡",
                      value: (
                        <div className="flex flex-col gap-0.5">
                          <span className="font-mono text-tiny">
                            {device.virtualDeviceName || device.virtualDeviceMode || "-"}
                          </span>
                          {device.virtualDeviceError ? (
                            <span className="text-tiny text-danger">{device.virtualDeviceError}</span>
                          ) : null}
                        </div>
                      ),
                    },
                    {
                      label: "NAT",
                      value: (
                        <div className="flex flex-col gap-0.5">
                          <span>{peerNatProfile(device).label}</span>
                          <PeerNatBehaviorLine device={device} />
                          <span className="break-all text-tiny text-default-400">{device.lastEndpoint || "-"}</span>
                        </div>
                      ),
                    },
                    { label: "最后上线", value: formatDateTime(device.lastSeenAt) },
                  ]}
                  actions={
                    <div className="flex w-full items-center justify-between">
                      <span className="text-tiny text-default-500">私有组网</span>
                      <Switch
                        aria-label={`启用 ${device.clientName} 私有组网`}
                        isSelected={device.enabled}
                        isDisabled={updatingDeviceIds.has(device.clientId)}
                        onValueChange={(enabled) => void updateDevice(device, enabled)}
                      />
                    </div>
                  }
                />
              );
            }}
          />
        </div>

        {/* desktop: 表格 */}
        <div className="hidden min-w-0 overflow-x-auto lg:block">
        <Table aria-label="Peer mesh 设备" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>客户端</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>虚拟 IP</TableColumn>
            <TableColumn>状态</TableColumn>
            <TableColumn>虚拟网卡</TableColumn>
            <TableColumn>NAT / Endpoint</TableColumn>
            <TableColumn>最后上线</TableColumn>
            <TableColumn>启用</TableColumn>
          </TableHeader>
          <TableBody items={devices} isLoading={devicesLoading} emptyContent="暂无 peer mesh 设备">
            {(device) => (
              <TableRow key={device.clientId}>
                <TableCell>
                  <div className="flex min-w-0 flex-col">
                    <span className="font-medium">{device.clientName}</span>
                    <span className="text-tiny text-default-400">{device.clientId}</span>
                  </div>
                </TableCell>
                <TableCell>{device.ownerUsername || "-"}</TableCell>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="font-mono">{device.virtualIp || "-"}</span>
                    <span className="text-tiny text-default-400">{device.cidr}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    <Chip size="sm" color={device.online ? "success" : "default"} variant="flat">
                      {device.online ? "在线" : "离线"}
                    </Chip>
                    <Chip size="sm" color={device.enabled ? "primary" : "default"} variant="flat">
                      {device.enabled ? "组网启用" : "未启用"}
                    </Chip>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex max-w-64 flex-col gap-1 text-small">
                    <div className="flex flex-wrap items-center gap-1">
                      <Chip size="sm" color={virtualDeviceColor(device.virtualDeviceStatus)} variant="flat">
                        {virtualDeviceLabel(device.virtualDeviceStatus)}
                      </Chip>
                      <span className="font-mono text-tiny text-default-500">
                        {device.virtualDeviceName || device.virtualDeviceMode || "-"}
                      </span>
                    </div>
                    {device.virtualDeviceError && (
                      <span className="line-clamp-2 text-tiny text-danger">{device.virtualDeviceError}</span>
                    )}
                    {device.virtualDeviceUpdatedAt && (
                      <span className="text-tiny text-default-400">上报 {formatDateTime(device.virtualDeviceUpdatedAt)}</span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex max-w-72 flex-col gap-0.5 break-all text-small">
                    <span>{peerNatProfile(device).label}</span>
                    <PeerNatBehaviorLine device={device} />
                    <span className="text-tiny text-default-400">{device.lastEndpoint || "-"}</span>
                  </div>
                </TableCell>
                <TableCell>{formatDateTime(device.lastSeenAt)}</TableCell>
                <TableCell>
                  <Switch
                    aria-label={`启用 ${device.clientName} 私有组网`}
                    isSelected={device.enabled}
                    isDisabled={updatingDeviceIds.has(device.clientId)}
                    onValueChange={(enabled) => void updateDevice(device, enabled)}
                  />
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
        </div>
      </section>
      </>
      )}

      {peerView === "acl" && (
      <section className="grid gap-3">
        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div>
              <h3 className="text-base font-semibold">显式 ACL</h3>
              <p className="text-small text-default-500">同一用户默认放行；跨用户互访需要 admin 创建显式 ACL。</p>
            </div>
            <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)_auto]">
              <Select label="源客户端" selectedKeys={sourceClientId ? [sourceClientId] : []} onSelectionChange={(keys) => setSourceClientId(String(Array.from(keys)[0] ?? ""))}>
                {devices.map((device) => (<SelectItem key={String(device.clientId)}>{device.clientName}</SelectItem>))}
              </Select>
              <Select label="目标客户端" selectedKeys={targetClientId ? [targetClientId] : []} onSelectionChange={(keys) => setTargetClientId(String(Array.from(keys)[0] ?? ""))}>
                {devices.map((device) => (<SelectItem key={String(device.clientId)}>{device.clientName}</SelectItem>))}
              </Select>
              <Select label="方向" selectedKeys={[aclDirection]} onSelectionChange={(keys) => setAclDirection(String(Array.from(keys)[0] ?? "OUTBOUND") as typeof aclDirection)}>
                <SelectItem key="OUTBOUND">允许我连他人</SelectItem>
                <SelectItem key="INBOUND">允许他人连我</SelectItem>
                <SelectItem key="BOTH">双向允许</SelectItem>
              </Select>
              <Button className="md:self-end" color="primary" onPress={() => void createAcl()}>放行</Button>
            </div>

            {/* mobile: ACL 卡片 */}
            <div className="lg:hidden">
              <MobileListCardList
                items={acls}
                isLoading={devicesLoading}
                emptyContent="暂无显式 ACL"
                renderCard={(raw) => {
                  const acl = raw as PeerMeshAcl;
                  return (
                    <MobileListCard
                      key={acl.id}
                      title={
                        <span className="break-all">
                          {acl.sourceClientName} → {acl.targetClientName}
                        </span>
                      }
                      badges={
                        <Chip size="sm" color={acl.allowed ? "success" : "danger"} variant="flat">
                          {acl.allowed ? "允许" : "拒绝"}
                        </Chip>
                      }
                      actions={
                        <Button size="sm" color="danger" variant="flat" onPress={() => void deleteAcl(acl)}>
                          删除
                        </Button>
                      }
                    />
                  );
                }}
              />
            </div>

            {/* desktop: ACL 表格 */}
            <div className="hidden min-w-0 overflow-x-auto lg:block">
            <Table aria-label="Peer ACL" removeWrapper>
              <TableHeader>
                <TableColumn>源</TableColumn>
                <TableColumn>目标</TableColumn>
                <TableColumn>方向</TableColumn>
                <TableColumn>状态</TableColumn>
                <TableColumn>操作</TableColumn>
              </TableHeader>
              <TableBody items={acls} isLoading={devicesLoading} emptyContent="暂无显式 ACL">
                {(acl) => (
                  <TableRow key={acl.id}>
                    <TableCell>{acl.sourceClientName}</TableCell>
                    <TableCell>{acl.targetClientName}</TableCell>
                    <TableCell>
                      <Chip
                        aria-label={aclDirectionLabel(acl.direction)}
                        size="sm"
                        variant="flat"
                        color={acl.direction === "BOTH" ? "success" : acl.direction === "INBOUND" ? "warning" : "primary"}
                      >
                        {aclDirectionLabel(acl.direction)}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <Chip size="sm" color={acl.allowed ? "success" : "danger"} variant="flat">
                        {acl.allowed ? "允许" : "拒绝"}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <Button size="sm" color="danger" variant="flat" onPress={() => void deleteAcl(acl)}>
                        删除
                      </Button>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
            </div>
          </CardBody>
        </Card>
      </section>
      )}

      {peerView === "sessions" && (
      <section className="grid gap-3">
        <PeerPathStatsCard stats={pathStats} />
        {!sessionsLoading && activeSessions.length === 0 ? (
          <Card shadow="none" className="rounded-md border border-default-200">
            <CardBody className="p-3">
              <EmptyState icon="peer" title="暂无活跃 peer 会话" description="客户端之间建立直连或 relay 链路后，活跃会话将在这里显示。" actionLabel="配置私有组网" onAction={() => { window.location.hash = "/help/peer-mesh"; }} />
            </CardBody>
          </Card>
        ) : (
          <>
            {/* 桌面端主从分栏 */}
            <div className="hidden lg:flex lg:gap-3 lg:min-h-[320px]">
              <Card shadow="none" className="w-[38%] min-w-0 shrink-0 rounded-md border border-default-200">
                <CardBody className="gap-2 p-3">
                  <div className="flex items-center justify-between"><h3 className="text-small font-semibold">活跃会话</h3><span className="text-tiny text-default-500">有效 {activeSessions.length} / 未关闭 {sessionTotal}</span></div>
                  <div className="flex-1 space-y-1 overflow-y-auto">
                    {activeSessions.map((s) => {
                      const pathType = effectivePeerSessionPathType(s);
                      return (
                        <button key={s.id} type="button" onClick={() => setSelectedSession(s)}
                          className={`flex w-full items-center gap-3 rounded-md px-3 py-2.5 text-left transition-colors ${selectedSession?.id === s.id ? "bg-primary-50 dark:bg-primary-400/10" : "hover:bg-default-100"}`}>
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-small font-medium">{s.sourceClientName} → {s.targetClientName}</div>
                            <div className="mt-0.5 flex items-center gap-2 text-tiny text-default-500">
                              <Chip size="sm" variant="flat" color={pathType === "DIRECT" ? "success" : pathType === "RELAY" ? "warning" : "default"}>{pathType}</Chip>
                              <span>{s.rttMillis != null ? `${s.rttMillis} ms` : "-"}</span>
                              <span>·</span>
                              <span>{s.lastKeepaliveAt ? formatDateTime(s.lastKeepaliveAt) : "-"}</span>
                            </div>
                          </div>
                          <svg className="h-4 w-4 shrink-0 text-default-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
                        </button>
                      );
                    })}
                  </div>
                  {sessionTotalPages > 1 && <div className="flex justify-end pt-1"><Pagination showControls size="sm" page={sessionPage + 1} total={sessionTotalPages} onChange={(p) => setSessionPage(Math.max(0, p - 1))} /></div>}
                </CardBody>
              </Card>
              <Card shadow="none" className="flex-1 min-w-0 rounded-md border border-default-200">
                <CardBody className="gap-4 p-4">
                  {selectedSession ? <SessionDetail session={selectedSession} onDisconnect={(s) => void closeSession(s)} /> : <div className="flex h-full items-center justify-center text-small text-default-400">← 选择左侧会话查看详情</div>}
                </CardBody>
              </Card>
            </div>

            {/* 移动端全宽列表 + 详情 */}
            <div className="lg:hidden">
              {!mobileDetailOpen ? (
                <Card shadow="none" className="rounded-md border border-default-200">
                  <CardBody className="gap-2 p-3">
                    <h3 className="text-small font-semibold">活跃会话 · 有效 {activeSessions.length} / 未关闭 {sessionTotal}</h3>
                    <MobileListCardList items={activeSessions} isLoading={sessionsLoading} emptyContent="暂无活跃 peer session" renderCard={(raw) => {
                      const s = raw as PeerMeshSession;
                      const pathType = effectivePeerSessionPathType(s);
                      return (
                        <MobileListCard key={s.id}
                          title={<span className="break-all">{s.sourceClientName} → {s.targetClientName}</span>}
                          badges={<Chip size="sm" variant="flat" color={pathType === "DIRECT" ? "success" : pathType === "RELAY" ? "warning" : "default"}>{pathType}</Chip>}
                          fields={[
                            { label: "RTT", value: s.rttMillis == null ? "-" : `${s.rttMillis} ms` },
                            { label: "Keepalive", value: s.lastKeepaliveAt ? formatDateTime(s.lastKeepaliveAt) : "-" },
                          ]}
                          actions={<Button size="sm" variant="flat" onPress={() => { setSelectedSession(s); setMobileDetailOpen(true); }}>详情</Button>}
                        />
                      );
                    }} />
                    {sessionTotalPages > 1 && <div className="flex justify-end pt-1"><Pagination showControls size="sm" page={sessionPage + 1} total={sessionTotalPages} onChange={(p) => setSessionPage(Math.max(0, p - 1))} /></div>}
                  </CardBody>
                </Card>
              ) : (
                <Card shadow="none" className="rounded-md border border-default-200">
                  <CardBody className="gap-3 p-3">
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="light" isIconOnly onPress={() => setMobileDetailOpen(false)}>
                        <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" /></svg>
                      </Button>
                      <span className="text-small font-semibold">会话详情</span>
                    </div>
                    {selectedSession && <SessionDetail session={selectedSession} onDisconnect={(s) => void closeSession(s)} />}
                  </CardBody>
                </Card>
              )}
            </div>
          </>
        )}
      </section>
      )}

      <ConfirmModal
        danger
        isOpen={confirmState != null}
        title={confirmState?.title ?? ""}
        description={confirmState?.description}
        confirmLabel={confirmState?.confirmLabel ?? "确认"}
        onClose={() => setConfirmState(null)}
        onConfirm={async () => {
          await confirmState?.action();
        }}
      />
    </div>
  );
}


/* ──────── SessionDetail 会话详情面板 ──────── */

function SessionDetail({ session, onDisconnect }: { session: PeerMeshSession; onDisconnect: (session: PeerMeshSession) => void }) {
  const pathType = effectivePeerSessionPathType(session);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold">{session.sourceClientName} → {session.targetClientName}</h3>
        <div className="flex items-center gap-2">
          <Chip size="sm" variant="flat" color={pathType === "DIRECT" ? "success" : pathType === "RELAY" ? "warning" : "default"}>{pathType}</Chip>
          <Chip size="sm" variant="flat" color={session.status === "ACTIVE" ? "success" : session.status === "CLOSED" ? "danger" : "default"}>{session.status}</Chip>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3 rounded-md border border-default-200 bg-default-50 p-3 text-small">
        <div><span className="text-default-500">RTT</span><div className="font-semibold">{session.rttMillis != null ? `${session.rttMillis} ms` : "-"}</div></div>
        <div><span className="text-default-500">创建</span><div>{formatDateTime(session.startedAt)}</div></div>
        <div><span className="text-default-500">最后流量</span><div>{session.lastTrafficAt ? formatDateTime(session.lastTrafficAt) : "-"}</div></div>
        <div><span className="text-default-500">最后保活</span><div>{session.lastKeepaliveAt ? formatDateTime(session.lastKeepaliveAt) : "-"}</div></div>
        <div><span className="text-default-500">过期</span><div>{formatDateTime(session.expiresAt)}</div></div>
        <div><span className="text-default-500">更新</span><div>{formatDateTime(session.updatedAt)}</div></div>
      </div>
      <div>
        <h4 className="mb-2 text-small font-semibold">流量统计</h4>
        <div className="grid grid-cols-2 gap-3 rounded-md border border-default-200 bg-default-50 p-3 text-small">
          <div><span className="text-default-500">Direct</span><div className="font-semibold">{formatBytes(session.directBytes)}</div></div>
          <div><span className="text-default-500">Relay</span><div className="font-semibold">{formatBytes(session.relayBytes)}</div></div>
        </div>
      </div>
      <div>
        <h4 className="mb-2 text-small font-semibold">端点</h4>
        <div className="space-y-2 rounded-md border border-default-200 bg-default-50 p-3 text-small">
          <div className="break-all"><span className="text-default-500">Local: </span><span className="font-mono">{session.localEndpoint || "-"}</span></div>
          <div className="break-all"><span className="text-default-500">Remote: </span><span className="font-mono">{session.remoteEndpoint || "-"}</span></div>
        </div>
      </div>
      <div className="flex gap-2 pt-1">
        <Button size="sm" color="danger" variant="flat" isDisabled={session.status === "CLOSED"} onPress={() => onDisconnect(session)}>断开会话</Button>
      </div>
    </div>
  );
}


/* ──────── PeerPathStatsCard 打洞/路径统计 ──────── */

function PeerPathStatsCard({ stats }: { stats: PeerMeshPathStats | null }) {
  if (!stats) {
    // stats 暂不可用时静默隐藏。
    return null;
  }
  const ratioPercent = stats.activeDirectRatio == null ? null : Math.round(stats.activeDirectRatio * 100);
  const behaviorRatioPercent = stats.natBehaviorSuccessRatio == null
    ? null
    : Math.round(stats.natBehaviorSuccessRatio * 100);
  const pathTypeRows = [...stats.pathTypes].sort((a, b) => b.sessions - a.sessions);
  const addressFamilyRows = ["IPv4", "IPv6", "UNKNOWN"].map((addressFamily) => {
    const rows = (stats.addressFamilies ?? []).filter((item) => item.addressFamily === addressFamily);
    return {
      addressFamily,
      sessions: rows.reduce((sum, item) => sum + item.sessions, 0),
      activeSessions: rows
        .filter((item) => item.status === "ACTIVE")
        .reduce((sum, item) => sum + item.sessions, 0),
      directSessions: rows
        .filter((item) => item.status === "ACTIVE" && item.pathType === "DIRECT")
        .reduce((sum, item) => sum + item.sessions, 0),
      relaySessions: rows
        .filter((item) => item.status === "ACTIVE" && item.pathType === "RELAY")
        .reduce((sum, item) => sum + item.sessions, 0),
    };
  }).filter((item) => item.sessions > 0);
  const natTypeRows = [...stats.natTypes].sort((a, b) => b.devices - a.devices);
  const mappingRows = [...(stats.natMappingBehaviors ?? [])].sort((a, b) => b.devices - a.devices);
  const filteringRows = [...(stats.natFilteringBehaviors ?? [])].sort((a, b) => b.devices - a.devices);
  const discoveryRows = [...(stats.natBehaviorDiscoveries ?? [])].sort((a, b) => b.devices - a.devices);
  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-3 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-small font-semibold">打洞 / 路径统计</h3>
          <span className="text-tiny text-default-500">
            累计会话 {stats.totalSessions} · 确立过路径 {stats.reportedSessions} · 当前活跃 {stats.activeSessions}
          </span>
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex flex-wrap items-center justify-between gap-2 text-tiny text-default-500">
            <span>活跃会话直连占比（打洞成功率代理指标）</span>
            <span className="text-small font-semibold text-foreground">
              {ratioPercent == null ? "暂无活跃会话" : `${ratioPercent}%`}
            </span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-default-200">
            <div
              className="h-full rounded-full bg-success transition-[width] duration-500"
              style={{ width: `${ratioPercent ?? 0}%` }}
            />
          </div>
          <div className="flex justify-between text-tiny text-default-400">
            <span>Direct {stats.activeDirectSessions}</span>
            <span>Relay {stats.activeRelaySessions}</span>
          </div>
        </div>

        {addressFamilyRows.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 border-t border-default-200 pt-3">
            <span className="text-tiny text-default-500">实际路径地址族：</span>
            {addressFamilyRows.map((item) => (
              <Chip
                key={item.addressFamily}
                size="sm"
                variant="flat"
                color={item.addressFamily === "IPv6" ? "primary" : item.addressFamily === "IPv4" ? "success" : "default"}
              >
                {item.addressFamily} · 活跃 {item.activeSessions} · Direct {item.directSessions} / Relay {item.relaySessions}
              </Chip>
            ))}
          </div>
        )}

        {(stats.natBehaviorDevices ?? 0) > 0 && (
          <div className="flex flex-col gap-2 border-t border-default-200 pt-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-tiny text-default-500">
              <span>RFC 5780 双轴完整分类率</span>
              <span className="text-small font-semibold text-foreground">
                {behaviorRatioPercent == null ? "-" : `${behaviorRatioPercent}%`}
                <span className="ml-1 font-normal text-default-500">
                  ({stats.natBehaviorClassifiedDevices}/{stats.natBehaviorDevices})
                </span>
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-default-200">
              <div
                className="h-full rounded-full bg-primary transition-[width] duration-500"
                style={{ width: `${behaviorRatioPercent ?? 0}%` }}
              />
            </div>
            <NatBehaviorDistribution
              label="映射"
              items={mappingRows.map((item) => ({ ...item, label: natMappingBehaviorLabel(item.behavior) }))}
            />
            <NatBehaviorDistribution
              label="过滤"
              items={filteringRows.map((item) => ({ ...item, label: natFilteringBehaviorLabel(item.behavior) }))}
            />
            <NatBehaviorDistribution
              label="方式"
              items={discoveryRows.map((item) => ({ ...item, label: natBehaviorDiscoveryLabel(item.behavior) }))}
            />
          </div>
        )}

        {pathTypeRows.length > 0 && (
          <div className="min-w-0 overflow-x-auto">
            <Table aria-label="路径类型统计" removeWrapper>
              <TableHeader>
                <TableColumn>路径</TableColumn>
                <TableColumn>状态</TableColumn>
                <TableColumn>会话数</TableColumn>
                <TableColumn>确立过路径</TableColumn>
                <TableColumn>平均 RTT</TableColumn>
                <TableColumn>Direct 流量</TableColumn>
                <TableColumn>Relay 流量</TableColumn>
              </TableHeader>
              <TableBody>
                {pathTypeRows.map((row) => (
                  <TableRow key={`${row.pathType}-${row.status}`}>
                    <TableCell>
                      <Chip size="sm" variant="flat" color={row.pathType === "DIRECT" ? "success" : row.pathType === "RELAY" ? "warning" : "default"}>
                        {row.pathType}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <Chip size="sm" variant="flat" color={row.status === "ACTIVE" ? "success" : row.status === "CLOSED" ? "default" : "warning"}>
                        {row.status}
                      </Chip>
                    </TableCell>
                    <TableCell>{row.sessions}</TableCell>
                    <TableCell>{row.reportedSessions}</TableCell>
                    <TableCell>{row.avgRttMillis == null ? "-" : `${Math.round(row.avgRttMillis)} ms`}</TableCell>
                    <TableCell>{formatBytes(row.directBytes)}</TableCell>
                    <TableCell>{formatBytes(row.relayBytes)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {natTypeRows.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-tiny text-default-500">兼容 NAT 标签：</span>
            {natTypeRows.map((item) => (
              <Chip key={item.natType} size="sm" variant="flat" color={natTypeColor(item.natType)}>
                {natTypeLabel(item.natType)} · {item.devices}
              </Chip>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

function PeerNatInsight({
  devices,
  devicesTotal,
  filter,
  keyword,
  loading,
  onFilterChange,
  onKeywordChange,
  stats,
}: {
  devices: PeerMeshDevice[];
  devicesTotal: number;
  filter: PeerNatFilterKey;
  keyword: string;
  loading: boolean;
  onFilterChange: (value: PeerNatFilterKey) => void;
  onKeywordChange: (value: string) => void;
  stats: ReturnType<typeof buildPeerNatStats>;
}) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex min-w-0 flex-col gap-3">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-5">
          <PeerNatMetric label="行为已上报" value={`${stats.reported} / ${devicesTotal}`} tone={stats.reported > 0 ? "success" : "default"} />
          <PeerNatMetric label="在线设备" value={String(stats.online)} tone={stats.online > 0 ? "success" : "default"} />
          <PeerNatMetric label="直连友好" value={String(stats.directFriendly)} tone={stats.directFriendly > 0 ? "success" : "default"} />
          <PeerNatMetric label="Relay 优先" value={String(stats.relayPreferred)} tone={stats.relayPreferred > 0 ? "danger" : "default"} />
          <PeerNatMetric label="新鲜上报" value={String(stats.fresh)} tone={stats.fresh > 0 ? "success" : "default"} />
        </div>

        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <h3 className="text-base font-semibold">客户端 NAT 探测</h3>
                <p className="text-small text-default-500">
                  原生客户端使用业务 UDP socket 执行 RFC 5780，分别上报映射和过滤行为；兼容 NAT 标签仅用于旧版本识别。
                </p>
              </div>
              <Chip size="sm" variant="flat">
                {stats.distribution.length} 类 NAT
              </Chip>
            </div>

            <div className="grid gap-3 xl:grid-cols-[320px_minmax(0,1fr)]">
              <div className="space-y-2">
                {stats.distribution.length === 0 ? (
                  <div className="rounded-md border border-dashed border-default-200 p-3 text-small text-default-500">
                    暂无 NAT 上报。
                  </div>
                ) : (
                  stats.distribution.map((item) => (
                    <PeerNatDistributionRow key={item.profile.key} item={item} total={Math.max(1, devicesTotal)} />
                  ))
                )}
              </div>

              <div className="min-w-0 space-y-2">
                <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_220px] lg:hidden">
                  <Input
                    aria-label="搜索客户端 NAT 结果"
                    placeholder="搜索客户端 / IP / Endpoint"
                    value={keyword}
                    onValueChange={onKeywordChange}
                    variant="flat"
                  />
                  <Select
                    aria-label="筛选客户端 NAT 结果"
                    selectedKeys={[filter]}
                    onSelectionChange={(keys) => onFilterChange(String(Array.from(keys)[0] ?? "all") as PeerNatFilterKey)}
                    variant="flat"
                  >
                    {peerNatFilterOptions.map((option) => (
                      <SelectItem key={option.key}>{option.label}</SelectItem>
                    ))}
                  </Select>
                </div>

                <div className="lg:hidden">
                  <MobileListCardList
                    items={devices}
                    isLoading={loading}
                    emptyContent="暂无客户端 NAT 检测结果"
                    renderCard={(raw) => {
                      const device = raw as PeerMeshDevice;
                      const profile = peerNatProfile(device);
                      return (
                        <MobileListCard
                          key={device.clientId}
                          title={device.clientName}
                          subtitle={device.ownerUsername || "-"}
                          badges={
                            <>
                              <Chip size="sm" color={device.online ? "success" : "default"} variant="flat">
                                {device.online ? "在线" : "离线"}
                              </Chip>
                              <Chip size="sm" color={profile.tone} variant="flat">
                                {profile.label}
                              </Chip>
                              <Chip size="sm" color={peerNatFreshnessColor(device)} variant="flat">
                                {peerNatFreshnessLabel(device)}
                              </Chip>
                            </>
                          }
                          fields={[
                            { label: "虚拟 IP", value: <span className="font-mono">{device.virtualIp || "-"}</span> },
                            { label: "Endpoint", value: <span className="break-all font-mono">{device.lastEndpoint || "-"}</span> },
                            { label: "映射行为", value: natMappingBehaviorLabel(device.natMappingBehavior) },
                            { label: "过滤行为", value: natFilteringBehaviorLabel(device.natFilteringBehavior) },
                            { label: "兼容标签", value: natTypeLabel(device.natType) },
                            { label: "探测方式", value: natBehaviorDiscoveryLabel(device.natBehaviorDiscovery) },
                            { label: "路径建议", value: profile.reachabilityLabel },
                            { label: "最后上报", value: formatDateTime(peerNatLastReportAt(device)) },
                          ]}
                          extra={<p className="text-tiny leading-5 text-default-500">{profile.recommendation}</p>}
                        />
                      );
                    }}
                  />
                </div>

                <div className="hidden min-w-0 lg:block">
                  <Table
                    aria-label="客户端 NAT 检测结果"
                    classNames={{ table: "w-full table-fixed", th: "px-2", td: "px-2 align-middle" }}
                    removeWrapper
                  >
                    <TableHeader>
                      <TableColumn className="w-[22%]">
                        <PeerNatKeywordHeader keyword={keyword} onKeywordChange={onKeywordChange} />
                      </TableColumn>
                      <TableColumn className="w-[24%]">
                        <PeerNatTypeFilterHeader filter={filter} onFilterChange={onFilterChange} />
                      </TableColumn>
                      <TableColumn className="w-[18%]">Endpoint</TableColumn>
                      <TableColumn className="w-[22%]">建议</TableColumn>
                      <TableColumn className="w-[14%]">上报</TableColumn>
                    </TableHeader>
                    <TableBody items={devices} isLoading={loading} emptyContent="暂无客户端 NAT 检测结果">
                      {(device) => {
                        const profile = peerNatProfile(device);
                        return (
                          <TableRow key={device.clientId}>
                            <TableCell>
                              <div className="flex min-w-0 flex-col">
                                <span className="truncate font-semibold" title={device.clientName}>{device.clientName}</span>
                                <span className="truncate font-mono text-tiny text-default-400" title={device.virtualIp || "-"}>{device.virtualIp || "-"}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex min-w-0 flex-col gap-1">
                                <Chip className="w-fit" size="sm" color={profile.tone} variant="flat">
                                  {profile.label}
                                </Chip>
                                <PeerNatBehaviorLine device={device} />
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className="block truncate font-mono text-tiny" title={device.lastEndpoint || "-"}>{device.lastEndpoint || "-"}</span>
                            </TableCell>
                            <TableCell>
                              <div className="flex min-w-0 flex-col text-small">
                                <span className="truncate font-semibold" title={profile.reachabilityLabel}>{profile.reachabilityLabel}</span>
                                <span className="truncate text-tiny text-default-500" title={profile.recommendation}>{profile.recommendation}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex flex-col text-small">
                                <span className="truncate" title={formatDateTime(peerNatLastReportAt(device))}>{formatDateTime(peerNatLastReportAt(device))}</span>
                                <span className="truncate text-tiny text-default-400" title={peerNatAgeLabel(peerNatLastReportAt(device))}>{peerNatAgeLabel(peerNatLastReportAt(device))}</span>
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      }}
                    </TableBody>
                  </Table>
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      <div className="flex min-w-0 flex-col gap-3">
        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-base font-semibold">NAT 行为分类</h3>
                <p className="text-small text-default-500">映射与过滤是相互独立的两个轴，路径选择以实际 ICE 连通性为最终依据。</p>
              </div>
              <Button
                as="a"
                href="#/help/peer-mesh"
                size="sm"
                variant="flat"
              >
                查看详细文档
              </Button>
            </div>
            <div className="grid gap-4 lg:grid-cols-2">
              {NAT_BEHAVIOR_AXES.map((axis) => (
                <div key={axis.title} className="min-w-0">
                  <div className="mb-2">
                    <div className="text-small font-semibold">{axis.title}</div>
                    <div className="text-tiny text-default-500">{axis.subtitle}</div>
                  </div>
                  <div className="divide-y divide-default-200 border-y border-default-200">
                    {axis.items.map((item) => (
                      <div key={item.code} className="grid grid-cols-[56px_minmax(0,1fr)] gap-2 py-2 text-small">
                        <span className="font-mono font-semibold text-primary">{item.code}</span>
                        <span className="min-w-0">
                          <span className="font-medium">{item.label}</span>
                          <span className="ml-1 text-default-500">{item.detail}</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>
    </section>
  );
}

function PeerNatBehaviorLine({ device }: { device: PeerMeshDevice }) {
  const hasBehavior = Boolean(device.natMappingBehavior || device.natFilteringBehavior);
  if (!hasBehavior && !device.natBehaviorDiscovery) {
    return null;
  }
  const discovery = natBehaviorDiscoveryLabel(device.natBehaviorDiscovery);
  const detail = hasBehavior
    ? `映射 ${natMappingBehaviorLabel(device.natMappingBehavior)} · 过滤 ${natFilteringBehaviorLabel(device.natFilteringBehavior)}`
    : `${discovery} · 行为未细分`;
  return (
    <span className="truncate text-tiny text-default-500" title={hasBehavior ? `${discovery} · ${detail}` : detail}>
      {detail}
    </span>
  );
}

function NatBehaviorDistribution({
  label,
  items,
}: {
  label: string;
  items: Array<{ behavior: string; devices: number; label: string }>;
}) {
  if (items.length === 0) {
    return null;
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="w-8 shrink-0 text-tiny text-default-500">{label}</span>
      {items.map((item) => (
        <Chip
          key={`${label}-${item.behavior}`}
          size="sm"
          variant="flat"
          color={["UNKNOWN", "UNSUPPORTED"].includes(item.behavior.toUpperCase()) ? "warning" : "default"}
        >
          {item.label} · {item.devices}
        </Chip>
      ))}
    </div>
  );
}

function PeerNatKeywordHeader({
  keyword,
  onKeywordChange,
}: {
  keyword: string;
  onKeywordChange: (value: string) => void;
}) {
  const active = Boolean(keyword.trim());
  const label = active ? `客户端: ${keyword.trim()}` : "客户端";

  return (
    <div className="flex min-w-0 items-center gap-1">
      <span className="truncate" title={label}>
        {label}
      </span>
      <Popover placement="bottom-start" shouldBlockScroll={false}>
        <PopoverTrigger>
          <Button
            isIconOnly
            aria-label="搜索客户端 NAT 结果"
            className="h-7 min-w-7 text-default-500"
            color={active ? "primary" : "default"}
            size="sm"
            title="搜索客户端 NAT 结果"
            variant={active ? "flat" : "light"}
          >
            <PeerNatFilterIcon />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-72 p-3">
          <div className="flex w-full flex-col gap-3">
            <div className="text-small font-semibold">搜索客户端</div>
            <Input
              autoFocus
              label="关键词"
              placeholder="客户端 / IP / Endpoint"
              size="sm"
              value={keyword}
              onValueChange={onKeywordChange}
            />
            <Button size="sm" variant="flat" onPress={() => onKeywordChange("")}>
              清空搜索
            </Button>
          </div>
        </PopoverContent>
      </Popover>
      {active ? <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden /> : null}
    </div>
  );
}

function PeerNatTypeFilterHeader({
  filter,
  onFilterChange,
}: {
  filter: PeerNatFilterKey;
  onFilterChange: (value: PeerNatFilterKey) => void;
}) {
  const active = filter !== "all";
  const activeOption = peerNatFilterOptions.find((option) => option.key === filter) ?? peerNatFilterOptions[0];
  const label = active ? `状态: ${activeOption.label}` : "NAT 状态";

  return (
    <div className="flex min-w-0 items-center gap-1">
      <span className="truncate" title={label}>
        {label}
      </span>
      <Popover placement="bottom-start" shouldBlockScroll={false}>
        <PopoverTrigger>
          <Button
            isIconOnly
            aria-label="筛选 NAT 状态"
            className="h-7 min-w-7 text-default-500"
            color={active ? "primary" : "default"}
            size="sm"
            title="筛选 NAT 状态"
            variant={active ? "flat" : "light"}
          >
            <PeerNatFilterIcon />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-56 p-3">
          <div className="flex w-full flex-col gap-3">
            <div className="text-small font-semibold">NAT 状态筛选</div>
            <select
              className="h-9 w-full rounded-medium border border-default-200 bg-default-50 px-2 text-small outline-none transition-colors hover:border-default-300 focus:border-primary"
              value={filter}
              onChange={(event) => onFilterChange(event.target.value as PeerNatFilterKey)}
            >
              {peerNatFilterOptions.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </PopoverContent>
      </Popover>
      {active ? <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden /> : null}
    </div>
  );
}

function PeerNatFilterIcon() {
  return (
    <svg className="h-4 w-4" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" viewBox="0 0 24 24">
      <path d="M4 5h16l-6 7v5l-4 2v-7L4 5z" />
    </svg>
  );
}

function buildPeerNatStats(devices: PeerMeshDevice[]) {
  const distributionMap = new Map<string, { profile: ReturnType<typeof natClassificationProfile>; count: number }>();
  let directFriendly = 0;
  let relayPreferred = 0;
  let reported = 0;
  let fresh = 0;

  for (const device of devices) {
    const profile = peerNatProfile(device);
    const current = distributionMap.get(profile.key);
    distributionMap.set(profile.key, { profile, count: (current?.count ?? 0) + 1 });
    if (device.natType || device.natMappingBehavior || device.natFilteringBehavior || device.natBehaviorDiscovery) {
      reported += 1;
    }
    if (profile.reachability === "direct" || profile.reachability === "likely") {
      directFriendly += 1;
    }
    if (profile.reachability === "relay") {
      relayPreferred += 1;
    }
    if (isPeerNatFresh(device)) {
      fresh += 1;
    }
  }

  const distribution = Array.from(distributionMap.values())
    .sort(
      (left, right) =>
        right.count - left.count ||
        natProfileReachabilityWeight(right.profile) - natProfileReachabilityWeight(left.profile),
    );

  return {
    online: devices.filter((device) => device.online).length,
    reported,
    directFriendly,
    relayPreferred,
    fresh,
    distribution,
  };
}

function PeerNatDistributionRow({
  item,
  total,
}: {
  item: { profile: ReturnType<typeof natClassificationProfile>; count: number };
  total: number;
}) {
  const percent = Math.round((item.count / total) * 100);
  return (
    <div className="grid gap-1">
      <div className="flex items-center justify-between gap-2 text-small">
        <span className="flex min-w-0 items-center gap-2">
          <Chip className="shrink-0" size="sm" color={item.profile.tone} variant="flat">
            {item.profile.shortLabel}
          </Chip>
          <span className="truncate text-default-500">{item.profile.reachabilityLabel}</span>
        </span>
        <span className="font-mono text-default-500">
          {item.count} · {percent}%
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded bg-default-100">
        <div className={`h-full rounded ${peerNatBarColor(item.profile.tone)}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

function PeerNatMetric({
  label,
  tone = "default",
  value,
}: {
  label: string;
  tone?: "default" | "success" | "danger";
  value: string;
}) {
  const color = tone === "success" ? "text-success" : tone === "danger" ? "text-danger" : "text-foreground";
  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-1 p-3">
        <span className="text-small text-default-500">{label}</span>
        <span className={`text-xl font-semibold ${color}`}>{value}</span>
      </CardBody>
    </Card>
  );
}

function matchPeerNatFilter(device: PeerMeshDevice, filter: PeerNatFilterKey) {
  const profile = peerNatProfile(device);
  switch (filter) {
    case "online":
      return device.online;
    case "direct":
      return profile.reachability === "direct" || profile.reachability === "likely";
    case "relay":
      return profile.reachability === "relay";
    case "unknown":
      return !device.natType && !device.natMappingBehavior && !device.natFilteringBehavior;
    default:
      return true;
  }
}

function comparePeerNatDevice(left: PeerMeshDevice, right: PeerMeshDevice) {
  return (
    Number(right.online) - Number(left.online) ||
    natProfileReachabilityWeight(peerNatProfile(right)) - natProfileReachabilityWeight(peerNatProfile(left)) ||
    Date.parse(peerNatLastReportAt(right) || "") - Date.parse(peerNatLastReportAt(left) || "")
  );
}

function peerNatProfile(device: PeerMeshDevice) {
  return natClassificationProfile(
    device.natType,
    device.natMappingBehavior,
    device.natFilteringBehavior,
  );
}

function natProfileReachabilityWeight(profile: ReturnType<typeof natClassificationProfile>) {
  switch (profile.reachability) {
    case "direct":
      return 4;
    case "likely":
      return 3;
    case "conditional":
      return 2;
    case "relay":
      return 1;
    default:
      return 0;
  }
}

function peerNatLastReportAt(device: PeerMeshDevice) {
  return device.virtualDeviceUpdatedAt || device.lastSeenAt || device.updatedAt || null;
}

function isPeerNatFresh(device: PeerMeshDevice) {
  const value = peerNatLastReportAt(device);
  if (!value) {
    return false;
  }
  const time = Date.parse(value);
  return Number.isFinite(time) && Date.now() - time <= 120_000;
}

function peerNatFreshnessLabel(device: PeerMeshDevice) {
  if (!peerNatLastReportAt(device)) {
    return "未上报";
  }
  return isPeerNatFresh(device) ? "新鲜" : "历史";
}

function peerNatFreshnessColor(device: PeerMeshDevice): "default" | "success" | "warning" {
  if (!peerNatLastReportAt(device)) {
    return "default";
  }
  return isPeerNatFresh(device) ? "success" : "warning";
}

function peerNatAgeLabel(value: string | null | undefined) {
  if (!value) {
    return "-";
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    return value;
  }
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 60) {
    return `${seconds}s 前`;
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m 前`;
  }
  if (seconds < 86400) {
    return `${Math.floor(seconds / 3600)}h 前`;
  }
  return `${Math.floor(seconds / 86400)}d 前`;
}

function isPeerSessionEffectivelyActive(session: PeerMeshSession, deviceById: Map<number, PeerMeshDevice>, now: number) {
  return peerSessionEffectiveStatus(session, deviceById, now) === "ACTIVE";
}

function peerSessionEffectiveStatus(session: PeerMeshSession, deviceById: Map<number, PeerMeshDevice>, now: number) {
  if (session.status === "CLOSED") {
    return "CLOSED";
  }
  const sourceOnline = Boolean(deviceById.get(session.sourceClientId)?.online);
  const targetOnline = Boolean(deviceById.get(session.targetClientId)?.online);
  if (!sourceOnline || !targetOnline) {
    return "OFFLINE";
  }
  if (!isPeerSessionFresh(session, now)) {
    return "STALE";
  }
  return session.status || "NEGOTIATING";
}

function isPeerSessionFresh(session: PeerMeshSession, now: number) {
  const value = session.lastKeepaliveAt || session.updatedAt || session.startedAt;
  if (!value) {
    return false;
  }
  const time = Date.parse(value);
  return Number.isFinite(time) && now - time <= PEER_SESSION_FRESH_MILLIS;
}

function peerNatBarColor(tone: string) {
  switch (tone) {
    case "success":
      return "bg-success";
    case "primary":
      return "bg-primary";
    case "warning":
      return "bg-warning";
    case "danger":
      return "bg-danger";
    default:
      return "bg-default-400";
  }
}

function TopologyView({ devices, sessions }: { devices: PeerMeshDevice[]; sessions: PeerMeshSession[] }) {
  const enabledDevices = devices.filter((device) => device.enabled);
  const topologyLinks = useMemo(() => buildTopologyLinks(devices, sessions), [devices, sessions]);
  const shownDevices = enabledDevices.length > 0 ? enabledDevices : devices;
  const hiddenDeviceCount = Math.max(0, shownDevices.length - 8);
  const hiddenLinkCount = Math.max(0, topologyLinks.length - 12);

  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-3 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-base font-semibold">组网拓扑</h3>
            <p className="text-small text-default-500">
              拓扑按客户端对聚合展示；下方活跃会话保留 ICE/direct/relay 明细。
            </p>
          </div>
          <div className="flex flex-wrap gap-1">
            <Chip size="sm" variant="flat">
              {topologyLinks.length} 条逻辑链路
            </Chip>
            <Chip size="sm" variant="flat">
              {sessions.length} 个会话
            </Chip>
          </div>
        </div>

        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          {shownDevices.slice(0, 8).map((device) => (
            <div key={device.clientId} className="rounded-md border border-default-200 bg-content1 p-3">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate font-semibold">{device.clientName}</div>
                  <div className="font-mono text-small text-default-500">{device.virtualIp || "-"}</div>
                </div>
                <Chip size="sm" color={device.online ? "success" : "default"} variant="flat">
                  {device.online ? "online" : "offline"}
                </Chip>
              </div>
              <div className="mt-2 flex flex-wrap gap-1 text-tiny text-default-500">
                <span>{device.ownerUsername || "-"}</span>
                <span>{peerNatProfile(device).shortLabel}</span>
              </div>
            </div>
          ))}
        </div>
        {hiddenDeviceCount > 0 && (
          <p className="text-tiny text-default-400">仅展示前 8 台设备，其余 {hiddenDeviceCount} 台见下方设备表。</p>
        )}

        <div className="grid gap-2 lg:grid-cols-2">
          {topologyLinks.length === 0 ? (
            <div className="rounded-md border border-dashed border-default-200 p-4 text-small text-default-500">
              暂无活跃 peer 链路。
            </div>
          ) : (
            topologyLinks.slice(0, 12).map((link) => {
              const session = link.representative;
              const pathType = effectivePeerSessionPathType(session);
              return (
                <div key={link.key} className="rounded-md border border-default-200 bg-default-50 p-3 dark:bg-default-100/10">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0 text-small font-semibold">
                      <span>{link.firstName}</span>
                      <span className="px-2 text-default-400">{"<->"}</span>
                      <span>{link.secondName}</span>
                    </div>
                    <Chip size="sm" color={pathColor(pathType, session.status)} variant="flat">
                      {pathType} · {session.status}
                    </Chip>
                  </div>
                  <div className="mt-2 grid gap-1 text-tiny text-default-500 sm:grid-cols-2">
                    <span>
                      {link.firstIp} {"<->"} {link.secondIp}
                    </span>
                    <span>会话 {link.sessions.length} 个，活跃 {link.activeSessions} 个</span>
                    <span>RTT {link.rttMillis == null ? "-" : `${link.rttMillis} ms`}</span>
                    <span>direct {link.directSessions} 个 / {formatBytes(link.directBytes)}</span>
                    <span>relay {link.relaySessions} 个 / {formatBytes(link.relayBytes)}</span>
                    <span>总流量 {formatBytes(link.totalBytes)}</span>
                    <span>最后 {formatDateTime(link.lastActivityAt)}</span>
                    <span>
                      在线 {link.firstOnline ? "是" : "否"} / {link.secondOnline ? "是" : "否"}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
        {hiddenLinkCount > 0 && (
          <p className="text-tiny text-default-400">仅展示前 12 条链路，其余 {hiddenLinkCount} 条见「活跃会话」页。</p>
        )}
      </CardBody>
    </Card>
  );
}

type TopologyLink = {
  key: string;
  firstName: string;
  secondName: string;
  firstIp: string;
  secondIp: string;
  firstOnline: boolean;
  secondOnline: boolean;
  representative: PeerMeshSession;
  sessions: PeerMeshSession[];
  activeSessions: number;
  directSessions: number;
  relaySessions: number;
  directBytes: number;
  relayBytes: number;
  totalBytes: number;
  rttMillis: number | null;
  lastActivityAt: string | null;
};

function buildTopologyLinks(devices: PeerMeshDevice[], sessions: PeerMeshSession[]): TopologyLink[] {
  const deviceById = new Map(devices.map((device) => [device.clientId, device]));
  const grouped = new Map<string, PeerMeshSession[]>();

  for (const session of sessions) {
    const [firstClientId, secondClientId] = orderedClientIds(session);
    const key = `${firstClientId}:${secondClientId}`;
    grouped.set(key, [...(grouped.get(key) ?? []), session]);
  }

  return Array.from(grouped.entries())
    .map(([key, items]) => {
      const representative = [...items].sort(compareRepresentativeSession)[0];
      const [firstClientId, secondClientId] = orderedClientIds(representative);
      const first = deviceById.get(firstClientId);
      const second = deviceById.get(secondClientId);
      const directBytes = items.reduce((total, item) => total + (item.directBytes || 0), 0);
      const relayBytes = items.reduce((total, item) => total + (item.relayBytes || 0), 0);
      const activeItems = items.filter((item) => item.status !== "CLOSED");
      const rttValues = activeItems
        .map((item) => item.rttMillis)
        .filter((value): value is number => value != null);

      return {
        key,
        firstName: first?.clientName || sessionClientName(representative, firstClientId),
        secondName: second?.clientName || sessionClientName(representative, secondClientId),
        firstIp: first?.virtualIp || "-",
        secondIp: second?.virtualIp || "-",
        firstOnline: Boolean(first?.online),
        secondOnline: Boolean(second?.online),
        representative,
        sessions: items,
        activeSessions: activeItems.length,
        directSessions: activeItems.filter((item) => effectivePeerSessionPathType(item) === "DIRECT").length,
        relaySessions: activeItems.filter((item) => effectivePeerSessionPathType(item) === "RELAY").length,
        directBytes,
        relayBytes,
        totalBytes: directBytes + relayBytes,
        rttMillis: rttValues.length > 0 ? Math.min(...rttValues) : null,
        lastActivityAt: latestSessionTime(items),
      };
    })
    .sort((left, right) => sessionTimeMillis(right.representative) - sessionTimeMillis(left.representative));
}

function orderedClientIds(session: PeerMeshSession): [number, number] {
  return session.sourceClientId <= session.targetClientId
    ? [session.sourceClientId, session.targetClientId]
    : [session.targetClientId, session.sourceClientId];
}

function sessionClientName(session: PeerMeshSession, clientId: number) {
  if (session.sourceClientId === clientId) {
    return session.sourceClientName;
  }
  if (session.targetClientId === clientId) {
    return session.targetClientName;
  }
  return String(clientId);
}

function latestSessionTime(sessions: PeerMeshSession[]) {
  return sessions
    .map((session) => session.lastTrafficAt || session.updatedAt || session.startedAt || null)
    .filter((value): value is string => Boolean(value))
    .sort((left, right) => Date.parse(right) - Date.parse(left))[0] ?? null;
}

function compareRepresentativeSession(left: PeerMeshSession, right: PeerMeshSession) {
  const statusScore = (session: PeerMeshSession) => (session.status === "ACTIVE" ? 2 : session.status === "NEGOTIATING" ? 1 : 0);
  const pathScore = (session: PeerMeshSession) => (effectivePeerSessionPathType(session) === "DIRECT" ? 2 : effectivePeerSessionPathType(session) === "RELAY" ? 1 : 0);
  return (
    statusScore(right) - statusScore(left) ||
    pathScore(right) - pathScore(left) ||
    sessionTimeMillis(right) - sessionTimeMillis(left)
  );
}

function sessionTimeMillis(session: PeerMeshSession) {
  const time = Date.parse(session.lastTrafficAt || session.updatedAt || session.startedAt || "");
  return Number.isFinite(time) ? time : 0;
}

function effectivePeerSessionPathType(session: PeerMeshSession) {
  const directBytes = session.directBytes || 0;
  const relayBytes = session.relayBytes || 0;
  if (relayBytes > directBytes) {
    return "RELAY";
  }
  if (directBytes > relayBytes) {
    return "DIRECT";
  }
  return session.pathType || "DIRECT";
}

function pathColor(pathType: string, status: string): "default" | "success" | "warning" {
  if (status !== "ACTIVE") {
    return "default";
  }
  return pathType === "DIRECT" ? "success" : "warning";
}

function aclDirectionLabel(direction: PeerMeshAcl["direction"]) {
  switch (direction) {
    case "OUTBOUND":
      return "单向出 →";
    case "INBOUND":
      return "单向入 ←";
    case "BOTH":
      return "双向 ⇄";
    default:
      return String(direction);
  }
}

function virtualDeviceColor(status?: string | null): "default" | "success" | "warning" | "danger" {
  if (!status) {
    return "default";
  }
  if (status === "ACTIVE") {
    return "success";
  }
  if (status === "NOOP") {
    return "warning";
  }
  if (status.includes("FAILED")) {
    return "danger";
  }
  return "default";
}

function virtualDeviceLabel(status?: string | null) {
  if (!status) {
    return "未上报";
  }
  if (status === "ACTIVE") {
    return "已创建";
  }
  if (status === "NOOP") {
    return "未接管";
  }
  if (status === "FAILED_FALLBACK_NOOP") {
    return "失败回退";
  }
  return status;
}

function MetricCard({
  label,
  tone = "default",
  value,
}: {
  label: string;
  tone?: "default" | "success";
  value: string;
}) {
  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardBody className="gap-1 p-3">
        <span className="text-small text-default-500">{label}</span>
        <span className={tone === "success" ? "text-xl font-semibold text-success" : "text-xl font-semibold"}>
          {value}
        </span>
      </CardBody>
    </Card>
  );
}
