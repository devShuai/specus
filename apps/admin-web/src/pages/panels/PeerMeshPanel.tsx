import { useCallback, useEffect, useMemo, useState } from "react";
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
import { formatBytes, formatDateTime } from "../../lib/format";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";
import { EmptyState } from "../../components/EmptyState";
import { useNowTick } from "../../hooks/useNowTick";
import {
  NAT_TYPE_PROFILES,
  natReachabilityWeight,
  natTypeColor,
  natTypeLabel,
  natTypeProfile,
} from "../../lib/nat";

const peerNatFilterOptions = [
  { key: "all", label: "全部设备" },
  { key: "online", label: "仅在线" },
  { key: "direct", label: "直连友好" },
  { key: "relay", label: "建议 Relay" },
  { key: "unknown", label: "未检测" },
] as const;

type PeerNatFilterKey = (typeof peerNatFilterOptions)[number]["key"];
type PeerMeshViewKey = "devices" | "sessions" | "acl" | "nat";
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
  const [loading, setLoading] = useState(true);
  const [clearingSessions, setClearingSessions] = useState(false);
  const [sourceClientId, setSourceClientId] = useState("");
  const [targetClientId, setTargetClientId] = useState("");
  const [natFilter, setNatFilter] = useState<PeerNatFilterKey>("all");
  const [natKeyword, setNatKeyword] = useState("");
  const [peerView, setPeerView] = useState<PeerMeshViewKey>("devices");
  const [sessionPage, setSessionPage] = useState(0);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [sessionTotalPages, setSessionTotalPages] = useState(1);
  const now = useNowTick(1000);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextStatus, nextDevices, nextAcls, nextSessions, nextPathStats] = await Promise.all([
        adminApi.peerMeshStatus(),
        adminApi.listPeerMeshDevices(),
        adminApi.listPeerMeshAcls(),
        adminApi.listPeerMeshSessionsPage({
          page: sessionPage,
          size: SESSION_PAGE_SIZE,
          openOnly: true,
        }),
        // stats 暂不可用时降级为 null，不影响面板其余部分。
        adminApi.peerMeshStats().catch(() => null),
      ]);
      setStatus(nextStatus);
      setPathStats(nextPathStats);
      setDevices(nextDevices);
      setAcls(nextAcls);
      setSessions(nextSessions.items);
      setSessionTotal(nextSessions.total);
      setSessionTotalPages(Math.max(1, nextSessions.totalPages));
    } catch (error) {
      notifyError(error, "加载私有组网失败");
    } finally {
      setLoading(false);
    }
  }, [sessionPage]);

  useEffect(() => {
    void load();
  }, [load]);

  const enabledDevices = useMemo(() => devices.filter((device) => device.enabled), [devices]);
  const onlineDevices = useMemo(() => devices.filter((device) => device.online), [devices]);
  const deviceById = useMemo(() => new Map(devices.map((device) => [device.clientId, device])), [devices]);
  const openSessions = useMemo(() => sessions.filter((session) => session.status !== "CLOSED"), [sessions]);
  const activeSessions = useMemo(
    () => sessions.filter((session) => isPeerSessionEffectivelyActive(session, deviceById, now)),
    [sessions, deviceById, now],
  );
  const directSessions = useMemo(() => activeSessions.filter((session) => effectivePeerSessionPathType(session) === "DIRECT"), [activeSessions]);
  const relaySessions = useMemo(() => activeSessions.filter((session) => effectivePeerSessionPathType(session) === "RELAY"), [activeSessions]);
  const peerTrafficBytes = useMemo(
    () => sessions.reduce((total, session) => total + (session.directBytes || 0) + (session.relayBytes || 0), 0),
    [sessions],
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
          device.virtualDeviceName,
        ]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(normalizedKeyword));
      })
      .sort(comparePeerNatDevice);
  }, [devices, natFilter, natKeyword]);

  const updateDevice = async (device: PeerMeshDevice, enabled: boolean) => {
    try {
      const updated = await adminApi.updatePeerMeshDevice(device.clientId, { enabled });
      setDevices((items) => items.map((item) => (item.clientId === updated.clientId ? updated : item)));
      notify(enabled ? "已启用私有组网设备" : "已停用私有组网设备");
      await load();
    } catch (error) {
      notifyError(error, "更新设备失败");
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

  const deleteAcl = async (acl: PeerMeshAcl) => {
    if (!window.confirm(`确定删除 ${acl.sourceClientName} -> ${acl.targetClientName} 的 ACL 吗？`)) {
      return;
    }
    try {
      await adminApi.deletePeerMeshAcl(acl.id);
      setAcls((items) => items.filter((item) => item.id !== acl.id));
      notify("Peer ACL 已删除");
    } catch (error) {
      notifyError(error, "删除 ACL 失败");
    }
  };

  const closeSession = async (session: PeerMeshSession) => {
    if (!window.confirm(`确定断开 ${session.sourceClientName} -> ${session.targetClientName} 的 peer session 吗？`)) {
      return;
    }
    try {
      const closed = await adminApi.closePeerMeshSession(session.id);
      setSessions((items) => items.map((item) => (item.id === closed.id ? closed : item)));
      if (selectedSession?.id === session.id) setSelectedSession(null);
      notify("Peer session 已断开");
      await load();
    } catch (error) {
      notifyError(error, "断开 peer session 失败");
    }
  };

  const closeOpenSessions = async () => {
    if (openSessions.length === 0) {
      notify("当前没有未关闭 peer 链路");
      return;
    }
    if (!window.confirm(`确定清理当前权限范围内的未关闭 peer 链路吗？当前有效活跃 ${activeSessions.length} 条，未关闭 ${openSessions.length} 条。`)) {
      return;
    }
    setClearingSessions(true);
    try {
      const closedSessions = await adminApi.closeOpenPeerMeshSessions();
      const closedById = new Map(closedSessions.map((session) => [session.id, session]));
      setSessions((items) => items.map((item) => closedById.get(item.id) ?? item));
      setSessionPage(0);
      setSessionTotal(0);
      setSessionTotalPages(1);
      notify(`已清理 ${closedSessions.length} 条 peer 链路`);
    } catch (error) {
      notifyError(error, "清理 peer 链路失败");
    } finally {
      setClearingSessions(false);
    }
  };

  return (
    <div className="mt-3 flex min-w-0 flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-foreground">私有组网</h2>
          <p className="text-small text-default-500">同一用户下客户端分配虚拟 IP，优先直连，失败后切到内置 relay。</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            color="danger"
            variant="flat"
            isDisabled={openSessions.length === 0}
            isLoading={clearingSessions}
            onPress={() => void closeOpenSessions()}
          >
            清理未关闭链路
          </Button>
          <Button variant="flat" onPress={() => void load()}>
            刷新
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard label="全局开关" value={status?.enabled ? "已开启" : "默认关闭"} tone={status?.enabled ? "success" : "default"} />
        <MetricCard label="已启用设备" value={`${enabledDevices.length} / ${devices.length}`} />
        <MetricCard label="在线设备" value={String(onlineDevices.length)} tone={onlineDevices.length > 0 ? "success" : "default"} />
        <MetricCard label="活跃 Direct / Relay" value={`${directSessions.length} / ${relaySessions.length}`} />
        <MetricCard
          label="直连占比"
          value={pathStats?.activeDirectRatio == null ? "-" : `${Math.round(pathStats.activeDirectRatio * 100)}%`}
          tone={pathStats?.activeDirectRatio != null && pathStats.activeDirectRatio >= 0.5 ? "success" : "default"}
        />
        <MetricCard label="Peer 流量" value={formatBytes(peerTrafficBytes)} tone={peerTrafficBytes > 0 ? "success" : "default"} />
      </div>

      {!status?.enabled && (
        <Card shadow="none" className="rounded-md border border-warning-200 bg-warning-50 dark:border-warning-400/30 dark:bg-warning-500/10">
          <CardBody className="p-3 text-small text-warning-700 dark:text-warning-200">
            server 当前未启用 peer mesh。设置 TUNNEL_PEER_MESH_ENABLED=true 后，客户端下次登录会收到虚拟 IP、STUN/TURN 与 ICE 凭证。
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
        <Tab key="sessions" title={`活跃会话 ${activeSessions.length}`} />
        <Tab key="acl" title={`ACL ${acls.length}`} />
        <Tab key="nat" title="NAT 诊断" />
      </Tabs>

      {peerView === "nat" && (
      <PeerNatInsight
        devices={natDevices}
        devicesTotal={devices.length}
        filter={natFilter}
        keyword={natKeyword}
        loading={loading}
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
            isLoading={loading}
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
                        <div className="flex flex-col">
                          <span>{natTypeLabel(device.natType)}</span>
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
          <TableBody items={devices} isLoading={loading} emptyContent="暂无 peer mesh 设备">
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
                  <div className="flex max-w-72 flex-col break-all text-small">
                    <span>{natTypeLabel(device.natType)}</span>
                    <span className="text-tiny text-default-400">{device.lastEndpoint || "-"}</span>
                  </div>
                </TableCell>
                <TableCell>{formatDateTime(device.lastSeenAt)}</TableCell>
                <TableCell>
                  <Switch
                    aria-label={`启用 ${device.clientName} 私有组网`}
                    isSelected={device.enabled}
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
                isLoading={loading}
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
              <TableBody items={acls} isLoading={loading} emptyContent="暂无显式 ACL">
                {(acl) => (
                  <TableRow key={acl.id}>
                    <TableCell>{acl.sourceClientName}</TableCell>
                    <TableCell>{acl.targetClientName}</TableCell>
                    <TableCell><Chip size="sm" variant="flat" color={acl.direction === "BOTH" ? "success" : acl.direction === "INBOUND" ? "warning" : "primary"}>{acl.direction === "OUTBOUND" ? "→" : acl.direction === "INBOUND" ? "←" : "⇄"}</Chip></TableCell>
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
        {!loading && activeSessions.length === 0 ? (
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
                    <MobileListCardList items={activeSessions} isLoading={loading} emptyContent="暂无活跃 peer session" renderCard={(raw) => {
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
  const pathTypeRows = [...stats.pathTypes].sort((a, b) => b.sessions - a.sessions);
  const natTypeRows = [...stats.natTypes].sort((a, b) => b.devices - a.devices);
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
            <span className="text-tiny text-default-500">设备 NAT 分布：</span>
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
          <PeerNatMetric label="NAT 已检测" value={`${stats.reported} / ${devicesTotal}`} tone={stats.reported > 0 ? "success" : "default"} />
          <PeerNatMetric label="在线设备" value={String(stats.online)} tone={stats.online > 0 ? "success" : "default"} />
          <PeerNatMetric label="直连友好" value={String(stats.directFriendly)} tone={stats.directFriendly > 0 ? "success" : "default"} />
          <PeerNatMetric label="建议 Relay" value={String(stats.relayPreferred)} tone={stats.relayPreferred > 0 ? "danger" : "default"} />
          <PeerNatMetric label="新鲜上报" value={String(stats.fresh)} tone={stats.fresh > 0 ? "success" : "default"} />
        </div>

        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <h3 className="text-base font-semibold">客户端 NAT 探测</h3>
                <p className="text-small text-default-500">
                  这里展示 tunnel-client 上报的标准 STUN/TURN 子集探测结果，用于判断 Peer Mesh direct / relay 选择。
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
                      const profile = natTypeProfile(device.natType);
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
                      <TableColumn className="w-[24%]">
                        <PeerNatKeywordHeader keyword={keyword} onKeywordChange={onKeywordChange} />
                      </TableColumn>
                      <TableColumn className="w-[16%]">
                        <PeerNatTypeFilterHeader filter={filter} onFilterChange={onFilterChange} />
                      </TableColumn>
                      <TableColumn className="w-[22%]">Endpoint</TableColumn>
                      <TableColumn className="w-[24%]">建议</TableColumn>
                      <TableColumn className="w-[14%]">上报</TableColumn>
                    </TableHeader>
                    <TableBody items={devices} isLoading={loading} emptyContent="暂无客户端 NAT 检测结果">
                      {(device) => {
                        const profile = natTypeProfile(device.natType);
                        return (
                          <TableRow key={device.clientId}>
                            <TableCell>
                              <div className="flex min-w-0 flex-col">
                                <span className="truncate font-semibold" title={device.clientName}>{device.clientName}</span>
                                <span className="truncate font-mono text-tiny text-default-400" title={device.virtualIp || "-"}>{device.virtualIp || "-"}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Chip className="w-fit" size="sm" color={profile.tone} variant="flat">
                                {profile.label}
                              </Chip>
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
                <h3 className="text-base font-semibold">NAT 类型</h3>
                <p className="text-small text-default-500">点击类型跳转帮助文档查看详细说明与建议路径。</p>
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
            <div className="flex flex-wrap gap-2">
              {Object.values(NAT_TYPE_PROFILES).map((profile) => (
                <a
                  key={profile.key}
                  href="#/help/peer-mesh#nat-types"
                  title={profile.summary}
                  className="inline-flex items-center gap-1.5 rounded-md border border-default-200 bg-default-50 px-2.5 py-1 text-tiny transition-colors hover:border-primary-300 hover:bg-default-100 dark:bg-default-100/10 dark:hover:bg-default-200/10"
                >
                  <span className={`inline-block h-2 w-2 rounded-full ${peerNatBarColor(profile.tone)}`} />
                  <span className="font-medium text-foreground">{profile.label}</span>
                  <span className="text-default-500">· {profile.reachabilityLabel}</span>
                </a>
              ))}
            </div>
          </CardBody>
        </Card>
      </div>
    </section>
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
  const label = active ? `NAT: ${activeOption.label}` : "NAT 类型";

  return (
    <div className="flex min-w-0 items-center gap-1">
      <span className="truncate" title={label}>
        {label}
      </span>
      <Popover placement="bottom-start" shouldBlockScroll={false}>
        <PopoverTrigger>
          <Button
            isIconOnly
            aria-label="筛选 NAT 类型"
            className="h-7 min-w-7 text-default-500"
            color={active ? "primary" : "default"}
            size="sm"
            title="筛选 NAT 类型"
            variant={active ? "flat" : "light"}
          >
            <PeerNatFilterIcon />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-56 p-3">
          <div className="flex w-full flex-col gap-3">
            <div className="text-small font-semibold">NAT 类型筛选</div>
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
  const distributionMap = new Map<string, number>();
  let directFriendly = 0;
  let relayPreferred = 0;
  let reported = 0;
  let fresh = 0;

  for (const device of devices) {
    const profile = natTypeProfile(device.natType);
    distributionMap.set(profile.key, (distributionMap.get(profile.key) ?? 0) + 1);
    if (device.natType) {
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

  const distribution = Array.from(distributionMap.entries())
    .map(([key, count]) => ({ profile: natTypeProfile(key === "UNKNOWN" ? null : key), count }))
    .sort(
      (left, right) =>
        right.count - left.count ||
        natReachabilityWeight(right.profile.key) - natReachabilityWeight(left.profile.key),
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
  item: { profile: ReturnType<typeof natTypeProfile>; count: number };
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
  const profile = natTypeProfile(device.natType);
  switch (filter) {
    case "online":
      return device.online;
    case "direct":
      return profile.reachability === "direct" || profile.reachability === "likely";
    case "relay":
      return profile.reachability === "relay";
    case "unknown":
      return !device.natType;
    default:
      return true;
  }
}

function comparePeerNatDevice(left: PeerMeshDevice, right: PeerMeshDevice) {
  return (
    Number(right.online) - Number(left.online) ||
    natReachabilityWeight(right.natType) - natReachabilityWeight(left.natType) ||
    Date.parse(peerNatLastReportAt(right) || "") - Date.parse(peerNatLastReportAt(left) || "")
  );
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
          {(enabledDevices.length > 0 ? enabledDevices : devices).slice(0, 8).map((device) => (
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
                <span>{natTypeLabel(device.natType)}</span>
              </div>
            </div>
          ))}
        </div>

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
