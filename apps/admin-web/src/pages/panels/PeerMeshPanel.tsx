import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Card,
  CardBody,
  Chip,
  Select,
  SelectItem,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
} from "@heroui/react";
import { adminApi } from "../../api/client";
import type { PeerMeshAcl, PeerMeshDevice, PeerMeshSession, PeerMeshStatus } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { formatBytes, formatDateTime } from "../../lib/format";
import { MobileListCard, MobileListCardList } from "../../components/MobileListCard";

export function PeerMeshPanel() {
  const [status, setStatus] = useState<PeerMeshStatus | null>(null);
  const [devices, setDevices] = useState<PeerMeshDevice[]>([]);
  const [acls, setAcls] = useState<PeerMeshAcl[]>([]);
  const [sessions, setSessions] = useState<PeerMeshSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [clearingSessions, setClearingSessions] = useState(false);
  const [sourceClientId, setSourceClientId] = useState("");
  const [targetClientId, setTargetClientId] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nextStatus, nextDevices, nextAcls, nextSessions] = await Promise.all([
        adminApi.peerMeshStatus(),
        adminApi.listPeerMeshDevices(),
        adminApi.listPeerMeshAcls(),
        adminApi.listPeerMeshSessions(100),
      ]);
      setStatus(nextStatus);
      setDevices(nextDevices);
      setAcls(nextAcls);
      setSessions(nextSessions);
    } catch (error) {
      notifyError(error, "加载私有组网失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const enabledDevices = useMemo(() => devices.filter((device) => device.enabled), [devices]);
  const onlineDevices = useMemo(() => devices.filter((device) => device.online), [devices]);
  const activeSessions = useMemo(() => sessions.filter((session) => session.status !== "CLOSED"), [sessions]);
  const directSessions = useMemo(() => activeSessions.filter((session) => session.pathType === "DIRECT"), [activeSessions]);
  const relaySessions = useMemo(() => activeSessions.filter((session) => session.pathType === "RELAY"), [activeSessions]);
  const peerTrafficBytes = useMemo(
    () => sessions.reduce((total, session) => total + (session.directBytes || 0) + (session.relayBytes || 0), 0),
    [sessions],
  );

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
      const acl = await adminApi.createPeerMeshAcl({ sourceClientId: source, targetClientId: target, allowed: true });
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
      notify("Peer session 已断开");
    } catch (error) {
      notifyError(error, "断开 peer session 失败");
    }
  };

  const closeOpenSessions = async () => {
    if (activeSessions.length === 0) {
      notify("当前没有活跃 peer 链路");
      return;
    }
    if (!window.confirm(`确定清理当前权限范围内的活跃 peer 链路吗？页面当前显示 ${activeSessions.length} 条。`)) {
      return;
    }
    setClearingSessions(true);
    try {
      const closedSessions = await adminApi.closeOpenPeerMeshSessions();
      const closedById = new Map(closedSessions.map((session) => [session.id, session]));
      setSessions((items) => items.map((item) => closedById.get(item.id) ?? item));
      notify(`已清理 ${closedSessions.length} 条活跃 peer 链路`);
      await load();
    } catch (error) {
      notifyError(error, "清理活跃 peer 链路失败");
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
            isDisabled={activeSessions.length === 0}
            isLoading={clearingSessions}
            onPress={() => void closeOpenSessions()}
          >
            清理活跃链路
          </Button>
          <Button variant="flat" onPress={() => void load()}>
            刷新
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-2 md:grid-cols-5">
        <MetricCard label="全局开关" value={status?.enabled ? "已开启" : "默认关闭"} tone={status?.enabled ? "success" : "default"} />
        <MetricCard label="已启用设备" value={`${enabledDevices.length} / ${devices.length}`} />
        <MetricCard label="在线设备" value={String(onlineDevices.length)} tone={onlineDevices.length > 0 ? "success" : "default"} />
        <MetricCard label="Direct / Relay" value={`${directSessions.length} / ${relaySessions.length}`} />
        <MetricCard label="Peer 流量" value={formatBytes(peerTrafficBytes)} tone={peerTrafficBytes > 0 ? "success" : "default"} />
      </div>

      {!status?.enabled && (
        <Card shadow="none" className="rounded-md border border-warning-200 bg-warning-50 dark:border-warning-400/30 dark:bg-warning-500/10">
          <CardBody className="p-3 text-small text-warning-700 dark:text-warning-200">
            server 当前未启用 peer mesh。设置 TUNNEL_PEER_MESH_ENABLED=true 后，客户端下次登录会收到虚拟 IP、STUN/TURN 与 ICE 凭证。
          </CardBody>
        </Card>
      )}

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

      <section className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.8fr)]">
        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div>
              <h3 className="text-base font-semibold">显式 ACL</h3>
              <p className="text-small text-default-500">同一用户默认放行；跨用户互访需要 admin 创建显式 ACL。</p>
            </div>
            <div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
              <Select
                label="源客户端"
                selectedKeys={sourceClientId ? [sourceClientId] : []}
                onSelectionChange={(keys) => setSourceClientId(String(Array.from(keys)[0] ?? ""))}
              >
                {devices.map((device) => (
                  <SelectItem key={String(device.clientId)}>{device.clientName}</SelectItem>
                ))}
              </Select>
              <Select
                label="目标客户端"
                selectedKeys={targetClientId ? [targetClientId] : []}
                onSelectionChange={(keys) => setTargetClientId(String(Array.from(keys)[0] ?? ""))}
              >
                {devices.map((device) => (
                  <SelectItem key={String(device.clientId)}>{device.clientName}</SelectItem>
                ))}
              </Select>
              <Button className="md:self-end" color="primary" onPress={() => void createAcl()}>
                放行
              </Button>
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
                <TableColumn>状态</TableColumn>
                <TableColumn>操作</TableColumn>
              </TableHeader>
              <TableBody items={acls} isLoading={loading} emptyContent="暂无显式 ACL">
                {(acl) => (
                  <TableRow key={acl.id}>
                    <TableCell>{acl.sourceClientName}</TableCell>
                    <TableCell>{acl.targetClientName}</TableCell>
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

        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div>
              <h3 className="text-base font-semibold">活跃会话</h3>
              <p className="text-small text-default-500">只展示未关闭的 ICE 会话；清理后会同步断开拓扑链路。</p>
            </div>

            {/* mobile: 会话卡片 */}
            <div className="lg:hidden">
              <MobileListCardList
                items={activeSessions}
                isLoading={loading}
                emptyContent="暂无活跃 peer session"
                renderCard={(raw) => {
                  const session = raw as PeerMeshSession;
                  return (
                    <MobileListCard
                      key={session.id}
                      title={
                        <span className="break-all">
                          {session.sourceClientName} → {session.targetClientName}
                        </span>
                      }
                      badges={
                        <>
                          <Chip size="sm" color={session.status === "ACTIVE" ? "success" : "default"} variant="flat">
                            {session.pathType}
                          </Chip>
                          <Chip size="sm" variant="flat">{session.status}</Chip>
                        </>
                      }
                      fields={[
                        { label: "RTT", value: session.rttMillis == null ? "-" : `${session.rttMillis} ms` },
                        {
                          label: "流量",
                          value: (
                            <div className="flex flex-col gap-0.5">
                              <span>direct {formatBytes(session.directBytes)}</span>
                              <span className="text-default-400">relay {formatBytes(session.relayBytes)}</span>
                              <span className="text-tiny text-default-400">最后 {formatDateTime(session.lastTrafficAt)}</span>
                            </div>
                          ),
                        },
                        {
                          label: "Endpoint",
                          value: (
                            <div className="flex flex-col gap-0.5 break-all">
                              <span>local: {session.localEndpoint || "-"}</span>
                              <span className="text-default-400">remote: {session.remoteEndpoint || "-"}</span>
                            </div>
                          ),
                        },
                        {
                          label: "过期",
                          value: (
                            <div className="flex flex-col gap-0.5">
                              <span>{formatDateTime(session.expiresAt)}</span>
                              <span className="text-tiny text-default-400">更新 {formatDateTime(session.updatedAt)}</span>
                            </div>
                          ),
                        },
                      ]}
                      actions={
                        <Button
                          size="sm"
                          color="danger"
                          variant="flat"
                          isDisabled={session.status === "CLOSED"}
                          onPress={() => void closeSession(session)}
                        >
                          断开
                        </Button>
                      }
                    />
                  );
                }}
              />
            </div>

            {/* desktop: 会话表格 */}
            <div className="hidden min-w-0 overflow-x-auto lg:block">
            <Table aria-label="Peer mesh 会话" removeWrapper>
              <TableHeader>
                <TableColumn>Peer</TableColumn>
                <TableColumn>路径</TableColumn>
                <TableColumn>RTT</TableColumn>
                <TableColumn>流量</TableColumn>
                <TableColumn>Endpoint</TableColumn>
                <TableColumn>过期</TableColumn>
                <TableColumn>操作</TableColumn>
              </TableHeader>
              <TableBody items={activeSessions} isLoading={loading} emptyContent="暂无活跃 peer session">
                {(session) => (
                  <TableRow key={session.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span>{session.sourceClientName}</span>
                        <span className="text-tiny text-default-400">{"-> "}{session.targetClientName}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <Chip size="sm" color={session.status === "ACTIVE" ? "success" : "default"} variant="flat">
                          {session.pathType}
                        </Chip>
                        <span className="text-tiny text-default-400">{session.status}</span>
                      </div>
                    </TableCell>
                    <TableCell>{session.rttMillis == null ? "-" : `${session.rttMillis} ms`}</TableCell>
                    <TableCell>
                      <div className="flex flex-col text-tiny">
                        <span>direct {formatBytes(session.directBytes)}</span>
                        <span className="text-default-400">relay {formatBytes(session.relayBytes)}</span>
                        <span className="text-default-400">最后 {formatDateTime(session.lastTrafficAt)}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex max-w-56 flex-col break-all text-tiny">
                        <span>local: {session.localEndpoint || "-"}</span>
                        <span className="text-default-400">remote: {session.remoteEndpoint || "-"}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col text-tiny">
                        <span>{formatDateTime(session.expiresAt)}</span>
                        <span className="text-default-400">更新 {formatDateTime(session.updatedAt)}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        color="danger"
                        variant="flat"
                        isDisabled={session.status === "CLOSED"}
                        onPress={() => void closeSession(session)}
                      >
                        断开
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
    </div>
  );
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
              return (
                <div key={link.key} className="rounded-md border border-default-200 bg-default-50 p-3 dark:bg-default-100/10">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="min-w-0 text-small font-semibold">
                      <span>{link.firstName}</span>
                      <span className="px-2 text-default-400">{"<->"}</span>
                      <span>{link.secondName}</span>
                    </div>
                    <Chip size="sm" color={pathColor(session.pathType, session.status)} variant="flat">
                      {session.pathType} · {session.status}
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
        directSessions: activeItems.filter((item) => item.pathType === "DIRECT").length,
        relaySessions: activeItems.filter((item) => item.pathType === "RELAY").length,
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
  const pathScore = (session: PeerMeshSession) => (session.pathType === "DIRECT" ? 2 : session.pathType === "RELAY" ? 1 : 0);
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

function natTypeLabel(natType?: string | null) {
  switch (natType) {
    case "NO_NAT":
      return "无 NAT";
    case "PORT_PRESERVED_NAT":
      return "端口保持 NAT";
    case "FULL_CONE_OR_RESTRICTED_NAT":
      return "Full cone / Restricted NAT";
    case "PORT_RESTRICTED_NAT":
      return "Port Restricted NAT";
    case "SYMMETRIC_NAT":
      return "Symmetric NAT";
    case "NAT":
      return "NAT";
    default:
      return "NAT 未知";
  }
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
