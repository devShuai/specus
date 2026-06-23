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

export function PeerMeshPanel() {
  const [status, setStatus] = useState<PeerMeshStatus | null>(null);
  const [devices, setDevices] = useState<PeerMeshDevice[]>([]);
  const [acls, setAcls] = useState<PeerMeshAcl[]>([]);
  const [sessions, setSessions] = useState<PeerMeshSession[]>([]);
  const [loading, setLoading] = useState(true);
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
  const directSessions = useMemo(() => sessions.filter((session) => session.pathType === "DIRECT"), [sessions]);
  const relaySessions = useMemo(() => sessions.filter((session) => session.pathType === "RELAY"), [sessions]);
  const peerTrafficBytes = useMemo(
    () => sessions.reduce((total, session) => total + (session.directBytes || 0) + (session.relayBytes || 0), 0),
    [sessions],
  );

  const updateDevice = async (device: PeerMeshDevice, enabled: boolean) => {
    try {
      const updated = await adminApi.updatePeerMeshDevice(device.clientId, { enabled });
      setDevices((items) => items.map((item) => (item.clientId === updated.clientId ? updated : item)));
      notify(enabled ? "已启用私有组网设备" : "已停用私有组网设备");
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

  return (
    <div className="mt-3 flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-foreground">私有组网</h2>
          <p className="text-small text-default-500">同一用户下客户端分配虚拟 IP，优先直连，失败后切到内置 relay。</p>
        </div>
        <Button variant="flat" onPress={() => void load()}>
          刷新
        </Button>
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

      <section className="space-y-2">
        <h3 className="text-base font-semibold">设备与虚拟 IP</h3>
        <Table aria-label="Peer mesh 设备" isHeaderSticky removeWrapper>
          <TableHeader>
            <TableColumn>客户端</TableColumn>
            <TableColumn>归属</TableColumn>
            <TableColumn>虚拟 IP</TableColumn>
            <TableColumn>状态</TableColumn>
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
                  <div className="flex max-w-72 flex-col break-all text-small">
                    <span>{device.natType || "-"}</span>
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
          </CardBody>
        </Card>

        <Card shadow="none" className="rounded-md border border-default-200">
          <CardBody className="gap-3 p-3">
            <div>
              <h3 className="text-base font-semibold">活跃会话</h3>
              <p className="text-small text-default-500">记录 ICE 协商、direct/relay 路径和授权过期时间。</p>
            </div>
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
              <TableBody items={sessions} isLoading={loading} emptyContent="暂无 peer session">
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
          </CardBody>
        </Card>
      </section>
    </div>
  );
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
