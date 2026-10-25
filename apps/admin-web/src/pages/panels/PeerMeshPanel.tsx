import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Button } from "@heroui/react";
import { PageHeader } from "../../components/PageHeader";
import { Alert, Card, CardBody, Empty, Icon, Progress, RelativeTime, Section, Stat, StatGrid, TableWrap, Tabs, Tag, FilterBar } from "../../components/ui";
import { adminApi } from "../../api/client";
import type { PeerMeshAcl, PeerMeshDevice, PeerMeshPathStats, PeerMeshSession, PeerMeshStatus } from "../../api/types";
import { notify, notifyError } from "../../components/toast";
import { ConfirmModal } from "../../components/ConfirmModal";
import { formatBytes } from "../../lib/format";
import { useNowTick } from "../../hooks/useNowTick";
import { PeerMeshServicesTab } from "./PeerMeshServicesTab";
import { PeerMeshEgressTab } from "./PeerMeshEgressTab";
import { DescList, ModelTag, SelectField, TableLoadingRow, TableStateRow, Toggle } from "./meshSystemParts";
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
type PeerMeshViewKey = "devices" | "sessions" | "acl" | "nat" | "services" | "egress";
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
  // #/peer-mesh/services opens the services tab directly (the workbench's publish entry links there).
  const [peerView, setPeerView] = useState<PeerMeshViewKey>(() =>
    /^#\/?peer-mesh\/services(?:[/?#]|$)/.test(window.location.hash) ? "services" : "devices");
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
      notifyError(new Error("源和目标要选两台不同的客户端"), "创建 ACL 失败");
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
      title: "删除这条 ACL？",
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
      title: "断开这条 peer session？",
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
      title: "清理全部未关闭的 peer 链路？",
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

  const directRatio = pathStats?.activeDirectRatio;
  const meshCidr = devices.find((device) => device.cidr)?.cidr;

  return (
    <div className="ms-page flex min-w-0 flex-col">
      <PageHeader
        title="私有组网"
        description="设备通过虚拟 IP 互联；RFC 5780 双轴结果辅助选路，直连失败后切换认证 TURN。"
        actions={<>
          <Button
            color="danger"
            variant="flat"
            isDisabled={sessionTotal === 0 && openSessions.length === 0}
            isLoading={clearingSessions}
            onPress={closeOpenSessions}
          >
            清理未关闭链路
          </Button>
          <Button variant="flat" isLoading={refreshing} startContent={refreshing ? null : <Icon name="refresh" />} onPress={() => void refresh()}>
            刷新
          </Button>
        </>}
      />

      {status && !status.enabled ? (
        <Alert tone="warning" title="服务端没有开启 peer mesh" className="ms-block">
          设置 <code className="ms-inline-code">SPECUS_PEER_MESH_ENABLED=true</code> 后重启服务端；客户端下次登录会收到虚拟 IP、独立 STUN 拓扑和 TURN/ICE 凭证。
        </Alert>
      ) : null}

      <StatGrid className="ms-block">
        <Stat
          label="全局开关"
          value={status ? (status.enabled ? "已开启" : "默认关闭") : "—"}
          tone={status?.enabled ? "success" : undefined}
          meta={meshCidr ? <>虚拟网段 <span className="bd-num">{meshCidr}</span></> : "由服务端环境变量控制"}
        />
        <Stat
          label="已启用设备"
          value={<span className="bd-num">{enabledDevices.length}<span className="ms-stat-of"> / {devices.length}</span></span>}
          meta={`在线 ${onlineDevices.length} 台`}
        />
        <Stat
          label="活跃会话"
          value={<span className="bd-num">{globalActiveSessions}</span>}
          meta={globalDirectSessions == null || globalRelaySessions == null ? "路径统计暂不可用" : `Direct ${globalDirectSessions} · Relay ${globalRelaySessions}`}
        />
        <Stat
          label="直连占比"
          value={directRatio == null ? "—" : <span className="bd-num">{Math.round(directRatio * 100)}%</span>}
          tone={directRatio != null && directRatio >= 0.5 ? "success" : undefined}
          meta={peerTrafficBytes == null ? "暂无活跃会话" : `Peer 流量 ${formatBytes(peerTrafficBytes)}`}
        />
      </StatGrid>

      <Tabs
        label="私有组网视图"
        value={peerView}
        onChange={setPeerView}
        items={[
          { key: "devices", label: "设备拓扑", icon: "layers" },
          { key: "services", label: "服务", icon: "server" },
          { key: "egress", label: "出口分流", icon: "globe" },
          { key: "sessions", label: "活跃会话", icon: "activity", count: globalActiveSessions },
          { key: "acl", label: "ACL", icon: "shield", count: acls.length },
          { key: "nat", label: "NAT 诊断", icon: "locate" },
        ]}
      />

      <div role="tabpanel" aria-label={PEER_VIEW_LABEL[peerView]} className="min-w-0">
        {peerView === "services" && (
          <PeerMeshServicesTab deploymentEnabled={Boolean(status?.enabled)} devices={devices} />
        )}

        {peerView === "egress" && <PeerMeshEgressTab devices={devices} />}

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
            <Section title="设备与虚拟 IP" description="开关只影响私有组网，不影响设备的其他接入能力。">
              <TableWrap>
                <table className="bd-table jd-stack ms-table" aria-label="Peer mesh 设备">
                  <thead>
                    <tr>
                      <th scope="col">客户端</th>
                      <th scope="col">归属</th>
                      <th scope="col">虚拟 IP</th>
                      <th scope="col">状态</th>
                      <th scope="col">虚拟网卡</th>
                      <th scope="col">NAT / Endpoint</th>
                      <th scope="col">最后上线</th>
                      <th scope="col">启用</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devicesLoading && devices.length === 0 ? <TableLoadingRow colSpan={8} /> : null}
                    {!devicesLoading && devices.length === 0 ? (
                      <TableStateRow colSpan={8}>
                        <Empty icon="wifi" title="暂无 peer mesh 设备" description="客户端登录后会出现在这里；在这里打开开关后它才加入私有组网。" />
                      </TableStateRow>
                    ) : null}
                    {devices.map((device) => (
                      <tr key={device.clientId}>
                        <td>
                          <div className="ms-cell-main">
                            <span className="ms-cell-title">{device.clientName}</span>
                            <span className="ms-cell-sub bd-num">#{device.clientId}</span>
                          </div>
                        </td>
                        <td data-label="归属" className={device.ownerUsername ? undefined : "is-empty"}>{device.ownerUsername || "—"}</td>
                        <td data-label="虚拟 IP">
                          <div className="ms-cell-main">
                            <span className="ms-mono">{device.virtualIp || "—"}</span>
                            <span className="ms-cell-sub ms-mono">{device.cidr}</span>
                          </div>
                        </td>
                        <td className="jd-status-cell">
                          <div className="ms-tags">
                            <Tag tone={device.online ? "success" : "neutral"}>{device.online ? "在线" : "离线"}</Tag>
                            <Tag tone={device.enabled ? "info" : "neutral"} plain={!device.enabled}>{device.enabled ? "组网启用" : "未启用"}</Tag>
                          </div>
                        </td>
                        <td data-label="虚拟网卡" className="ms-wrap">
                          <div className="ms-cell-main">
                            <span className="ms-tags">
                              <ModelTag color={virtualDeviceColor(device.virtualDeviceStatus)}>{virtualDeviceLabel(device.virtualDeviceStatus)}</ModelTag>
                              {device.virtualDeviceName || device.virtualDeviceMode ? (
                                <span className="ms-mono ms-cell-sub">{device.virtualDeviceName || device.virtualDeviceMode}</span>
                              ) : null}
                            </span>
                            {device.virtualDeviceError ? <span className="ms-cell-error">{device.virtualDeviceError}</span> : null}
                            {device.virtualDeviceUpdatedAt ? (
                              <span className="ms-cell-sub">上报 <RelativeTime value={device.virtualDeviceUpdatedAt} /></span>
                            ) : null}
                          </div>
                        </td>
                        <td data-label="NAT" className="ms-wrap">
                          <div className="ms-cell-main">
                            <span>{peerNatProfile(device).label}</span>
                            <PeerNatBehaviorLine device={device} />
                            {device.lastEndpoint ? <span className="ms-cell-sub ms-mono ms-break">{device.lastEndpoint}</span> : null}
                          </div>
                        </td>
                        <td data-label="最后上线" className={device.lastSeenAt ? undefined : "is-empty"}>
                          {device.lastSeenAt ? <RelativeTime value={device.lastSeenAt} /> : "—"}
                        </td>
                        <td className="jd-cell-actions">
                          <Toggle
                            label={`启用 ${device.clientName} 私有组网`}
                            checked={device.enabled}
                            disabled={updatingDeviceIds.has(device.clientId)}
                            busy={updatingDeviceIds.has(device.clientId)}
                            onChange={(enabled) => void updateDevice(device, enabled)}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </Section>
          </>
        )}

        {peerView === "acl" && (
          <Section title="显式 ACL" description="同一用户默认放行；跨用户互访需要管理员创建显式 ACL。">
            <Card className="ms-block">
              <CardBody>
                <div className="bd-form-grid ms-acl-form">
                  <SelectField
                    label="源客户端"
                    value={sourceClientId}
                    placeholder="选择客户端"
                    onChange={setSourceClientId}
                    options={devices.map((device) => ({ value: String(device.clientId), label: device.clientName }))}
                  />
                  <SelectField
                    label="目标客户端"
                    value={targetClientId}
                    placeholder="选择客户端"
                    onChange={setTargetClientId}
                    options={devices.map((device) => ({ value: String(device.clientId), label: device.clientName }))}
                  />
                  <SelectField
                    label="方向"
                    value={aclDirection}
                    onChange={setAclDirection}
                    options={[
                      { value: "OUTBOUND", label: "允许我连他人" },
                      { value: "INBOUND", label: "允许他人连我" },
                      { value: "BOTH", label: "双向允许" },
                    ]}
                  />
                  <div className="ms-form-action">
                    <Button color="primary" startContent={<Icon name="plus" />} onPress={() => void createAcl()}>放行</Button>
                  </div>
                </div>
              </CardBody>
            </Card>
            <TableWrap>
              <table className="bd-table jd-stack ms-table" aria-label="Peer ACL">
                <thead>
                  <tr>
                    <th scope="col">源</th>
                    <th scope="col">目标</th>
                    <th scope="col">方向</th>
                    <th scope="col">状态</th>
                    <th scope="col" className="ms-col-actions">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {devicesLoading && acls.length === 0 ? <TableLoadingRow colSpan={5} /> : null}
                  {!devicesLoading && acls.length === 0 ? (
                    <TableStateRow colSpan={5}>
                      <Empty icon="shield" title="暂无显式 ACL" description="同一用户的设备默认互通；要让不同用户的设备互访，在上面选源、目标和方向后放行。" />
                    </TableStateRow>
                  ) : null}
                  {acls.map((acl) => (
                    <tr key={acl.id}>
                      <td><span className="ms-cell-title">{acl.sourceClientName}</span></td>
                      <td data-label="目标">{acl.targetClientName}</td>
                      <td>
                        <Tag tone={acl.direction === "BOTH" ? "success" : acl.direction === "INBOUND" ? "warning" : "info"}>
                          {aclDirectionLabel(acl.direction)}
                        </Tag>
                      </td>
                      <td>
                        <Tag tone={acl.allowed ? "success" : "danger"}>{acl.allowed ? "允许" : "拒绝"}</Tag>
                      </td>
                      <td className="jd-cell-actions ms-col-actions">
                        <Button size="sm" color="danger" variant="light" onPress={() => void deleteAcl(acl)}>
                          删除
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Section>
        )}

        {peerView === "sessions" && (
          <>
            <PeerPathStatsCard stats={pathStats} />
            <Section
              title="活跃会话"
              description={`有效 ${activeSessions.length} 条 · 未关闭 ${sessionTotal} 条；保活超过 2 分钟或任一端离线的不算有效。`}
            >
              {!sessionsLoading && activeSessions.length === 0 ? (
                <Card>
                  <Empty
                    icon="activity"
                    title="暂无活跃 peer 会话"
                    description="客户端之间建立直连或 relay 链路后，活跃会话会出现在这里。"
                    actions={<Button color="primary" size="sm" onPress={() => { window.location.hash = "/help/peer-mesh"; }}>查看组网配置说明</Button>}
                  />
                </Card>
              ) : (
                <div className="ms-master" data-detail={mobileDetailOpen ? "open" : undefined}>
                  <Card className="ms-master-list">
                    <div className="ms-master-head">
                      <h3 className="bd-card-title">会话</h3>
                      <span className="jd-subtle jd-small bd-num">有效 {activeSessions.length} / 未关闭 {sessionTotal}</span>
                    </div>
                    {sessionsLoading && activeSessions.length === 0 ? (
                      <div className="ms-loading ms-pad" role="status"><span className="ms-spinner" aria-hidden="true" />正在加载…</div>
                    ) : (
                      <ul className="ms-session-list">
                        {activeSessions.map((s) => {
                          const pathType = effectivePeerSessionPathType(s);
                          const selected = selectedSession?.id === s.id;
                          return (
                            <li key={s.id}>
                              <button
                                type="button"
                                className="ms-session-row"
                                aria-pressed={selected}
                                onClick={() => { setSelectedSession(s); setMobileDetailOpen(true); }}
                              >
                                <span className="ms-session-main">
                                  <span className="ms-cell-title jd-ellipsis">{s.sourceClientName} → {s.targetClientName}</span>
                                  <span className="ms-session-meta">
                                    <Tag tone={pathTone(pathType)}>{pathType}</Tag>
                                    {s.rttMillis != null ? <span className="bd-num">{s.rttMillis} ms</span> : null}
                                    {s.lastKeepaliveAt ? <span>保活 <RelativeTime value={s.lastKeepaliveAt} /></span> : null}
                                  </span>
                                </span>
                                <Icon name="chevron-right" size={16} className="ms-session-chevron" />
                              </button>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                    {sessionTotalPages > 1 ? (
                      <SessionPager page={sessionPage} totalPages={sessionTotalPages} onChange={setSessionPage} />
                    ) : null}
                  </Card>
                  <Card className="ms-master-detail">
                    <div className="ms-master-back">
                      <button type="button" className="bd-btn bd-btn--ghost bd-btn--sm" onClick={() => setMobileDetailOpen(false)}>
                        <Icon name="chevron-left" />
                        <span>返回会话列表</span>
                      </button>
                    </div>
                    {selectedSession ? (
                      <SessionDetail session={selectedSession} onDisconnect={(s) => void closeSession(s)} />
                    ) : (
                      <Empty icon="activity" title="选择一条会话" description="左侧选中后，这里显示路径、端点、保活和流量。" />
                    )}
                  </Card>
                </div>
              )}
            </Section>
          </>
        )}
      </div>

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

const PEER_VIEW_LABEL: Record<PeerMeshViewKey, string> = {
  devices: "设备拓扑",
  services: "服务",
  egress: "出口分流",
  sessions: "活跃会话",
  acl: "ACL",
  nat: "NAT 诊断",
};

function SessionPager({ page, totalPages, onChange }: { page: number; totalPages: number; onChange: (page: number) => void }) {
  return (
    <nav className="bd-pagination ms-pager" aria-label="会话分页">
      <span className="bd-page-total bd-num">第 {page + 1} / {totalPages} 页</span>
      <button type="button" className="bd-page" aria-label="上一页" disabled={page <= 0} onClick={() => onChange(Math.max(0, page - 1))}>
        <Icon name="chevron-left" size={14} />
      </button>
      <button type="button" className="bd-page" aria-label="下一页" disabled={page >= totalPages - 1} onClick={() => onChange(Math.min(totalPages - 1, page + 1))}>
        <Icon name="chevron-right" size={14} />
      </button>
    </nav>
  );
}


/* ──────── SessionDetail 会话详情面板 ──────── */

function SessionDetail({ session, onDisconnect }: { session: PeerMeshSession; onDisconnect: (session: PeerMeshSession) => void }) {
  const pathType = effectivePeerSessionPathType(session);
  return (
    <div className="ms-detail">
      <div className="ms-detail-head">
        <h3 className="ms-detail-title">{session.sourceClientName} → {session.targetClientName}</h3>
        <div className="ms-tags">
          <Tag tone={pathTone(pathType)}>{pathType}</Tag>
          <Tag tone={session.status === "ACTIVE" ? "success" : session.status === "CLOSED" ? "danger" : "neutral"}>{session.status}</Tag>
        </div>
      </div>
      <DescList
        cols={3}
        items={[
          { label: "RTT", value: session.rttMillis != null ? <span className="bd-num">{session.rttMillis} ms</span> : null },
          { label: "创建", value: session.startedAt ? <RelativeTime value={session.startedAt} /> : null },
          { label: "最后流量", value: session.lastTrafficAt ? <RelativeTime value={session.lastTrafficAt} /> : null },
          { label: "最后保活", value: session.lastKeepaliveAt ? <RelativeTime value={session.lastKeepaliveAt} /> : null },
          { label: "过期", value: session.expiresAt ? <RelativeTime value={session.expiresAt} /> : null },
          { label: "更新", value: session.updatedAt ? <RelativeTime value={session.updatedAt} /> : null },
        ]}
      />
      <div className="ms-detail-group">
        <h4 className="ms-detail-sub">流量</h4>
        <DescList
          cols={2}
          items={[
            { label: "Direct", value: <span className="bd-num ms-strong">{formatBytes(session.directBytes)}</span> },
            { label: "Relay", value: <span className="bd-num ms-strong">{formatBytes(session.relayBytes)}</span> },
          ]}
        />
      </div>
      {session.localEndpoint || session.remoteEndpoint ? (
        <div className="ms-detail-group">
          <h4 className="ms-detail-sub">端点</h4>
          <DescList
            cols={2}
            items={[
              { label: "Local", value: session.localEndpoint ? <span className="ms-mono ms-break">{session.localEndpoint}</span> : null },
              { label: "Remote", value: session.remoteEndpoint ? <span className="ms-mono ms-break">{session.remoteEndpoint}</span> : null },
            ]}
          />
        </div>
      ) : null}
      <div className="ms-detail-actions">
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
    <Section
      title="打洞与路径"
      description={`累计会话 ${stats.totalSessions} · 确立过路径 ${stats.reportedSessions} · 当前活跃 ${stats.activeSessions}`}
    >
      <div className="ms-meter-grid ms-block">
        <Card className="ms-meter">
          <div className="ms-meter-head">
            <span>活跃会话直连占比</span>
            <span className="ms-meter-value bd-num">{ratioPercent == null ? "暂无活跃会话" : `${ratioPercent}%`}</span>
          </div>
          <Progress value={ratioPercent ?? 0} label="活跃会话直连占比" />
          <div className="ms-meter-foot bd-num">
            <span>Direct {stats.activeDirectSessions}</span>
            <span>Relay {stats.activeRelaySessions}</span>
          </div>
          <p className="ms-meter-note">打洞成功率的代理指标：活跃会话里走直连的比例。</p>
          {addressFamilyRows.length > 0 && (
            <div className="ms-tag-row">
              <span className="ms-tag-row-label">实际路径地址族</span>
              {addressFamilyRows.map((item) => (
                <Tag key={item.addressFamily} tone={item.addressFamily === "IPv6" ? "info" : item.addressFamily === "IPv4" ? "success" : "neutral"}>
                  {item.addressFamily} · 活跃 {item.activeSessions} · Direct {item.directSessions} / Relay {item.relaySessions}
                </Tag>
              ))}
            </div>
          )}
        </Card>

        {(stats.natBehaviorDevices ?? 0) > 0 && (
          <Card className="ms-meter">
            <div className="ms-meter-head">
              <span>RFC 5780 双轴完整分类率</span>
              <span className="ms-meter-value bd-num">
                {behaviorRatioPercent == null ? "—" : `${behaviorRatioPercent}%`}
                <span className="ms-meter-of"> {stats.natBehaviorClassifiedDevices} / {stats.natBehaviorDevices} 台</span>
              </span>
            </div>
            <Progress value={behaviorRatioPercent ?? 0} label="RFC 5780 双轴完整分类率" />
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
          </Card>
        )}
      </div>

      {pathTypeRows.length > 0 && (
        <TableWrap className="ms-block">
          <table className="bd-table bd-table--compact jd-stack ms-table" aria-label="路径类型统计">
            <thead>
              <tr>
                <th scope="col">路径</th>
                <th scope="col">状态</th>
                <th scope="col" className="bd-col-num">会话数</th>
                <th scope="col" className="bd-col-num">确立过路径</th>
                <th scope="col" className="bd-col-num">平均 RTT</th>
                <th scope="col" className="bd-col-num">Direct 流量</th>
                <th scope="col" className="bd-col-num">Relay 流量</th>
              </tr>
            </thead>
            <tbody>
              {pathTypeRows.map((row) => (
                <tr key={`${row.pathType}-${row.status}`}>
                  <td>
                    <Tag tone={pathTone(row.pathType)}>{row.pathType}</Tag>
                  </td>
                  <td>
                    <Tag tone={row.status === "ACTIVE" ? "success" : row.status === "CLOSED" ? "neutral" : "warning"} plain={row.status === "CLOSED"}>
                      {row.status}
                    </Tag>
                  </td>
                  <td className="bd-col-num" data-label="会话">{row.sessions}</td>
                  <td className="bd-col-num" data-label="确立">{row.reportedSessions}</td>
                  <td className="bd-col-num" data-label="RTT">{row.avgRttMillis == null ? "—" : `${Math.round(row.avgRttMillis)} ms`}</td>
                  <td className="bd-col-num" data-label="Direct">{formatBytes(row.directBytes)}</td>
                  <td className="bd-col-num" data-label="Relay">{formatBytes(row.relayBytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}

      {natTypeRows.length > 0 && (
        <div className="ms-tag-row">
          <span className="ms-tag-row-label">兼容 NAT 标签</span>
          {natTypeRows.map((item) => (
            <ModelTag key={item.natType} color={natTypeColor(item.natType)}>
              {natTypeLabel(item.natType)} · {item.devices}
            </ModelTag>
          ))}
        </div>
      )}
    </Section>
  );
}

type NatStageState = "done" | "partial" | "none";

function NatStage({ index, title, state, value, detail, tag }: {
  index: number; title: string; state: NatStageState; value: ReactNode; detail: ReactNode; tag: ReactNode;
}) {
  return (
    <li className="ms-stage" data-state={state}>
      <span className="ms-stage-mark" aria-hidden="true">
        {state === "done" ? <Icon name="check" size={14} /> : <span className="bd-num">{index}</span>}
      </span>
      <div className="ms-stage-body">
        <div className="ms-stage-title">{title}</div>
        <div className="ms-stage-value bd-num">{value}</div>
        <div className="ms-stage-detail">{detail}</div>
        <div className="ms-stage-tag">{tag}</div>
      </div>
    </li>
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
  const reportedState: NatStageState = devicesTotal > 0 && stats.reported === devicesTotal ? "done" : stats.reported > 0 ? "partial" : "none";
  const classifiedState: NatStageState = stats.reported > 0 && stats.classified === stats.reported ? "done" : stats.classified > 0 ? "partial" : "none";
  const pathState: NatStageState = stats.reported === 0 ? "none" : stats.relayPreferred > 0 ? "partial" : "done";
  const freshState: NatStageState = stats.reported === 0 ? "none" : stats.fresh >= stats.online && stats.fresh > 0 ? "done" : stats.fresh > 0 ? "partial" : "none";
  return (
    <>
      <Section
        title="检测结果"
        description="原生客户端用业务 UDP socket 执行 RFC 5780，分别上报映射和过滤行为；兼容 NAT 标签只用于识别旧版本。"
      >
        <ol className="ms-stages" aria-label="NAT 检测阶段">
          <NatStage
            index={1}
            title="上报行为"
            state={reportedState}
            value={<>{stats.reported}<span className="ms-stage-of"> / {devicesTotal} 台</span></>}
            detail="至少上报了映射、过滤或探测方式之一"
            tag={reportedState === "done" ? <Tag tone="success">全部上报</Tag> : reportedState === "partial" ? <Tag tone="warning">{devicesTotal - stats.reported} 台未上报</Tag> : <Tag plain>没有上报</Tag>}
          />
          <NatStage
            index={2}
            title="双轴分类"
            state={classifiedState}
            value={<>{stats.classified}<span className="ms-stage-of"> 台</span></>}
            detail="映射与过滤都得到了明确分类"
            tag={classifiedState === "done" ? <Tag tone="success">分类完整</Tag> : classifiedState === "partial" ? <Tag tone="warning">{stats.reported - stats.classified} 台只有兼容标签</Tag> : <Tag plain>等待分类</Tag>}
          />
          <NatStage
            index={3}
            title="路径建议"
            state={pathState}
            value={<>{stats.directFriendly}<span className="ms-stage-of"> 台直连友好</span></>}
            detail={`Relay 优先 ${stats.relayPreferred} 台；最终路径以 ICE 实测为准`}
            tag={pathState === "done" ? <Tag tone="success">可尝试直连</Tag> : pathState === "partial" ? <Tag tone="warning">{stats.relayPreferred} 台建议 Relay</Tag> : <Tag plain>等待上报</Tag>}
          />
          <NatStage
            index={4}
            title="上报新鲜度"
            state={freshState}
            value={<>{stats.fresh}<span className="ms-stage-of"> 台新鲜</span></>}
            detail={`2 分钟内有上报；在线 ${stats.online} 台`}
            tag={freshState === "done" ? <Tag tone="success">在线设备都新鲜</Tag> : freshState === "partial" ? <Tag tone="warning">部分是历史结果</Tag> : <Tag plain>没有新鲜上报</Tag>}
          />
        </ol>
      </Section>

      <Section title="各设备的结果" description="按在线、直连友好程度和上报时间排序。">
        <div className="ms-nat-layout">
          <Card className="ms-nat-dist">
            <div className="ms-meter-head">
              <span>NAT 分布</span>
              <Tag plain>{stats.distribution.length} 类</Tag>
            </div>
            {stats.distribution.length === 0 ? (
              <p className="ms-muted-note">暂无 NAT 上报。</p>
            ) : (
              <div className="ms-dist-list">
                {stats.distribution.map((item) => (
                  <PeerNatDistributionRow key={item.profile.key} item={item} total={Math.max(1, devicesTotal)} />
                ))}
              </div>
            )}
          </Card>

          <div className="min-w-0">
            <FilterBar end={<span className="bd-num">{devices.length} / {devicesTotal} 台</span>}>
              <input
                className="bd-input jd-filter-search"
                type="search"
                aria-label="搜索客户端 NAT 结果"
                placeholder="搜索客户端 / IP / Endpoint"
                value={keyword}
                onChange={(event) => onKeywordChange(event.target.value)}
              />
              <select
                className="bd-select"
                aria-label="筛选客户端 NAT 结果"
                value={filter}
                onChange={(event) => onFilterChange(event.target.value as PeerNatFilterKey)}
              >
                {peerNatFilterOptions.map((option) => (
                  <option key={option.key} value={option.key}>{option.label}</option>
                ))}
              </select>
            </FilterBar>
            <TableWrap>
              <table className="bd-table jd-stack ms-table ms-nat-table" aria-label="客户端 NAT 检测结果">
                <thead>
                  <tr>
                    <th scope="col">客户端</th>
                    <th scope="col">NAT 状态</th>
                    <th scope="col">Endpoint</th>
                    <th scope="col">建议</th>
                    <th scope="col">上报</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && devices.length === 0 ? <TableLoadingRow colSpan={5} /> : null}
                  {!loading && devices.length === 0 ? (
                    <TableStateRow colSpan={5}>
                      <Empty
                        icon="locate"
                        title="暂无客户端 NAT 检测结果"
                        description={keyword || filter !== "all" ? "换个关键词，或把筛选改回“全部设备”。" : "启用私有组网的原生客户端登录后会自动检测并上报。"}
                      />
                    </TableStateRow>
                  ) : null}
                  {devices.map((device) => {
                    const profile = peerNatProfile(device);
                    const reportAt = peerNatLastReportAt(device);
                    return (
                      <tr key={device.clientId}>
                        <td>
                          <div className="ms-cell-main">
                            <span className="ms-cell-title">{device.clientName}</span>
                            <span className="ms-cell-sub ms-mono">{device.virtualIp || "—"}</span>
                          </div>
                        </td>
                        <td className="ms-wrap">
                          <div className="ms-cell-main">
                            <span className="ms-tags">
                              <ModelTag color={profile.tone}>{profile.label}</ModelTag>
                              <Tag tone={device.online ? "success" : "neutral"} plain={!device.online}>{device.online ? "在线" : "离线"}</Tag>
                            </span>
                            <PeerNatBehaviorLine device={device} />
                          </div>
                        </td>
                        <td data-label="Endpoint" className={device.lastEndpoint ? "ms-wrap" : "is-empty"}>
                          <span className="ms-mono ms-break ms-cell-sub">{device.lastEndpoint || "—"}</span>
                        </td>
                        <td className="ms-wrap jd-cell-full">
                          <div className="ms-cell-main">
                            <span className="ms-strong">{profile.reachabilityLabel}</span>
                            <span className="ms-cell-sub">{profile.recommendation}</span>
                          </div>
                        </td>
                        <td data-label="上报" className={reportAt ? undefined : "is-empty"}>
                          {reportAt ? (
                            <span className="ms-cell-main">
                              <RelativeTime value={reportAt} />
                              <ModelTag color={peerNatFreshnessColor(device)}>{peerNatFreshnessLabel(device)}</ModelTag>
                            </span>
                          ) : "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </TableWrap>
          </div>
        </div>
      </Section>

      <Section
        title="NAT 行为分类"
        description="映射与过滤是相互独立的两个轴，路径选择以实际 ICE 连通性为最终依据。"
        actions={<Button as="a" href="#/help/peer-mesh" size="sm" variant="flat" endContent={<Icon name="arrow-up-right" size={14} />}>查看详细文档</Button>}
      >
        <div className="ms-axis-grid">
          {NAT_BEHAVIOR_AXES.map((axis) => (
            <Card key={axis.title} className="ms-axis">
              <div className="ms-axis-head">
                <h3 className="bd-card-title">{axis.title}</h3>
                <p className="app-card-desc">{axis.subtitle}</p>
              </div>
              <ul className="ms-axis-list">
                {axis.items.map((item) => (
                  <li key={item.code}>
                    <span className="ms-axis-code">{item.code}</span>
                    <span className="min-w-0">
                      <span className="ms-strong">{item.label}</span>
                      <span className="ms-axis-detail">{item.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      </Section>
    </>
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
    <span className="ms-cell-sub" title={hasBehavior ? `${discovery} · ${detail}` : detail}>
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
    <div className="ms-tag-row">
      <span className="ms-tag-row-label ms-tag-row-label--short">{label}</span>
      {items.map((item) => (
        <Tag
          key={`${label}-${item.behavior}`}
          tone={["UNKNOWN", "UNSUPPORTED"].includes(item.behavior.toUpperCase()) ? "warning" : "neutral"}
        >
          {item.label} · {item.devices}
        </Tag>
      ))}
    </div>
  );
}

function buildPeerNatStats(devices: PeerMeshDevice[]) {
  const distributionMap = new Map<string, { profile: ReturnType<typeof natClassificationProfile>; count: number }>();
  let directFriendly = 0;
  let relayPreferred = 0;
  let reported = 0;
  let classified = 0;
  let fresh = 0;

  for (const device of devices) {
    const profile = peerNatProfile(device);
    const current = distributionMap.get(profile.key);
    distributionMap.set(profile.key, { profile, count: (current?.count ?? 0) + 1 });
    if (device.natType || device.natMappingBehavior || device.natFilteringBehavior || device.natBehaviorDiscovery) {
      reported += 1;
    }
    if (isNatBehaviorClassified(device.natMappingBehavior) && isNatBehaviorClassified(device.natFilteringBehavior)) {
      classified += 1;
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
    classified,
    directFriendly,
    relayPreferred,
    fresh,
    distribution,
  };
}

function isNatBehaviorClassified(behavior: string | null | undefined) {
  return Boolean(behavior) && !["UNKNOWN", "UNSUPPORTED"].includes(String(behavior).toUpperCase());
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
    <div className="ms-dist-row">
      <div className="ms-dist-head">
        <span className="ms-dist-name">
          <ModelTag color={item.profile.tone}>{item.profile.shortLabel}</ModelTag>
          <span className="jd-ellipsis jd-muted">{item.profile.reachabilityLabel}</span>
        </span>
        <span className="bd-num jd-muted">{item.count} 台 · {percent}%</span>
      </div>
      <div className="ms-dist-bar" data-tone={item.profile.tone} aria-hidden="true">
        <span style={{ width: `${percent}%` }} />
      </div>
    </div>
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

function TopologyView({ devices, sessions }: { devices: PeerMeshDevice[]; sessions: PeerMeshSession[] }) {
  const enabledDevices = devices.filter((device) => device.enabled);
  const topologyLinks = useMemo(() => buildTopologyLinks(devices, sessions), [devices, sessions]);
  const shownDevices = enabledDevices.length > 0 ? enabledDevices : devices;
  const hiddenDeviceCount = Math.max(0, shownDevices.length - 8);
  const hiddenLinkCount = Math.max(0, topologyLinks.length - 12);

  return (
    <Section
      title="组网拓扑"
      description="按客户端对聚合；ICE、direct 与 relay 的明细在“活跃会话”里。"
      actions={<>
        <Tag plain className="bd-num">{topologyLinks.length} 条逻辑链路</Tag>
        <Tag plain className="bd-num">{sessions.length} 个会话</Tag>
      </>}
    >
      <div className="ms-node-grid">
        {shownDevices.slice(0, 8).map((device) => (
          <div key={device.clientId} className="bd-card ms-node" data-online={device.online ? "true" : undefined}>
            <span className="ms-node-icon" aria-hidden="true"><Icon name="monitor" size={18} /></span>
            <div className="ms-node-main">
              <div className="ms-node-name jd-ellipsis">{device.clientName}</div>
              <div className="ms-mono ms-cell-sub">{device.virtualIp || "—"}</div>
              <div className="ms-node-meta">
                {device.ownerUsername ? <span>{device.ownerUsername}</span> : null}
                <span>{peerNatProfile(device).shortLabel}</span>
              </div>
            </div>
            <Tag tone={device.online ? "success" : "neutral"} className="ms-node-tag">{device.online ? "在线" : "离线"}</Tag>
          </div>
        ))}
      </div>
      {hiddenDeviceCount > 0 && (
        <p className="ms-muted-note">只显示前 8 台设备，其余 {hiddenDeviceCount} 台在下面的设备表里。</p>
      )}

      <div className="ms-link-grid">
        {topologyLinks.length === 0 ? (
          <div className="ms-link-empty">
            <Icon name="link" size={16} />
            <span>暂无活跃 peer 链路。两台已启用的设备互相访问后，这里会出现它们之间的链路。</span>
          </div>
        ) : (
          topologyLinks.slice(0, 12).map((link) => {
            const session = link.representative;
            const pathType = effectivePeerSessionPathType(session);
            return (
              <div key={link.key} className="bd-card ms-link">
                <div className="ms-link-head">
                  <div className="min-w-0">
                    <div className="ms-link-ends">
                      <span className="jd-ellipsis">{link.firstName}</span>
                      <span className="ms-link-sep" aria-label="与">↔</span>
                      <span className="jd-ellipsis">{link.secondName}</span>
                    </div>
                    <div className="ms-mono ms-cell-sub">{link.firstIp} ↔ {link.secondIp}</div>
                  </div>
                  <ModelTag color={pathColor(pathType, session.status)}>{pathType} · {session.status}</ModelTag>
                </div>
                <DescList
                  cols={4}
                  className="ms-link-desc"
                  items={[
                    { label: "会话", value: <span className="bd-num">{link.sessions.length} 个，活跃 {link.activeSessions} 个</span> },
                    { label: "RTT", value: link.rttMillis == null ? null : <span className="bd-num">{link.rttMillis} ms</span> },
                    { label: "最后活动", value: link.lastActivityAt ? <RelativeTime value={link.lastActivityAt} /> : null },
                    { label: "Direct", value: <span className="bd-num">{link.directSessions} 个 · {formatBytes(link.directBytes)}</span> },
                    { label: "Relay", value: <span className="bd-num">{link.relaySessions} 个 · {formatBytes(link.relayBytes)}</span> },
                    { label: "总流量", value: <span className="bd-num">{formatBytes(link.totalBytes)}</span> },
                    { label: "两端在线", value: `${link.firstOnline ? "是" : "否"} / ${link.secondOnline ? "是" : "否"}` },
                  ]}
                />
              </div>
            );
          })
        )}
      </div>
      {hiddenLinkCount > 0 && (
        <p className="ms-muted-note">只显示前 12 条链路，其余 {hiddenLinkCount} 条在“活跃会话”里。</p>
      )}
    </Section>
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
        firstIp: first?.virtualIp || "—",
        secondIp: second?.virtualIp || "—",
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

function pathTone(pathType: string): "success" | "warning" | "neutral" {
  return pathType === "DIRECT" ? "success" : pathType === "RELAY" ? "warning" : "neutral";
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
