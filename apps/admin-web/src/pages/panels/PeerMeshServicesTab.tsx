import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@heroui/react";
import { adminApi, recordWorkbenchOpenAsCaller } from "../../api/client";
import type {
  PeerMeshDevice,
  PeerMeshServiceAuditEvent,
  PeerMeshServiceSharing,
  PeerMeshSharedService,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmModal } from "../../components/ConfirmModal";
import { Alert, Card, CardBody, Empty, Icon, RelativeTime, Section, TableWrap } from "../../components/ui";
import { notify, notifyError } from "../../components/toast";
import { copyTextWithFeedback } from "../../lib/clipboard";
import { copyThenRecord } from "../../lib/workbenchRecording";
import {
  groupPeerMeshServices,
  PeerMeshOperationLocks,
  peerServiceAvailability,
  peerServiceSharingControl,
  peerDirectoryCheckGuidance,
  type PeerMeshServiceInstanceRow,
} from "./peerMeshServicesModel";
import { CheckGroup, ModelTag, RadioCards, SelectField, SettingRow, TextField, Toggle } from "./meshSystemParts";

const applications = ["http", "https", "ssh", "tcp", "udp"] as const;

function instanceSummary(row: PeerMeshServiceInstanceRow): string {
  const instance = row.instance;
  if (!instance) {
    return row.availability.reason;
  }
  const bytes = (instance.bytesIn ?? 0) + (instance.bytesOut ?? 0);
  const traffic = bytes > 0 ? ` · ${formatBytes(bytes)}` : "";
  const conns = instance.activeConnections ? ` · ${instance.activeConnections} 个活动连接` : "";
  return `${row.availability.reason}${traffic}${conns}`;
}

function statusChip(row: PeerMeshServiceInstanceRow): { color: "success" | "warning" | "default"; text: string } {
  if (row.availability.available) {
    return { color: "success", text: "目录可用" };
  }
  if (row.availability.state === "offline" || row.availability.state === "expired") {
    return { color: "warning", text: row.availability.reason };
  }
  return { color: "default", text: row.availability.reason };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function PeerMeshServicesTab({
  deploymentEnabled,
  devices,
}: {
  deploymentEnabled: boolean;
  devices: PeerMeshDevice[];
}) {
  const { profile } = useAuth();
  const isAdmin = Boolean(profile?.admin);
  const [sharing, setSharing] = useState<PeerMeshServiceSharing | null>(null);
  const [services, setServices] = useState<PeerMeshSharedService[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [updatingShare, setUpdatingShare] = useState(false);
  const [updatingServices, setUpdatingServices] = useState<Set<number>>(new Set());
  const [testingInstances, setTestingInstances] = useState<Set<string>>(new Set());
  const [directoryChecks, setDirectoryChecks] = useState<Record<string, { checkedAt: string; result: string; detail: string }>>({});
  const [deletingServices, setDeletingServices] = useState<Set<number>>(new Set());
  const [savingService, setSavingService] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const loadInFlight = useRef<Promise<void> | null>(null);
  const operationLocks = useRef(new PeerMeshOperationLocks());
  const [confirm, setConfirm] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    danger?: boolean;
    action: () => Promise<void>;
  } | null>(null);
  const [audits, setAudits] = useState<PeerMeshServiceAuditEvent[]>([]);
  const [importing, setImporting] = useState(false);
  const [draft, setDraft] = useState({
    clientId: "",
    name: "",
    application: "http",
    targetHost: "127.0.0.1",
    targetPort: "80",
    publishedPort: "8080",
    path: "/",
    visibility: "OWNER",
    allowedClientIds: [] as string[],
  });

  const load = useCallback((silent = false): Promise<void> => {
    if (loadInFlight.current) {
      return loadInFlight.current;
    }
    if (!silent) {
      setLoading(true);
    }
    const pending = (async () => {
      try {
        const [nextSharing, nextServices, nextAudits] = await Promise.all([
          adminApi.peerMeshServiceSharing(),
          adminApi.listPeerMeshServices(),
          adminApi.listPeerMeshServiceAudit().catch(() => []),
        ]);
        setSharing(nextSharing);
        setServices(nextServices);
        setAudits(nextAudits);
        setLoadError(null);
      } catch (error) {
        setLoadError(error instanceof Error ? error.message : "无法读取 Peer 服务状态");
        if (!silent) {
          notifyError(error, "加载 Peer 服务失败");
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    })();
    loadInFlight.current = pending;
    void pending.finally(() => {
      if (loadInFlight.current === pending) {
        loadInFlight.current = null;
      }
    });
    return pending;
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(true), 5_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const grouped = useMemo(
    () => groupPeerMeshServices(services, Boolean(sharing?.effectiveEnabled)),
    [services, sharing?.effectiveEnabled],
  );

  const setSharingEnabled = (enabled: boolean) => {
    if (!sharing || updatingShare || confirm) {
      return;
    }
    const enabledCount = sharing.enabledServiceCount;
    setConfirm({
      title: enabled ? "开启 Peer 服务共享" : "关闭并撤回服务目录",
      description: enabled
        ? enabledCount > 0
          ? `将恢复 ${enabledCount} 个历史上已启用服务的发布资格。仅对在线且 ACL 允许的对端可见，默认仍不扫描本机端口。`
          : "开启后仅向在线且 ACL 允许的对端发布已启用服务。不会扫描局域网或全端口。"
        : "将立即撤回服务目录、拒绝新的服务桥接，并关闭由本功能建立的连接。基础 Peer Mesh 不受影响。",
      confirmLabel: enabled ? "开启" : "关闭并撤回",
      danger: !enabled,
      action: async () => {
        if (!operationLocks.current.acquire("sharing")) {
          return;
        }
        setUpdatingShare(true);
        try {
          const next = await adminApi.updatePeerMeshServiceSharing(enabled);
          setSharing(next);
          if (!enabled) {
            setServices((items) => items.map((item) => ({ ...item, instances: [] })));
          }
          await load(true);
          notify(enabled ? "已开启 Peer 服务共享" : "已关闭并撤回服务目录");
        } catch (error) {
          notifyError(error, "更新服务共享失败");
          throw error;
        } finally {
          setUpdatingShare(false);
          operationLocks.current.release("sharing");
        }
      },
    });
  };

  const saveService = async () => {
    if (!operationLocks.current.acquire("save")) {
      return;
    }
    setSavingService(true);
    const clientId = Number(draft.clientId);
    if (!clientId) {
      notifyError(new Error("还没选发布设备：先在“设备”里选一台"), "新增服务失败");
      setSavingService(false);
      operationLocks.current.release("save");
      return;
    }
    try {
      const mutation = {
        clientId,
        name: draft.name.trim(),
        application: draft.application,
        transport: draft.application === "udp" ? "udp" : "tcp",
        targetHost: draft.targetHost.trim(),
        targetPort: Number(draft.targetPort),
        publishedPort: Number(draft.publishedPort),
        path: draft.path.trim(),
        visibility: draft.visibility as "OWNER" | "ACL",
        allowedClientIds: draft.visibility === "ACL"
          ? draft.allowedClientIds.map((id) => Number(id)).filter((id) => id > 0)
          : [],
        enabled: editingId == null ? false : services.find((item) => item.id === editingId)?.enabled ?? false,
      };
      const saved = editingId == null
        ? await adminApi.createPeerMeshService(mutation)
        : await adminApi.updatePeerMeshService(editingId, mutation);
      setServices((items) => [saved, ...items.filter((item) => item.id !== saved.id)]);
      setEditingId(null);
      notify(editingId == null ? "服务已创建（默认关闭）" : "服务设置已保存");
    } catch (error) {
      notifyError(error, "新增服务失败");
    } finally {
      setSavingService(false);
      operationLocks.current.release("save");
    }
  };

  const importMdns = async () => {
    const clientId = Number(draft.clientId);
    if (!clientId) {
      notifyError(new Error("还没选发布设备：先在“设备”里选一台"), "导入失败");
      return;
    }
    setImporting(true);
    try {
      const result = await adminApi.importPeerMeshServices(clientId, "mdns");
      setServices((items) => {
        const next = [...result.services, ...items];
        const seen = new Set<number>();
        return next.filter((item) => {
          if (seen.has(item.id)) {
            return false;
          }
          seen.add(item.id);
          return true;
        });
      });
      notify(`已导入 ${result.created} 个 mDNS 候选（默认关闭），跳过 ${result.skipped} 个`);
    } catch (error) {
      notifyError(error, "导入 mDNS 候选失败");
    } finally {
      setImporting(false);
    }
  };

  const importCandidates = async () => {
    const clientId = Number(draft.clientId);
    if (!clientId) {
      notifyError(new Error("还没选发布设备：先在“设备”里选一台"), "导入失败");
      return;
    }
    setImporting(true);
    try {
      const result = await adminApi.importPeerMeshServices(clientId, "tcp-http");
      setServices((items) => {
        const next = [...result.services, ...items];
        const seen = new Set<number>();
        return next.filter((item) => {
          if (seen.has(item.id)) {
            return false;
          }
          seen.add(item.id);
          return true;
        });
      });
      notify(`已导入 ${result.created} 个候选（默认关闭），跳过 ${result.skipped} 个`);
    } catch (error) {
      notifyError(error, "导入 TCP/HTTP 候选失败");
    } finally {
      setImporting(false);
    }
  };

  const toggleService = async (service: PeerMeshSharedService, enabled: boolean) => {
    const lockKey = `service:${service.id}`;
    if (!operationLocks.current.acquire(lockKey)) {
      return;
    }
    setUpdatingServices((current) => new Set(current).add(service.id));
    setServices((items) => items.map((item) => (item.id === service.id ? { ...item, enabled } : item)));
    try {
      const updated = await adminApi.updatePeerMeshService(service.id, { enabled });
      setServices((items) => items.map((item) => (item.id === updated.id ? updated : item)));
      setSharing((current) => current == null ? current : {
        ...current,
        enabledServiceCount: Math.max(0, current.enabledServiceCount + (enabled ? 1 : -1)),
      });
    } catch (error) {
      setServices((items) => items.map((item) => (item.id === service.id ? service : item)));
      notifyError(error, "更新服务失败");
    } finally {
      setUpdatingServices((current) => {
        const next = new Set(current);
        next.delete(service.id);
        return next;
      });
      operationLocks.current.release(lockKey);
    }
  };

  const editService = (service: PeerMeshSharedService) => {
    setEditingId(service.id);
    setDraft({
      clientId: String(service.clientId),
      name: service.name,
      application: service.application,
      targetHost: service.targetHost ?? "127.0.0.1",
      targetPort: String(service.targetPort ?? 0),
      publishedPort: String(service.publishedPort),
      path: service.path ?? "",
      visibility: service.visibility,
      allowedClientIds: (service.allowedClientIds ?? []).map(String),
    });
  };

  const removeService = (service: PeerMeshSharedService) => {
    setConfirm({
      title: "删除服务",
      description: `将删除 ${service.clientName} 上的 ${service.name}，对端目录会立即撤回且不可恢复。`,
      confirmLabel: "删除",
      danger: true,
      action: async () => {
        const lockKey = `service:${service.id}`;
        if (!operationLocks.current.acquire(lockKey)) {
          return;
        }
        setDeletingServices((current) => new Set(current).add(service.id));
        try {
          await adminApi.deletePeerMeshService(service.id);
          setServices((items) => items.filter((item) => item.id !== service.id));
          notify("服务已删除");
        } catch (error) {
          notifyError(error, "删除服务失败");
          throw error;
        } finally {
          setDeletingServices((current) => {
            const next = new Set(current);
            next.delete(service.id);
            return next;
          });
          operationLocks.current.release(lockKey);
        }
      },
    });
  };

  const copyAddress = async (row: PeerMeshServiceInstanceRow) => {
    if (!row.availability.available || !row.service.publishedAddress) {
      notifyError(new Error(row.availability.reason), "复制地址失败");
      return;
    }
    // Copying the address is how a Peer service is opened: it counts for 「最近打开」 once copied.
    await copyThenRecord(() => copyTextWithFeedback(row.service.publishedAddress!, "已复制虚拟地址"),
      () => recordWorkbenchOpenAsCaller("peer-service.copy-address", { kind: "peer-service", id: row.service.id }));
  };

  const checkDirectoryStatus = async (row: PeerMeshServiceInstanceRow) => {
    const lockKey = `test:${row.key}`;
    if (!operationLocks.current.acquire(lockKey)) {
      return;
    }
    setTestingInstances((current) => new Set(current).add(row.key));
    try {
      const [latest, latestSharing] = await Promise.all([adminApi.listPeerMeshServices(), adminApi.peerMeshServiceSharing()]);
      setServices(latest);
      setSharing(latestSharing);
      setLoadError(null);
      const service = latest.find((item) => item.id === row.service.id);
      const instance = service?.instances?.find((item) =>
        item.publisherSessionId === row.instance?.publisherSessionId) ?? null;
      const availability = service
        ? peerServiceAvailability(service, instance, latestSharing.effectiveEnabled)
        : { available: false, state: "disabled" as const, reason: "服务已撤回或删除" };
      setDirectoryChecks((current) => ({ ...current, [row.key]: {
        checkedAt: new Date().toISOString(), result: availability.available ? "目录有效" : availability.reason,
        detail: peerDirectoryCheckGuidance(availability),
      } }));
      notify(`目录检查：${availability.available ? "目录有效，目标连通性未检测" : availability.reason}`, availability.available ? undefined : "error");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "无法读取 Peer 服务状态");
      setDirectoryChecks((current) => ({ ...current, [row.key]: { checkedAt: new Date().toISOString(), result: "检查失败，状态未知", detail: "读不到后台：检查网络后重新检查；本次没有验证目标连通性。" } }));
      notifyError(error, "目录检查失败");
    } finally {
      setTestingInstances((current) => {
        const next = new Set(current);
        next.delete(row.key);
        return next;
      });
      operationLocks.current.release(lockKey);
    }
  };

  const sharingControl = peerServiceSharingControl({
    deploymentEnabled,
    isAdmin,
    loading,
    loadError,
    updating: updatingShare,
    sharing,
  });

  const setMdnsImportEnabled = async (enabled: boolean) => {
    if (!operationLocks.current.acquire("sharing")) {
      return;
    }
    setUpdatingShare(true);
    try {
      const next = await adminApi.updatePeerMeshServiceSharing(undefined, enabled);
      setSharing(next);
      notify(enabled ? "已允许 mDNS 候选导入" : "已关闭 mDNS 候选导入");
    } catch (error) {
      notifyError(error, "更新 mDNS 导入失败");
    } finally {
      setUpdatingShare(false);
      operationLocks.current.release("sharing");
    }
  };

  return (
    <div className="ms-tab" aria-busy={loading || updatingShare}>
      <Alert tone="info" title="目录状态不等于目标可连接" className="ms-block">
        目录状态只说明设备上报是否在线、服务记录是否有效。在已加入私有组网的设备上打开或连接发布地址，才能验证实际访问。
      </Alert>
      {loadError && (
        <Alert
          tone="danger"
          role="alert"
          title="Peer 服务状态未知"
          className="ms-block"
          actions={<Button size="sm" color="danger" variant="flat" startContent={<Icon name="refresh" />} onPress={() => void load()}>重新加载</Button>}
        >
          {loadError}。检查后台连接后重新加载；在此之前各服务的状态都按未知处理。
        </Alert>
      )}

      <Section title="服务共享" description="两个开关都立即生效，作用于本组织的全部设备。">
        <Card className="ms-settings">
          <SettingRow
            title="Peer 服务共享"
            description={sharingControl.label}
            descriptionId="peer-service-sharing-help"
            control={(
              <Toggle
                label="Peer 服务共享"
                describedBy="peer-service-sharing-help"
                busy={updatingShare}
                checked={sharingControl.selected}
                disabled={sharingControl.disabled}
                onChange={(enabled) => setSharingEnabled(enabled)}
              />
            )}
          />
          <SettingRow
            title="允许 mDNS 候选导入"
            description="默认关闭。开启后发布端才浏览本机 DNS-SD，候选不会进入对端目录。"
            descriptionId="peer-mdns-help"
            control={(
              <Toggle
                label="允许 mDNS 候选导入"
                describedBy="peer-mdns-help"
                busy={updatingShare}
                checked={Boolean(sharing?.mdnsImportEnabled)}
                disabled={sharingControl.disabled || !sharing?.configuredEnabled}
                onChange={(enabled) => void setMdnsImportEnabled(enabled)}
              />
            )}
          />
        </Card>
      </Section>

      {isAdmin && (
        <Section
          title={editingId == null ? "新增服务" : "编辑服务"}
          description="新增的服务默认关闭；在服务目录里启用后，才向获授权的对端发布。"
        >
          <Card>
            <CardBody>
              <div className="bd-form-grid ms-service-form">
                <SelectField
                  label="设备"
                  value={draft.clientId}
                  placeholder="选择发布设备"
                  onChange={(clientId) => setDraft((current) => ({ ...current, clientId }))}
                  options={devices.map((device) => ({ value: String(device.clientId), label: device.clientName }))}
                />
                <TextField label="名称" value={draft.name} placeholder="grafana" onChange={(name) => setDraft((current) => ({ ...current, name }))} />
                <SelectField
                  label="类型"
                  value={draft.application}
                  onChange={(application) => setDraft((current) => ({ ...current, application: application || "tcp" }))}
                  options={applications.map((item) => ({ value: item, label: item }))}
                />
                <TextField
                  label="本机目标"
                  value={draft.targetHost}
                  help="发布端本机能访问到的地址"
                  onChange={(targetHost) => setDraft((current) => ({ ...current, targetHost }))}
                />
                <TextField
                  label="目标端口"
                  inputMode="numeric"
                  value={draft.targetPort}
                  onChange={(targetPort) => setDraft((current) => ({ ...current, targetPort }))}
                />
                <TextField
                  label="发布端口"
                  inputMode="numeric"
                  value={draft.publishedPort}
                  help="对端通过虚拟 IP 的这个端口访问"
                  onChange={(publishedPort) => setDraft((current) => ({ ...current, publishedPort }))}
                />
                <div className="bd-col-full">
                  <RadioCards
                    legend="可见范围"
                    value={draft.visibility === "ACL" ? "ACL" : "OWNER"}
                    onChange={(visibility) => setDraft((current) => ({ ...current, visibility }))}
                    options={[
                      { value: "OWNER", title: "同归属", description: "同一用户的设备都能在目录里看到它" },
                      { value: "ACL", title: "ACL", description: "只有下面勾选的客户端能看到它" },
                    ]}
                  />
                </div>
                {draft.visibility === "ACL" && (
                  <div className="bd-col-full">
                    <CheckGroup
                      legend="允许的客户端"
                      values={draft.allowedClientIds}
                      onChange={(allowedClientIds) => setDraft((current) => ({ ...current, allowedClientIds }))}
                      options={devices
                        .filter((device) => String(device.clientId) !== draft.clientId)
                        .map((device) => ({ value: String(device.clientId), label: device.clientName }))}
                      empty="除发布设备外没有其他组网设备"
                    />
                  </div>
                )}
              </div>
            </CardBody>
            <div className="bd-card-footer ms-form-foot">
              <div className="ms-row-actions">
                <Button
                  size="sm"
                  variant="flat"
                  startContent={<Icon name="download" size={14} />}
                  isDisabled={!draft.clientId || importing}
                  onPress={() => void importCandidates()}
                >
                  导入 TCP/HTTP 候选
                </Button>
                <Button
                  size="sm"
                  variant="flat"
                  startContent={<Icon name="download" size={14} />}
                  isDisabled={!draft.clientId || importing || !sharing?.mdnsImportEnabled}
                  onPress={() => void importMdns()}
                >
                  导入 mDNS 候选
                </Button>
              </div>
              <div className="ms-form-foot-end">
                {editingId != null && (
                  <Button variant="light" isDisabled={savingService} onPress={() => setEditingId(null)}>取消编辑</Button>
                )}
                <Button color="primary" isLoading={savingService} isDisabled={savingService} onPress={() => void saveService()}>
                  {editingId == null ? "新增（默认关闭）" : "保存更改"}
                </Button>
              </div>
            </div>
          </Card>
        </Section>
      )}

      <Section title="服务目录" description="按发布设备和运行实例分组；复制的是对端用来访问的虚拟地址。">
        {grouped.length === 0 ? (
          <Card>
            <Empty icon="server" title="暂无本机服务" description="服务默认关闭。管理员添加并显式启用后，才会向获授权对端发布。" />
          </Card>
        ) : (
          <div className="ms-groups">
            {grouped.map((group) => (
              <div key={group.key} className="ms-group">
                <div className="ms-group-head">
                  <h3 className="ms-group-title">
                    {group.publisherClientName}
                    <span className="ms-cell-sub bd-num">客户端 #{group.publisherClientId}</span>
                  </h3>
                  <span className="ms-mono ms-cell-sub">
                    {group.publisherSessionId == null
                      ? "尚无运行实例"
                      : `会话 ${group.publisherSessionId}${group.instanceId ? ` · 实例 ${group.instanceId}` : ""}`}
                  </span>
                </div>
                <TableWrap>
                  <table className="bd-table jd-stack ms-table" aria-label={`${group.publisherClientName} 会话 ${group.publisherSessionId ?? "未上报"} 的 Peer 服务`}>
                    <thead>
                      <tr>
                        <th scope="col">服务</th>
                        <th scope="col">类型</th>
                        <th scope="col">发布地址</th>
                        <th scope="col">可见范围</th>
                        <th scope="col">状态</th>
                        <th scope="col">运行实例</th>
                        <th scope="col" className="ms-col-actions">操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {group.rows.map((row) => {
                        const service = row.service;
                        const chip = loadError ? { color: "default" as const, text: "状态未知" } : statusChip(row);
                        const rowBusy = updatingServices.has(service.id)
                          || deletingServices.has(service.id)
                          || testingInstances.has(row.key);
                        const check = directoryChecks[row.key];
                        return (
                          <tr key={row.key} aria-busy={rowBusy}>
                            <td>
                              <div className="ms-cell-main">
                                <span className="ms-cell-title">{service.name}</span>
                                <span className="ms-mono ms-cell-sub">{service.serviceId}</span>
                              </div>
                            </td>
                            <td data-label="类型">
                              {service.application}
                              {service.transport === "udp" ? " / udp" : ""}
                            </td>
                            <td data-label="地址" className={service.publishedAddress ? "ms-wrap" : "is-empty"}>
                              <span className="ms-mono ms-break">{service.publishedAddress || "—"}</span>
                            </td>
                            <td data-label="可见">
                              {service.visibility === "ACL"
                                ? `ACL${service.allowedClientIds?.length ? ` · ${service.allowedClientIds.length} 台` : ""}`
                                : "同归属"}
                            </td>
                            <td className="ms-wrap jd-cell-full">
                              <div className="ms-cell-main">
                                <ModelTag color={chip.color}>{chip.text}</ModelTag>
                                {check ? (
                                  <p role="status" className="ms-cell-sub ms-check-result">
                                    上次检查 <RelativeTime value={check.checkedAt} /> · <span className="ms-strong">{check.result}</span>
                                    <br />{check.detail}
                                  </p>
                                ) : <p className="ms-cell-sub">目标连通性未检测</p>}
                              </div>
                            </td>
                            <td data-label="实例" className="ms-wrap">
                              <span className="ms-cell-sub">{instanceSummary(row)}</span>
                            </td>
                            <td className="jd-cell-actions ms-actions-row ms-col-actions">
                              <div className="ms-row-actions">
                                {isAdmin && (
                                  <Toggle
                                    label={`启用 ${service.name}`}
                                    busy={updatingServices.has(service.id)}
                                    checked={service.enabled}
                                    disabled={rowBusy || updatingShare || loadError != null}
                                    onChange={(enabled) => void toggleService(service, enabled)}
                                  />
                                )}
                                {isAdmin && (
                                  <Button size="sm" variant="light" isDisabled={rowBusy} onPress={() => editService(service)}>
                                    编辑
                                  </Button>
                                )}
                                {isAdmin && service.enabled && (
                                  <Button
                                    size="sm"
                                    color="warning"
                                    variant="light"
                                    isDisabled={rowBusy || updatingShare || loadError != null}
                                    onPress={() => void toggleService(service, false)}
                                  >
                                    撤回
                                  </Button>
                                )}
                                <Button
                                  size="sm"
                                  variant="flat"
                                  title={row.availability.available ? "复制当前发布地址" : row.availability.reason}
                                  startContent={<Icon name="copy" size={14} />}
                                  isDisabled={rowBusy || !row.availability.available}
                                  onPress={() => void copyAddress(row)}
                                >
                                  复制地址
                                </Button>
                                <Button
                                  size="sm"
                                  variant="flat"
                                  title="刷新共享开关与实例上报状态，不检测目标连通性"
                                  isLoading={testingInstances.has(row.key)}
                                  isDisabled={rowBusy || updatingShare}
                                  onPress={() => void checkDirectoryStatus(row)}
                                >
                                  检查目录状态
                                </Button>
                                {isAdmin && (
                                  <Button
                                    size="sm"
                                    color="danger"
                                    variant="light"
                                    isLoading={deletingServices.has(service.id)}
                                    isDisabled={rowBusy}
                                    onPress={() => removeService(service)}
                                  >
                                    删除
                                  </Button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </TableWrap>
              </div>
            ))}
          </div>
        )}
      </Section>

      {audits.length > 0 && (
        <Section title="最近审计" description="服务共享相关的最近 8 条操作与拒绝。">
          <Card>
            <ul className="ms-log">
              {audits.slice(0, 8).map((item, index) => (
                <li key={`${item.at}-${item.action}-${index}`}>
                  <span className="ms-mono ms-log-action">{item.action}</span>
                  <span className="ms-log-text">
                    {item.reason ?? ""}
                    {item.serviceId ? <span className="ms-mono ms-cell-sub"> {item.serviceId}</span> : null}
                  </span>
                  {item.at ? <RelativeTime value={item.at} className="ms-log-time" /> : null}
                </li>
              ))}
            </ul>
          </Card>
        </Section>
      )}

      <ConfirmModal
        isOpen={confirm != null}
        onClose={() => setConfirm(null)}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        confirmLabel={confirm?.confirmLabel}
        danger={confirm?.danger}
        onConfirm={async () => {
          if (!confirm) {
            return;
          }
          await confirm.action();
        }}
      />
    </div>
  );
}
