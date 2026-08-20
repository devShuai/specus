import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Chip, Input, Label, ListBox, ListBoxItem, Select, SelectIndicator, SelectPopover, SelectTrigger, SelectValue, Spinner, Switch, Table, TableBody, TableCell, TableColumn, TableHeader, TableRow, TextField } from "@heroui/react";
import { adminApi } from "../../api/client";
import type {
  PeerMeshDevice,
  PeerMeshServiceAuditEvent,
  PeerMeshServiceSharing,
  PeerMeshSharedService,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmModal } from "../../components/ConfirmModal";
import { EmptyState } from "../../components/EmptyState";
import { notify, notifyError } from "../../components/toast";
import { copyTextWithFeedback } from "../../lib/clipboard";
import {
  groupPeerMeshServices,
  PeerMeshOperationLocks,
  peerServiceAvailability,
  peerServiceSharingControl,
  type PeerMeshServiceInstanceRow,
} from "./peerMeshServicesModel";

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
      notifyError(new Error("请选择设备"), "新增服务失败");
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
      notifyError(new Error("请选择设备"), "导入失败");
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
      notifyError(new Error("请选择设备"), "导入失败");
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
    await copyTextWithFeedback(row.service.publishedAddress, "已复制虚拟地址");
  };

  const testAvailability = async (row: PeerMeshServiceInstanceRow) => {
    const lockKey = `test:${row.key}`;
    if (!operationLocks.current.acquire(lockKey)) {
      return;
    }
    setTestingInstances((current) => new Set(current).add(row.key));
    try {
      const latest = await adminApi.listPeerMeshServices();
      setServices(latest);
      const service = latest.find((item) => item.id === row.service.id);
      const instance = service?.instances?.find((item) =>
        item.publisherSessionId === row.instance?.publisherSessionId) ?? null;
      const availability = service
        ? peerServiceAvailability(service, instance, Boolean(sharing?.effectiveEnabled))
        : { available: false, reason: "服务已撤回或删除" };
      if (!availability.available) {
        throw new Error(availability.reason);
      }
      notify(`目录可用：${service?.name} · 实例 ${instance?.publisherSessionId}`);
    } catch (error) {
      notifyError(error, "可用性检查失败");
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

  return (
    <section className="space-y-4" aria-busy={loading || updatingShare}>
      {loadError && (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-danger-200 bg-danger-50 p-3 text-small text-danger-700">
          <span>Peer 服务状态未知：{loadError}</span>
          <Button size="sm" variant="danger-soft" onPress={() => void load()}>
            重新加载
          </Button>
        </div>
      )}
      <div className="flex flex-col gap-2 rounded-md border border-default-200 p-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold">Peer 服务共享</h3>
            <p id="peer-service-sharing-help" className="text-small text-default-500">
              {sharingControl.label}
            </p>
          </div>
          <Switch
            aria-label="Peer 服务共享"
            aria-describedby="peer-service-sharing-help"
            aria-busy={updatingShare}
            isSelected={sharingControl.selected}
            isDisabled={sharingControl.disabled}
            onChange={(enabled) => setSharingEnabled(enabled)}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-default-200 pt-2">
          <p id="peer-mdns-help" className="text-small text-default-500">
            允许 mDNS 候选导入（默认关闭）。开启后发布端才浏览本机 DNS-SD，候选不会进入对端目录。
          </p>
          <Switch
            aria-label="允许 mDNS 候选导入"
            aria-describedby="peer-mdns-help"
            aria-busy={updatingShare}
            isSelected={Boolean(sharing?.mdnsImportEnabled)}
            isDisabled={sharingControl.disabled || !sharing?.configuredEnabled}
            onChange={async (enabled) => {
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
            }}
          />
        </div>
      </div>

      {isAdmin && (
        <div className="grid grid-cols-1 gap-2 md:grid-cols-3 xl:grid-cols-7">
          <Select
            aria-label="发布设备"
            onSelectionChange={(key) => setDraft((current) => ({ ...current, clientId: String(key ?? "") }))} selectedKey={draft.clientId || null}>
            <Label>设备</Label>
            <SelectTrigger>
              <SelectValue />
              <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                {devices.map((device) => (
              <ListBoxItem key={String(device.clientId)} id={String(device.clientId)}>{device.clientName}</ListBoxItem>
            ))}
              </ListBox>
            </SelectPopover>
          </Select>
          <TextField value={draft.name} onChange={(name) => setDraft((current) => ({ ...current, name }))}>
            <Label>名称</Label>
            <Input />
          </TextField>
          <Select
            aria-label="应用类型"
            onSelectionChange={(key) =>
              setDraft((current) => ({ ...current, application: String(key ?? "tcp") }))
            } selectedKey={draft.application}>
            <Label>类型</Label>
            <SelectTrigger>
              <SelectValue />
              <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                {applications.map((item) => (
              <ListBoxItem id={item}>{item}</ListBoxItem>
            ))}
              </ListBox>
            </SelectPopover>
          </Select>
          <TextField value={draft.targetHost} onChange={(targetHost) => setDraft((current) => ({ ...current, targetHost }))}>
            <Label>本机目标</Label>
            <Input />
          </TextField>
          <TextField value={draft.targetPort} onChange={(targetPort) => setDraft((current) => ({ ...current, targetPort }))}>
            <Label>目标端口</Label>
            <Input />
          </TextField>
          <TextField value={draft.publishedPort} onChange={(publishedPort) => setDraft((current) => ({ ...current, publishedPort }))}>
            <Label>发布端口</Label>
            <Input />
          </TextField>
          <Select
            aria-label="可见范围"
            onSelectionChange={(key) =>
              setDraft((current) => ({ ...current, visibility: String(key ?? "OWNER") }))
            } selectedKey={draft.visibility}>
            <Label>可见范围</Label>
            <SelectTrigger>
              <SelectValue />
              <SelectIndicator />
            </SelectTrigger>
            <SelectPopover>
              <ListBox>
                <ListBoxItem id="OWNER">同归属</ListBoxItem>
            <ListBoxItem id="ACL">ACL</ListBoxItem>
              </ListBox>
            </SelectPopover>
          </Select>
          {draft.visibility === "ACL" && (
            <Select
              aria-label="允许的客户端"
              selectionMode="multiple"
              onSelectionChange={(keys) =>
                // HeroUI 3 的 onSelectionChange 签名没跟着 selectionMode 走：多选时
                // 运行时收到的是 Set<Key>，类型上却仍标成单个 key。
                setDraft((current) => ({
                  ...current,
                  allowedClientIds: [...(keys as unknown as Iterable<string | number>)].map(String),
                }))
              } selectedKey={new Set(draft.allowedClientIds) as unknown as string | null}>
              <Label>允许的客户端</Label>
              <SelectTrigger>
                <SelectValue />
                <SelectIndicator />
              </SelectTrigger>
              <SelectPopover>
                <ListBox>
                  {devices
                .filter((device) => String(device.clientId) !== draft.clientId)
                .map((device) => (
                  <ListBoxItem key={String(device.clientId)} id={String(device.clientId)}>{device.clientName}</ListBoxItem>
                ))}
                </ListBox>
              </SelectPopover>
            </Select>
          )}
          <div className="flex items-end">
            <Button variant="primary" isDisabled={savingService || savingService} onPress={() => void saveService()}>{savingService ? <Spinner size="sm" /> : null}
              {editingId == null ? "新增（默认关闭）" : "保存更改"}
            </Button>
            {editingId != null && (
              <Button variant="ghost" isDisabled={savingService} onPress={() => setEditingId(null)}>取消编辑</Button>
            )}
          </div>
          <div className="flex items-end gap-2">
            <Button variant="secondary"
              isDisabled={!draft.clientId || importing}
              onPress={() => void importCandidates()}
            >
              从 TCP/HTTP 导入候选
            </Button>
            <Button variant="secondary"
              isDisabled={!draft.clientId || importing || !sharing?.mdnsImportEnabled}
              onPress={() => void importMdns()}
            >
              导入 mDNS 候选
            </Button>
          </div>
        </div>
      )}

      {grouped.length === 0 ? (
        <EmptyState title="暂无本机服务" description="服务默认关闭。管理员添加并显式启用后，才会向获授权对端发布。" />
      ) : (
        grouped.map((group) => (
          <div key={group.key} className="space-y-2 rounded-md border border-default-200 p-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h4 className="text-small font-semibold text-default-700">
                {group.publisherClientName} · 客户端 #{group.publisherClientId}
              </h4>
              <span className="font-mono text-tiny text-default-500">
                {group.publisherSessionId == null
                  ? "尚无运行实例"
                  : `会话 ${group.publisherSessionId}${group.instanceId ? ` · 实例 ${group.instanceId}` : ""}`}
              </span>
            </div>
            <Table aria-label={`${group.publisherClientName} 会话 ${group.publisherSessionId ?? "未上报"} 的 Peer 服务`}>
              <TableHeader>
                <TableColumn>服务</TableColumn>
                <TableColumn>类型</TableColumn>
                <TableColumn>发布地址</TableColumn>
                <TableColumn>可见范围</TableColumn>
                <TableColumn>状态</TableColumn>
                <TableColumn>运行实例</TableColumn>
                <TableColumn>操作</TableColumn>
              </TableHeader>
              <TableBody>
                {group.rows.map((row) => {
                  const service = row.service;
                  const chip = statusChip(row);
                  const rowBusy = updatingServices.has(service.id)
                    || deletingServices.has(service.id)
                    || testingInstances.has(row.key);
                  return (
                  <TableRow key={row.key} aria-busy={rowBusy}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span>{service.name}</span>
                        <span className="font-mono text-tiny text-default-400">{service.serviceId}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      {service.application}
                      {service.transport === "udp" ? " / udp" : ""}
                    </TableCell>
                    <TableCell className="font-mono">{service.publishedAddress || "-"}</TableCell>
                    <TableCell>
                      {service.visibility === "ACL"
                        ? `ACL${service.allowedClientIds?.length ? ` · ${service.allowedClientIds.length} 台` : ""}`
                        : "同归属"}
                    </TableCell>
                    <TableCell>
                      <Chip size="sm" color={chip.color} variant="soft">
                        {chip.text}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <span className="text-tiny text-default-500">{instanceSummary(row)}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-2">
                        {isAdmin && (
                          <Switch
                            aria-label={`启用 ${service.name}`}
                            aria-busy={updatingServices.has(service.id)}
                            isSelected={service.enabled}
                            isDisabled={rowBusy || updatingShare || loadError != null}
                            onChange={(enabled) => void toggleService(service, enabled)}
                          />
                        )}
                        {isAdmin && (
                          <Button size="sm" variant="ghost" isDisabled={rowBusy} onPress={() => editService(service)}>
                            编辑
                          </Button>
                        )}
                        {isAdmin && service.enabled && (
                          <Button
                            size="sm" variant="ghost"
                            isDisabled={rowBusy || updatingShare || loadError != null}
                            onPress={() => void toggleService(service, false)}
                          >
                            撤回
                          </Button>
                        )}
                        <Button
                          size="sm" variant="secondary"
                          isDisabled={rowBusy || !row.availability.available}
                          onPress={() => void copyAddress(row)}
                        >
                          复制地址
                        </Button>
                        <Button
                          size="sm" variant="secondary" isDisabled={rowBusy || !sharing?.effectiveEnabled || !service.enabled || loadError != null || testingInstances.has(row.key)}
                          onPress={() => void testAvailability(row)}
                        >{testingInstances.has(row.key) ? <Spinner size="sm" /> : null}
                          测试可用性
                        </Button>
                        {isAdmin && (
                          <Button
                            size="sm" variant="danger" isDisabled={rowBusy || deletingServices.has(service.id)}
                            onPress={() => removeService(service)}
                          >{deletingServices.has(service.id) ? <Spinner size="sm" /> : null}
                            删除
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        ))
      )}

      {audits.length > 0 && (
        <div className="rounded-md border border-default-200 p-3">
          <h4 className="mb-2 text-small font-semibold text-default-600">最近审计</h4>
          <ul className="space-y-1 text-tiny text-default-500">
            {audits.slice(0, 8).map((item, index) => (
              <li key={`${item.at}-${item.action}-${index}`}>
                {item.action} · {item.reason ?? "-"}
                {item.serviceId ? ` · ${item.serviceId}` : ""}
              </li>
            ))}
          </ul>
        </div>
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
    </section>
  );
}
