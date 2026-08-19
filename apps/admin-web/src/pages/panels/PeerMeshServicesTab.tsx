import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  Chip,
  Input,
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

const applications = ["http", "https", "ssh", "tcp", "udp"] as const;

function healthChip(service: PeerMeshSharedService): { color: "success" | "warning" | "default"; text: string } {
  if (!service.enabled) {
    return { color: "default", text: "已关闭" };
  }
  const instances = service.instances ?? [];
  if (instances.some((item) => item.advertised && item.online)) {
    return { color: "success", text: "已发布" };
  }
  if (instances.some((item) => item.online)) {
    return { color: "warning", text: "在线未探测到" };
  }
  return { color: "default", text: "已启用 · 未上报" };
}

function instanceSummary(service: PeerMeshSharedService): string {
  const instances = service.instances ?? [];
  if (instances.length === 0) {
    return "无上报实例";
  }
  return instances
    .map((item) => {
      const state = item.advertised ? "已发布" : item.online ? "在线" : "离线";
      const bytes = (item.bytesIn ?? 0) + (item.bytesOut ?? 0);
      const traffic = bytes > 0 ? ` · ${formatBytes(bytes)}` : "";
      const conns = item.activeConnections ? ` · ${item.activeConnections} 连接` : "";
      return `${item.publisherSessionId} ${state}${traffic}${conns}`;
    })
    .join("；");
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
  const [updatingShare, setUpdatingShare] = useState(false);
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

  const load = useCallback(async () => {
    try {
      const [nextSharing, nextServices, nextAudits] = await Promise.all([
        adminApi.peerMeshServiceSharing(),
        adminApi.listPeerMeshServices(),
        adminApi.listPeerMeshServiceAudit().catch(() => []),
      ]);
      setSharing(nextSharing);
      setServices(nextServices);
      setAudits(nextAudits);
    } catch (error) {
      notifyError(error, "加载 Peer 服务失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const grouped = useMemo(() => {
    const map = new Map<string, PeerMeshSharedService[]>();
    for (const service of services) {
      const key = `${service.clientId}:${service.clientName}`;
      const list = map.get(key) ?? [];
      list.push(service);
      map.set(key, list);
    }
    return [...map.entries()];
  }, [services]);

  const setSharingEnabled = (enabled: boolean) => {
    if (!sharing) {
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
        setUpdatingShare(true);
        try {
          const next = await adminApi.updatePeerMeshServiceSharing(enabled);
          setSharing(next);
          notify(enabled ? "已开启 Peer 服务共享" : "已关闭并撤回服务目录");
        } catch (error) {
          notifyError(error, "更新服务共享失败");
          throw error;
        } finally {
          setUpdatingShare(false);
        }
      },
    });
  };

  const createService = async () => {
    const clientId = Number(draft.clientId);
    if (!clientId) {
      notifyError(new Error("请选择设备"), "新增服务失败");
      return;
    }
    try {
      const created = await adminApi.createPeerMeshService({
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
        enabled: false,
      });
      setServices((items) => [created, ...items.filter((item) => item.id !== created.id)]);
      notify("服务已创建（默认关闭）");
    } catch (error) {
      notifyError(error, "新增服务失败");
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
    const previous = services;
    setServices((items) => items.map((item) => (item.id === service.id ? { ...item, enabled } : item)));
    try {
      const updated = await adminApi.updatePeerMeshService(service.id, { enabled });
      setServices((items) => items.map((item) => (item.id === updated.id ? updated : item)));
    } catch (error) {
      setServices(previous);
      notifyError(error, "更新服务失败");
    }
  };

  const removeService = (service: PeerMeshSharedService) => {
    setConfirm({
      title: "删除服务",
      description: `将删除 ${service.clientName} 上的 ${service.name}，对端目录会立即撤回且不可恢复。`,
      confirmLabel: "删除",
      danger: true,
      action: async () => {
        await adminApi.deletePeerMeshService(service.id);
        setServices((items) => items.filter((item) => item.id !== service.id));
        notify("服务已删除");
      },
    });
  };

  const copyAddress = async (service: PeerMeshSharedService) => {
    if (!service.publishedAddress) {
      notifyError(new Error("设备尚未分配虚拟 IP"), "复制地址失败");
      return;
    }
    await copyTextWithFeedback(service.publishedAddress, "已复制虚拟地址");
  };

  const shareDisabled = !deploymentEnabled || updatingShare || !isAdmin;
  const shareLabel = !deploymentEnabled
    ? "部署端未启用 Peer Mesh，不能开启服务共享"
    : sharing?.configuredEnabled
      ? "已开启 · 仅向在线且 ACL 允许的对端发布已启用服务"
      : "已关闭（默认）· 不会上报本机服务";

  return (
    <section className="space-y-4">
      <div className="flex flex-col gap-2 rounded-md border border-default-200 p-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold">Peer 服务共享</h3>
            <p id="peer-service-sharing-help" className="text-small text-default-500">
              {shareLabel}
            </p>
          </div>
          <Switch
            aria-label="Peer 服务共享"
            aria-describedby="peer-service-sharing-help"
            isSelected={Boolean(sharing?.configuredEnabled)}
            isDisabled={shareDisabled || loading}
            onValueChange={(enabled) => setSharingEnabled(enabled)}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-default-200 pt-2">
          <p id="peer-mdns-help" className="text-small text-default-500">
            允许 mDNS 候选导入（默认关闭）。开启后发布端才浏览本机 DNS-SD，候选不会进入对端目录。
          </p>
          <Switch
            aria-label="允许 mDNS 候选导入"
            aria-describedby="peer-mdns-help"
            isSelected={Boolean(sharing?.mdnsImportEnabled)}
            isDisabled={shareDisabled || loading || !sharing?.configuredEnabled}
            onValueChange={async (enabled) => {
              setUpdatingShare(true);
              try {
                const next = await adminApi.updatePeerMeshServiceSharing(undefined, enabled);
                setSharing(next);
                notify(enabled ? "已允许 mDNS 候选导入" : "已关闭 mDNS 候选导入");
              } catch (error) {
                notifyError(error, "更新 mDNS 导入失败");
              } finally {
                setUpdatingShare(false);
              }
            }}
          />
        </div>
      </div>

      {isAdmin && (
        <div className="grid grid-cols-1 gap-2 md:grid-cols-3 xl:grid-cols-7">
          <Select
            aria-label="发布设备"
            label="设备"
            selectedKeys={draft.clientId ? [draft.clientId] : []}
            onSelectionChange={(keys) => setDraft((current) => ({ ...current, clientId: String([...keys][0] ?? "") }))}
          >
            {devices.map((device) => (
              <SelectItem key={String(device.clientId)}>{device.clientName}</SelectItem>
            ))}
          </Select>
          <Input label="名称" value={draft.name} onValueChange={(name) => setDraft((current) => ({ ...current, name }))} />
          <Select
            aria-label="应用类型"
            label="类型"
            selectedKeys={[draft.application]}
            onSelectionChange={(keys) =>
              setDraft((current) => ({ ...current, application: String([...keys][0] ?? "tcp") }))
            }
          >
            {applications.map((item) => (
              <SelectItem key={item}>{item}</SelectItem>
            ))}
          </Select>
          <Input
            label="本机目标"
            value={draft.targetHost}
            onValueChange={(targetHost) => setDraft((current) => ({ ...current, targetHost }))}
          />
          <Input
            label="目标端口"
            value={draft.targetPort}
            onValueChange={(targetPort) => setDraft((current) => ({ ...current, targetPort }))}
          />
          <Input
            label="发布端口"
            value={draft.publishedPort}
            onValueChange={(publishedPort) => setDraft((current) => ({ ...current, publishedPort }))}
          />
          <Select
            aria-label="可见范围"
            label="可见范围"
            selectedKeys={[draft.visibility]}
            onSelectionChange={(keys) =>
              setDraft((current) => ({ ...current, visibility: String([...keys][0] ?? "OWNER") }))
            }
          >
            <SelectItem key="OWNER">同归属</SelectItem>
            <SelectItem key="ACL">ACL</SelectItem>
          </Select>
          {draft.visibility === "ACL" && (
            <Select
              aria-label="允许的客户端"
              label="允许的客户端"
              selectionMode="multiple"
              selectedKeys={new Set(draft.allowedClientIds)}
              onSelectionChange={(keys) =>
                setDraft((current) => ({ ...current, allowedClientIds: [...keys].map(String) }))
              }
            >
              {devices
                .filter((device) => String(device.clientId) !== draft.clientId)
                .map((device) => (
                  <SelectItem key={String(device.clientId)}>{device.clientName}</SelectItem>
                ))}
            </Select>
          )}
          <div className="flex items-end">
            <Button color="primary" onPress={() => void createService()}>
              新增（默认关闭）
            </Button>
          </div>
          <div className="flex items-end gap-2">
            <Button
              variant="flat"
              isDisabled={!draft.clientId || importing}
              onPress={() => void importCandidates()}
            >
              从 TCP/HTTP 导入候选
            </Button>
            <Button
              variant="flat"
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
        grouped.map(([group, items]) => (
          <div key={group} className="space-y-2">
            <h4 className="text-small font-semibold text-default-600">{items[0]?.clientName}</h4>
            <Table aria-label={`${items[0]?.clientName} 的 Peer 服务`} removeWrapper>
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
                {items.map((service) => (
                  <TableRow key={service.id}>
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
                      <Chip size="sm" color={healthChip(service).color} variant="flat">
                        {healthChip(service).text}
                      </Chip>
                    </TableCell>
                    <TableCell>
                      <span className="text-tiny text-default-500">{instanceSummary(service)}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-2">
                        {isAdmin && (
                          <Switch
                            aria-label={`启用 ${service.name}`}
                            isSelected={service.enabled}
                            onValueChange={(enabled) => void toggleService(service, enabled)}
                          />
                        )}
                        <Button size="sm" variant="flat" onPress={() => void copyAddress(service)}>
                          复制地址
                        </Button>
                        {isAdmin && (
                          <Button size="sm" color="danger" variant="light" onPress={() => removeService(service)}>
                            删除
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
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
