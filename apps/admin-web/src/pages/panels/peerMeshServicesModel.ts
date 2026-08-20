import type {
  PeerMeshServiceSharing,
  PeerMeshSharedService,
  PeerMeshSharedServiceInstance,
} from "../../api/types";

export interface PeerMeshServiceAvailability {
  available: boolean;
  reason: string;
  state: "available" | "disabled" | "offline" | "expired" | "unreported";
}

export interface PeerMeshServiceInstanceRow {
  key: string;
  service: PeerMeshSharedService;
  instance: PeerMeshSharedServiceInstance | null;
  availability: PeerMeshServiceAvailability;
}

export interface PeerMeshPublisherGroup {
  key: string;
  publisherClientId: number;
  publisherClientName: string;
  publisherSessionId: number | null;
  instanceId: string | null;
  rows: PeerMeshServiceInstanceRow[];
}

export class PeerMeshOperationLocks {
  private readonly active = new Set<string>();

  acquire(key: string): boolean {
    if (this.active.has(key)) {
      return false;
    }
    this.active.add(key);
    return true;
  }

  release(key: string): void {
    this.active.delete(key);
  }

  has(key: string): boolean {
    return this.active.has(key);
  }
}

export function peerServiceSharingControl(input: {
  deploymentEnabled: boolean;
  isAdmin: boolean;
  loading: boolean;
  loadError: string | null;
  updating: boolean;
  sharing: PeerMeshServiceSharing | null;
}): { disabled: boolean; selected: boolean; label: string } {
  const { deploymentEnabled, isAdmin, loading, loadError, updating, sharing } = input;
  const label = loading || (sharing == null && loadError == null)
    ? "正在读取服务共享状态…"
    : loadError
      ? "状态未知 · 重新加载后才能操作"
      : !deploymentEnabled
        ? "部署端未启用 Peer Mesh，不能开启服务共享"
        : sharing?.configuredEnabled
          ? "已开启 · 仅向在线且 ACL 允许的对端发布已启用服务"
          : "已关闭（默认）· 不会上报本机服务";
  return {
    disabled: !deploymentEnabled || !isAdmin || loading || updating || loadError != null || sharing == null,
    selected: Boolean(sharing?.configuredEnabled),
    label,
  };
}

export function peerServiceAvailability(
  service: PeerMeshSharedService,
  instance: PeerMeshSharedServiceInstance | null,
  sharingEnabled: boolean,
  now = Date.now(),
): PeerMeshServiceAvailability {
  if (!sharingEnabled) {
    return { available: false, state: "disabled", reason: "全局服务共享已关闭" };
  }
  if (!service.enabled) {
    return { available: false, state: "disabled", reason: "服务配置未启用" };
  }
  if (!instance) {
    return { available: false, state: "unreported", reason: "尚无运行实例上报" };
  }
  if (!instance.online) {
    return { available: false, state: "offline", reason: "发布实例已离线" };
  }
  const expiresAt = Date.parse(instance.expiresAt ?? "");
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    return { available: false, state: "expired", reason: "服务目录已过期" };
  }
  if (!instance.advertised) {
    return { available: false, state: "unreported", reason: "发布实例尚未上报此服务" };
  }
  if (!service.publishedAddress) {
    return { available: false, state: "unreported", reason: "发布实例缺少可用地址" };
  }
  return { available: true, state: "available", reason: "目录可用" };
}

export function groupPeerMeshServices(
  services: PeerMeshSharedService[],
  sharingEnabled: boolean,
  now = Date.now(),
): PeerMeshPublisherGroup[] {
  const groups = new Map<string, PeerMeshPublisherGroup>();
  for (const service of services) {
    const instances = service.instances?.length ? service.instances : [null];
    for (const instance of instances) {
      const sessionId = instance?.publisherSessionId ?? null;
      const key = `${service.clientId}:${sessionId ?? "unreported"}`;
      let group = groups.get(key);
      if (!group) {
        group = {
          key,
          publisherClientId: service.clientId,
          publisherClientName: service.clientName,
          publisherSessionId: sessionId,
          instanceId: instance?.instanceId ?? null,
          rows: [],
        };
        groups.set(key, group);
      }
      group.rows.push({
        key: `${service.id}:${sessionId ?? "unreported"}`,
        service,
        instance,
        availability: peerServiceAvailability(service, instance, sharingEnabled, now),
      });
    }
  }
  return [...groups.values()]
    .map((group) => ({
      ...group,
      rows: group.rows.sort((left, right) =>
        left.service.name.localeCompare(right.service.name, "zh-CN")
          || left.service.serviceId.localeCompare(right.service.serviceId)),
    }))
    .sort((left, right) =>
      left.publisherClientName.localeCompare(right.publisherClientName, "zh-CN")
        || left.publisherClientId - right.publisherClientId
        || (left.publisherSessionId ?? Number.MAX_SAFE_INTEGER)
          - (right.publisherSessionId ?? Number.MAX_SAFE_INTEGER));
}
