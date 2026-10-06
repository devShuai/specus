import type {
  Client,
  HttpRoute,
  PeerMeshServiceSharing,
  PeerMeshSharedService,
  Specus,
  WorkbenchKind,
  WorkbenchRef,
} from "../api/types";
import { WORKBENCH_KINDS } from "../api/types";

// Pending problems of the service workbench, derived only from state the page already reads
// (devices, HTTP routes, TCP mappings, Peer service sharing and Peer services). Nothing here
// probes or checks a target: a device being online never says a service can be reached.
// The rule and its cases live in protocol/test-vectors/service-workbench-v1.json ("problems").

export const PROBLEM_SOURCES = ["clients", "httpRoutes", "tcpMappings", "peerServices"] as const;
export type ProblemSource = typeof PROBLEM_SOURCES[number];

/** ok; failed (network error, 5xx, malformed answer); unsupported (404/405: no such service here). */
export type ProblemSourceState = "ok" | "failed" | "unsupported";

export type ProblemCode =
  | "DEVICE_DISABLED"
  | "DEVICE_OFFLINE"
  | "PEER_SHARING_OFF"
  | "PEER_NOT_REPORTED"
  | "PEER_DIRECTORY_EXPIRED"
  | "PEER_NOT_ADVERTISED";

export type ProblemSeverity = "blocking" | "attention";

/** The order is the rule order: a service appears under the first rule it meets, and only there. */
export const PROBLEM_CODES: ReadonlyArray<{ code: ProblemCode; severity: ProblemSeverity }> = [
  { code: "DEVICE_DISABLED", severity: "blocking" },
  { code: "DEVICE_OFFLINE", severity: "blocking" },
  { code: "PEER_SHARING_OFF", severity: "blocking" },
  { code: "PEER_NOT_REPORTED", severity: "attention" },
  { code: "PEER_DIRECTORY_EXPIRED", severity: "attention" },
  { code: "PEER_NOT_ADVERTISED", severity: "attention" },
];

export interface ProblemServiceState {
  id: number;
  clientId: number;
  enabled: boolean;
}

export interface ProblemPeerInstance {
  online: boolean;
  expired: boolean;
  advertised: boolean;
  hasAddress: boolean;
}

export interface ProblemPeerServiceState extends ProblemServiceState {
  instance: ProblemPeerInstance | null;
}

/** What the page read, abstracted to the fields the rule looks at. */
export interface ProblemInput {
  sources: Record<ProblemSource, ProblemSourceState>;
  clients?: Array<{ id: number; enabled: boolean; online: boolean }>;
  httpRoutes?: ProblemServiceState[];
  tcpMappings?: ProblemServiceState[];
  peerSharing?: { deploymentEnabled: boolean; configuredEnabled: boolean } | null;
  peerServices?: ProblemPeerServiceState[];
}

export interface PendingProblem {
  code: ProblemCode;
  severity: ProblemSeverity;
  /** The device the services run on; absent for the tenant-wide PEER_SHARING_OFF. */
  clientId?: number;
  services: WorkbenchRef[];
}

export interface PendingProblems {
  /** false when any source could not be read: the list is then incomplete, never "no problems". */
  complete: boolean;
  unreadSources: ProblemSource[];
  problems: PendingProblem[];
}

const codeOrder = new Map(PROBLEM_CODES.map((entry, index) => [entry.code, index]));
const severityOf = new Map(PROBLEM_CODES.map((entry) => [entry.code, entry.severity]));

export function kindOrder(kind: WorkbenchKind): number {
  return WORKBENCH_KINDS.indexOf(kind);
}

export function compareRefs(left: WorkbenchRef, right: WorkbenchRef): number {
  return kindOrder(left.kind) - kindOrder(right.kind) || left.id - right.id;
}

export function derivePendingProblems(input: ProblemInput): PendingProblems {
  const { sources } = input;
  const unreadSources = PROBLEM_SOURCES.filter((source) => sources[source] === "failed");
  const clients = sources.clients === "ok"
    ? new Map((input.clients ?? []).map((client) => [client.id, client]))
    : null;

  const services: Array<{ kind: WorkbenchKind; service: ProblemServiceState | ProblemPeerServiceState }> = [];
  if (sources.httpRoutes === "ok") {
    for (const service of input.httpRoutes ?? []) services.push({ kind: "http-route", service });
  }
  if (sources.tcpMappings === "ok") {
    for (const service of input.tcpMappings ?? []) services.push({ kind: "tcp-mapping", service });
  }
  if (sources.peerServices === "ok") {
    for (const service of input.peerServices ?? []) services.push({ kind: "peer-service", service });
  }
  const sharingOn = Boolean(input.peerSharing?.deploymentEnabled) && Boolean(input.peerSharing?.configuredEnabled);

  const found = new Map<string, PendingProblem>();
  for (const { kind, service } of services) {
    if (!service.enabled) continue; // a choice, not a problem
    // A device missing from a list that did load (a race between two reads) is not reported.
    const client = clients?.get(service.clientId);
    let code: ProblemCode | null = null;
    if (client && !client.enabled) {
      code = "DEVICE_DISABLED";
    } else if (client && !client.online) {
      code = "DEVICE_OFFLINE";
    } else if (kind === "peer-service") {
      const instance = (service as ProblemPeerServiceState).instance ?? null;
      if (!sharingOn) code = "PEER_SHARING_OFF";
      else if (!instance || !instance.online) code = "PEER_NOT_REPORTED";
      else if (instance.expired) code = "PEER_DIRECTORY_EXPIRED";
      else if (!instance.advertised || !instance.hasAddress) code = "PEER_NOT_ADVERTISED";
    }
    if (!code) continue;
    const grouped = code !== "PEER_SHARING_OFF";
    const key = grouped ? `${code}:${service.clientId}` : code;
    let problem = found.get(key);
    if (!problem) {
      problem = { code, severity: severityOf.get(code)!, ...(grouped ? { clientId: service.clientId } : {}), services: [] };
      found.set(key, problem);
    }
    problem.services.push({ kind, id: service.id });
  }

  const problems = [...found.values()];
  for (const problem of problems) problem.services.sort(compareRefs);
  problems.sort((left, right) =>
    (left.severity === "blocking" ? 0 : 1) - (right.severity === "blocking" ? 0 : 1)
      || codeOrder.get(left.code)! - codeOrder.get(right.code)!
      || (left.clientId ?? 0) - (right.clientId ?? 0));
  return { complete: unreadSources.length === 0, unreadSources, problems };
}

// ---- from the existing list endpoints -------------------------------------------------------

export type SourceRead<T> = { state: "ok"; data: T } | { state: "failed" } | { state: "unsupported" };

export interface WorkbenchReads {
  clients: SourceRead<Client[]>;
  httpRoutes: SourceRead<HttpRoute[]>;
  tcpMappings: SourceRead<Specus[]>;
  peerSharing: SourceRead<PeerMeshServiceSharing>;
  peerServices: SourceRead<PeerMeshSharedService[]>;
}

/**
 * The state of one Peer service's publisher for the rule: the instance closest to listing it
 * (online, then unexpired, then advertised). The address is the server's authoritative
 * publishedAddress, the same field the Peer service tab copies.
 */
export function peerProblemInstance(service: PeerMeshSharedService, now: number): ProblemPeerInstance | null {
  const instances = service.instances ?? [];
  if (instances.length === 0) return null;
  let best: ProblemPeerInstance | null = null;
  let bestScore = -1;
  for (const instance of instances) {
    const expiresAt = Date.parse(instance.expiresAt ?? "");
    const candidate: ProblemPeerInstance = {
      online: instance.online,
      expired: !Number.isFinite(expiresAt) || expiresAt <= now,
      advertised: instance.advertised,
      hasAddress: Boolean(service.publishedAddress),
    };
    const score = (candidate.online ? 4 : 0) + (candidate.expired ? 0 : 2) + (candidate.advertised ? 1 : 0);
    if (score > bestScore) {
      best = candidate;
      bestScore = score;
    }
  }
  return best;
}

/**
 * Turns what the five list endpoints answered into the rule's input. The sharing switch belongs to
 * the Peer source: without it no Peer rule can be decided, so its failure makes that source failed.
 */
export function problemInputFromReads(reads: WorkbenchReads, now = Date.now()): ProblemInput {
  let peerState: ProblemSourceState = reads.peerServices.state;
  if (peerState === "ok" && reads.peerSharing.state !== "ok") peerState = reads.peerSharing.state;
  const sources: Record<ProblemSource, ProblemSourceState> = {
    clients: reads.clients.state,
    httpRoutes: reads.httpRoutes.state,
    tcpMappings: reads.tcpMappings.state,
    peerServices: peerState,
  };
  const input: ProblemInput = { sources };
  if (reads.clients.state === "ok") {
    input.clients = reads.clients.data.map((client) => ({ id: client.id, enabled: client.enabled, online: client.online }));
  }
  if (reads.httpRoutes.state === "ok") {
    input.httpRoutes = reads.httpRoutes.data.map((route) => ({ id: route.id, clientId: route.clientId, enabled: route.enabled }));
  }
  if (reads.tcpMappings.state === "ok") {
    input.tcpMappings = reads.tcpMappings.data.map((mapping) => ({ id: mapping.id, clientId: mapping.clientId, enabled: mapping.enabled }));
  }
  if (reads.peerSharing.state === "ok") {
    input.peerSharing = {
      deploymentEnabled: reads.peerSharing.data.deploymentEnabled,
      configuredEnabled: reads.peerSharing.data.configuredEnabled,
    };
  }
  if (peerState === "ok" && reads.peerServices.state === "ok") {
    input.peerServices = reads.peerServices.data.map((service) => ({
      id: service.id,
      clientId: service.clientId,
      enabled: service.enabled,
      instance: peerProblemInstance(service, now),
    }));
  }
  return input;
}

/** 404/405 mean the server has no such list (older server, or no Peer services); anything else failed. */
export function sourceStateOfError(error: unknown): "failed" | "unsupported" {
  const status = (error as { status?: unknown } | null)?.status;
  return status === 404 || status === 405 ? "unsupported" : "failed";
}

// ---- wording ------------------------------------------------------------------------------
// Online is not reachable: no wording may call a service normal, healthy, available, reachable
// or connected. "Blocking" problems are certain; "attention" ones say the cause is undetermined.

export const SOURCE_LABELS: Record<ProblemSource, string> = {
  clients: "设备列表",
  httpRoutes: "HTTP 路由",
  tcpMappings: "端口映射",
  peerServices: "Peer 服务",
};

export const NO_KNOWN_PROBLEM = "未发现已知问题";
export const NO_KNOWN_PROBLEM_CAVEAT = "这不代表服务可以访问；需要确认时，请对单个 HTTP 服务做连接检查";
export const MULTI_INSTANCE_OFFLINE_CAVEAT =
  "多实例部署时，请求可能落到不持有该设备连接的实例，设备也会显示离线。";
export const ATTENTION_NOTE = "原因未定：目录里没有这项服务，但从现有状态无法判断原因，不代表目标服务出错。";

export function problemTitle(problem: PendingProblem): string {
  const count = problem.services.length;
  switch (problem.code) {
    case "DEVICE_DISABLED": return `设备已停用，其上 ${count} 个已启用的服务不会对外提供`;
    case "DEVICE_OFFLINE": return `设备离线，其上 ${count} 个已启用的服务现在无法经 specus 访问`;
    case "PEER_SHARING_OFF": return `服务共享已关闭，${count} 个已启用的 Peer 服务不会出现在任何对端的目录中`;
    case "PEER_NOT_REPORTED": return "发布设备还没有上报这些服务";
    case "PEER_DIRECTORY_EXPIRED": return "服务目录已过期";
    case "PEER_NOT_ADVERTISED": return "发布设备在线，但没有发布这些服务";
  }
}

export function problemNextStep(problem: PendingProblem, isAdmin: boolean): string {
  switch (problem.code) {
    case "DEVICE_DISABLED":
      return isAdmin ? "启用该设备，或停用这些服务" : "启用该设备，或停用这些服务；普通用户请联系租户管理员";
    case "DEVICE_OFFLINE": return "启动该设备上的客户端，或检查它到服务端的网络";
    case "PEER_SHARING_OFF": return "租户管理员在「Peer 服务」中开启服务共享";
    case "PEER_NOT_REPORTED":
      return "发布端只在存在获授权的在线对端时才探测和上报；如果有对端在线，确认设备上的目标服务已启动";
    case "PEER_DIRECTORY_EXPIRED": return "发布设备可能停止了上报；稍后刷新，持续出现时检查该设备的客户端";
    case "PEER_NOT_ADVERTISED": return "发布端本机探测没有成功：确认目标服务已启动并在配置的端口上监听";
  }
}

/** Older than this since the last successful read, the problem list is marked stale. */
export const PROBLEMS_STALE_AFTER_MS = 60_000;
/** While the page is visible the lists are read again at most this often. */
export const PROBLEMS_REFRESH_MS = 30_000;
