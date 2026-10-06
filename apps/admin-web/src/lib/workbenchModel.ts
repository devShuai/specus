import type {
  Client,
  HttpRoute,
  PeerMeshSharedService,
  Specus,
  WorkbenchDocument,
  WorkbenchKind,
  WorkbenchRef,
} from "../api/types";
import { compareRefs } from "./workbenchProblems";

// Everything the workbench page shows about a service comes from the lists the person can already
// read; a favourite or a recent entry is only a (kind, id) reference resolved against them.

export type WorkbenchService =
  | { kind: "http-route"; id: number; clientId: number; enabled: boolean; route: HttpRoute }
  | { kind: "tcp-mapping"; id: number; clientId: number; enabled: boolean; mapping: Specus }
  | { kind: "peer-service"; id: number; clientId: number; enabled: boolean; service: PeerMeshSharedService };

export function refKey(ref: WorkbenchRef): string {
  return `${ref.kind}:${ref.id}`;
}

export const KIND_LABELS: Record<WorkbenchKind, string> = {
  "http-route": "HTTP 服务",
  "tcp-mapping": "TCP 端口",
  "peer-service": "Peer 服务",
};

export function collectServices(lists: {
  httpRoutes?: HttpRoute[] | null;
  tcpMappings?: Specus[] | null;
  peerServices?: PeerMeshSharedService[] | null;
}): WorkbenchService[] {
  const services: WorkbenchService[] = [];
  for (const route of lists.httpRoutes ?? []) {
    services.push({ kind: "http-route", id: route.id, clientId: route.clientId, enabled: route.enabled, route });
  }
  for (const mapping of lists.tcpMappings ?? []) {
    services.push({ kind: "tcp-mapping", id: mapping.id, clientId: mapping.clientId, enabled: mapping.enabled, mapping });
  }
  for (const service of lists.peerServices ?? []) {
    services.push({ kind: "peer-service", id: service.id, clientId: service.clientId, enabled: service.enabled, service });
  }
  return services.sort(compareRefs);
}

export function serviceName(service: WorkbenchService): string {
  switch (service.kind) {
    case "http-route": return service.route.route;
    case "tcp-mapping": return `公网端口 ${service.mapping.listenPort}`;
    case "peer-service": return service.service.name || service.service.serviceId;
  }
}

export function serviceClientName(service: WorkbenchService): string {
  switch (service.kind) {
    case "http-route": return service.route.clientName;
    case "tcp-mapping": return service.mapping.clientName;
    case "peer-service": return service.service.clientName;
  }
}

/** The target as the kind's own panel shows it; Peer targets are not in that table either. */
export function serviceTarget(service: WorkbenchService): string | null {
  switch (service.kind) {
    case "http-route": return service.route.targetBaseUrl;
    case "tcp-mapping": return `${service.mapping.targetAddress}:${service.mapping.targetPort}`;
    case "peer-service": return service.service.publishedAddress;
  }
}

/** The public entry of an HTTP route, exactly as the HTTP routes panel builds it. */
export function httpRouteAccessUrl(route: Pick<HttpRoute, "clientName" | "route">, origin: string): string {
  const segment = (value: string) => encodeURIComponent(value.trim());
  return `${origin}/http/${segment(route.clientName)}/${segment(route.route)}/`;
}

/** A Peer HTTP(S) path: starts with "/", no full URL, "..", backslash or blank (peer-mesh.md). */
export function safePeerPath(path: string | null | undefined): string | null {
  const value = path ?? "";
  if (value === "") return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("..") || value.includes("\\")
    || /\s/.test(value) || /^[a-z][a-z0-9+.-]*:/i.test(value)) {
    return null;
  }
  return value;
}

/**
 * The "open" link of a Peer HTTP(S) service: only the server's authoritative virtual address and
 * published port plus a safe path, never a URL a peer reported. Other applications have none.
 */
export function peerOpenUrl(service: PeerMeshSharedService): string | null {
  const application = service.application?.toLowerCase();
  if ((application !== "http" && application !== "https") || !service.publishedAddress) return null;
  if (!/^[0-9a-fA-F:.[\]]+:\d{1,5}$/.test(service.publishedAddress)) return null;
  const path = safePeerPath(service.path);
  return path ? `${application}://${service.publishedAddress}${path}` : null;
}

/** 404/405 from GET /workbench: an older server that keeps no favourites or recent opens. */
export function isWorkbenchUnsupported(error: unknown): boolean {
  const status = (error as { status?: unknown } | null)?.status;
  return status === 404 || status === 405;
}

export function isFavorite(document: WorkbenchDocument | null, ref: WorkbenchRef): boolean {
  return Boolean(document?.favorites.some((entry) => entry.kind === ref.kind && entry.id === ref.id));
}

export function clientsById(clients: Client[] | null): Map<number, Client> {
  return new Map((clients ?? []).map((client) => [client.id, client]));
}

export function formatClock(timestamp: number): string {
  const date = new Date(timestamp);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
