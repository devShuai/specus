import type {
  Client,
  ClientCredential,
  ClientCredentialMutation,
  ClientCredentialResult,
  ClientDownloadLink,
  ClientDownloadLinkMutation,
  ClientMutation,
  ConnectionPage,
  ClientResult,
  DatabaseInitResult,
  HttpRoute,
  HttpRouteMutation,
  HttpTrafficExchange,
  HttpTrafficExchangePage,
  HttpResponseBodyType,
  HttpTrafficSearchField,
  ManagementUser,
  ManagementUserMutation,
  NatControlResult,
  OidcConfig,
  Overview,
  PeerMeshAcl,
  PeerMeshAclMutation,
  PeerMeshDevice,
  PeerMeshDeviceMutation,
  PeerMeshSessionPage,
  PeerMeshSession,
  PeerMeshStatus,
  ResourceTrafficType,
  ResourceTrafficUsage,
  TcpTrafficFrame,
  TcpTrafficFramePage,
  TcpTrafficStream,
  TrafficInspectionStatus,
  TokenResponse,
  TrafficUsage,
  Tunnel,
  TunnelMutation,
} from "./types";

const ADMIN_PREFIX = "/api/admin";

const TOKEN_KEY = "access_token";
const EXPIRY_KEY = "token_expiry";
const LOGIN_TYPE_KEY = "login_type";
let unauthorizedHandled = false;

export type LoginType = "password" | "oidc";

// ---- token storage (sessionStorage, matching the original SPA) ------------------------

export const tokenStore = {
  get(): string | null {
    return sessionStorage.getItem(TOKEN_KEY);
  },
  expiry(): number {
    return Number(sessionStorage.getItem(EXPIRY_KEY) || 0);
  },
  loginType(): LoginType | null {
    return sessionStorage.getItem(LOGIN_TYPE_KEY) as LoginType | null;
  },
  save(token: string, expiresIn: number | undefined, loginType: LoginType): void {
    sessionStorage.setItem(TOKEN_KEY, token);
    sessionStorage.setItem(LOGIN_TYPE_KEY, loginType);
    if (expiresIn) {
      sessionStorage.setItem(EXPIRY_KEY, String(Date.now() + expiresIn * 1000));
    }
    unauthorizedHandled = false;
  },
  clear(): void {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(EXPIRY_KEY);
    sessionStorage.removeItem(LOGIN_TYPE_KEY);
  },
  valid(): boolean {
    if (!sessionStorage.getItem(TOKEN_KEY)) {
      return false;
    }
    const expiry = Number(sessionStorage.getItem(EXPIRY_KEY) || 0);
    return expiry === 0 || Date.now() < expiry - 5000;
  },
};

let unauthorizedHandler: (() => void) | null = null;

// setUnauthorizedHandler registers the callback invoked on any 401 from the admin API.
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
  unauthorizedHandled = false;
}

class ApiError extends Error {}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  const token = tokenStore.get();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(`${ADMIN_PREFIX}${path}`, { ...init, headers });
  if (response.status === 401) {
    if (!unauthorizedHandled) {
      unauthorizedHandled = true;
      unauthorizedHandler?.();
    }
    throw new ApiError("登录已过期");
  }
  if (response.status === 204) {
    return null as T;
  }
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError(body?.error || response.statusText);
  }
  return body as T;
}

// ---- auth endpoints (outside /api/admin) ----------------------------------------------

export async function fetchOidcConfig(): Promise<OidcConfig | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch("/oidc-config", { signal: controller.signal });
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as OidcConfig;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function passwordLogin(username: string, password: string): Promise<TokenResponse> {
  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const body = (await response.json()) as TokenResponse;
  if (!response.ok) {
    throw new ApiError(body?.error || "登录失败");
  }
  return body;
}

export async function refreshToken(): Promise<TokenResponse> {
  const token = tokenStore.get();
  const response = await fetch("/auth/refresh", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new ApiError("刷新失败");
  }
  return (await response.json()) as TokenResponse;
}

export async function oidcExchange(code: string, codeVerifier: string): Promise<TokenResponse> {
  const response = await fetch("/oidc/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, codeVerifier }),
  });
  const body = (await response.json()) as TokenResponse;
  if (!response.ok) {
    throw new ApiError(body?.error_description || body?.error || "令牌交换失败");
  }
  return body;
}

// ---- admin API ------------------------------------------------------------------------

export interface ConnectionQuery {
  page: number;
  size: number;
  clientId?: number;
  success?: boolean;
  from?: string;
  to?: string;
}

export interface HttpTrafficExchangeQuery {
  page: number;
  size: number;
  clientId?: number;
  route?: string;
  responseBodyType?: HttpResponseBodyType | string;
  field?: HttpTrafficSearchField;
  q?: string;
}

export interface TcpTrafficFrameQuery {
  page: number;
  size: number;
  clientId?: number;
  listenPort?: number;
}

export interface PeerMeshSessionQuery {
  page: number;
  size: number;
  openOnly?: boolean;
}

export const adminApi = {
  me: () => request<ManagementUser>("/me"),
  overview: () => request<Overview>("/overview"),
  initializeDatabase: () => request<DatabaseInitResult>("/database/initialize", { method: "POST" }),
  listUsers: () => request<ManagementUser[]>("/users"),
  createUser: (body: ManagementUserMutation) =>
    request<ManagementUser>("/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (username: string, body: ManagementUserMutation) =>
    request<ManagementUser>(`/users/${encodeURIComponent(username)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteUser: (username: string) => request<null>(`/users/${encodeURIComponent(username)}`, { method: "DELETE" }),

  listClients: () => request<Client[]>("/clients"),
  createClient: (body: ClientMutation) =>
    request<ClientResult>("/clients", { method: "POST", body: JSON.stringify(body) }),
  updateClient: (id: number, body: ClientMutation) =>
    request<ClientResult>(`/clients/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteClient: (id: number) => request<null>(`/clients/${id}`, { method: "DELETE" }),
  pushNatControl: (id: number) => request<NatControlResult>(`/clients/${id}/nat-control`, { method: "POST" }),

  listClientCredentials: () => request<ClientCredential[]>("/client-credentials"),
  createClientCredential: (body: ClientCredentialMutation) =>
    request<ClientCredentialResult>("/client-credentials", { method: "POST", body: JSON.stringify(body) }),
  updateClientCredential: (id: number, body: ClientCredentialMutation) =>
    request<ClientCredentialResult>(`/client-credentials/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteClientCredential: (id: number) => request<null>(`/client-credentials/${id}`, { method: "DELETE" }),

  listTunnels: (clientId?: number) =>
    request<Tunnel[]>(`/tunnels${clientId ? `?clientId=${clientId}` : ""}`),
  createTunnel: (clientId: number, body: TunnelMutation) =>
    request<Tunnel>(`/clients/${clientId}/tunnels`, { method: "POST", body: JSON.stringify(body) }),
  updateTunnel: (id: number, body: TunnelMutation) =>
    request<Tunnel>(`/tunnels/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteTunnel: (id: number) => request<null>(`/tunnels/${id}`, { method: "DELETE" }),

  listHttpRoutes: (clientId?: number) =>
    request<HttpRoute[]>(`/http-routes${clientId ? `?clientId=${clientId}` : ""}`),
  createHttpRoute: (clientId: number, body: HttpRouteMutation) =>
    request<HttpRoute>(`/clients/${clientId}/http-routes`, { method: "POST", body: JSON.stringify(body) }),
  updateHttpRoute: (id: number, body: HttpRouteMutation) =>
    request<HttpRoute>(`/http-routes/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteHttpRoute: (id: number) => request<null>(`/http-routes/${id}`, { method: "DELETE" }),

  listConnections: (query: ConnectionQuery) => {
    const params = new URLSearchParams();
    params.set("page", String(query.page));
    params.set("size", String(query.size));
    if (query.clientId) {
      params.set("clientId", String(query.clientId));
    }
    if (query.success !== undefined) {
      params.set("success", String(query.success));
    }
    if (query.from) {
      params.set("from", query.from);
    }
    if (query.to) {
      params.set("to", query.to);
    }
    return request<ConnectionPage>(`/connections?${params.toString()}`);
  },

  listTraffic: (limit = 100) => request<TrafficUsage[]>(`/traffic?limit=${limit}`),
  listResourceTraffic: (type?: ResourceTrafficType, limit = 200) => {
    const params = new URLSearchParams();
    params.set("limit", String(limit));
    if (type) {
      params.set("type", type);
    }
    return request<ResourceTrafficUsage[]>(`/traffic/resources?${params.toString()}`);
  },
  listHttpTrafficExchanges: async (query: HttpTrafficExchangeQuery) => {
    const params = new URLSearchParams();
    params.set("page", String(query.page));
    params.set("size", String(query.size));
    if (query.clientId) {
      params.set("clientId", String(query.clientId));
    }
    if (query.route) {
      params.set("route", query.route);
    }
    if (query.responseBodyType) {
      params.set("responseBodyType", query.responseBodyType);
    }
    if (query.field) {
      params.set("field", query.field);
    }
    if (query.q) {
      params.set("q", query.q);
    }
    const data = await request<HttpTrafficExchangePage | HttpTrafficExchange[]>(
      `/traffic/http-exchanges?${params.toString()}`,
    );
    if (Array.isArray(data)) {
      return {
        items: data,
        total: data.length,
        page: 0,
        size: data.length,
        totalPages: 1,
      } satisfies HttpTrafficExchangePage;
    }
    return data;
  },
  listTcpTrafficFrames: async (query: TcpTrafficFrameQuery) => {
    const params = new URLSearchParams();
    params.set("page", String(query.page));
    params.set("size", String(query.size));
    if (query.clientId) {
      params.set("clientId", String(query.clientId));
    }
    if (query.listenPort) {
      params.set("listenPort", String(query.listenPort));
    }
    const data = await request<TcpTrafficFramePage | TcpTrafficFrame[]>(`/traffic/tcp-frames?${params.toString()}`);
    if (Array.isArray(data)) {
      return {
        items: data,
        total: data.length,
        page: 0,
        size: data.length,
        totalPages: 1,
      } satisfies TcpTrafficFramePage;
    }
    return data;
  },
  getTcpTrafficFrame: (id: string) => request<TcpTrafficFrame>(`/traffic/tcp-frames/${id}`),
  getTcpTrafficStream: (channelId: string, page = 0, size = 200) => {
    const params = new URLSearchParams();
    params.set("channelId", channelId);
    params.set("page", String(page));
    params.set("size", String(size));
    return request<TcpTrafficStream>(`/traffic/tcp-streams?${params.toString()}`);
  },
  getTrafficInspectionStatus: () => request<TrafficInspectionStatus>("/traffic/inspection-status"),
  peerMeshStatus: () => request<PeerMeshStatus>("/peer-mesh/status"),
  listPeerMeshDevices: () => request<PeerMeshDevice[]>("/peer-mesh/devices"),
  updatePeerMeshDevice: (clientId: number, body: PeerMeshDeviceMutation) =>
    request<PeerMeshDevice>(`/peer-mesh/devices/${clientId}`, { method: "PUT", body: JSON.stringify(body) }),
  listPeerMeshAcls: () => request<PeerMeshAcl[]>("/peer-mesh/acls"),
  createPeerMeshAcl: (body: PeerMeshAclMutation) =>
    request<PeerMeshAcl>("/peer-mesh/acls", { method: "POST", body: JSON.stringify(body) }),
  deletePeerMeshAcl: (id: number) => request<null>(`/peer-mesh/acls/${id}`, { method: "DELETE" }),
  listPeerMeshSessions: (limit = 100) => request<PeerMeshSession[]>(`/peer-mesh/sessions?limit=${limit}`),
  listPeerMeshSessionsPage: (query: PeerMeshSessionQuery) => {
    const params = new URLSearchParams();
    params.set("page", String(query.page));
    params.set("size", String(query.size));
    if (query.openOnly !== undefined) {
      params.set("openOnly", String(query.openOnly));
    }
    return request<PeerMeshSessionPage>(`/peer-mesh/sessions?${params.toString()}`);
  },
  closePeerMeshSession: (id: number) => request<PeerMeshSession>(`/peer-mesh/sessions/${id}`, { method: "DELETE" }),
  closeOpenPeerMeshSessions: () => request<PeerMeshSession[]>("/peer-mesh/sessions", { method: "DELETE" }),

  listClientDownloads: () => request<ClientDownloadLink[]>(`/client-downloads`),
  createClientDownload: (body: ClientDownloadLinkMutation) =>
    request<ClientDownloadLink>(`/client-downloads`, { method: "POST", body: JSON.stringify(body) }),
  updateClientDownload: (id: number, body: ClientDownloadLinkMutation) =>
    request<ClientDownloadLink>(`/client-downloads/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteClientDownload: (id: number) => request<null>(`/client-downloads/${id}`, { method: "DELETE" }),
};

// ---- public API（无需 Bearer，登录页和未登录上下文可用）-------------------------------

/**
 * 公开下载列表。任何端点失败/异常都返回空数组（登录页应静默降级，不打扰未登录用户）。
 */
export async function fetchPublicClientDownloads(): Promise<ClientDownloadLink[]> {
  try {
    const response = await fetch(`/api/public/client-downloads`);
    if (!response.ok) {
      return [];
    }
    const body = (await response.json()) as ClientDownloadLink[];
    return Array.isArray(body) ? body : [];
  } catch {
    return [];
  }
}
