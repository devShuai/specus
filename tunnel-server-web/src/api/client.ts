import type {
  Client,
  ClientMutation,
  ConnectionPage,
  CredentialView,
  DatabaseInitResult,
  HttpRoute,
  HttpRouteMutation,
  NatControlResult,
  OidcConfig,
  Overview,
  TokenResponse,
  TrafficUsage,
  Tunnel,
  TunnelMutation,
} from "./types";

const ADMIN_PREFIX = "/api/admin";

const TOKEN_KEY = "access_token";
const EXPIRY_KEY = "token_expiry";
const LOGIN_TYPE_KEY = "login_type";

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
    unauthorizedHandler?.();
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

export const adminApi = {
  overview: () => request<Overview>("/overview"),
  initializeDatabase: () => request<DatabaseInitResult>("/database/initialize", { method: "POST" }),

  listClients: () => request<Client[]>("/clients"),
  createClient: (body: ClientMutation) =>
    request<CredentialView>("/clients", { method: "POST", body: JSON.stringify(body) }),
  updateClient: (id: number, body: ClientMutation) =>
    request<CredentialView>(`/clients/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteClient: (id: number) => request<null>(`/clients/${id}`, { method: "DELETE" }),
  pushNatControl: (id: number) => request<NatControlResult>(`/clients/${id}/nat-control`, { method: "POST" }),

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
};
