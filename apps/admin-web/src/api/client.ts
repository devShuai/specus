import type {
  Client,
  ClientCredential,
  ClientCredentialMutation,
  ClientCredentialResult,
  ClientDetail,
  ClientDownloadLink,
  ClientDownloadLinkMutation,
  ClientMutation,
  ClientNameAvailability,
  ConnectionPage,
  AttachmentCompleteRequest,
  AttachmentPresignDownloadRequest,
  AttachmentPresignDownloadResponse,
  AttachmentPresignUploadRequest,
  AttachmentPresignUploadResponse,
  ClientResult,
  DatabaseInitResult,
  HttpRoute,
  HttpRouteMutation,
  HttpMediaCapturePage,
  HttpMediaPlaybackTicket,
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
  PeerMeshPathStats,
  PeerMeshSessionPage,
  PeerMeshSession,
  PeerMeshStatus,
  PublicTransferIceConfig,
  PublicTransferClientNameAvailability,
  PublicTransferCreatedAccessToken,
  PublicTransferPairingCode,
  PublicTransferRedeemedPairingCode,
  PublicTransferDiagramVersion,
  PublicTransferDiagramVersionDetail,
  PublicTransferRoomAccessToken,
  PublicTransferRoomCredential,
  PublicTransferRoomRole,
  PublicNatProbeConfig,
  PublicPeerStunConfig,
  ResourceTrafficType,
  ResourceTrafficUsage,
  RegistrationChallengeResponse,
  TcpTrafficFrame,
  TcpTrafficFramePage,
  TcpTrafficStream,
  TrafficInspectionStatus,
  TokenResponse,
  TrafficUsage,
  Specus,
  SpecusMutation,
  UserDiagramDocument,
  UserDiagramDocumentDetail,
  UserDiagramDocumentMutation,
  WebSocketTicket,
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

export async function passwordLogin(
  username: string,
  password: string,
  turnstileToken: string,
): Promise<TokenResponse> {
  const response = await fetch("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, turnstileToken }),
  });
  const body = (await response.json()) as TokenResponse;
  if (!response.ok) {
    throw new ApiError(body?.error || "登录失败");
  }
  return body;
}

export async function registerAccount(
  username: string,
  email: string,
  password: string,
  turnstileToken: string,
): Promise<RegistrationChallengeResponse> {
  const response = await fetch("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password, turnstileToken }),
  });
  const body = (await response.json()) as RegistrationChallengeResponse & { error?: string };
  if (!response.ok) {
    throw new ApiError(body?.error || "注册失败");
  }
  return body;
}

export async function verifyRegistration(registrationId: string, code: string): Promise<TokenResponse> {
  const response = await fetch("/auth/register/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ registrationId, code }),
  });
  const body = (await response.json()) as TokenResponse;
  if (!response.ok) {
    throw new ApiError(body?.error || "邮箱验证失败");
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

export async function oidcExchange(code: string, codeVerifier: string, nonce: string): Promise<TokenResponse> {
  const response = await fetch("/oidc/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, codeVerifier, nonce }),
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
  createWebSocketTicket: (endpoint: "connections" | "client-messages") =>
    request<WebSocketTicket>("/ws-tickets", {
      method: "POST",
      body: JSON.stringify({ endpoint }),
    }),
  me: () => request<ManagementUser>("/me"),
  overview: () => request<Overview>("/overview"),
  initializeDatabase: () => request<DatabaseInitResult>("/database/initialize", { method: "POST" }),
  listUsers: () => request<ManagementUser[]>("/users"),
  createUser: (body: ManagementUserMutation) =>
    request<ManagementUser>("/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (username: string, body: ManagementUserMutation) =>
    request<ManagementUser>(`/users/${encodeURIComponent(username)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteUser: (username: string) => request<null>(`/users/${encodeURIComponent(username)}`, { method: "DELETE" }),

  listDiagrams: () => request<UserDiagramDocument[]>("/diagrams"),
  getDiagram: (id: number) => request<UserDiagramDocumentDetail>(`/diagrams/${id}`),
  createDiagram: (body: UserDiagramDocumentMutation) =>
    request<UserDiagramDocument>("/diagrams", { method: "POST", body: JSON.stringify(body) }),
  updateDiagram: (id: number, body: UserDiagramDocumentMutation) =>
    request<UserDiagramDocument>(`/diagrams/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteDiagram: (id: number) => request<null>(`/diagrams/${id}`, { method: "DELETE" }),

  listClients: () => request<Client[]>("/clients"),
  createClient: (body: ClientMutation) =>
    request<ClientResult>("/clients", { method: "POST", body: JSON.stringify(body) }),
  updateClient: (id: number, body: ClientMutation) =>
    request<ClientResult>(`/clients/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  checkClientNameAvailability: (clientName: string, excludeClientId?: number) => {
    const params = new URLSearchParams({ clientName });
    if (excludeClientId != null) {
      params.set("excludeClientId", String(excludeClientId));
    }
    return request<ClientNameAvailability>(`/clients/name-availability?${params}`);
  },
  deleteClient: (id: number) => request<null>(`/clients/${id}`, { method: "DELETE" }),
  pushNatControl: (id: number) => request<NatControlResult>(`/clients/${id}/nat-control`, { method: "POST" }),
  getClient: (id: number) => request<ClientDetail>(`/clients/${id}`),
  forceRefreshPortMapping: (id: number) => request<NatControlResult>(`/clients/${id}/force-refresh-port-mapping`, { method: "POST" }),
  /** S3.2 单客户端聚合详情 */
  /** S3.2 强制刷新端口映射 */

  listClientCredentials: () => request<ClientCredential[]>("/client-credentials"),
  createClientCredential: (body: ClientCredentialMutation) =>
    request<ClientCredentialResult>("/client-credentials", { method: "POST", body: JSON.stringify(body) }),
  updateClientCredential: (id: number, body: ClientCredentialMutation) =>
    request<ClientCredentialResult>(`/client-credentials/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteClientCredential: (id: number) => request<null>(`/client-credentials/${id}`, { method: "DELETE" }),

  listSpecusMappings: (clientId?: number) =>
    request<Specus[]>(`/specus-mappings${clientId ? `?clientId=${clientId}` : ""}`),
  createSpecus: (clientId: number, body: SpecusMutation) =>
    request<Specus>(`/clients/${clientId}/specus-mappings`, { method: "POST", body: JSON.stringify(body) }),
  updateSpecus: (id: number, body: SpecusMutation) =>
    request<Specus>(`/specus-mappings/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteSpecus: (id: number) => request<null>(`/specus-mappings/${id}`, { method: "DELETE" }),

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
  getHttpTrafficExchange: (id: number | string) =>
    request<HttpTrafficExchange>(`/traffic/http-exchanges/${encodeURIComponent(String(id))}`),
  listHttpMediaCaptures: (page = 0, size = 50) =>
    request<HttpMediaCapturePage>(`/traffic/media-captures?page=${page}&size=${size}`),
  createHttpMediaPlaybackTicket: (id: number, backfillMissing = false) =>
    request<HttpMediaPlaybackTicket>(
      `/traffic/media-captures/${id}/playback-ticket?backfillMissing=${backfillMissing}`,
      { method: "POST" },
    ),
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
  peerMeshStats: () => request<PeerMeshPathStats>("/peer-mesh/stats"),
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

  presignClientMessageAttachmentUpload: (body: AttachmentPresignUploadRequest) =>
    request<AttachmentPresignUploadResponse>("/client-messages/attachments/presign-upload", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  completeClientMessageAttachment: (attachmentId: number) =>
    request<AttachmentPresignUploadResponse["attachment"]>(`/client-messages/attachments/${attachmentId}/complete`, {
      method: "POST",
    }),
  presignClientMessageAttachmentDownload: (attachmentId: number) =>
    request<AttachmentPresignDownloadResponse>(`/client-messages/attachments/${attachmentId}/presign-download`, {
      method: "POST",
    }),
};

// ---- public API（默认免登录；公开互传附件单独要求 Bearer）-----------------------------

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

export async function fetchPublicPeerStunConfig(): Promise<PublicPeerStunConfig | null> {
  try {
    const response = await fetch(`/api/public/peer-mesh/stun-config`);
    if (!response.ok) {
      return null;
    }
    const body = (await response.json()) as PublicPeerStunConfig;
    return body && Array.isArray(body.stunServers) ? body : null;
  } catch {
    return null;
  }
}

export async function fetchPublicNatProbeConfig(): Promise<PublicNatProbeConfig | null> {
  try {
    const response = await fetch(`/api/public/peer-mesh/nat-probe-config`);
    if (!response.ok) {
      return null;
    }
    const body = (await response.json()) as PublicNatProbeConfig;
    return body && Array.isArray(body.endpoints) && body.capabilities ? body : null;
  } catch {
    return null;
  }
}

async function publicJsonRequest<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError(parsed?.detail || parsed?.message || parsed?.error || response.statusText);
  }
  return parsed as T;
}

async function authenticatedPublicJsonRequest<T>(path: string, body?: unknown): Promise<T> {
  const token = tokenStore.get();
  if (!token || !tokenStore.valid()) {
    throw new ApiError("登录后才可使用云端中转");
  }
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body ?? {}),
  });
  if (response.status === 401) {
    if (!unauthorizedHandled) {
      unauthorizedHandled = true;
      unauthorizedHandler?.();
    }
    throw new ApiError("登录已过期，请重新登录");
  }
  const text = await response.text();
  const parsed = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError(parsed?.detail || parsed?.message || parsed?.error || response.statusText);
  }
  return parsed as T;
}

export async function fetchPublicTransferIceConfig(): Promise<PublicTransferIceConfig | null> {
  try {
    const response = await fetch(`/api/public/transfer/ice-config`);
    if (!response.ok) {
      return null;
    }
    const body = (await response.json()) as PublicTransferIceConfig;
    return body && Array.isArray(body.iceServers) ? body : null;
  } catch {
    return null;
  }
}

export function publicCreateTransferWebSocketTicket(body: {
  roomId: string;
  roomToken: string;
  peerId: string;
  displayName: string;
  /** 关闭后本设备不出现在他人的设备列表里，但仍能看到他人并主动发送。 */
  discoverable?: boolean;
}): Promise<WebSocketTicket> {
  return publicJsonRequest<WebSocketTicket>("/api/public/transfer/ws-tickets", body);
}

export async function publicCheckTransferClientNameAvailability(
  clientName: string,
  excludePeerId?: string,
): Promise<PublicTransferClientNameAvailability> {
  const params = new URLSearchParams({ clientName });
  if (excludePeerId) {
    params.set("excludePeerId", excludePeerId);
  }
  const response = await fetch(`/api/public/transfer/clients/name-availability?${params}`);
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new ApiError(body?.error || body?.detail || body?.message || response.statusText);
  }
  return body as PublicTransferClientNameAvailability;
}

export function publicPresignAttachmentUpload(
  body: AttachmentPresignUploadRequest,
): Promise<AttachmentPresignUploadResponse> {
  return authenticatedPublicJsonRequest<AttachmentPresignUploadResponse>(
    "/api/public/transfer/attachments/presign-upload",
    body,
  );
}

export function publicCompleteAttachment(
  attachmentId: number,
  body: AttachmentCompleteRequest,
): Promise<AttachmentPresignUploadResponse["attachment"]> {
  return authenticatedPublicJsonRequest<AttachmentPresignUploadResponse["attachment"]>(
    `/api/public/transfer/attachments/${attachmentId}/complete`,
    body,
  );
}

export function publicPresignAttachmentDownload(
  attachmentId: number,
  body: AttachmentPresignDownloadRequest,
): Promise<AttachmentPresignDownloadResponse> {
  return authenticatedPublicJsonRequest<AttachmentPresignDownloadResponse>(
    `/api/public/transfer/attachments/${attachmentId}/presign-download`,
    body,
  );
}

function publicTransferRoomPath(suffix: string): string {
  return `/api/public/transfer/rooms/${suffix}`;
}

export function publicListTransferRoomAccessTokens(
  roomId: string,
  credential: PublicTransferRoomCredential,
): Promise<PublicTransferRoomAccessToken[]> {
  return publicJsonRequest(publicTransferRoomPath("access-tokens/list"), { roomId, ...credential });
}

export function publicCreateTransferRoomAccessToken(
  roomId: string,
  credential: PublicTransferRoomCredential,
  role: Exclude<PublicTransferRoomRole, "OWNER">,
  label: string,
  expiresInSeconds?: number,
): Promise<PublicTransferCreatedAccessToken> {
  return publicJsonRequest(publicTransferRoomPath("access-tokens"), {
    roomId,
    ...credential,
    role,
    label,
    ...(expiresInSeconds ? { expiresInSeconds } : {}),
  });
}

export function publicCreateTransferPairingCode(
  roomId: string,
  credential: PublicTransferRoomCredential,
  role: Exclude<PublicTransferRoomRole, "OWNER">,
  label: string,
  maxUses = 1,
): Promise<PublicTransferPairingCode> {
  return publicJsonRequest(publicTransferRoomPath("pairing-codes"), {
    roomId,
    ...credential,
    role,
    label,
    maxUses,
  });
}

export function publicRedeemTransferPairingCode(
  code: string,
  peerId: string,
): Promise<PublicTransferRedeemedPairingCode> {
  return publicJsonRequest(publicTransferRoomPath("pairing-codes/redeem"), { code, peerId });
}

export function publicRevokeTransferRoomAccessToken(
  roomId: string,
  accessId: number,
  credential: PublicTransferRoomCredential,
): Promise<PublicTransferRoomAccessToken> {
  return publicJsonRequest(publicTransferRoomPath(`access-tokens/${accessId}/revoke`), { roomId, ...credential });
}

export function publicListTransferDiagramVersions(
  roomId: string,
  credential: PublicTransferRoomCredential,
): Promise<PublicTransferDiagramVersion[]> {
  return publicJsonRequest(publicTransferRoomPath("diagram/versions/list"), { roomId, ...credential });
}

export function publicCreateTransferDiagramVersion(
  roomId: string,
  credential: PublicTransferRoomCredential,
  name: string,
  update: string,
): Promise<PublicTransferDiagramVersion> {
  return publicJsonRequest(publicTransferRoomPath("diagram/versions"), { roomId, ...credential, name, update });
}

export function publicGetTransferDiagramVersion(
  roomId: string,
  versionId: number,
  credential: PublicTransferRoomCredential,
): Promise<PublicTransferDiagramVersionDetail> {
  return publicJsonRequest(publicTransferRoomPath(`diagram/versions/${versionId}`), { roomId, ...credential });
}

export function publicDeleteTransferDiagramVersion(
  roomId: string,
  versionId: number,
  credential: PublicTransferRoomCredential,
): Promise<null> {
  return publicJsonRequest(publicTransferRoomPath(`diagram/versions/${versionId}/delete`), { roomId, ...credential });
}
