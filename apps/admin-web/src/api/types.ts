// API DTOs mirroring the admin REST surface served by every tunnel-server implementation.

export interface OidcConfig {
  configured: boolean;
  passwordLoginEnabled: boolean;
  authorizationEndpoint: string;
  endSessionEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope: string;
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  error?: string;
  error_description?: string;
}

export interface Overview {
  clients: number;
  onlineClients: number;
  successfulConnections: number;
  failedConnections: number;
  externalConnections: number;
  rejectedExternalConnections: number;
  uploadBytes: number;
  downloadBytes: number;
}

export interface Client {
  id: number;
  clientName: string;
  ownerUsername?: string | null;
  enabled: boolean;
  online: boolean;
  connectedSinceMs: number | null;
  connectionRateLimitPerMinute: number;
  uploadBytes: number;
  downloadBytes: number;
  createdAt: string;
  updatedAt: string;
}

export interface ClientResult {
  client: Client;
}

export interface ClientDetail {
  client: Client;
  tunnels: Tunnel[];
  httpRoutes: HttpRoute[];
}

/** S3.2 单客户端聚合详情 */
export interface ClientDetail {
  client: Client;
  tunnels: Tunnel[];
  httpRoutes: HttpRoute[];
}

export interface ClientCredential {
  id: number;
  apiKey: string;
  ownerUsername?: string | null;
  enabled: boolean;
  maxOnlineInstances: number;
  createdAt: string;
  updatedAt: string;
}

export interface ClientCredentialResult {
  credential: ClientCredential;
  secret?: string;
}

export interface Tunnel {
  id: number;
  clientId: number;
  clientName: string;
  listenPort: number;
  targetAddress: string;
  targetPort: number;
  enabled: boolean;
  detailCaptureEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface HttpRoute {
  id: number;
  clientId: number;
  clientName: string;
  route: string;
  targetBaseUrl: string;
  enabled: boolean;
  detailCaptureEnabled: boolean;
  pathRewriteEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ConnectionRecord {
  id: number;
  clientId: number | null;
  clientName: string;
  channelId: string | null;
  remoteAddress: string | null;
  connectedAt: string;
  disconnectedAt: string | null;
  success: boolean;
  failureReason: string | null;
  disconnectReason: string | null;
  disconnectReasonText: string | null;
}

export interface ConnectionPage {
  items: ConnectionRecord[];
  total: number;
  page: number;
  size: number;
  totalPages: number;
}

export interface TrafficUsage {
  id: number;
  clientId: number;
  clientName: string;
  usageDate: string;
  uploadBytes: number;
  downloadBytes: number;
  updatedAt: string;
}

export type ResourceTrafficType = "TCP_TUNNEL" | "HTTP_ROUTE";

export interface ResourceTrafficUsage {
  id: number;
  clientId: number;
  clientName: string;
  resourceType: ResourceTrafficType;
  resourceKey: string;
  resourceId: number | null;
  resourceName: string;
  usageDate: string;
  uploadBytes: number;
  downloadBytes: number;
  updatedAt: string;
}

export interface HttpTrafficExchange {
  id: number;
  clientId: number;
  clientName: string;
  route: string;
  resourceId: number | null;
  resourceName: string;
  method: string;
  relativePath: string;
  rawQuery: string | null;
  statusCode: number;
  success: boolean;
  error: string | null;
  remoteAddress: string | null;
  requestBytes: number;
  responseBytes: number;
  elapsedMs: number;
  requestContentType: string | null;
  responseContentType: string | null;
  responseBodyType: HttpResponseBodyType | string | null;
  requestHeaders: string;
  responseHeaders: string;
  requestPreviewHex: string;
  requestPreviewText: string;
  responsePreviewHex: string;
  responsePreviewText: string;
  requestTruncated: boolean;
  responseTruncated: boolean;
  capturedAt: string;
}

export interface HttpTrafficExchangePage {
  items: HttpTrafficExchange[];
  total: number;
  page: number;
  size: number;
  totalPages: number;
}

export type HttpResponseBodyType =
  | "empty"
  | "json"
  | "html"
  | "xml"
  | "image"
  | "video"
  | "audio"
  | "form"
  | "script"
  | "text"
  | "binary";

export type HttpTrafficSearchField =
  | "summary"
  | "all"
  | "id"
  | "method"
  | "status"
  | "path"
  | "route"
  | "client"
  | "resource"
  | "remote"
  | "contentType"
  | "error"
  | "requestHeaders"
  | "responseHeaders"
  | "requestBody"
  | "responseBody";

export interface TcpTrafficFrame {
  id: string;
  clientId: number;
  clientName: string;
  listenPort: number;
  resourceId: number | null;
  resourceName: string;
  channelId: string;
  direction: "PUBLIC_TO_CLIENT" | "CLIENT_TO_PUBLIC" | string;
  remoteAddress: string | null;
  sourceAddress: string | null;
  sourcePort: number | null;
  destinationAddress: string | null;
  destinationPort: number | null;
  streamOffset: number;
  streamEndOffset: number;
  frameIndex: number;
  payloadBytes: number;
  payloadBase64: string;
  payloadPreviewHex: string;
  payloadPreviewText: string;
  truncated: boolean;
  frameTime: string;
}

export interface TcpTrafficFramePage {
  items: TcpTrafficFrame[];
  total: number;
  page: number;
  size: number;
  totalPages: number;
}

export interface TcpTrafficStream {
  channelId: string;
  items: TcpTrafficFrame[];
  total: number;
  page: number;
  size: number;
  limit: number;
  totalPages: number;
  truncated: boolean;
}

export interface TrafficInspectionStatus {
  enabled: boolean;
  pendingHttp: number;
  pendingTcp: number;
  droppedHttp: number;
  droppedTcp: number;
  lastFlushedAt: string | null;
}

export interface NatControlResult {
  tunnels: number;
  httpRoutes: number;
}

export interface PeerMeshStatus {
  enabled: boolean;
}

export interface PublicPeerStunConfig {
  peerMeshEnabled: boolean;
  selfHostedStunServer: string;
  stunServers: string[];
  stunTurnPort: number;
}

export interface PeerMeshDevice {
  id: number;
  clientId: number;
  clientName: string;
  ownerUsername: string;
  enabled: boolean;
  online: boolean;
  virtualIp: string;
  cidr: string;
  publicKey: string | null;
  natType: string | null;
  lastEndpoint: string | null;
  virtualDeviceMode: string | null;
  virtualDeviceName: string | null;
  virtualDeviceStatus: string | null;
  virtualDeviceError: string | null;
  virtualDeviceUpdatedAt: string | null;
  lastSeenAt: string | null;
  updatedAt: string | null;
}

export interface PeerMeshDeviceMutation {
  enabled?: boolean;
}

export interface PeerMeshAcl {
  id: number;
  sourceClientId: number;
  sourceClientName: string;
  targetClientId: number;
  targetClientName: string;
  allowed: boolean;
  /** S4.4 ACL 方向: OUTBOUND=允许source→target, INBOUND=允许target→source, BOTH=双向 */
  direction: "OUTBOUND" | "INBOUND" | "BOTH";
  createdAt: string;
  updatedAt: string;
}

export interface PeerMeshAclMutation {
  sourceClientId: number;
  targetClientId: number;
  allowed?: boolean;
  direction?: "OUTBOUND" | "INBOUND" | "BOTH";
}

export interface PeerMeshSession {
  id: number;
  sourceClientId: number;
  sourceClientName: string;
  targetClientId: number;
  targetClientName: string;
  pathType: "DIRECT" | "RELAY" | string;
  status: "NEGOTIATING" | "ACTIVE" | "CLOSED" | string;
  rttMillis: number | null;
  localEndpoint: string | null;
  remoteEndpoint: string | null;
  directBytes: number;
  relayBytes: number;
  lastTrafficAt: string | null;
  lastKeepaliveAt: string | null;
  startedAt: string;
  updatedAt: string;
  expiresAt: string;
  closedAt: string | null;
}

export interface PeerMeshSessionPage {
  items: PeerMeshSession[];
  total: number;
  page: number;
  size: number;
  totalPages: number;
}

export interface PeerMeshPathTypeStat {
  /** 有业务流量时按 direct/relay 字节占优方归类；无业务流量时使用客户端 PATH_REPORT 的探测路径 */
  pathType: string;
  status: string;
  sessions: number;
  /** rttMillis 非空的会话数 = 至少确立过一次路径（收到过 PATH_REPORT） */
  reportedSessions: number;
  avgRttMillis: number | null;
  directBytes: number;
  relayBytes: number;
}

export interface PeerMeshNatTypeStat {
  natType: string;
  devices: number;
}

export interface PeerMeshPathStats {
  totalSessions: number;
  reportedSessions: number;
  activeSessions: number;
  activeDirectSessions: number;
  activeRelaySessions: number;
  /** 活跃会话中 DIRECT 占比，打洞成功率的代理指标；无活跃会话时为 null */
  activeDirectRatio: number | null;
  pathTypes: PeerMeshPathTypeStat[];
  natTypes: PeerMeshNatTypeStat[];
}

export interface DatabaseInitResult {
  initialized: boolean;
  orm: string;
  dialect: string;
  clients: number;
}

export type ManagementRole = "ADMIN" | "USER";

export interface ManagementUser {
  username: string;
  tenantId: string;
  role: ManagementRole;
  admin: boolean;
  builtIn: boolean;
  enabled: boolean;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface ManagementUserMutation {
  username?: string;
  password?: string | null;
  role?: ManagementRole;
  enabled?: boolean;
}

export interface ClientMutation {
  clientName?: string;
  enabled?: boolean;
  connectionRateLimitPerMinute?: number;
}

export interface ClientCredentialMutation {
  apiKey?: string;
  secret?: string | null;
  enabled?: boolean;
  maxOnlineInstances?: number;
}

export interface TunnelMutation {
  listenPort: number;
  targetAddress: string;
  targetPort: number;
  enabled?: boolean;
  detailCaptureEnabled?: boolean;
}

export interface HttpRouteMutation {
  route: string;
  targetBaseUrl: string;
  enabled?: boolean;
  detailCaptureEnabled?: boolean;
  pathRewriteEnabled?: boolean;
}

// 客户端下载链接 —— 管理员维护、登录页/Dashboard 展示。仅存 URL 字符串，不托管二进制。
export type ClientImplementation = "java" | "go" | "csharp";
export type ClientPlatform = "windows" | "linux" | "macos" | "any";
export type ClientArch = "x64" | "arm64" | "any";

export interface ClientDownloadLink {
  id: number;
  implementation: ClientImplementation;
  platform: ClientPlatform;
  arch: ClientArch;
  displayName: string;
  downloadUrl: string;
  description?: string | null;
  displayOrder: number;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ClientDownloadLinkMutation {
  implementation: ClientImplementation;
  platform: ClientPlatform;
  arch: ClientArch;
  displayName: string;
  downloadUrl: string;
  description?: string | null;
  displayOrder?: number;
  enabled?: boolean;
}

// LiveConnectionEvent is the JSON pushed over /ws/connections.
export interface LiveConnectionEvent {
  tenantId?: string;
  type: "created" | "updated";
  connection: ConnectionRecord;
}
