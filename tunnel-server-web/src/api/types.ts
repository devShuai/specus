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
  enabled: boolean;
  online: boolean;
  connectedSinceMs: number | null;
  connectionRateLimitPerMinute: number;
  uploadBytes: number;
  downloadBytes: number;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialView {
  client: Client;
  password?: string;
}

export interface ClientCredential {
  id: number;
  apiKey: string;
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

export interface TcpTrafficFrame {
  id: number;
  clientId: number;
  clientName: string;
  listenPort: number;
  resourceId: number | null;
  resourceName: string;
  channelId: string;
  direction: "PUBLIC_TO_CLIENT" | "CLIENT_TO_PUBLIC" | string;
  remoteAddress: string | null;
  payloadBytes: number;
  payloadPreviewHex: string;
  payloadPreviewText: string;
  truncated: boolean;
  frameTime: string;
}

export interface NatControlResult {
  tunnels: number;
  httpRoutes: number;
}

export interface DatabaseInitResult {
  initialized: boolean;
  orm: string;
  dialect: string;
  clients: number;
}

export interface ClientMutation {
  clientName?: string;
  password?: string | null;
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
}

export interface HttpRouteMutation {
  route: string;
  targetBaseUrl: string;
  enabled?: boolean;
}

// LiveConnectionEvent is the JSON pushed over /ws/connections.
export interface LiveConnectionEvent {
  tenantId?: string;
  type: "created" | "updated";
  connection: ConnectionRecord;
}
