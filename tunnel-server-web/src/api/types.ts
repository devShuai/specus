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
  type: "created" | "updated";
  connection: ConnectionRecord;
}
