// API DTOs mirroring the admin REST surface served by every specus-server implementation.

export interface OidcConfig {
  configured: boolean;
  passwordLoginEnabled: boolean;
  registrationEnabled?: boolean;
  emailVerificationRequired?: boolean;
  turnstileEnabled?: boolean;
  turnstileSiteKey?: string;
  authorizationEndpoint: string;
  endSessionEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope: string;
}

export interface TokenResponse {
  accessToken: string;
  idToken?: string;
  tokenType: string;
  expiresIn: number;
  error?: string;
  error_description?: string;
}

export interface RegistrationChallengeResponse {
  registrationId: string;
  emailMasked: string;
  expiresAt: string;
  resendAfterSeconds: number;
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
  messageSendCapable: boolean;
  messageReceiveCapable: boolean;
  messageAttachmentsCapable: boolean;
  messageMediaPreviewCapable: boolean;
  messageMaxAttachmentBytes: number;
  connectionRateLimitPerMinute: number;
  uploadBytes: number;
  downloadBytes: number;
  createdAt: string;
  updatedAt: string;
}

export interface ClientResult {
  client: Client;
}

export interface ClientNameAvailability {
  clientName: string;
  available: boolean;
}

export interface ClientDetail {
  client: Client;
  specusMappings: Specus[];
  httpRoutes: HttpRoute[];
}

/** S3.2 单客户端聚合详情 */
export interface ClientDetail {
  client: Client;
  specusMappings: Specus[];
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

export interface Specus {
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
  mediaCaptureEnabled: boolean;
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

export type ResourceTrafficType = "TCP_SPECUS" | "HTTP_ROUTE";

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
  id: string;
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
  requestHeaders: string | null;
  responseHeaders: string | null;
  requestPreviewHex: string | null;
  requestPreviewText: string | null;
  responsePreviewHex: string | null;
  responsePreviewText: string | null;
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
  specusMappings: number;
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

export interface PublicNatProbeEndpoint {
  id: "A1P1" | "A1P2" | "A2P1" | "A2P2" | string;
  url: string;
  host: string;
  port: number;
  addressSlot: "PRIMARY" | "ALTERNATE" | string;
  portSlot: "PRIMARY" | "ALTERNATE" | string;
}

export interface PublicNatProbeCapabilities {
  binding: boolean;
  changeRequest: boolean;
  responseOrigin: boolean;
  otherAddress: boolean;
  responsePort: boolean;
  padding: boolean;
  browserMappingObservation: boolean;
  browserFilteringObservation: boolean;
}

export interface PublicNatProbeConfig {
  available: boolean;
  protocol: "RFC8489" | string;
  discoveryMethod: "RFC5780" | "BASIC_STUN" | string;
  endpoints: PublicNatProbeEndpoint[];
  capabilities: PublicNatProbeCapabilities;
}

export interface PublicIceServer {
  urls: string;
  username: string;
  credential: string;
}

export interface PublicTransferIceConfig {
  peerMeshEnabled: boolean;
  iceServers: PublicIceServer[];
  turnAuthRequired: boolean;
  stunTurnPort: number;
}

export interface TransferAttachment {
  attachmentId: number;
  objectId: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256?: string | null;
  status: "PENDING" | "UPLOADED" | "EXPIRED" | string;
  expiresAt: string;
}

export interface AttachmentPresignUploadRequest {
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256?: string | null;
  roomId?: string;
  roomToken?: string;
  targetClientId?: number;
}

export interface AttachmentPresignUploadResponse {
  attachmentId: number;
  objectId: string;
  objectKey: string;
  uploadUrl: string;
  uploadHeaders: Record<string, string>;
  expiresAt: string;
  attachment: TransferAttachment;
}

export interface AttachmentCompleteRequest {
  roomToken?: string;
}

export interface AttachmentPresignDownloadRequest {
  roomToken?: string;
}

export interface AttachmentPresignDownloadResponse {
  attachmentId: number;
  objectId: string;
  downloadUrl: string;
  downloadHeaders: Record<string, string>;
  expiresAt: string;
  attachment: TransferAttachment;
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
  natMappingBehavior?: string | null;
  natFilteringBehavior?: string | null;
  natBehaviorDiscovery?: string | null;
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

export type HttpMediaKind = "PROGRESSIVE" | "MEDIA_SEGMENT" | "HLS_MANIFEST" | "DASH_MANIFEST";
export type HttpMediaCaptureState = "STARTING" | "CAPTURING" | "COMPLETE" | "INCOMPLETE" | "FAILED";

export interface HttpMediaCapture {
  id: number;
  clientId: number;
  clientName: string;
  route: string;
  resourceId: number | null;
  sourceUrl: string;
  method: string;
  statusCode: number;
  contentType: string | null;
  mediaKind: HttpMediaKind | string;
  entityTag: string | null;
  contentRangeStart: number | null;
  contentRangeEnd: number | null;
  totalBytes: number | null;
  capturedBytes: number;
  segmentSequence: number | null;
  initializationSegment: boolean;
  liveStream: boolean;
  state: HttpMediaCaptureState | string;
  failureReason: string | null;
  playable: boolean;
  offlineReady: boolean;
  playbackMessage: string | null;
  capturedAt: string;
  completedAt: string | null;
  expiresAt: string;
}

export interface HttpMediaCapturePage {
  items: HttpMediaCapture[];
  total: number;
  page: number;
  size: number;
  totalPages: number;
}

export interface HttpMediaPlaybackTicket {
  ticket: string;
  mediaKind: HttpMediaKind | string;
  playUrl: string;
  manifestUrl: string;
  totalBytes: number;
  initialRangeStart: number | null;
  initialRangeEnd: number | null;
  cachedRanges: HttpMediaPlaybackByteRange[];
  backfillMissing: boolean;
  expiresAt: string;
}

export interface HttpMediaPlaybackByteRange {
  start: number;
  end: number;
}

export interface PeerMeshAddressFamilyStat {
  addressFamily: "IPv4" | "IPv6" | "UNKNOWN" | string;
  status: string;
  pathType: string;
  sessions: number;
  reportedSessions: number;
}

export interface PeerMeshNatBehaviorStat {
  behavior: string;
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
  /** 按实际 PATH_REPORT 端点区分的 IPv4/IPv6 路径；未上报端点时为 UNKNOWN */
  addressFamilies: PeerMeshAddressFamilyStat[];
  natTypes: PeerMeshNatTypeStat[];
  /** 至少上报映射、过滤或探测方式之一的设备数 */
  natBehaviorDevices: number;
  /** 同时得到有效映射行为和过滤行为分类的设备数 */
  natBehaviorClassifiedDevices: number;
  natBehaviorSuccessRatio: number | null;
  natMappingBehaviors: PeerMeshNatBehaviorStat[];
  natFilteringBehaviors: PeerMeshNatBehaviorStat[];
  natBehaviorDiscoveries: PeerMeshNatBehaviorStat[];
}

export interface DatabaseInitResult {
  initialized: boolean;
  orm: string;
  dialect: string;
  clients: number;
}

export type PublicTransferRoomRole = "OWNER" | "EDITOR" | "VIEWER";

export interface PublicTransferRoomCredential {
  roomToken: string;
  peerId: string;
}

export interface PublicTransferClientNameAvailability {
  clientName: string;
  available: boolean;
}

export interface PublicTransferRoomAccessToken {
  id: number;
  role: Exclude<PublicTransferRoomRole, "OWNER">;
  label: string;
  createdAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

export interface PublicTransferCreatedAccessToken {
  access: PublicTransferRoomAccessToken;
  token: string;
}

export interface PublicTransferPairingCode {
  id: number;
  code: string;
  role: Exclude<PublicTransferRoomRole, "OWNER">;
  label: string;
  createdAt: string;
  expiresAt: string;
  maxUses: number;
  usedCount: number;
}

export interface PublicTransferRedeemedPairingCode {
  roomId: string;
  role: Exclude<PublicTransferRoomRole, "OWNER">;
  roomToken: string;
  expiresAt: string;
}

export interface PublicTransferDiagramVersion {
  id: number;
  name: string;
  authorPeerId: string;
  sizeBytes: number;
  createdAt: string;
}

export interface PublicTransferDiagramVersionDetail {
  version: PublicTransferDiagramVersion;
  update: string;
}

export interface UserDiagramDocument {
  id: number;
  name: string;
  sizeBytes: number;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export interface UserDiagramDocumentDetail {
  document: UserDiagramDocument;
  update: string;
}

export interface UserDiagramDocumentMutation {
  name: string;
  update: string;
  revision?: number;
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

export interface SpecusMutation {
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
  mediaCaptureEnabled?: boolean;
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

export interface WebSocketTicket {
  ticket: string;
  expiresAt: string;
}
