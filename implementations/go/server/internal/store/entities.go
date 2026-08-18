package store

import "time"

const (
	ManagementRoleAdmin = "ADMIN"
	ManagementRoleUser  = "USER"
)

// DisconnectReason wire strings (UPPER_SNAKE_CASE, matching the Java enum names).
const (
	ReasonLoginFailure       = "LOGIN_FAILURE"
	ReasonClientClosed       = "CLIENT_CLOSED"
	ReasonIOError            = "IO_ERROR"
	ReasonIdleTimeout        = "IDLE_TIMEOUT"
	ReasonHeartbeatWriteFail = "HEARTBEAT_WRITE_FAILED"
	ReasonProtocolViolation  = "PROTOCOL_VIOLATION"
	ReasonRegisterFailed     = "REGISTER_FAILED"
	ReasonReplacedByNewLogin = "REPLACED_BY_NEW_LOGIN"
	ReasonAdminDisabled      = "ADMIN_DISABLED"
	ReasonAdminRenamed       = "ADMIN_RENAMED"
	ReasonAdminDeleted       = "ADMIN_DELETED"
	ReasonServerBusy         = "SERVER_BUSY"
	ReasonServerShutdown     = "SERVER_SHUTDOWN"
	ReasonServerRestarted    = "SERVER_RESTARTED"
	ReasonUnknown            = "UNKNOWN"
)

// ReasonText maps a disconnect-reason wire string to its Chinese label (matches the C# UI text).
func ReasonText(reason string) string {
	switch reason {
	case ReasonLoginFailure:
		return "登录失败"
	case ReasonClientClosed:
		return "客户端正常断开"
	case ReasonIOError:
		return "传输异常"
	case ReasonIdleTimeout:
		return "读空闲超时(60s)"
	case ReasonHeartbeatWriteFail:
		return "心跳发送失败"
	case ReasonProtocolViolation:
		return "协议违规"
	case ReasonRegisterFailed:
		return "注册失败"
	case ReasonReplacedByNewLogin:
		return "被新登录替换"
	case ReasonAdminDisabled:
		return "管理员停用账号"
	case ReasonAdminRenamed:
		return "管理员修改账号名"
	case ReasonAdminDeleted:
		return "管理员删除账号"
	case ReasonServerBusy:
		return "服务端繁忙拒绝"
	case ReasonServerShutdown:
		return "服务端优雅停机"
	case ReasonServerRestarted:
		return "服务端重启时清理"
	default:
		return "未知"
	}
}

// ClientAccount mirrors specus_client_account.
type ClientAccount struct {
	ID                           int64
	TenantID                     string
	OwnerUsername                string
	ClientName                   string
	PasswordHash                 string
	Enabled                      bool
	ConnectionRateLimitPerMinute int
	CreatedAt                    time.Time
	UpdatedAt                    time.Time
}

// ClientCredential mirrors specus_client_credential.
type ClientCredential struct {
	ID                 int64
	TenantID           string
	OwnerUsername      string
	APIKey             string
	SecretHash         string
	Enabled            bool
	MaxOnlineInstances int
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// WebSocketTicket stores only a digest of a short-lived, single-use upgrade credential.
type WebSocketTicket struct {
	TokenHash         string
	Scope             string
	Username          string
	TenantID          string
	Admin             bool
	RoomID            string
	RoomKey           string
	RoomRole          string
	PeerID            string
	DisplayName       string
	PublicAddress     string
	SharedRoom        bool
	Discoverable      bool
	RemoteAddressHash string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// ManagementUser mirrors specus_management_user.
type ManagementUser struct {
	Username        string
	TenantID        string
	PasswordHash    string
	OIDCIssuer      string
	OIDCSubject     string
	OIDCIdentityKey string
	Role            string
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type ManagementUserEmail struct {
	Username   string
	Email      string
	VerifiedAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type ManagementRegistrationChallenge struct {
	RegistrationID    string
	Username          string
	Email             string
	PasswordHash      string
	CodeHash          string
	AttemptsRemaining int
	ExpiresAt         time.Time
	ResendAvailableAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ClientDownloadLink mirrors client_download_link.
type ClientDownloadLink struct {
	ID             int64
	Implementation string
	Platform       string
	Arch           string
	DisplayName    string
	DownloadURL    string
	Description    *string
	DisplayOrder   int
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TransferAttachment mirrors transfer_attachment used by public transfers and admin messages.
type TransferAttachment struct {
	ID            int64
	TenantID      *string
	Scope         string
	RoomID        *string
	RoomTokenHash *string
	// PublicTransferRoomID binds the attachment to the persistent room row rather than to one
	// room token, so rotating or revoking a token keeps room membership authoritative.
	PublicTransferRoomID *int64
	OwnerUsername        *string
	TargetClientID       *int64
	ObjectKey            string
	FileName             string
	MimeType             string
	SizeBytes            int64
	SHA256               *string
	Status               string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	UploadExpiresAt      time.Time
	ExpiresAt            time.Time
	UploadedAt           *time.Time
}

// TransferAttachmentDownloadGrant stores only the hash of a single-use download token.
type TransferAttachmentDownloadGrant struct {
	ID           int64
	TokenHash    string
	TenantID     string
	Username     string
	AttachmentID int64
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
}

// ClientIdentity mirrors specus_client_identity.
type ClientIdentity struct {
	ID                 int64
	TenantID           string
	CredentialID       int64
	ClientID           int64
	ClientName         string
	MachineFingerprint string
	OSUser             string
	Hostname           string
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
}

// ClientSession mirrors specus_client_session.
type ClientSession struct {
	ID                         int64
	TenantID                   string
	CredentialID               int64
	IdentityID                 int64
	ClientID                   int64
	ClientName                 string
	TokenHash                  string
	Status                     string
	MachineFingerprint         string
	OSUser                     string
	Hostname                   *string
	OSName                     *string
	OSVersion                  *string
	OSArch                     *string
	ClientVersion              *string
	JavaVersion                *string
	LocalAddresses             *string
	MessageSendCapable         bool
	MessageReceiveCapable      bool
	MessageAttachmentsCapable  bool
	MessageMediaPreviewCapable bool
	MessageMaxAttachmentBytes  int64
	HTTPLoginAt                time.Time
	NettyConnectedAt           *time.Time
	DisconnectedAt             *time.Time
	ExpiresAt                  time.Time
	ChannelID                  *string
	RemoteAddress              *string
}

// PeerMeshDevice mirrors peer_mesh_device.
type PeerMeshDevice struct {
	ID                     int64
	TenantID               string
	OwnerUsername          string
	ClientID               int64
	ClientName             string
	VirtualIP              string
	CIDR                   string
	PublicKey              *string
	NatType                *string
	NatMappingBehavior     *string
	NatFilteringBehavior   *string
	NatBehaviorDiscovery   *string
	LastEndpoint           *string
	VirtualDeviceMode      *string
	VirtualDeviceName      *string
	VirtualDeviceStatus    *string
	VirtualDeviceError     *string
	VirtualDeviceUpdatedAt *time.Time
	Enabled                bool
	LastSeenAt             *time.Time
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// PeerMeshACL mirrors peer_mesh_acl.
type PeerMeshACL struct {
	ID               int64
	TenantID         string
	OwnerUsername    string
	SourceClientID   int64
	SourceClientName string
	TargetClientID   int64
	TargetClientName string
	Allowed          bool
	Direction        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PeerMeshSession mirrors peer_mesh_session.
type PeerMeshSession struct {
	ID               int64
	TenantID         string
	SourceClientID   int64
	SourceClientName string
	TargetClientID   int64
	TargetClientName string
	PathType         string
	Status           string
	TokenHash        *string
	StartedAt        time.Time
	UpdatedAt        time.Time
	ExpiresAt        time.Time
	ClosedAt         *time.Time
	RTTMillis        *int64
	LocalEndpoint    *string
	RemoteEndpoint   *string
	DirectBytes      int64
	RelayBytes       int64
	LastTrafficAt    *time.Time
}

// ConnectionRecord mirrors specus_connection_record.
type ConnectionRecord struct {
	ID               int64
	TenantID         string
	ClientID         *int64
	ClientName       string
	ChannelID        *string
	RemoteAddress    *string
	ConnectedAt      time.Time
	DisconnectedAt   *time.Time
	Success          bool
	FailureReason    *string
	DisconnectReason *string
}

// SpecusMapping mirrors specus_mapping.
type SpecusMapping struct {
	ID                   int64
	TenantID             string
	ClientID             int64
	ClientName           string
	ListenPort           int
	TargetAddress        string
	TargetPort           int
	Enabled              bool
	DetailCaptureEnabled bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// HTTPRouteMapping mirrors http_route_mapping.
type HTTPRouteMapping struct {
	ID                   int64
	TenantID             string
	ClientID             int64
	ClientName           string
	Route                string
	TargetBaseURL        string
	Enabled              bool
	DetailCaptureEnabled bool
	MediaCaptureEnabled  bool
	PathRewriteEnabled   bool
	AuthEnabled          bool
	AuthUsername         string
	AuthPasswordHash     string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// HTTPRouteAccessPolicy contains only the server-side settings needed before a public
// HTTP/WS request is allowed into a client's tunnel. A nil policy means the route is not
// managed by the server and therefore retains the legacy public-access behaviour.
type HTTPRouteAccessPolicy struct {
	TenantID            string
	ClientID            int64
	ResourceID          int64
	Enabled             bool
	PathRewriteEnabled  bool
	MediaCaptureEnabled bool
	AuthEnabled         bool
	AuthUsername        string
	AuthPasswordHash    string
}

// HTTPMediaCapture mirrors specus_http_media_capture. Nullable HTTP metadata remains
// pointer-valued so a missing Content-Range/Content-Length is distinct from zero.
type HTTPMediaCapture struct {
	ID                    int64
	TenantID              string
	ClientID              int64
	ClientName            string
	Route                 string
	ResourceID            *int64
	SourceURL             string
	ResourceKey           string
	DeduplicationKey      *string
	Method                string
	StatusCode            int
	ContentType           *string
	ContentEncoding       *string
	MediaKind             string
	EntityTag             *string
	LastModified          *string
	ContentRangeStart     *int64
	ContentRangeEnd       *int64
	TotalBytes            *int64
	CapturedBytes         int64
	SegmentSequence       *int64
	InitializationSegment bool
	LiveStream            bool
	ObjectKey             string
	UploadID              *string
	ObjectETag            *string
	State                 string
	FailureReason         *string
	ResponseHeaders       string
	CapturedAt            time.Time
	CompletedAt           *time.Time
	ExpiresAt             time.Time
}

// HTTPMediaReference mirrors specus_http_media_reference.
type HTTPMediaReference struct {
	ID                int64
	TenantID          string
	ManifestCaptureID int64
	RelationType      string
	SequenceIndex     *int64
	OriginalURI       string
	ResolvedSourceURL string
	CreatedAt         time.Time
}

type HTTPMediaCaptureFilter struct {
	TenantID  string
	ClientID  *int64
	ClientIDs []int64
	Route     string
	Page      int
	Size      int
}

// TrafficUsage mirrors specus_traffic_usage.
type TrafficUsage struct {
	ID            int64
	TenantID      string
	ClientID      int64
	ClientName    string
	UsageDate     string
	UploadBytes   int64
	DownloadBytes int64
	UpdatedAt     time.Time
}

// ResourceTrafficUsage mirrors specus_resource_traffic_usage.
type ResourceTrafficUsage struct {
	ID            int64
	TenantID      string
	ClientID      int64
	ClientName    string
	ResourceType  string
	ResourceKey   string
	ResourceID    *int64
	ResourceName  string
	UsageDate     string
	UploadBytes   int64
	DownloadBytes int64
	UpdatedAt     time.Time
}

// HTTPTrafficExchange mirrors specus_http_traffic_exchange.
type HTTPTrafficExchange struct {
	ID                  int64
	TenantID            string
	ClientID            int64
	ClientName          string
	Route               string
	ResourceID          *int64
	ResourceName        *string
	Method              string
	RelativePath        string
	RawQuery            string
	StatusCode          int
	Success             bool
	Error               *string
	RemoteAddress       *string
	RequestBytes        int64
	ResponseBytes       int64
	ElapsedMs           int64
	RequestContentType  *string
	ResponseContentType *string
	ResponseBodyType    string
	RequestHeaders      string
	ResponseHeaders     string
	RequestPreviewHex   string
	RequestPreviewText  string
	ResponsePreviewHex  string
	ResponsePreviewText string
	RequestTruncated    bool
	ResponseTruncated   bool
	CapturedAt          time.Time
}

// TCPTrafficFrame mirrors specus_tcp_traffic_frame.
type TCPTrafficFrame struct {
	ID                 int64
	TenantID           string
	ClientID           int64
	ClientName         string
	ListenPort         int
	ResourceID         *int64
	ResourceName       *string
	ChannelID          string
	Direction          string
	RemoteAddress      *string
	SourceAddress      *string
	SourcePort         *int
	DestinationAddress *string
	DestinationPort    *int
	StreamOffset       int64
	StreamEndOffset    int64
	FrameIndex         int64
	PayloadBytes       int64
	PayloadData        []byte
	PayloadPreviewHex  string
	PayloadPreviewText string
	Truncated          bool
	FrameTime          time.Time
}

// ConnectionStat mirrors specus_connection_stat.
type ConnectionStat struct {
	ID           int64
	TenantID     string
	ClientID     *int64
	ClientName   string
	StatMonth    string
	TotalCount   int64
	SuccessCount int64
	FailureCount int64
	UpdatedAt    time.Time
}

// PublicTransferRoom mirrors public_transfer_room (Java PublicTransferRoom).
type PublicTransferRoom struct {
	ID              int64
	RoomName        string
	OwnerTokenHash  string
	CreatedByPeerID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// PublicTransferRoomAccess mirrors public_transfer_room_access (Java PublicTransferRoomAccess).
type PublicTransferRoomAccess struct {
	ID        int64
	RoomID    int64
	TokenHash string
	Role      string
	Label     string
	CreatedAt time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// PublicTransferRoomPairingCode mirrors public_transfer_room_pairing_code. The plaintext
// eight-digit code is never persisted.
type PublicTransferRoomPairingCode struct {
	ID        int64
	RoomID    int64
	CodeHash  string
	Role      string
	Label     string
	CreatedAt time.Time
	ExpiresAt time.Time
	MaxUses   int
	UsedCount int
	RevokedAt *time.Time
}

// PublicTransferDiagramVersion mirrors public_transfer_diagram_version.
type PublicTransferDiagramVersion struct {
	ID           int64
	RoomID       int64
	Name         string
	AuthorPeerID string
	SnapshotData []byte
	SizeBytes    int64
	CreatedAt    time.Time
}

// UserDiagramDocument mirrors user_diagram_document (Java UserDiagramDocument).
type UserDiagramDocument struct {
	ID            int64
	TenantID      string
	OwnerUsername string
	Name          string
	SnapshotData  []byte
	SizeBytes     int64
	Revision      int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
