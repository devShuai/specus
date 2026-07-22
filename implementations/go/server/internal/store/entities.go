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

// ClientAccount mirrors tunnel_client_account.
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

// ClientCredential mirrors tunnel_client_credential.
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
	PeerID            string
	DisplayName       string
	SharedRoom        bool
	RemoteAddressHash string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// ManagementUser mirrors tunnel_management_user.
type ManagementUser struct {
	Username     string
	TenantID     string
	PasswordHash string
	Role         string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
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
	ID              int64
	TenantID        *string
	Scope           string
	RoomID          *string
	RoomTokenHash   *string
	OwnerUsername   *string
	TargetClientID  *int64
	ObjectKey       string
	FileName        string
	MimeType        string
	SizeBytes       int64
	SHA256          *string
	Status          string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	UploadExpiresAt time.Time
	ExpiresAt       time.Time
	UploadedAt      *time.Time
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

// ClientIdentity mirrors tunnel_client_identity.
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

// ClientSession mirrors tunnel_client_session.
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

// ConnectionRecord mirrors tunnel_connection_record.
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

// TunnelMapping mirrors tunnel_mapping.
type TunnelMapping struct {
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
	PathRewriteEnabled   bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// TrafficUsage mirrors tunnel_traffic_usage.
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

// ResourceTrafficUsage mirrors tunnel_resource_traffic_usage.
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

// HTTPTrafficExchange mirrors tunnel_http_traffic_exchange.
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

// TCPTrafficFrame mirrors tunnel_tcp_traffic_frame.
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

// ConnectionStat mirrors tunnel_connection_stat.
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
