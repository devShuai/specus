package store

import "time"

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

// ConnectionRecord mirrors tunnel_connection_record.
type ConnectionRecord struct {
	ID               int64
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
	ID            int64
	ClientID      int64
	ClientName    string
	ListenPort    int
	TargetAddress string
	TargetPort    int
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// HTTPRouteMapping mirrors http_route_mapping.
type HTTPRouteMapping struct {
	ID            int64
	ClientID      int64
	ClientName    string
	Route         string
	TargetBaseURL string
	Enabled       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// TrafficUsage mirrors tunnel_traffic_usage.
type TrafficUsage struct {
	ID            int64
	ClientID      int64
	ClientName    string
	UsageDate     string
	UploadBytes   int64
	DownloadBytes int64
	UpdatedAt     time.Time
}

// ConnectionStat mirrors tunnel_connection_stat.
type ConnectionStat struct {
	ID           int64
	ClientID     *int64
	ClientName   string
	StatMonth    string
	TotalCount   int64
	SuccessCount int64
	FailureCount int64
	UpdatedAt    time.Time
}
