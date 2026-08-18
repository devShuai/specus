// Package management implements the admin REST API (/auth/*, /api/admin/*) backed by the
// store, session registry, local JWT, and NAT control push. Mirrors the C# Management layer.
package management

import "errors"

// Sentinel errors mapped to HTTP status codes by the handlers.
var (
	ErrValidation  = errors.New("validation error") // -> 400
	ErrConflict    = errors.New("conflict")         // -> 409
	ErrForbidden   = errors.New("forbidden")        // -> 403
	ErrRateLimited = errors.New("rate limited")     // -> 429
	ErrUnavailable = errors.New("unavailable")      // -> 503
)

// ManagementUserView is the JSON representation of a management UI user.
type ManagementUserView struct {
	Username  string `json:"username"`
	TenantID  string `json:"tenantId"`
	Role      string `json:"role"`
	Admin     bool   `json:"admin"`
	BuiltIn   bool   `json:"builtIn"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// ClientView is the JSON representation of a client account for the SPA.
type ClientView struct {
	ID                           int64   `json:"id"`
	ClientName                   string  `json:"clientName"`
	OwnerUsername                string  `json:"ownerUsername,omitempty"`
	Enabled                      bool    `json:"enabled"`
	ConnectionRateLimitPerMinute int     `json:"connectionRateLimitPerMinute"`
	Online                       bool    `json:"online"`
	ConnectedSinceMs             *int64  `json:"connectedSinceMs"`
	MessageSendCapable           bool    `json:"messageSendCapable"`
	MessageReceiveCapable        bool    `json:"messageReceiveCapable"`
	MessageAttachmentsCapable    bool    `json:"messageAttachmentsCapable"`
	MessageMediaPreviewCapable   bool    `json:"messageMediaPreviewCapable"`
	MessageMaxAttachmentBytes    int64   `json:"messageMaxAttachmentBytes"`
	ClientVersion                *string `json:"clientVersion,omitempty"`
	UploadBytes                  int64   `json:"uploadBytes"`
	DownloadBytes                int64   `json:"downloadBytes"`
	CreatedAt                    string  `json:"createdAt"`
	UpdatedAt                    string  `json:"updatedAt"`
}

// ClientResult wraps a client mutation result.
type ClientResult struct {
	Client ClientView `json:"client"`
}

// ClientDetail is the aggregate detail shape used by the management drawer.
type ClientDetail struct {
	Client         ClientView      `json:"client"`
	SpecusMappings []SpecusView    `json:"specusMappings"`
	HTTPRoutes     []HTTPRouteView `json:"httpRoutes"`
}

// CredentialView is the JSON representation of a startup credential.
type CredentialView struct {
	ID                 int64  `json:"id"`
	APIKey             string `json:"apiKey"`
	OwnerUsername      string `json:"ownerUsername,omitempty"`
	Enabled            bool   `json:"enabled"`
	MaxOnlineInstances int    `json:"maxOnlineInstances"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
}

type CredentialResult struct {
	Credential CredentialView `json:"credential"`
	Secret     string         `json:"secret,omitempty"`
}

// ClientDownloadLinkView is the JSON representation of a managed/public client download link.
type ClientDownloadLinkView struct {
	ID                  int64   `json:"id"`
	Implementation      string  `json:"implementation"`
	Platform            string  `json:"platform"`
	Arch                string  `json:"arch"`
	Version             string  `json:"version"`
	DisplayName         string  `json:"displayName"`
	DownloadURL         string  `json:"downloadUrl"`
	Description         *string `json:"description,omitempty"`
	SHA256              string  `json:"sha256"`
	FileSize            int64   `json:"fileSize"`
	IsLatest            bool    `json:"isLatest"`
	ChangelogURL        *string `json:"changelogUrl,omitempty"`
	MinSupportedVersion *string `json:"minSupportedVersion,omitempty"`
	Hosted              bool    `json:"hosted"`
	PackageID           *int64  `json:"packageId"`
	DisplayOrder        int     `json:"displayOrder"`
	Enabled             bool    `json:"enabled"`
	CreatedAt           string  `json:"createdAt"`
	UpdatedAt           string  `json:"updatedAt"`
}

type ClientVersionCheckView struct {
	UpdateAvailable bool    `json:"updateAvailable"`
	Mandatory       bool    `json:"mandatory"`
	LatestVersion   *string `json:"latestVersion"`
	PackageID       *int64  `json:"packageId"`
	DownloadURL     *string `json:"downloadUrl"`
	SHA256          *string `json:"sha256"`
	FileSize        int64   `json:"fileSize"`
	ChangelogURL    *string `json:"changelogUrl,omitempty"`
}

// SpecusView is the JSON representation of a specus mapping.
type SpecusView struct {
	ID                   int64  `json:"id"`
	ClientID             int64  `json:"clientId"`
	ClientName           string `json:"clientName"`
	ListenPort           int    `json:"listenPort"`
	TargetAddress        string `json:"targetAddress"`
	TargetPort           int    `json:"targetPort"`
	Enabled              bool   `json:"enabled"`
	DetailCaptureEnabled bool   `json:"detailCaptureEnabled"`
	CreatedAt            string `json:"createdAt"`
	UpdatedAt            string `json:"updatedAt"`
}

// HTTPRouteView is the JSON representation of an HTTP route mapping.
type HTTPRouteView struct {
	ID                     int64  `json:"id"`
	ClientID               int64  `json:"clientId"`
	ClientName             string `json:"clientName"`
	Route                  string `json:"route"`
	TargetBaseURL          string `json:"targetBaseUrl"`
	Enabled                bool   `json:"enabled"`
	DetailCaptureEnabled   bool   `json:"detailCaptureEnabled"`
	MediaCaptureEnabled    bool   `json:"mediaCaptureEnabled"`
	PathRewriteEnabled     bool   `json:"pathRewriteEnabled"`
	AuthEnabled            bool   `json:"authEnabled"`
	AuthUsername           string `json:"authUsername"`
	AuthPasswordConfigured bool   `json:"authPasswordConfigured"`
	CreatedAt              string `json:"createdAt"`
	UpdatedAt              string `json:"updatedAt"`
}

// ConnectionItem is one row in a paged connection listing.
type ConnectionItem struct {
	ID                   int64   `json:"id"`
	ClientID             *int64  `json:"clientId"`
	ClientName           string  `json:"clientName"`
	ChannelID            *string `json:"channelId"`
	RemoteAddress        *string `json:"remoteAddress"`
	ConnectedAt          string  `json:"connectedAt"`
	DisconnectedAt       *string `json:"disconnectedAt"`
	Success              bool    `json:"success"`
	FailureReason        *string `json:"failureReason"`
	DisconnectReason     *string `json:"disconnectReason"`
	DisconnectReasonText *string `json:"disconnectReasonText"`
}

// ConnectionPage is a paged connection listing.
type ConnectionPage struct {
	Items      []ConnectionItem `json:"items"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	Size       int              `json:"size"`
	TotalPages int              `json:"totalPages"`
}

// TrafficView is one traffic-usage row.
type TrafficView struct {
	ID            int64  `json:"id"`
	ClientID      int64  `json:"clientId"`
	ClientName    string `json:"clientName"`
	UsageDate     string `json:"usageDate"`
	UploadBytes   int64  `json:"uploadBytes"`
	DownloadBytes int64  `json:"downloadBytes"`
	UpdatedAt     string `json:"updatedAt"`
}

type ResourceTrafficUsageView struct {
	ID            int64  `json:"id"`
	ClientID      int64  `json:"clientId"`
	ClientName    string `json:"clientName"`
	ResourceType  string `json:"resourceType"`
	ResourceKey   string `json:"resourceKey"`
	ResourceID    *int64 `json:"resourceId,omitempty"`
	ResourceName  string `json:"resourceName"`
	UsageDate     string `json:"usageDate"`
	UploadBytes   int64  `json:"uploadBytes"`
	DownloadBytes int64  `json:"downloadBytes"`
	UpdatedAt     string `json:"updatedAt"`
}

// HTTPTrafficExchangeView mirrors the Java HTTP exchange detail payload.
type HTTPTrafficExchangeView struct {
	ID                  string  `json:"id"`
	ClientID            int64   `json:"clientId"`
	ClientName          string  `json:"clientName"`
	Route               string  `json:"route"`
	ResourceID          *int64  `json:"resourceId,omitempty"`
	ResourceName        *string `json:"resourceName,omitempty"`
	Method              string  `json:"method"`
	RelativePath        string  `json:"relativePath"`
	RawQuery            string  `json:"rawQuery"`
	StatusCode          int     `json:"statusCode"`
	Success             bool    `json:"success"`
	Error               *string `json:"error,omitempty"`
	RemoteAddress       *string `json:"remoteAddress,omitempty"`
	RequestBytes        int64   `json:"requestBytes"`
	ResponseBytes       int64   `json:"responseBytes"`
	ElapsedMs           int64   `json:"elapsedMs"`
	RequestContentType  *string `json:"requestContentType,omitempty"`
	ResponseContentType *string `json:"responseContentType,omitempty"`
	ResponseBodyType    string  `json:"responseBodyType"`
	RequestHeaders      string  `json:"requestHeaders"`
	ResponseHeaders     string  `json:"responseHeaders"`
	RequestPreviewHex   string  `json:"requestPreviewHex"`
	RequestPreviewText  string  `json:"requestPreviewText"`
	ResponsePreviewHex  string  `json:"responsePreviewHex"`
	ResponsePreviewText string  `json:"responsePreviewText"`
	RequestTruncated    bool    `json:"requestTruncated"`
	ResponseTruncated   bool    `json:"responseTruncated"`
	CapturedAt          string  `json:"capturedAt"`
}

// TCPTrafficFrameView mirrors the Java TCP frame detail payload.
type TCPTrafficFrameView struct {
	ID                 string  `json:"id"`
	ClientID           int64   `json:"clientId"`
	ClientName         string  `json:"clientName"`
	ListenPort         int     `json:"listenPort"`
	ResourceID         *int64  `json:"resourceId,omitempty"`
	ResourceName       *string `json:"resourceName,omitempty"`
	ChannelID          string  `json:"channelId"`
	Direction          string  `json:"direction"`
	RemoteAddress      *string `json:"remoteAddress,omitempty"`
	SourceAddress      *string `json:"sourceAddress,omitempty"`
	SourcePort         *int    `json:"sourcePort,omitempty"`
	DestinationAddress *string `json:"destinationAddress,omitempty"`
	DestinationPort    *int    `json:"destinationPort,omitempty"`
	StreamOffset       int64   `json:"streamOffset"`
	StreamEndOffset    int64   `json:"streamEndOffset"`
	FrameIndex         int64   `json:"frameIndex"`
	PayloadBytes       int64   `json:"payloadBytes"`
	PayloadBase64      string  `json:"payloadBase64,omitempty"`
	PayloadPreviewHex  string  `json:"payloadPreviewHex"`
	PayloadPreviewText string  `json:"payloadPreviewText"`
	Truncated          bool    `json:"truncated"`
	FrameTime          string  `json:"frameTime"`
}

// TrafficDetailPage is the shared paged payload used by detail traffic endpoints.
type TrafficDetailPage[T any] struct {
	Items      []T `json:"items"`
	Total      int `json:"total"`
	Page       int `json:"page"`
	Size       int `json:"size"`
	TotalPages int `json:"totalPages"`
}

// ConnectionStatView is one archived monthly stat row.
type ConnectionStatView struct {
	ID         int64  `json:"id"`
	ClientID   *int64 `json:"clientId"`
	ClientName string `json:"clientName"`
	Month      string `json:"month"`
	Total      int64  `json:"total"`
	Success    int64  `json:"success"`
	Failure    int64  `json:"failure"`
	UpdatedAt  string `json:"updatedAt"`
}

// OverviewView is the dashboard summary.
type OverviewView struct {
	Clients                     int64 `json:"clients"`
	OnlineClients               int   `json:"onlineClients"`
	SuccessfulConnections       int64 `json:"successfulConnections"`
	FailedConnections           int64 `json:"failedConnections"`
	UploadBytes                 int64 `json:"uploadBytes"`
	DownloadBytes               int64 `json:"downloadBytes"`
	ExternalConnections         int64 `json:"externalConnections"`
	RejectedExternalConnections int64 `json:"rejectedExternalConnections"`
}

// clientMutation is the create/update client request body.
type clientMutation struct {
	ClientName                   string `json:"clientName"`
	Enabled                      *bool  `json:"enabled"`
	ConnectionRateLimitPerMinute *int   `json:"connectionRateLimitPerMinute"`
}

type credentialMutation struct {
	APIKey             string `json:"apiKey"`
	Secret             string `json:"secret"`
	Enabled            *bool  `json:"enabled"`
	MaxOnlineInstances *int   `json:"maxOnlineInstances"`
}

type clientDownloadLinkMutation struct {
	Implementation      string `json:"implementation"`
	Platform            string `json:"platform"`
	Arch                string `json:"arch"`
	Version             string `json:"version"`
	DisplayName         string `json:"displayName"`
	DownloadURL         string `json:"downloadUrl"`
	Description         string `json:"description"`
	ChangelogURL        string `json:"changelogUrl"`
	MinSupportedVersion string `json:"minSupportedVersion"`
	DisplayOrder        *int   `json:"displayOrder"`
	Enabled             *bool  `json:"enabled"`
	IsLatest            *bool  `json:"isLatest"`
}

// specusMutation is the create/update specus request body.
type specusMutation struct {
	ListenPort           int    `json:"listenPort"`
	TargetAddress        string `json:"targetAddress"`
	TargetPort           int    `json:"targetPort"`
	Enabled              *bool  `json:"enabled"`
	DetailCaptureEnabled *bool  `json:"detailCaptureEnabled"`
}

// httpRouteMutation is the create/update HTTP route request body.
type httpRouteMutation struct {
	Route                string  `json:"route"`
	TargetBaseURL        string  `json:"targetBaseUrl"`
	Enabled              *bool   `json:"enabled"`
	DetailCaptureEnabled *bool   `json:"detailCaptureEnabled"`
	MediaCaptureEnabled  *bool   `json:"mediaCaptureEnabled"`
	PathRewriteEnabled   *bool   `json:"pathRewriteEnabled"`
	AuthEnabled          *bool   `json:"authEnabled"`
	AuthUsername         *string `json:"authUsername"`
	AuthPassword         *string `json:"authPassword"`
}

// loginRequest is the admin login body.
type loginRequest struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	TurnstileToken string `json:"turnstileToken"`
}

type registrationRequest struct {
	Username       string `json:"username"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	TurnstileToken string `json:"turnstileToken"`
}

type registrationVerificationRequest struct {
	RegistrationID string `json:"registrationId"`
	Code           string `json:"code"`
}

type userMutation struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Enabled  *bool  `json:"enabled"`
}
