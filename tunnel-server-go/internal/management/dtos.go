// Package management implements the admin REST API (/auth/*, /api/admin/*) backed by the
// store, session registry, local JWT, and NAT control push. Mirrors the C# Management layer.
package management

import "errors"

// Sentinel errors mapped to HTTP status codes by the handlers.
var (
	ErrValidation = errors.New("validation error") // -> 400
	ErrConflict   = errors.New("conflict")         // -> 409
)

// ClientView is the JSON representation of a client account for the SPA.
type ClientView struct {
	ID                           int64  `json:"id"`
	ClientName                   string `json:"clientName"`
	Enabled                      bool   `json:"enabled"`
	ConnectionRateLimitPerMinute int    `json:"connectionRateLimitPerMinute"`
	Online                       bool   `json:"online"`
	ConnectedSinceMs             *int64 `json:"connectedSinceMs"`
	UploadBytes                  int64  `json:"uploadBytes"`
	DownloadBytes                int64  `json:"downloadBytes"`
	CreatedAt                    string `json:"createdAt"`
	UpdatedAt                    string `json:"updatedAt"`
}

// CredentialView wraps a client with a one-time plaintext password (create/update with password).
type CredentialView struct {
	Client   ClientView `json:"client"`
	Password string     `json:"password,omitempty"`
}

// TunnelView is the JSON representation of a tunnel mapping.
type TunnelView struct {
	ID            int64  `json:"id"`
	ClientID      int64  `json:"clientId"`
	ClientName    string `json:"clientName"`
	ListenPort    int    `json:"listenPort"`
	TargetAddress string `json:"targetAddress"`
	TargetPort    int    `json:"targetPort"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// HTTPRouteView is the JSON representation of an HTTP route mapping.
type HTTPRouteView struct {
	ID            int64  `json:"id"`
	ClientID      int64  `json:"clientId"`
	ClientName    string `json:"clientName"`
	Route         string `json:"route"`
	TargetBaseURL string `json:"targetBaseUrl"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
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
	Password                     string `json:"password"`
	Enabled                      *bool  `json:"enabled"`
	ConnectionRateLimitPerMinute *int   `json:"connectionRateLimitPerMinute"`
}

// tunnelMutation is the create/update tunnel request body.
type tunnelMutation struct {
	ListenPort    int    `json:"listenPort"`
	TargetAddress string `json:"targetAddress"`
	TargetPort    int    `json:"targetPort"`
	Enabled       *bool  `json:"enabled"`
}

// httpRouteMutation is the create/update HTTP route request body.
type httpRouteMutation struct {
	Route         string `json:"route"`
	TargetBaseURL string `json:"targetBaseUrl"`
	Enabled       *bool  `json:"enabled"`
}

// loginRequest is the admin login body.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
