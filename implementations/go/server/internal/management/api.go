package management

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/auth"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/nat"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/peermesh"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/security"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/session"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/wsevents"
)

// API holds the dependencies for the admin REST surface.
type API struct {
	db           *store.DB
	sessions     *session.Registry
	tokens       *security.LocalTokenService
	oidcAuth     *security.OidcValidator
	natControl   *nat.ControlService
	remotePorts  *nat.RemotePortManager
	oidc         config.OidcConfig
	authConfig   config.AuthConfig
	clientAuth   config.ClientAuthConfig
	traffic      config.TrafficConfig
	trafficUsage *nat.TrafficService
	seedDemo     func(ctx context.Context) error
	peerMesh     *peermesh.Service
}

// NewAPI builds the admin API.
func NewAPI(db *store.DB, sessions *session.Registry, tokens *security.LocalTokenService,
	oidcAuth *security.OidcValidator, natControl *nat.ControlService, remotePorts *nat.RemotePortManager,
	oidc config.OidcConfig, authConfig config.AuthConfig, clientAuth config.ClientAuthConfig,
	traffic config.TrafficConfig, trafficUsage *nat.TrafficService,
	seedDemo func(ctx context.Context) error, peerMesh *peermesh.Service) *API {
	return &API{db: db, sessions: sessions, tokens: tokens, oidcAuth: oidcAuth, natControl: natControl,
		remotePorts: remotePorts, oidc: oidc, authConfig: authConfig, clientAuth: clientAuth,
		traffic: traffic, trafficUsage: trafficUsage, seedDemo: seedDemo,
		peerMesh: peerMesh}
}

// Register attaches all auth and admin routes to mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/login", a.handleLogin)
	mux.HandleFunc("POST /auth/refresh", a.requireAuth(a.handleRefresh))
	mux.HandleFunc("GET /oidc-config", a.handleOidcConfig)
	mux.HandleFunc("POST /oidc/token", a.handleOidcToken)
	mux.HandleFunc("GET /api/public/client-downloads", a.handlePublicClientDownloads)
	mux.HandleFunc("GET /api/public/peer-mesh/stun-config", a.handlePublicPeerMeshStunConfig)

	mux.HandleFunc("GET /api/admin/overview", a.requireAuth(a.handleOverview))
	mux.HandleFunc("POST /api/admin/database/initialize", a.requireAuth(a.handleDatabaseInitialize))
	mux.HandleFunc("GET /api/admin/me", a.requireAuth(a.handleMe))
	mux.HandleFunc("GET /api/admin/users", a.requireAuth(a.handleListUsers))
	mux.HandleFunc("POST /api/admin/users", a.requireAuth(a.handleCreateUser))
	mux.HandleFunc("PUT /api/admin/users/{username}", a.requireAuth(a.handleUpdateUser))
	mux.HandleFunc("DELETE /api/admin/users/{username}", a.requireAuth(a.handleDeleteUser))

	mux.HandleFunc("GET /api/admin/clients", a.requireAuth(a.handleListClients))
	mux.HandleFunc("GET /api/admin/clients/{id}", a.requireAuth(a.handleGetClient))
	mux.HandleFunc("POST /api/admin/clients", a.requireAuth(a.handleCreateClient))
	mux.HandleFunc("PUT /api/admin/clients/{id}", a.requireAuth(a.handleUpdateClient))
	mux.HandleFunc("DELETE /api/admin/clients/{id}", a.requireAuth(a.handleDeleteClient))
	mux.HandleFunc("POST /api/admin/clients/{id}/force-refresh-port-mapping", a.requireAuth(a.handleNatControl))

	mux.HandleFunc("GET /api/admin/client-credentials", a.requireAuth(a.handleListCredentials))
	mux.HandleFunc("POST /api/admin/client-credentials", a.requireAuth(a.handleCreateCredential))
	mux.HandleFunc("PUT /api/admin/client-credentials/{id}", a.requireAuth(a.handleUpdateCredential))
	mux.HandleFunc("DELETE /api/admin/client-credentials/{id}", a.requireAuth(a.handleDeleteCredential))
	mux.HandleFunc("GET /api/admin/client-downloads", a.requireAuth(a.handleListClientDownloads))
	mux.HandleFunc("POST /api/admin/client-downloads", a.requireAuth(a.handleCreateClientDownload))
	mux.HandleFunc("PUT /api/admin/client-downloads/{id}", a.requireAuth(a.handleUpdateClientDownload))
	mux.HandleFunc("DELETE /api/admin/client-downloads/{id}", a.requireAuth(a.handleDeleteClientDownload))

	mux.HandleFunc("GET /api/admin/tunnels", a.requireAuth(a.handleListTunnels))
	mux.HandleFunc("POST /api/admin/clients/{id}/tunnels", a.requireAuth(a.handleCreateTunnel))
	mux.HandleFunc("PUT /api/admin/tunnels/{tunnelId}", a.requireAuth(a.handleUpdateTunnel))
	mux.HandleFunc("DELETE /api/admin/tunnels/{tunnelId}", a.requireAuth(a.handleDeleteTunnel))
	mux.HandleFunc("POST /api/admin/clients/{id}/nat-control", a.requireAuth(a.handleNatControl))

	mux.HandleFunc("GET /api/admin/http-routes", a.requireAuth(a.handleListHTTPRoutes))
	mux.HandleFunc("POST /api/admin/clients/{id}/http-routes", a.requireAuth(a.handleCreateHTTPRoute))
	mux.HandleFunc("PUT /api/admin/http-routes/{routeId}", a.requireAuth(a.handleUpdateHTTPRoute))
	mux.HandleFunc("DELETE /api/admin/http-routes/{routeId}", a.requireAuth(a.handleDeleteHTTPRoute))

	mux.HandleFunc("GET /api/admin/connections", a.requireAuth(a.handleListConnections))
	mux.HandleFunc("GET /api/admin/traffic", a.requireAuth(a.handleListTraffic))
	mux.HandleFunc("GET /api/admin/traffic/resources", a.requireAuth(a.handleListResourceTraffic))
	mux.HandleFunc("GET /api/admin/traffic/http-exchanges", a.requireAuth(a.handleListHTTPExchanges))
	mux.HandleFunc("GET /api/admin/traffic/tcp-frames", a.requireAuth(a.handleListTCPFrames))
	mux.HandleFunc("GET /api/admin/traffic/tcp-frames/{id}", a.requireAuth(a.handleGetTCPFrame))
	mux.HandleFunc("GET /api/admin/traffic/tcp-streams", a.requireAuth(a.handleGetTCPStream))
	mux.HandleFunc("GET /api/admin/traffic/inspection-status", a.requireAuth(a.handleTrafficInspectionStatus))
	mux.HandleFunc("GET /api/admin/connection-stats", a.requireAuth(a.handleListConnectionStats))

	mux.HandleFunc("GET /api/admin/peer-mesh/status", a.requireAuth(a.handlePeerMeshStatus))
	mux.HandleFunc("GET /api/admin/peer-mesh/devices", a.requireAuth(a.handlePeerMeshDevices))
	mux.HandleFunc("PUT /api/admin/peer-mesh/devices/{clientId}", a.requireAuth(a.handlePeerMeshUpdateDevice))
	mux.HandleFunc("GET /api/admin/peer-mesh/acls", a.requireAuth(a.handlePeerMeshACLs))
	mux.HandleFunc("POST /api/admin/peer-mesh/acls", a.requireAuth(a.handlePeerMeshCreateACL))
	mux.HandleFunc("DELETE /api/admin/peer-mesh/acls/{id}", a.requireAuth(a.handlePeerMeshDeleteACL))
	mux.HandleFunc("GET /api/admin/peer-mesh/sessions", a.requireAuth(a.handlePeerMeshSessions))
	mux.HandleFunc("DELETE /api/admin/peer-mesh/sessions/{id}", a.requireAuth(a.handlePeerMeshCloseSession))
	mux.HandleFunc("DELETE /api/admin/peer-mesh/sessions", a.requireAuth(a.handlePeerMeshCloseSessions))
}

func (a *API) handlePublicPeerMeshStunConfig(w http.ResponseWriter, r *http.Request) {
	if a.peerMesh == nil {
		writeJSON(w, http.StatusOK, peermesh.PublicStunConfig{})
		return
	}
	writeJSON(w, http.StatusOK, a.peerMesh.PublicStunConfig(forwardedHost(r)))
}

// ValidateToken reports whether a raw token is a valid admin token (used by the WS hub).
func (a *API) ValidateToken(token string) bool {
	_, ok := a.authenticate(context.Background(), token)
	return ok
}

// ValidateConnectionWebSocketToken returns the principal used by the connection-event websocket hub.
func (a *API) ValidateConnectionWebSocketToken(token string) (wsevents.Access, bool) {
	principal, ok := a.authenticate(context.Background(), token)
	if !ok {
		return wsevents.Access{}, false
	}
	return wsevents.Access{
		Username: principal.Username,
		TenantID: principal.TenantID,
		Admin:    principal.Admin,
	}, true
}

// ---- auth ----------------------------------------------------------------------------

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	principal, ok, err := a.authenticatePassword(r.Context(), req.Username, req.Password)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	writeJSON(w, http.StatusOK, a.tokens.IssueBodyForUser(principal.Username, principal.TenantID, principal.Role))
}

func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeJSON(w, http.StatusOK, a.tokens.IssueBodyForUser(principal.Username, principal.TenantID, principal.Role))
}

func (a *API) authenticatePassword(ctx context.Context, username, password string) (managementPrincipal, bool, error) {
	normalized, err := normalizeUsername(username)
	if err != nil || password == "" {
		return managementPrincipal{}, false, nil
	}
	if strings.EqualFold(normalized, a.adminUsername()) {
		if !a.tokens.Authenticate(normalized, password) {
			return managementPrincipal{}, false, nil
		}
		return managementPrincipal{
			Username: a.adminUsername(),
			TenantID: a.defaultTenant(),
			Role:     store.ManagementRoleAdmin,
			Admin:    true,
			BuiltIn:  true,
		}, true, nil
	}
	user, err := a.db.FindManagementUserByUsername(ctx, normalized)
	if err != nil {
		return managementPrincipal{}, false, err
	}
	if user == nil || !user.Enabled || !passwordMatches(password, user.PasswordHash) {
		return managementPrincipal{}, false, nil
	}
	role := normalizeRole(user.Role)
	return managementPrincipal{
		Username: user.Username,
		TenantID: normalizeTenant(user.TenantID),
		Role:     role,
		Admin:    role == store.ManagementRoleAdmin,
		BuiltIn:  false,
	}, true, nil
}

func (a *API) handleOidcConfig(w http.ResponseWriter, r *http.Request) {
	configured := strings.TrimSpace(a.oidc.ClientID) != ""
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":            configured,
		"authorizationEndpoint": a.oidc.AuthorizationEndpoint,
		"endSessionEndpoint":    a.oidc.EndSessionEndpoint,
		"clientId":              a.oidc.ClientID,
		"redirectUri":           a.oidc.RedirectURI,
		"scope":                 a.oidc.Scope,
		"passwordLoginEnabled":  a.tokens.PasswordLoginEnabled(),
	})
}

func (a *API) handleOidcToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code         string `json:"code"`
		RedirectURI  string `json:"redirectUri"`
		CodeVerifier string `json:"codeVerifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusBadRequest, "缺少授权码")
		return
	}
	if a.oidcAuth == nil {
		writeError(w, http.StatusServiceUnavailable, "OIDC 未配置")
		return
	}
	result, err := a.oidcAuth.Exchange(r.Context(), security.ExchangeRequest{
		Code: req.Code, RedirectURI: req.RedirectURI, CodeVerifier: req.CodeVerifier,
	})
	if err != nil {
		if errors.Is(err, security.ErrOidcNotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "OIDC 未配置")
			return
		}
		writeError(w, http.StatusBadGateway, "令牌交换失败")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ---- users ---------------------------------------------------------------------------

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeJSON(w, http.StatusOK, a.managementUserView(principal))
}

func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("需要 admin 权限"))
		return
	}
	users, err := a.db.ListManagementUsersByTenant(r.Context(), principal.TenantID)
	if err != nil {
		a.fail(w, err)
		return
	}
	now := time.Now().Format(time.RFC3339Nano)
	views := []ManagementUserView{{
		Username:  a.adminUsername(),
		TenantID:  principal.TenantID,
		Role:      store.ManagementRoleAdmin,
		Admin:     true,
		BuiltIn:   true,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}}
	for _, user := range users {
		views = append(views, managementUserView(user))
	}
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].BuiltIn != views[j].BuiltIn {
			return views[i].BuiltIn
		}
		return strings.ToLower(views[i].Username) < strings.ToLower(views[j].Username)
	})
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("需要 admin 权限"))
		return
	}
	var req userMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	username, err := normalizeUsername(req.Username)
	if err != nil {
		a.fail(w, err)
		return
	}
	if strings.EqualFold(username, a.adminUsername()) {
		a.fail(w, validation("内置 admin 用户不能重复创建"))
		return
	}
	if existing, err := a.db.FindManagementUserByUsername(r.Context(), username); err != nil {
		a.fail(w, err)
		return
	} else if existing != nil {
		a.fail(w, validation("用户名已存在: "+username))
		return
	}
	password, err := requirePassword(req.Password)
	if err != nil {
		a.fail(w, err)
		return
	}
	now := time.Now()
	user := store.ManagementUser{
		Username:     username,
		TenantID:     principal.TenantID,
		PasswordHash: auth.HashPassword(password),
		Role:         normalizeRole(req.Role),
		Enabled:      boolOr(req.Enabled, true),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := a.db.InsertManagementUser(r.Context(), user); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, managementUserView(user))
}

func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("需要 admin 权限"))
		return
	}
	username, err := normalizeUsername(r.PathValue("username"))
	if err != nil {
		a.fail(w, err)
		return
	}
	if strings.EqualFold(username, a.adminUsername()) {
		a.fail(w, validation("内置 admin 用户只能通过配置文件修改"))
		return
	}
	var req userMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	user, err := a.db.FindManagementUserByUsername(r.Context(), username)
	if err != nil {
		a.fail(w, err)
		return
	}
	if user == nil || !sameTenant(user.TenantID, principal.TenantID) {
		a.fail(w, store.ErrNotFound)
		return
	}
	if strings.TrimSpace(req.Password) != "" {
		password, err := requirePassword(req.Password)
		if err != nil {
			a.fail(w, err)
			return
		}
		user.PasswordHash = auth.HashPassword(password)
	}
	if strings.TrimSpace(req.Role) != "" {
		user.Role = normalizeRole(req.Role)
	}
	if req.Enabled != nil {
		user.Enabled = *req.Enabled
	}
	user.UpdatedAt = time.Now()
	if err := a.db.UpdateManagementUser(r.Context(), *user); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, managementUserView(*user))
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("需要 admin 权限"))
		return
	}
	username, err := normalizeUsername(r.PathValue("username"))
	if err != nil {
		a.fail(w, err)
		return
	}
	if strings.EqualFold(username, a.adminUsername()) {
		a.fail(w, validation("内置 admin 用户不能删除"))
		return
	}
	user, err := a.db.FindManagementUserByUsername(r.Context(), username)
	if err != nil {
		a.fail(w, err)
		return
	}
	if user == nil || !sameTenant(user.TenantID, principal.TenantID) {
		a.fail(w, store.ErrNotFound)
		return
	}
	if err := a.db.DeleteManagementUser(r.Context(), username); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- overview / database -------------------------------------------------------------

func (a *API) handleOverview(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clients, err := a.visibleClients(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	clientIDs := clientIDs(clients)
	successful, failed := 0, 0
	if len(clientIDs) > 0 {
		success := true
		_, total, err := a.db.ListConnections(r.Context(), store.ConnectionFilter{
			TenantID: principal.TenantID, ClientIDs: clientIDs, Success: &success, Size: 1,
		})
		if err != nil {
			a.fail(w, err)
			return
		}
		successful = total
		success = false
		_, total, err = a.db.ListConnections(r.Context(), store.ConnectionFilter{
			TenantID: principal.TenantID, ClientIDs: clientIDs, Success: &success, Size: 1,
		})
		if err != nil {
			a.fail(w, err)
			return
		}
		failed = total
	}
	var upload, download int64
	online := 0
	for _, client := range clients {
		if bound, ok := a.sessions.Find(client.ClientName); ok && bound != nil {
			online++
		}
		if up, down, err := a.db.SumTraffic(r.Context(), client.ClientName); err == nil {
			upload += up
			download += down
		}
	}
	writeJSON(w, http.StatusOK, OverviewView{
		Clients:                     int64(len(clients)),
		OnlineClients:               online,
		SuccessfulConnections:       int64(successful),
		FailedConnections:           int64(failed),
		UploadBytes:                 upload,
		DownloadBytes:               download,
		ExternalConnections:         adminOnlyCounter(principal, a.remotePorts.ActiveExternalConnections()),
		RejectedExternalConnections: adminOnlyCounter(principal, a.remotePorts.RejectedExternalConnections()),
	})
}

func (a *API) handleDatabaseInitialize(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("需要 admin 权限"))
		return
	}
	if a.seedDemo != nil {
		if err := a.seedDemo(r.Context()); err != nil {
			a.fail(w, err)
			return
		}
	}
	clients, err := a.db.CountClientsByTenant(r.Context(), principal.TenantID)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": true,
		"tenantId":    principal.TenantID,
		"orm":         "database/sql",
		"dialect":     string(a.db.Dialect()),
		"clients":     clients,
	})
}

// ---- clients -------------------------------------------------------------------------

func (a *API) handleListClients(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clients, err := a.visibleClients(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]ClientView, 0, len(clients))
	for i := range clients {
		views = append(views, a.clientView(r.Context(), clients[i]))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleGetClient(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	account, err := a.requireClientAccess(r.Context(), principal, clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	tunnels, err := a.db.ListTunnels(r.Context(), &clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	routes, err := a.db.ListHTTPRoutes(r.Context(), &clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	tunnelViews := make([]TunnelView, 0, len(tunnels))
	for _, tunnel := range tunnels {
		tunnelViews = append(tunnelViews, tunnelView(tunnel))
	}
	routeViews := make([]HTTPRouteView, 0, len(routes))
	for _, route := range routes {
		routeViews = append(routeViews, httpRouteView(route))
	}
	writeJSON(w, http.StatusOK, ClientDetail{
		Client:     a.clientView(r.Context(), *account),
		Tunnels:    tunnelViews,
		HTTPRoutes: routeViews,
	})
}

func (a *API) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	var req clientMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		a.fail(w, validation("clientName 不能为空"))
		return
	}
	if existing, err := a.db.FindClientByName(r.Context(), name); err != nil {
		a.fail(w, err)
		return
	} else if existing != nil {
		a.fail(w, conflict("客户端名称已存在"))
		return
	}
	now := time.Now()
	account := store.ClientAccount{
		ID:                           auth.NewClientID(),
		TenantID:                     principal.TenantID,
		OwnerUsername:                principal.Username,
		ClientName:                   name,
		PasswordHash:                 auth.HashPassword(strconv.FormatInt(auth.NewClientID(), 10)),
		Enabled:                      boolOr(req.Enabled, true),
		ConnectionRateLimitPerMinute: intOr(req.ConnectionRateLimitPerMinute, 30),
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}
	if err := a.db.InsertClient(r.Context(), account); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, ClientResult{Client: a.clientView(r.Context(), account)})
}

func (a *API) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req clientMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	account, err := a.db.GetClient(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !principal.canAccessClient(*account) {
		a.fail(w, forbidden("无权访问客户端"))
		return
	}

	oldName := account.ClientName
	wasEnabled := account.Enabled
	if name := strings.TrimSpace(req.ClientName); name != "" {
		account.ClientName = name
	}
	if req.Enabled != nil {
		account.Enabled = *req.Enabled
	}
	if req.ConnectionRateLimitPerMinute != nil {
		account.ConnectionRateLimitPerMinute = *req.ConnectionRateLimitPerMinute
	}
	account.UpdatedAt = time.Now()
	if err := a.db.UpdateClient(r.Context(), *account); err != nil {
		a.fail(w, err)
		return
	}

	// Kick the live session if the account was renamed or disabled.
	if oldName != account.ClientName {
		a.kick(oldName, store.ReasonAdminRenamed)
	} else if wasEnabled && !account.Enabled {
		a.kick(account.ClientName, store.ReasonAdminDisabled)
	}

	writeJSON(w, http.StatusOK, ClientResult{Client: a.clientView(r.Context(), *account)})
}

func (a *API) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	account, err := a.db.GetClient(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !principal.canAccessClient(*account) {
		a.fail(w, forbidden("无权访问客户端"))
		return
	}
	if err := a.db.DeleteClient(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.kick(account.ClientName, store.ReasonAdminDeleted)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	credentials, err := a.db.ListCredentials(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]CredentialView, 0, len(credentials))
	for _, credential := range credentials {
		if !principal.canAccessCredential(credential) {
			continue
		}
		views = append(views, credentialView(credential))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	var req credentialMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		apiKey = "ck_" + strconv.FormatInt(auth.NewClientID(), 10)
	}
	if existing, err := a.db.FindCredentialByAPIKey(r.Context(), apiKey); err != nil {
		a.fail(w, err)
		return
	} else if existing != nil {
		a.fail(w, conflict("apiKey already exists"))
		return
	}
	secret := strings.TrimSpace(req.Secret)
	if secret == "" {
		secret = auth.GeneratePassword()
	}
	maxOnlineInstances, err := normalizeMaxOnline(req.MaxOnlineInstances, a.clientAuth.DefaultMaxOnlineInstances)
	if err != nil {
		a.fail(w, err)
		return
	}
	now := time.Now()
	credential := store.ClientCredential{
		ID:                 auth.NewClientID(),
		TenantID:           principal.TenantID,
		OwnerUsername:      principal.Username,
		APIKey:             apiKey,
		SecretHash:         auth.HashPassword(secret),
		Enabled:            boolOr(req.Enabled, true),
		MaxOnlineInstances: maxOnlineInstances,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := a.db.InsertCredential(r.Context(), credential); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, CredentialResult{Credential: credentialView(credential), Secret: secret})
}

func (a *API) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req credentialMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	credential, err := a.db.GetCredential(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !principal.canAccessCredential(*credential) {
		a.fail(w, forbidden("无权访问客户端凭证"))
		return
	}
	if apiKey := strings.TrimSpace(req.APIKey); apiKey != "" && apiKey != credential.APIKey {
		if existing, err := a.db.FindCredentialByAPIKey(r.Context(), apiKey); err != nil {
			a.fail(w, err)
			return
		} else if existing != nil {
			a.fail(w, conflict("apiKey already exists"))
			return
		}
		credential.APIKey = apiKey
	}
	var revealed string
	if secret := strings.TrimSpace(req.Secret); secret != "" {
		revealed = secret
		credential.SecretHash = auth.HashPassword(secret)
	}
	if req.Enabled != nil {
		credential.Enabled = *req.Enabled
	}
	if req.MaxOnlineInstances != nil {
		maxOnlineInstances, err := normalizeMaxOnline(req.MaxOnlineInstances, a.clientAuth.DefaultMaxOnlineInstances)
		if err != nil {
			a.fail(w, err)
			return
		}
		credential.MaxOnlineInstances = maxOnlineInstances
	}
	credential.UpdatedAt = time.Now()
	if err := a.db.UpdateCredential(r.Context(), *credential); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, CredentialResult{Credential: credentialView(*credential), Secret: revealed})
}

func (a *API) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	credential, err := a.db.GetCredential(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !principal.canAccessCredential(*credential) {
		a.fail(w, forbidden("无权访问客户端凭证"))
		return
	}
	if err := a.db.DeleteCredential(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handlePublicClientDownloads(w http.ResponseWriter, r *http.Request) {
	links, err := a.db.ListClientDownloadLinks(r.Context(), true)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]ClientDownloadLinkView, 0, len(links))
	for _, link := range links {
		views = append(views, clientDownloadLinkView(link))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleListClientDownloads(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("仅管理员可以维护客户端下载链接"))
		return
	}
	links, err := a.db.ListClientDownloadLinks(r.Context(), false)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]ClientDownloadLinkView, 0, len(links))
	for _, link := range links {
		views = append(views, clientDownloadLinkView(link))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateClientDownload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("仅管理员可以维护客户端下载链接"))
		return
	}
	var req clientDownloadLinkMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	link, err := newClientDownloadLink(req)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.db.InsertClientDownloadLink(r.Context(), link); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, clientDownloadLinkView(link))
}

func (a *API) handleUpdateClientDownload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("仅管理员可以维护客户端下载链接"))
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req clientDownloadLinkMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	link, err := a.db.GetClientDownloadLink(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := applyClientDownloadLinkMutation(link, req); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.db.UpdateClientDownloadLink(r.Context(), *link); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, clientDownloadLinkView(*link))
}

func (a *API) handleDeleteClientDownload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("仅管理员可以维护客户端下载链接"))
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	if _, err := a.db.GetClientDownloadLink(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.db.DeleteClientDownloadLink(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- tunnels -------------------------------------------------------------------------

func (a *API) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID := queryInt64Ptr(r, "clientId")
	visibleIDs, err := a.visibleClientIDSet(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if clientID != nil && !visibleIDs[*clientID] {
		a.fail(w, forbidden("无权访问客户端"))
		return
	}
	mappings, err := a.db.ListTunnels(r.Context(), clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]TunnelView, 0, len(mappings))
	for _, m := range mappings {
		if !visibleIDs[m.ClientID] {
			continue
		}
		views = append(views, tunnelView(m))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req tunnelMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	account, err := a.requireClientAccess(r.Context(), principal, clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := validateTunnel(req); err != nil {
		a.fail(w, err)
		return
	}
	if inUse, err := a.db.ListenPortInUse(r.Context(), req.ListenPort, 0); err != nil {
		a.fail(w, err)
		return
	} else if inUse {
		a.fail(w, conflict("监听端口已被占用"))
		return
	}
	now := time.Now()
	mapping := store.TunnelMapping{
		ID:                   auth.NewClientID(),
		ClientID:             account.ID,
		ClientName:           account.ClientName,
		ListenPort:           req.ListenPort,
		TargetAddress:        strings.TrimSpace(req.TargetAddress),
		TargetPort:           req.TargetPort,
		Enabled:              boolOr(req.Enabled, true),
		DetailCaptureEnabled: boolOr(req.DetailCaptureEnabled, false),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := a.db.InsertTunnel(r.Context(), mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), account.ID, account.ClientName)
	writeJSON(w, http.StatusCreated, tunnelView(mapping))
}

func (a *API) handleUpdateTunnel(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "tunnelId")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req tunnelMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	mapping, err := a.db.GetTunnel(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if _, err := a.requireClientAccess(r.Context(), principal, mapping.ClientID); err != nil {
		a.fail(w, err)
		return
	}
	if err := validateTunnel(req); err != nil {
		a.fail(w, err)
		return
	}
	if inUse, err := a.db.ListenPortInUse(r.Context(), req.ListenPort, id); err != nil {
		a.fail(w, err)
		return
	} else if inUse {
		a.fail(w, conflict("监听端口已被占用"))
		return
	}
	mapping.ListenPort = req.ListenPort
	mapping.TargetAddress = strings.TrimSpace(req.TargetAddress)
	mapping.TargetPort = req.TargetPort
	mapping.Enabled = boolOr(req.Enabled, mapping.Enabled)
	mapping.DetailCaptureEnabled = boolOr(req.DetailCaptureEnabled, mapping.DetailCaptureEnabled)
	mapping.UpdatedAt = time.Now()
	if err := a.db.UpdateTunnel(r.Context(), *mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	writeJSON(w, http.StatusOK, tunnelView(*mapping))
}

func (a *API) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "tunnelId")
	if err != nil {
		a.fail(w, err)
		return
	}
	mapping, err := a.db.GetTunnel(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if _, err := a.requireClientAccess(r.Context(), principal, mapping.ClientID); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.db.DeleteTunnel(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleNatControl(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	account, err := a.requireClientAccess(r.Context(), principal, clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	result, online, err := a.natControl.PushToID(r.Context(), account.ID, account.ClientName)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !online {
		a.fail(w, conflict("客户端不在线，无法下发映射"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pushed":     result.Tunnels,
		"tunnels":    result.Tunnels,
		"httpRoutes": result.HTTPRoutes,
	})
}

// ---- http routes ---------------------------------------------------------------------

func (a *API) handleListHTTPRoutes(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID := queryInt64Ptr(r, "clientId")
	visibleIDs, err := a.visibleClientIDSet(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if clientID != nil && !visibleIDs[*clientID] {
		a.fail(w, forbidden("无权访问客户端"))
		return
	}
	routes, err := a.db.ListHTTPRoutes(r.Context(), clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]HTTPRouteView, 0, len(routes))
	for _, route := range routes {
		if !visibleIDs[route.ClientID] {
			continue
		}
		views = append(views, httpRouteView(route))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateHTTPRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req httpRouteMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	account, err := a.requireClientAccess(r.Context(), principal, clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	route := strings.TrimSpace(req.Route)
	if err := validateRoute(route, req.TargetBaseURL); err != nil {
		a.fail(w, err)
		return
	}
	if inUse, err := a.db.RouteInUse(r.Context(), account.ID, route, 0); err != nil {
		a.fail(w, err)
		return
	} else if inUse {
		a.fail(w, conflict("路由已存在"))
		return
	}
	now := time.Now()
	mapping := store.HTTPRouteMapping{
		ID:                   auth.NewClientID(),
		ClientID:             account.ID,
		ClientName:           account.ClientName,
		Route:                route,
		TargetBaseURL:        strings.TrimSpace(req.TargetBaseURL),
		Enabled:              boolOr(req.Enabled, true),
		DetailCaptureEnabled: boolOr(req.DetailCaptureEnabled, false),
		PathRewriteEnabled:   boolOr(req.PathRewriteEnabled, false),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := a.db.InsertHTTPRoute(r.Context(), mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), account.ID, account.ClientName)
	writeJSON(w, http.StatusCreated, httpRouteView(mapping))
}

func (a *API) handleUpdateHTTPRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "routeId")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req httpRouteMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	mapping, err := a.db.GetHTTPRoute(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if _, err := a.requireClientAccess(r.Context(), principal, mapping.ClientID); err != nil {
		a.fail(w, err)
		return
	}
	route := strings.TrimSpace(req.Route)
	if err := validateRoute(route, req.TargetBaseURL); err != nil {
		a.fail(w, err)
		return
	}
	if inUse, err := a.db.RouteInUse(r.Context(), mapping.ClientID, route, id); err != nil {
		a.fail(w, err)
		return
	} else if inUse {
		a.fail(w, conflict("路由已存在"))
		return
	}
	mapping.Route = route
	mapping.TargetBaseURL = strings.TrimSpace(req.TargetBaseURL)
	mapping.Enabled = boolOr(req.Enabled, mapping.Enabled)
	mapping.DetailCaptureEnabled = boolOr(req.DetailCaptureEnabled, mapping.DetailCaptureEnabled)
	mapping.PathRewriteEnabled = boolOr(req.PathRewriteEnabled, mapping.PathRewriteEnabled)
	mapping.UpdatedAt = time.Now()
	if err := a.db.UpdateHTTPRoute(r.Context(), *mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	writeJSON(w, http.StatusOK, httpRouteView(*mapping))
}

func (a *API) handleDeleteHTTPRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "routeId")
	if err != nil {
		a.fail(w, err)
		return
	}
	mapping, err := a.db.GetHTTPRoute(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if _, err := a.requireClientAccess(r.Context(), principal, mapping.ClientID); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.db.DeleteHTTPRoute(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	w.WriteHeader(http.StatusNoContent)
}

// ---- read models ---------------------------------------------------------------------

func (a *API) handleListConnections(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	filter := store.ConnectionFilter{
		TenantID: principal.TenantID,
		ClientID: queryInt64Ptr(r, "clientId"),
		FromISO:  r.URL.Query().Get("from"),
		ToISO:    r.URL.Query().Get("to"),
		Page:     queryInt(r, "page", 0),
		Size:     queryInt(r, "size", 20),
	}
	if filter.ClientID != nil {
		if !containsInt64(visibleIDs, *filter.ClientID) {
			a.fail(w, forbidden("无权访问客户端"))
			return
		}
	} else if len(visibleIDs) == 0 {
		writeJSON(w, http.StatusOK, ConnectionPage{Items: []ConnectionItem{}, Total: 0, Page: filter.Page, Size: normalizedPageSize(filter.Size), TotalPages: 0})
		return
	} else {
		filter.ClientIDs = visibleIDs
	}
	if success := r.URL.Query().Get("success"); success != "" {
		value := success == "true"
		filter.Success = &value
	}
	records, total, err := a.db.ListConnections(r.Context(), filter)
	if err != nil {
		a.fail(w, err)
		return
	}
	items := make([]ConnectionItem, 0, len(records))
	for _, record := range records {
		items = append(items, connectionItem(record))
	}
	size := filter.Size
	if size <= 0 {
		size = 20
	}
	totalPages := (total + size - 1) / size
	writeJSON(w, http.StatusOK, ConnectionPage{Items: items, Total: total, Page: filter.Page, Size: size, TotalPages: totalPages})
}

func (a *API) handleListTraffic(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if queryBool(r, "flush", false) && a.trafficUsage != nil {
		a.trafficUsage.Flush(r.Context())
	}
	clientID := queryInt64Ptr(r, "clientId")
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if clientID != nil {
		if !containsInt64(visibleIDs, *clientID) {
			a.fail(w, forbidden("无权访问客户端"))
			return
		}
	} else if len(visibleIDs) == 0 {
		writeJSON(w, http.StatusOK, []TrafficView{})
		return
	}
	usages, err := a.db.ListTrafficScoped(r.Context(), principal.TenantID, clientID, visibleIDs, queryInt(r, "limit", 100))
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]TrafficView, 0, len(usages))
	for _, u := range usages {
		views = append(views, TrafficView{
			ID: u.ID, ClientID: u.ClientID, ClientName: u.ClientName, UsageDate: u.UsageDate,
			UploadBytes: u.UploadBytes, DownloadBytes: u.DownloadBytes, UpdatedAt: u.UpdatedAt.Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleListResourceTraffic(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if queryBool(r, "flush", false) && a.trafficUsage != nil {
		a.trafficUsage.Flush(r.Context())
	}
	clientID := queryInt64Ptr(r, "clientId")
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if clientID != nil {
		if !containsInt64(visibleIDs, *clientID) {
			a.fail(w, forbidden("无权访问客户端"))
			return
		}
	} else if len(visibleIDs) == 0 {
		writeJSON(w, http.StatusOK, []ResourceTrafficUsageView{})
		return
	}
	usages, err := a.db.ListResourceTrafficScoped(r.Context(), principal.TenantID, clientID, visibleIDs,
		r.URL.Query().Get("type"), queryInt(r, "limit", 100))
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]ResourceTrafficUsageView, 0, len(usages))
	for _, u := range usages {
		views = append(views, ResourceTrafficUsageView{
			ID:            u.ID,
			ClientID:      u.ClientID,
			ClientName:    u.ClientName,
			ResourceType:  u.ResourceType,
			ResourceKey:   u.ResourceKey,
			ResourceID:    u.ResourceID,
			ResourceName:  u.ResourceName,
			UsageDate:     u.UsageDate,
			UploadBytes:   u.UploadBytes,
			DownloadBytes: u.DownloadBytes,
			UpdatedAt:     u.UpdatedAt.Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleListHTTPExchanges(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !a.flushTrafficDetailsIfRequested(w, r) {
		return
	}
	clientID := queryInt64Ptr(r, "clientId")
	if clientID != nil {
		if !containsInt64(visibleIDs, *clientID) {
			a.fail(w, forbidden("无权访问客户端"))
			return
		}
	} else if len(visibleIDs) == 0 {
		writeJSON(w, http.StatusOK, TrafficDetailPage[HTTPTrafficExchangeView]{Items: []HTTPTrafficExchangeView{}, Total: 0, Page: 0, Size: normalizedTrafficSize(queryInt(r, "size", 50)), TotalPages: 0})
		return
	}
	bodyType := firstText(r.URL.Query().Get("responseBodyType"), r.URL.Query().Get("responseDataType"))
	filter := store.HTTPExchangeFilter{
		TenantID:         principal.TenantID,
		ClientID:         clientID,
		ClientIDs:        visibleIDs,
		Route:            strings.TrimSpace(r.URL.Query().Get("route")),
		ResponseBodyType: strings.TrimSpace(bodyType),
		Field:            r.URL.Query().Get("field"),
		Query:            r.URL.Query().Get("q"),
		Page:             queryInt(r, "page", 0),
		Size:             queryInt(r, "size", 50),
	}
	items, total, err := a.db.ListHTTPExchanges(r.Context(), filter)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]HTTPTrafficExchangeView, 0, len(items))
	for _, item := range items {
		views = append(views, httpTrafficExchangeView(item))
	}
	size := normalizedTrafficSize(filter.Size)
	page := filter.Page
	if page < 0 {
		page = 0
	}
	writeJSON(w, http.StatusOK, TrafficDetailPage[HTTPTrafficExchangeView]{
		Items: views, Total: total, Page: page, Size: size, TotalPages: totalPages(total, size),
	})
}

func (a *API) handleListTCPFrames(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !a.flushTrafficDetailsIfRequested(w, r) {
		return
	}
	clientID := queryInt64Ptr(r, "clientId")
	if clientID != nil {
		if !containsInt64(visibleIDs, *clientID) {
			a.fail(w, forbidden("无权访问客户端"))
			return
		}
	} else if len(visibleIDs) == 0 {
		writeJSON(w, http.StatusOK, TrafficDetailPage[TCPTrafficFrameView]{Items: []TCPTrafficFrameView{}, Total: 0, Page: 0, Size: normalizedTrafficSize(queryInt(r, "size", queryInt(r, "limit", 50))), TotalPages: 0})
		return
	}
	filter := store.TCPFrameFilter{
		TenantID:   principal.TenantID,
		ClientID:   clientID,
		ClientIDs:  visibleIDs,
		ListenPort: queryIntPtr(r, "listenPort"),
		Page:       queryInt(r, "page", 0),
		Size:       queryInt(r, "size", queryInt(r, "limit", 50)),
	}
	items, total, err := a.db.ListTCPFrames(r.Context(), filter)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]TCPTrafficFrameView, 0, len(items))
	for _, item := range items {
		views = append(views, tcpTrafficFrameView(item, false))
	}
	size := normalizedTrafficSize(filter.Size)
	page := filter.Page
	if page < 0 {
		page = 0
	}
	writeJSON(w, http.StatusOK, TrafficDetailPage[TCPTrafficFrameView]{
		Items: views, Total: total, Page: page, Size: size, TotalPages: totalPages(total, size),
	})
}

func (a *API) handleGetTCPFrame(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	frame, err := a.db.GetTCPFrame(r.Context(), principal.TenantID, id, visibleIDs)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tcpTrafficFrameView(*frame, true))
}

func (a *API) handleGetTCPStream(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	channelID := strings.TrimSpace(r.URL.Query().Get("channelId"))
	if channelID == "" {
		a.fail(w, validation("channelId 不能为空"))
		return
	}
	visibleIDs, err := a.visibleClientIDs(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !a.flushTrafficDetailsIfRequested(w, r) {
		return
	}
	limit := queryInt(r, "limit", 500)
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	items, err := a.db.ListTCPStream(r.Context(), principal.TenantID, channelID, visibleIDs, limit)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]TCPTrafficFrameView, 0, len(items))
	for _, item := range items {
		views = append(views, tcpTrafficFrameView(item, true))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"channelId": channelID,
		"items":     views,
		"total":     len(views),
		"limit":     limit,
		"truncated": len(views) >= limit,
	})
}

func (a *API) handleTrafficInspectionStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.db.TrafficInspectionSnapshot(a.traffic.CaptureDetailEnabled))
}

func (a *API) flushTrafficDetailsIfRequested(w http.ResponseWriter, r *http.Request) bool {
	if !queryBool(r, "flush", false) {
		return true
	}
	if err := a.db.FlushTrafficDetails(r.Context()); err != nil {
		a.fail(w, err)
		return false
	}
	return true
}

func (a *API) handleListConnectionStats(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientName := r.URL.Query().Get("clientName")
	visibleClients, err := a.visibleClients(r.Context(), principal)
	if err != nil {
		a.fail(w, err)
		return
	}
	visibleIDs := clientIDs(visibleClients)
	if clientName != "" {
		if !principal.Admin && !containsClientName(visibleClients, clientName) {
			a.fail(w, forbidden("无权访问客户端"))
			return
		}
	} else if !principal.Admin && len(visibleIDs) == 0 {
		writeJSON(w, http.StatusOK, []ConnectionStatView{})
		return
	}
	var scopedIDs []int64
	if !principal.Admin {
		scopedIDs = visibleIDs
	}
	stats, err := a.db.ListConnectionStatsScoped(r.Context(), principal.TenantID, clientName, scopedIDs, queryInt(r, "limit", 100))
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]ConnectionStatView, 0, len(stats))
	for _, s := range stats {
		views = append(views, ConnectionStatView{
			ID: s.ID, ClientID: s.ClientID, ClientName: s.ClientName, Month: s.StatMonth,
			Total: s.TotalCount, Success: s.SuccessCount, Failure: s.FailureCount,
			UpdatedAt: s.UpdatedAt.Format(time.RFC3339Nano),
		})
	}
	writeJSON(w, http.StatusOK, views)
}

// ---- peer mesh -----------------------------------------------------------------------

func (a *API) peerAccess(principal managementPrincipal) peermesh.AccessContext {
	return peermesh.AccessContext{
		Username: principal.Username,
		TenantID: normalizeTenant(principal.TenantID),
		Admin:    principal.Admin,
	}
}

func (a *API) handlePeerMeshStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"enabled": a.peerMesh != nil && a.peerMesh.Enabled()})
}

func (a *API) handlePeerMeshDevices(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	items, err := a.peerMesh.ListDevices(r.Context(), a.peerAccess(principal))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) handlePeerMeshUpdateDevice(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	clientID, err := pathInt(r, "clientId")
	if err != nil {
		a.fail(w, err)
		return
	}
	var req peermesh.DeviceMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	item, err := a.peerMesh.UpdateDevice(r.Context(), a.peerAccess(principal), clientID, req)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *API) handlePeerMeshACLs(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	items, err := a.peerMesh.ListACLs(r.Context(), a.peerAccess(principal))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) handlePeerMeshCreateACL(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	var req peermesh.ACLMutation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	item, err := a.peerMesh.CreateACL(r.Context(), a.peerAccess(principal), req)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (a *API) handlePeerMeshDeleteACL(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.peerMesh.DeleteACL(r.Context(), a.peerAccess(principal), id); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handlePeerMeshSessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	query := r.URL.Query()
	if query.Has("page") || query.Has("size") || query.Has("openOnly") {
		page, err := a.peerMesh.ListSessionsPage(r.Context(), a.peerAccess(principal),
			queryInt(r, "page", 0), queryInt(r, "size", queryInt(r, "limit", 100)), queryBool(r, "openOnly", false))
		if err != nil {
			a.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
		return
	}
	items, err := a.peerMesh.ListSessions(r.Context(), a.peerAccess(principal), queryInt(r, "limit", 100))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) handlePeerMeshCloseSession(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	item, err := a.peerMesh.ForceClose(r.Context(), a.peerAccess(principal), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *API) handlePeerMeshCloseSessions(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	items, err := a.peerMesh.CloseOpenSessions(r.Context(), a.peerAccess(principal))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// ---- helpers -------------------------------------------------------------------------

func (a *API) pushNatControl(ctx context.Context, clientID int64, clientName string) {
	pushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _ = a.natControl.PushToID(pushCtx, clientID, clientName)
}

func (a *API) kick(clientName, reason string) {
	if bound, ok := a.sessions.Find(clientName); ok {
		bound.Close(reason)
	}
}

func (a *API) clientView(ctx context.Context, account store.ClientAccount) ClientView {
	view := ClientView{
		ID:                           account.ID,
		ClientName:                   account.ClientName,
		OwnerUsername:                account.OwnerUsername,
		Enabled:                      account.Enabled,
		ConnectionRateLimitPerMinute: account.ConnectionRateLimitPerMinute,
		CreatedAt:                    account.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:                    account.UpdatedAt.Format(time.RFC3339Nano),
	}
	if bound, ok := a.sessions.Find(account.ClientName); ok {
		view.Online = true
		login := bound.LoginTimeMs()
		view.ConnectedSinceMs = &login
	}
	if up, down, err := a.db.SumTraffic(ctx, account.ClientName); err == nil {
		view.UploadBytes = up
		view.DownloadBytes = down
	}
	return view
}

func credentialView(credential store.ClientCredential) CredentialView {
	return CredentialView{
		ID:                 credential.ID,
		APIKey:             credential.APIKey,
		OwnerUsername:      credential.OwnerUsername,
		Enabled:            credential.Enabled,
		MaxOnlineInstances: credential.MaxOnlineInstances,
		CreatedAt:          credential.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:          credential.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func clientDownloadLinkView(link store.ClientDownloadLink) ClientDownloadLinkView {
	return ClientDownloadLinkView{
		ID:             link.ID,
		Implementation: link.Implementation,
		Platform:       link.Platform,
		Arch:           link.Arch,
		DisplayName:    link.DisplayName,
		DownloadURL:    link.DownloadURL,
		Description:    link.Description,
		DisplayOrder:   link.DisplayOrder,
		Enabled:        link.Enabled,
		CreatedAt:      link.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:      link.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func (a *API) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrValidation):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "资源不存在")
	default:
		writeError(w, http.StatusInternalServerError, "服务器内部错误")
	}
}

type ctxKey int

const principalKey ctxKey = 0

type managementPrincipal struct {
	Username string
	TenantID string
	Role     string
	Admin    bool
	BuiltIn  bool
}

func (p managementPrincipal) canAccessClient(account store.ClientAccount) bool {
	if !sameTenant(p.TenantID, account.TenantID) {
		return false
	}
	return p.Admin || strings.EqualFold(account.OwnerUsername, p.Username)
}

func (p managementPrincipal) canAccessCredential(credential store.ClientCredential) bool {
	if !sameTenant(p.TenantID, credential.TenantID) {
		return false
	}
	return p.Admin || strings.EqualFold(credential.OwnerUsername, p.Username)
}

func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		principal, ok := a.authenticate(r.Context(), token)
		if !ok {
			writeError(w, http.StatusUnauthorized, "未授权")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next(w, r.WithContext(ctx))
	}
}

// authenticate validates a bearer token: local HS256 first, then OIDC RS256 as a fallback.
func (a *API) authenticate(ctx context.Context, token string) (managementPrincipal, bool) {
	if claims, ok := a.tokens.ValidateClaims(token); ok {
		role := normalizeRole(claims.Role)
		return managementPrincipal{
			Username: claims.Username,
			TenantID: normalizeTenant(claims.TenantID),
			Role:     role,
			Admin:    role == store.ManagementRoleAdmin || strings.EqualFold(claims.Username, a.adminUsername()),
			BuiltIn:  strings.EqualFold(claims.Username, a.adminUsername()),
		}, true
	}
	if a.oidcAuth != nil {
		if identity, ok := a.oidcAuth.ValidateIdentity(ctx, token); ok {
			admin := strings.EqualFold(identity.Username, a.adminUsername())
			role := store.ManagementRoleUser
			if admin {
				role = store.ManagementRoleAdmin
			}
			return managementPrincipal{
				Username: identity.Username,
				TenantID: normalizeTenant(firstText(identity.TenantID, a.defaultTenant())),
				Role:     role,
				Admin:    admin,
				BuiltIn:  admin,
			}, true
		}
	}
	return managementPrincipal{}, false
}

func principalFromContext(r *http.Request) (managementPrincipal, bool) {
	principal, ok := r.Context().Value(principalKey).(managementPrincipal)
	return principal, ok
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

func (a *API) adminUsername() string {
	if strings.TrimSpace(a.authConfig.Username) == "" {
		return "admin"
	}
	return strings.TrimSpace(a.authConfig.Username)
}

func (a *API) defaultTenant() string {
	return normalizeTenant(a.authConfig.TenantID)
}

func (a *API) managementUserView(principal managementPrincipal) ManagementUserView {
	now := time.Now().Format(time.RFC3339Nano)
	return ManagementUserView{
		Username:  principal.Username,
		TenantID:  normalizeTenant(principal.TenantID),
		Role:      normalizeRole(principal.Role),
		Admin:     principal.Admin,
		BuiltIn:   principal.BuiltIn,
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func managementUserView(user store.ManagementUser) ManagementUserView {
	role := normalizeRole(user.Role)
	return ManagementUserView{
		Username:  user.Username,
		TenantID:  normalizeTenant(user.TenantID),
		Role:      role,
		Admin:     role == store.ManagementRoleAdmin,
		BuiltIn:   false,
		Enabled:   user.Enabled,
		CreatedAt: user.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func (a *API) visibleClients(ctx context.Context, principal managementPrincipal) ([]store.ClientAccount, error) {
	clients, err := a.db.ListClients(ctx)
	if err != nil {
		return nil, err
	}
	visible := make([]store.ClientAccount, 0, len(clients))
	for _, client := range clients {
		if principal.canAccessClient(client) {
			visible = append(visible, client)
		}
	}
	sort.SliceStable(visible, func(i, j int) bool { return visible[i].ID > visible[j].ID })
	return visible, nil
}

func (a *API) visibleClientIDs(ctx context.Context, principal managementPrincipal) ([]int64, error) {
	clients, err := a.visibleClients(ctx, principal)
	if err != nil {
		return nil, err
	}
	return clientIDs(clients), nil
}

func (a *API) visibleClientNames(ctx context.Context, principal managementPrincipal) ([]string, error) {
	clients, err := a.visibleClients(ctx, principal)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(clients))
	for _, client := range clients {
		names = append(names, client.ClientName)
	}
	return names, nil
}

func (a *API) visibleClientIDSet(ctx context.Context, principal managementPrincipal) (map[int64]bool, error) {
	ids, err := a.visibleClientIDs(ctx, principal)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

func (a *API) requireClientAccess(ctx context.Context, principal managementPrincipal, clientID int64) (*store.ClientAccount, error) {
	account, err := a.db.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !principal.canAccessClient(*account) {
		return nil, forbidden("无权访问客户端")
	}
	return account, nil
}

func normalizeUsername(username string) (string, error) {
	normalized := strings.TrimSpace(username)
	if normalized == "" {
		return "", validation("username cannot be blank")
	}
	if len(normalized) > 80 {
		return "", validation("username is too long")
	}
	return normalized, nil
}

func requirePassword(password string) (string, error) {
	normalized := strings.TrimSpace(password)
	if normalized == "" {
		return "", validation("password cannot be blank")
	}
	if len(normalized) > 120 {
		return "", validation("password is too long")
	}
	return normalized, nil
}

func passwordMatches(password, expectedHash string) bool {
	expected := strings.ToLower(strings.TrimSpace(expectedHash))
	actual := auth.HashPassword(password)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func normalizeTenant(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}

func normalizeRole(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), store.ManagementRoleAdmin) {
		return store.ManagementRoleAdmin
	}
	return store.ManagementRoleUser
}

func sameTenant(left, right string) bool {
	return strings.EqualFold(normalizeTenant(left), normalizeTenant(right))
}

func clientIDs(clients []store.ClientAccount) []int64 {
	ids := make([]int64, 0, len(clients))
	for _, client := range clients {
		ids = append(ids, client.ID)
	}
	return ids
}

func containsInt64(values []int64, target int64) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func containsClientName(values []store.ClientAccount, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value.ClientName, target) {
			return true
		}
	}
	return false
}

func normalizedPageSize(size int) int {
	if size <= 0 || size > 200 {
		return 20
	}
	return size
}

func normalizedTrafficSize(size int) int {
	if size <= 0 || size > 500 {
		return 50
	}
	return size
}

func totalPages(total, size int) int {
	if size <= 0 {
		return 0
	}
	return (total + size - 1) / size
}

func firstText(first, second string) string {
	if strings.TrimSpace(first) != "" {
		return first
	}
	return second
}

func forwardedHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.Header.Get("X-Forwarded-Host")
	if strings.TrimSpace(host) == "" {
		host = r.Header.Get("Host")
	}
	if strings.TrimSpace(host) == "" {
		host = r.Host
	}
	if comma := strings.IndexByte(host, ','); comma >= 0 {
		host = host[:comma]
	}
	return strings.TrimSpace(host)
}

func adminOnlyCounter(principal managementPrincipal, value int64) int64 {
	if principal.Admin {
		return value
	}
	return 0
}

func validateTunnel(req tunnelMutation) error {
	if req.ListenPort <= 0 || req.ListenPort > 65535 {
		return validation("监听端口无效")
	}
	if req.TargetPort <= 0 || req.TargetPort > 65535 {
		return validation("目标端口无效")
	}
	if strings.TrimSpace(req.TargetAddress) == "" {
		return validation("目标地址不能为空")
	}
	return nil
}

func validateRoute(route, targetBaseURL string) error {
	if route == "" || strings.ContainsAny(route, "/?#") {
		return validation("路由格式无效")
	}
	if strings.TrimSpace(targetBaseURL) == "" {
		return validation("目标地址不能为空")
	}
	return nil
}

var (
	allowedDownloadImplementations = map[string]struct{}{"java": {}, "go": {}, "csharp": {}}
	allowedDownloadPlatforms       = map[string]struct{}{"windows": {}, "linux": {}, "macos": {}, "any": {}}
	allowedDownloadArchitectures   = map[string]struct{}{"x64": {}, "arm64": {}, "any": {}}
)

func newClientDownloadLink(req clientDownloadLinkMutation) (store.ClientDownloadLink, error) {
	now := time.Now()
	link := store.ClientDownloadLink{
		ID:        auth.NewClientID(),
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := applyClientDownloadLinkMutation(&link, req); err != nil {
		return store.ClientDownloadLink{}, err
	}
	link.CreatedAt = now
	if link.UpdatedAt.Before(now) {
		link.UpdatedAt = now
	}
	return link, nil
}

func applyClientDownloadLinkMutation(link *store.ClientDownloadLink, req clientDownloadLinkMutation) error {
	implementation, err := requireDownloadEnum(req.Implementation, allowedDownloadImplementations,
		"implementation must be one of [java go csharp]")
	if err != nil {
		return err
	}
	platform, err := requireDownloadEnum(req.Platform, allowedDownloadPlatforms,
		"platform must be one of [windows linux macos any]")
	if err != nil {
		return err
	}
	arch, err := requireDownloadEnum(req.Arch, allowedDownloadArchitectures,
		"arch must be one of [x64 arm64 any]")
	if err != nil {
		return err
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return validation("displayName cannot be blank")
	}
	if len(displayName) > 120 {
		return validation("displayName is too long (max 120)")
	}
	downloadURL, err := requireDownloadURL(req.DownloadURL)
	if err != nil {
		return err
	}
	description := normalizeDownloadDescription(req.Description)

	link.Implementation = implementation
	link.Platform = platform
	link.Arch = arch
	link.DisplayName = displayName
	link.DownloadURL = downloadURL
	link.Description = description
	if req.DisplayOrder != nil {
		link.DisplayOrder = *req.DisplayOrder
	}
	if req.Enabled != nil {
		link.Enabled = *req.Enabled
	}
	link.UpdatedAt = time.Now()
	return nil
}

func requireDownloadEnum(value string, allowed map[string]struct{}, message string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if _, ok := allowed[normalized]; !ok {
		return "", validation(message)
	}
	return normalized, nil
}

func requireDownloadURL(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", validation("downloadUrl cannot be blank")
	}
	if len(trimmed) > 1024 {
		return "", validation("downloadUrl is too long (max 1024)")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", validation("downloadUrl is not a valid URI: " + err.Error())
	}
	if !parsed.IsAbs() || parsed.Host == "" ||
		(!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
		return "", validation("downloadUrl must be an absolute http(s) URL")
	}
	return trimmed, nil
}

func normalizeDownloadDescription(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if len(trimmed) > 512 {
		trimmed = trimmed[:512]
	}
	return &trimmed
}

func validation(message string) error { return wrap(ErrValidation, message) }
func conflict(message string) error   { return wrap(ErrConflict, message) }
func forbidden(message string) error  { return wrap(ErrForbidden, message) }

func wrap(sentinel error, message string) error {
	return &apiError{sentinel: sentinel, message: message}
}

type apiError struct {
	sentinel error
	message  string
}

func (e *apiError) Error() string        { return e.message }
func (e *apiError) Is(target error) bool { return target == e.sentinel }

func tunnelView(m store.TunnelMapping) TunnelView {
	return TunnelView{
		ID: m.ID, ClientID: m.ClientID, ClientName: m.ClientName, ListenPort: m.ListenPort,
		TargetAddress: m.TargetAddress, TargetPort: m.TargetPort, Enabled: m.Enabled,
		DetailCaptureEnabled: m.DetailCaptureEnabled,
		CreatedAt:            m.CreatedAt.Format(time.RFC3339Nano), UpdatedAt: m.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func httpRouteView(r store.HTTPRouteMapping) HTTPRouteView {
	return HTTPRouteView{
		ID: r.ID, ClientID: r.ClientID, ClientName: r.ClientName, Route: r.Route,
		TargetBaseURL: r.TargetBaseURL, Enabled: r.Enabled,
		DetailCaptureEnabled: r.DetailCaptureEnabled, PathRewriteEnabled: r.PathRewriteEnabled,
		CreatedAt: r.CreatedAt.Format(time.RFC3339Nano), UpdatedAt: r.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func httpTrafficExchangeView(item store.HTTPTrafficExchange) HTTPTrafficExchangeView {
	return HTTPTrafficExchangeView{
		ID:                  strconv.FormatInt(item.ID, 10),
		ClientID:            item.ClientID,
		ClientName:          item.ClientName,
		Route:               item.Route,
		ResourceID:          item.ResourceID,
		ResourceName:        item.ResourceName,
		Method:              item.Method,
		RelativePath:        item.RelativePath,
		RawQuery:            item.RawQuery,
		StatusCode:          item.StatusCode,
		Success:             item.Success,
		Error:               item.Error,
		RemoteAddress:       item.RemoteAddress,
		RequestBytes:        item.RequestBytes,
		ResponseBytes:       item.ResponseBytes,
		ElapsedMs:           item.ElapsedMs,
		RequestContentType:  item.RequestContentType,
		ResponseContentType: item.ResponseContentType,
		ResponseBodyType:    item.ResponseBodyType,
		RequestHeaders:      item.RequestHeaders,
		ResponseHeaders:     item.ResponseHeaders,
		RequestPreviewHex:   item.RequestPreviewHex,
		RequestPreviewText:  item.RequestPreviewText,
		ResponsePreviewHex:  item.ResponsePreviewHex,
		ResponsePreviewText: item.ResponsePreviewText,
		RequestTruncated:    item.RequestTruncated,
		ResponseTruncated:   item.ResponseTruncated,
		CapturedAt:          item.CapturedAt.Format(time.RFC3339Nano),
	}
}

func tcpTrafficFrameView(item store.TCPTrafficFrame, includePayload bool) TCPTrafficFrameView {
	view := TCPTrafficFrameView{
		ID:                 strconv.FormatInt(item.ID, 10),
		ClientID:           item.ClientID,
		ClientName:         item.ClientName,
		ListenPort:         item.ListenPort,
		ResourceID:         item.ResourceID,
		ResourceName:       item.ResourceName,
		ChannelID:          item.ChannelID,
		Direction:          item.Direction,
		RemoteAddress:      item.RemoteAddress,
		SourceAddress:      item.SourceAddress,
		SourcePort:         item.SourcePort,
		DestinationAddress: item.DestinationAddress,
		DestinationPort:    item.DestinationPort,
		StreamOffset:       item.StreamOffset,
		StreamEndOffset:    item.StreamEndOffset,
		FrameIndex:         item.FrameIndex,
		PayloadBytes:       item.PayloadBytes,
		PayloadPreviewHex:  item.PayloadPreviewHex,
		PayloadPreviewText: item.PayloadPreviewText,
		Truncated:          item.Truncated,
		FrameTime:          item.FrameTime.Format(time.RFC3339Nano),
	}
	if includePayload && len(item.PayloadData) > 0 {
		view.PayloadBase64 = base64.StdEncoding.EncodeToString(item.PayloadData)
	}
	return view
}

func connectionItem(r store.ConnectionRecord) ConnectionItem {
	item := ConnectionItem{
		ID: r.ID, ClientID: r.ClientID, ClientName: r.ClientName, ChannelID: r.ChannelID,
		RemoteAddress: r.RemoteAddress, ConnectedAt: r.ConnectedAt.Format(time.RFC3339Nano),
		Success: r.Success, FailureReason: r.FailureReason, DisconnectReason: r.DisconnectReason,
	}
	if r.DisconnectedAt != nil {
		formatted := r.DisconnectedAt.Format(time.RFC3339Nano)
		item.DisconnectedAt = &formatted
	}
	if r.DisconnectReason != nil {
		text := store.ReasonText(*r.DisconnectReason)
		item.DisconnectReasonText = &text
	}
	return item
}

func boolOr(value *bool, fallback bool) bool {
	if value != nil {
		return *value
	}
	return fallback
}

func intOr(value *int, fallback int) int {
	if value != nil {
		return *value
	}
	return fallback
}

func normalizeMaxOnline(value *int, fallback int) (int, error) {
	normalized := intOr(value, fallback)
	if normalized < 1 || normalized > 10000 {
		return 0, validation("maxOnlineInstances must be between 1 and 10000")
	}
	return normalized, nil
}

func pathInt(r *http.Request, name string) (int64, error) {
	value, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		return 0, validation("路径参数无效: " + name)
	}
	return value, nil
}

func queryInt(r *http.Request, name string, fallback int) int {
	if value := r.URL.Query().Get(name); value != "" {
		if n, err := strconv.Atoi(value); err == nil {
			return n
		}
	}
	return fallback
}

func queryBool(r *http.Request, name string, fallback bool) bool {
	if value := r.URL.Query().Get(name); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func queryInt64Ptr(r *http.Request, name string) *int64 {
	if value := r.URL.Query().Get(name); value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return &n
		}
	}
	return nil
}

func queryIntPtr(r *http.Request, name string) *int {
	if value := r.URL.Query().Get(name); value != "" {
		if n, err := strconv.Atoi(value); err == nil {
			return &n
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
