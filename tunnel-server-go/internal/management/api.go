package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/auth"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/nat"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/security"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/session"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

// API holds the dependencies for the admin REST surface.
type API struct {
	db          *store.DB
	sessions    *session.Registry
	tokens      *security.LocalTokenService
	oidcAuth    *security.OidcValidator
	natControl  *nat.ControlService
	remotePorts *nat.RemotePortManager
	oidc        config.OidcConfig
	seedDemo    func(ctx context.Context) error
}

// NewAPI builds the admin API.
func NewAPI(db *store.DB, sessions *session.Registry, tokens *security.LocalTokenService,
	oidcAuth *security.OidcValidator, natControl *nat.ControlService, remotePorts *nat.RemotePortManager,
	oidc config.OidcConfig, seedDemo func(ctx context.Context) error) *API {
	return &API{db: db, sessions: sessions, tokens: tokens, oidcAuth: oidcAuth, natControl: natControl,
		remotePorts: remotePorts, oidc: oidc, seedDemo: seedDemo}
}

// Register attaches all auth and admin routes to mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/login", a.handleLogin)
	mux.HandleFunc("POST /auth/refresh", a.requireAuth(a.handleRefresh))
	mux.HandleFunc("GET /oidc-config", a.handleOidcConfig)
	mux.HandleFunc("POST /oidc/token", a.handleOidcToken)

	mux.HandleFunc("GET /api/admin/overview", a.requireAuth(a.handleOverview))
	mux.HandleFunc("POST /api/admin/database/initialize", a.requireAuth(a.handleDatabaseInitialize))

	mux.HandleFunc("GET /api/admin/clients", a.requireAuth(a.handleListClients))
	mux.HandleFunc("POST /api/admin/clients", a.requireAuth(a.handleCreateClient))
	mux.HandleFunc("PUT /api/admin/clients/{id}", a.requireAuth(a.handleUpdateClient))
	mux.HandleFunc("DELETE /api/admin/clients/{id}", a.requireAuth(a.handleDeleteClient))

	mux.HandleFunc("GET /api/admin/client-credentials", a.requireAuth(a.handleListCredentials))
	mux.HandleFunc("POST /api/admin/client-credentials", a.requireAuth(a.handleCreateCredential))
	mux.HandleFunc("PUT /api/admin/client-credentials/{id}", a.requireAuth(a.handleUpdateCredential))
	mux.HandleFunc("DELETE /api/admin/client-credentials/{id}", a.requireAuth(a.handleDeleteCredential))

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
	mux.HandleFunc("GET /api/admin/connection-stats", a.requireAuth(a.handleListConnectionStats))
}

// ValidateToken reports whether a raw token is a valid admin token (used by the WS hub).
func (a *API) ValidateToken(token string) bool {
	_, ok := a.authenticate(context.Background(), token)
	return ok
}

// ---- auth ----------------------------------------------------------------------------

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	if !a.tokens.Authenticate(req.Username, req.Password) {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	writeJSON(w, http.StatusOK, a.tokens.IssueBody(req.Username))
}

func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	username, _ := subjectFromContext(r)
	if username == "" {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeJSON(w, http.StatusOK, a.tokens.IssueBody(username))
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

// ---- overview / database -------------------------------------------------------------

func (a *API) handleOverview(w http.ResponseWriter, r *http.Request) {
	overview, err := a.db.LoadOverview(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OverviewView{
		Clients:                     overview.Clients,
		OnlineClients:               len(a.sessions.Names()),
		SuccessfulConnections:       overview.SuccessfulConnections,
		FailedConnections:           overview.FailedConnections,
		UploadBytes:                 overview.UploadBytes,
		DownloadBytes:               overview.DownloadBytes,
		ExternalConnections:         a.remotePorts.ActiveExternalConnections(),
		RejectedExternalConnections: a.remotePorts.RejectedExternalConnections(),
	})
}

func (a *API) handleDatabaseInitialize(w http.ResponseWriter, r *http.Request) {
	if a.seedDemo != nil {
		if err := a.seedDemo(r.Context()); err != nil {
			a.fail(w, err)
			return
		}
	}
	clients, err := a.db.CountClients(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": true,
		"orm":         "database/sql",
		"dialect":     string(a.db.Dialect()),
		"clients":     clients,
	})
}

// ---- clients -------------------------------------------------------------------------

func (a *API) handleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := a.db.ListClients(r.Context())
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

func (a *API) handleCreateClient(w http.ResponseWriter, r *http.Request) {
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
		TenantID:                     "default",
		OwnerUsername:                "admin",
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
	if err := a.db.DeleteClient(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.kick(account.ClientName, store.ReasonAdminDeleted)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	credentials, err := a.db.ListCredentials(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]CredentialView, 0, len(credentials))
	for _, credential := range credentials {
		views = append(views, credentialView(credential))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
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
	now := time.Now()
	credential := store.ClientCredential{
		ID:                 auth.NewClientID(),
		TenantID:           "default",
		OwnerUsername:      "admin",
		APIKey:             apiKey,
		SecretHash:         auth.HashPassword(secret),
		Enabled:            boolOr(req.Enabled, true),
		MaxOnlineInstances: intOr(req.MaxOnlineInstances, 2),
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
		credential.MaxOnlineInstances = *req.MaxOnlineInstances
	}
	credential.UpdatedAt = time.Now()
	if err := a.db.UpdateCredential(r.Context(), *credential); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, CredentialResult{Credential: credentialView(*credential), Secret: revealed})
}

func (a *API) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.db.DeleteCredential(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- tunnels -------------------------------------------------------------------------

func (a *API) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	clientID := queryInt64Ptr(r, "clientId")
	mappings, err := a.db.ListTunnels(r.Context(), clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]TunnelView, 0, len(mappings))
	for _, m := range mappings {
		views = append(views, tunnelView(m))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
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
	account, err := a.db.GetClient(r.Context(), clientID)
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
		ID:            auth.NewClientID(),
		ClientID:      account.ID,
		ClientName:    account.ClientName,
		ListenPort:    req.ListenPort,
		TargetAddress: strings.TrimSpace(req.TargetAddress),
		TargetPort:    req.TargetPort,
		Enabled:       boolOr(req.Enabled, true),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := a.db.InsertTunnel(r.Context(), mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), account.ID, account.ClientName)
	writeJSON(w, http.StatusCreated, tunnelView(mapping))
}

func (a *API) handleUpdateTunnel(w http.ResponseWriter, r *http.Request) {
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
	mapping.UpdatedAt = time.Now()
	if err := a.db.UpdateTunnel(r.Context(), *mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	writeJSON(w, http.StatusOK, tunnelView(*mapping))
}

func (a *API) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
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
	if err := a.db.DeleteTunnel(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleNatControl(w http.ResponseWriter, r *http.Request) {
	clientID, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	account, err := a.db.GetClient(r.Context(), clientID)
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
	clientID := queryInt64Ptr(r, "clientId")
	routes, err := a.db.ListHTTPRoutes(r.Context(), clientID)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]HTTPRouteView, 0, len(routes))
	for _, route := range routes {
		views = append(views, httpRouteView(route))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleCreateHTTPRoute(w http.ResponseWriter, r *http.Request) {
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
	account, err := a.db.GetClient(r.Context(), clientID)
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
		ID:            auth.NewClientID(),
		ClientID:      account.ID,
		ClientName:    account.ClientName,
		Route:         route,
		TargetBaseURL: strings.TrimSpace(req.TargetBaseURL),
		Enabled:       boolOr(req.Enabled, true),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := a.db.InsertHTTPRoute(r.Context(), mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), account.ID, account.ClientName)
	writeJSON(w, http.StatusCreated, httpRouteView(mapping))
}

func (a *API) handleUpdateHTTPRoute(w http.ResponseWriter, r *http.Request) {
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
	mapping.UpdatedAt = time.Now()
	if err := a.db.UpdateHTTPRoute(r.Context(), *mapping); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	writeJSON(w, http.StatusOK, httpRouteView(*mapping))
}

func (a *API) handleDeleteHTTPRoute(w http.ResponseWriter, r *http.Request) {
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
	if err := a.db.DeleteHTTPRoute(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.pushNatControl(r.Context(), mapping.ClientID, mapping.ClientName)
	w.WriteHeader(http.StatusNoContent)
}

// ---- read models ---------------------------------------------------------------------

func (a *API) handleListConnections(w http.ResponseWriter, r *http.Request) {
	filter := store.ConnectionFilter{
		ClientID: queryInt64Ptr(r, "clientId"),
		FromISO:  r.URL.Query().Get("from"),
		ToISO:    r.URL.Query().Get("to"),
		Page:     queryInt(r, "page", 0),
		Size:     queryInt(r, "size", 20),
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
	usages, err := a.db.ListTraffic(r.Context(), queryInt64Ptr(r, "clientId"), queryInt(r, "limit", 100))
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

func (a *API) handleListConnectionStats(w http.ResponseWriter, r *http.Request) {
	stats, err := a.db.ListConnectionStats(r.Context(), r.URL.Query().Get("clientName"), queryInt(r, "limit", 100))
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

func (a *API) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrValidation):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "资源不存在")
	default:
		writeError(w, http.StatusInternalServerError, "服务器内部错误")
	}
}

type ctxKey int

const subjectKey ctxKey = 0

func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		subject, ok := a.authenticate(r.Context(), token)
		if !ok {
			writeError(w, http.StatusUnauthorized, "未授权")
			return
		}
		ctx := context.WithValue(r.Context(), subjectKey, subject)
		next(w, r.WithContext(ctx))
	}
}

// authenticate validates a bearer token: local HS256 first, then OIDC RS256 as a fallback.
func (a *API) authenticate(ctx context.Context, token string) (string, bool) {
	if subject, ok := a.tokens.Validate(token); ok {
		return subject, true
	}
	if a.oidcAuth != nil {
		if subject, ok := a.oidcAuth.Validate(ctx, token); ok {
			return subject, true
		}
	}
	return "", false
}

func subjectFromContext(r *http.Request) (string, bool) {
	subject, ok := r.Context().Value(subjectKey).(string)
	return subject, ok
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(header) > len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
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

func validation(message string) error { return wrap(ErrValidation, message) }
func conflict(message string) error   { return wrap(ErrConflict, message) }

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
		CreatedAt: m.CreatedAt.Format(time.RFC3339Nano), UpdatedAt: m.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func httpRouteView(r store.HTTPRouteMapping) HTTPRouteView {
	return HTTPRouteView{
		ID: r.ID, ClientID: r.ClientID, ClientName: r.ClientName, Route: r.Route,
		TargetBaseURL: r.TargetBaseURL, Enabled: r.Enabled,
		CreatedAt: r.CreatedAt.Format(time.RFC3339Nano), UpdatedAt: r.UpdatedAt.Format(time.RFC3339Nano),
	}
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

func queryInt64Ptr(r *http.Request, name string) *int64 {
	if value := r.URL.Query().Get(name); value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
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
