package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type clientAuthLoginRequest struct {
	APIKey      string                `json:"apiKey"`
	Timestamp   string                `json:"timestamp"`
	Nonce       string                `json:"nonce"`
	Signature   string                `json:"signature"`
	Environment clientEnvironmentInfo `json:"environment"`
}

type clientEnvironmentInfo struct {
	MachineFingerprint        string                    `json:"machineFingerprint"`
	Hostname                  string                    `json:"hostname"`
	OSUser                    string                    `json:"osUser"`
	OSName                    string                    `json:"osName"`
	OSVersion                 string                    `json:"osVersion"`
	OSArch                    string                    `json:"osArch"`
	ClientVersion             string                    `json:"clientVersion"`
	JavaVersion               string                    `json:"javaVersion"`
	PeerPublicKey             string                    `json:"peerPublicKey"`
	ClientMessageCapabilities clientMessageCapabilities `json:"clientMessageCapabilities"`
	LocalAddresses            []string                  `json:"localAddresses"`
	StartedAt                 string                    `json:"startedAt"`
}

type clientMessageCapabilities struct {
	SendMessages       bool  `json:"sendMessages"`
	ReceiveMessages    bool  `json:"receiveMessages"`
	Attachments        bool  `json:"attachments"`
	MediaPreview       bool  `json:"mediaPreview"`
	MaxAttachmentBytes int64 `json:"maxAttachmentBytes"`
}

type clientAuthLoginResponse struct {
	TenantID             string               `json:"tenantId"`
	ClientID             int64                `json:"clientId"`
	ClientName           string               `json:"clientName"`
	ClientSessionID      int64                `json:"clientSessionId"`
	AccessToken          string               `json:"accessToken"`
	TokenTTLSeconds      int64                `json:"tokenTtlSeconds"`
	NettyHost            string               `json:"nettyHost"`
	NettyPort            int                  `json:"nettyPort"`
	MaxOnlineInstances   int                  `json:"maxOnlineInstances"`
	Policy               clientPolicy         `json:"policy"`
	PeerMesh             peermesh.LoginConfig `json:"peerMesh"`
	SpecusConfigList     []specusEndpoint     `json:"specusConfigList"`
	HTTPSpecusConfigList []httpRouteEndpoint  `json:"httpSpecusConfigList"`
}

type clientPolicy struct {
	Enabled           bool   `json:"enabled"`
	BillingStatus     string `json:"billingStatus"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds"`
}

type specusEndpoint struct {
	Port          int    `json:"port"`
	SpecusAddress string `json:"specusAddress"`
	SpecusPort    int    `json:"specusPort"`
}

type httpRouteEndpoint struct {
	Route         string `json:"route"`
	TargetBaseURL string `json:"targetBaseUrl"`
}

func (a *App) handleClientAuthLogin(w http.ResponseWriter, r *http.Request) {
	var request clientAuthLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeClientAuthError(w, http.StatusBadRequest, "登录请求无效")
		return
	}
	if strings.TrimSpace(request.Environment.MachineFingerprint) == "" ||
		strings.TrimSpace(request.Environment.OSUser) == "" {
		writeClientAuthError(w, http.StatusBadRequest, "environment 不能为空")
		return
	}
	credential, err := a.authenticateClientStartup(r.Context(), request)
	if err != nil {
		var rejection errClientAuth
		if errors.As(err, &rejection) {
			writeClientAuthError(w, http.StatusBadRequest, rejection.Error())
		} else {
			a.failClientAuthInternal(w, "startup-authentication", "客户端认证暂时不可用", err)
		}
		return
	}
	if !credential.Enabled {
		writeClientAuthError(w, http.StatusBadRequest, "客户端凭证已停用")
		return
	}
	account, identity, err := a.findOrCreateClientIdentity(r.Context(), *credential, request.Environment)
	if err != nil {
		a.failClientAuthInternal(w, "create-identity", "客户端身份创建失败", err)
		return
	}
	if !account.Enabled {
		writeClientAuthError(w, http.StatusBadRequest, "客户端已停用")
		return
	}
	ttl := time.Duration(a.cfg.ClientAuth.TokenTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	machineFingerprint := limit(strings.TrimSpace(request.Environment.MachineFingerprint), 160)
	osUser := limit(strings.TrimSpace(request.Environment.OSUser), 120)
	if _, err := a.db.CloseHTTPAuthenticatedClientSessions(r.Context(), credential.ID,
		machineFingerprint, osUser, auth.StatusHTTPAuthenticated, auth.StatusDisconnected, time.Now()); err != nil {
		a.failClientAuthInternal(w, "close-stale-sessions", "清理旧客户端会话失败", err)
		return
	}
	session := a.clientAuth.CreateForClient(*account,
		credential.ID,
		machineFingerprint,
		osUser,
		ttl)
	now := time.Now()
	if err := a.db.InsertClientSession(r.Context(), store.ClientSession{
		ID:                         session.ID,
		TenantID:                   session.TenantID,
		CredentialID:               credential.ID,
		IdentityID:                 identity.ID,
		ClientID:                   account.ID,
		ClientName:                 account.ClientName,
		TokenHash:                  session.TokenHash,
		Status:                     auth.StatusHTTPAuthenticated,
		MachineFingerprint:         machineFingerprint,
		OSUser:                     osUser,
		Hostname:                   limitedTextPtr(request.Environment.Hostname, 160),
		OSName:                     limitedTextPtr(request.Environment.OSName, 120),
		OSVersion:                  limitedTextPtr(request.Environment.OSVersion, 80),
		OSArch:                     limitedTextPtr(request.Environment.OSArch, 60),
		ClientVersion:              limitedTextPtr(request.Environment.ClientVersion, 80),
		JavaVersion:                limitedTextPtr(request.Environment.JavaVersion, 80),
		LocalAddresses:             limitedTextPtr(strings.Join(request.Environment.LocalAddresses, ","), 2000),
		MessageSendCapable:         request.Environment.ClientMessageCapabilities.SendMessages,
		MessageReceiveCapable:      request.Environment.ClientMessageCapabilities.ReceiveMessages,
		MessageAttachmentsCapable:  request.Environment.ClientMessageCapabilities.Attachments,
		MessageMediaPreviewCapable: request.Environment.ClientMessageCapabilities.MediaPreview,
		MessageMaxAttachmentBytes:  max64(0, request.Environment.ClientMessageCapabilities.MaxAttachmentBytes),
		HTTPLoginAt:                now,
		ExpiresAt:                  session.ExpiresAt,
	}); err != nil {
		a.failClientAuthInternal(w, "save-session", "保存客户端会话失败", err)
		return
	}
	specusMappings, err := a.db.ListEnabledSpecusMappings(r.Context(), account.ID)
	if err != nil {
		a.failClientAuthInternal(w, "load-tcp-mappings", "加载 TCP 映射失败", err)
		return
	}
	routes, err := a.db.ListEnabledHTTPRoutes(r.Context(), account.ID)
	if err != nil {
		a.failClientAuthInternal(w, "load-http-routes", "加载 HTTP 路由失败", err)
		return
	}
	peerMesh, err := a.peerMesh.BuildLoginConfig(r.Context(), *account, request.Environment.PeerPublicKey, r.Host)
	if err != nil {
		a.failClientAuthInternal(w, "load-peer-mesh", "加载私有组网配置失败", err)
		return
	}
	response := clientAuthLoginResponse{
		TenantID:           firstText(credential.TenantID, "default"),
		ClientID:           account.ID,
		ClientName:         account.ClientName,
		ClientSessionID:    session.ID,
		AccessToken:        session.AccessToken,
		TokenTTLSeconds:    int64(ttl / time.Second),
		NettyHost:          a.nettyHost(r.Host),
		NettyPort:          a.cfg.Netty.Port,
		MaxOnlineInstances: credential.MaxOnlineInstances,
		Policy:             clientPolicy{Enabled: true, BillingStatus: "ACTIVE"},
		PeerMesh:           peerMesh,
	}
	for _, item := range specusMappings {
		response.SpecusConfigList = append(response.SpecusConfigList, specusEndpoint{
			Port:          item.ListenPort,
			SpecusAddress: item.TargetAddress,
			SpecusPort:    item.TargetPort,
		})
	}
	for _, item := range routes {
		response.HTTPSpecusConfigList = append(response.HTTPSpecusConfigList, httpRouteEndpoint{
			Route:         item.Route,
			TargetBaseURL: item.TargetBaseURL,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func max64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func (a *App) authenticateClientStartup(ctx context.Context, request clientAuthLoginRequest) (*store.ClientCredential, error) {
	credential, err := a.db.FindCredentialByAPIKey(ctx, strings.TrimSpace(request.APIKey))
	if err != nil {
		return nil, err
	}
	if credential == nil {
		return nil, errClientAuth("客户端凭证不存在")
	}
	if !validAPIKeySignature(request, credential.SecretHash) {
		return nil, errClientAuth("客户端签名无效或已过期")
	}
	now := time.Now().UTC()
	apiKeyDigest := sha256.Sum256([]byte(strings.TrimSpace(request.APIKey)))
	consumed, err := a.db.ConsumeClientAuthNonce(ctx, hex.EncodeToString(apiKeyDigest[:]),
		request.Nonce, now, now.Add(2*time.Minute))
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, errClientAuth("客户端 nonce 已使用")
	}
	return credential, nil
}

func (a *App) findOrCreateClientIdentity(ctx context.Context, credential store.ClientCredential,
	environment clientEnvironmentInfo) (*store.ClientAccount, *store.ClientIdentity, error) {
	machine := limit(strings.TrimSpace(environment.MachineFingerprint), 160)
	osUser := limit(strings.TrimSpace(environment.OSUser), 120)
	hostname := limit(firstText(environment.Hostname, "unknown-host"), 160)
	identity, err := a.db.FindIdentity(ctx, credential.ID, machine, osUser)
	if err != nil {
		return nil, nil, err
	}
	if identity != nil {
		_ = a.db.UpdateIdentityLastSeen(ctx, identity.ID, hostname, time.Now())
		account, err := a.db.GetClient(ctx, identity.ClientID)
		if err != nil {
			return nil, nil, err
		}
		return account, identity, nil
	}

	now := time.Now()
	clientName, err := a.generateClientName(ctx, credential, machine, osUser, hostname)
	if err != nil {
		return nil, nil, err
	}
	account := store.ClientAccount{
		ID:                           auth.NewClientID(),
		TenantID:                     firstText(credential.TenantID, "default"),
		OwnerUsername:                credential.OwnerUsername,
		ClientName:                   clientName,
		PasswordHash:                 auth.HashPassword(time.Now().Format(time.RFC3339Nano)),
		Enabled:                      true,
		ConnectionRateLimitPerMinute: 30,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	}
	if err := a.db.InsertClient(ctx, account); err != nil {
		return nil, nil, err
	}
	identity = &store.ClientIdentity{
		ID:                 auth.NewClientID(),
		TenantID:           account.TenantID,
		CredentialID:       credential.ID,
		ClientID:           account.ID,
		ClientName:         account.ClientName,
		MachineFingerprint: machine,
		OSUser:             osUser,
		Hostname:           hostname,
		FirstSeenAt:        now,
		LastSeenAt:         now,
	}
	if err := a.db.InsertIdentity(ctx, *identity); err != nil {
		return nil, nil, err
	}
	return &account, identity, nil
}

func (a *App) generateClientName(ctx context.Context, credential store.ClientCredential,
	machineFingerprint, osUser, hostname string) (string, error) {
	host := slug(hostname, "client")
	user := slug(osUser, "user")
	sum := sha256.Sum256([]byte(strconv.FormatInt(credential.ID, 10) + "\n" + machineFingerprint + "\n" + osUser))
	base := limit(host+"-"+user+"-"+hex.EncodeToString(sum[:])[:8], 120)
	candidate := base
	for i := 2; ; i++ {
		existing, err := a.db.FindClientByName(ctx, candidate)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return candidate, nil
		}
		extra := "-" + strconv.Itoa(i)
		candidate = limit(base, 120-len(extra)) + extra
	}
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func limit(value string, maxLength int) string {
	if len(value) <= maxLength {
		return value
	}
	return value[:maxLength]
}

func limitedTextPtr(value string, maxLength int) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	limited := limit(trimmed, maxLength)
	return &limited
}

func slug(value, fallback string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = fallback
	}
	var out strings.Builder
	lastDash := false
	for _, ch := range normalized {
		ok := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-'
		if ok {
			out.WriteRune(ch)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(out.String(), "-")
	if result == "" {
		result = fallback
	}
	return limit(result, 50)
}

func validAPIKeySignature(request clientAuthLoginRequest, secretHash string) bool {
	if request.Timestamp == "" || request.Nonce == "" || request.Signature == "" {
		return false
	}
	var timestamp int64
	for _, ch := range request.Timestamp {
		if ch < '0' || ch > '9' {
			return false
		}
		timestamp = timestamp*10 + int64(ch-'0')
	}
	delta := time.Now().UnixMilli() - timestamp
	if delta < 0 {
		delta = -delta
	}
	if delta > 60_000 {
		return false
	}
	key, err := hex.DecodeString(secretHash)
	if err != nil || len(key) != 32 {
		return false
	}
	message := strings.Join([]string{
		request.APIKey,
		request.Timestamp,
		request.Nonce,
		request.Environment.MachineFingerprint,
		request.Environment.OSUser,
	}, "\n")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(request.Signature)))
}

func (a *App) nettyHost(requestHost string) string {
	if strings.TrimSpace(a.cfg.PublicAddress) != "" {
		return strings.TrimSpace(a.cfg.PublicAddress)
	}
	host, _, err := net.SplitHostPort(requestHost)
	if err == nil && host != "" {
		return host
	}
	if requestHost == "" {
		return "127.0.0.1"
	}
	return requestHost
}

type errClientAuth string

func (e errClientAuth) Error() string { return string(e) }

func writeClientAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (a *App) failClientAuthInternal(w http.ResponseWriter, stage, message string, err error) {
	a.logger.Error("client authentication failed", "stage", stage, "err", err)
	writeClientAuthError(w, http.StatusInternalServerError, message)
}
