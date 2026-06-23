package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/auth"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

type clientAuthLoginRequest struct {
	AuthType    string                `json:"authType"`
	APIKey      string                `json:"apiKey"`
	Username    string                `json:"username"`
	Password    string                `json:"password"`
	Timestamp   string                `json:"timestamp"`
	Nonce       string                `json:"nonce"`
	Signature   string                `json:"signature"`
	Environment clientEnvironmentInfo `json:"environment"`
}

type clientEnvironmentInfo struct {
	MachineFingerprint string   `json:"machineFingerprint"`
	Hostname           string   `json:"hostname"`
	OSUser             string   `json:"osUser"`
	LocalAddresses     []string `json:"localAddresses"`
}

type clientAuthLoginResponse struct {
	TenantID             string              `json:"tenantId"`
	ClientID             int64               `json:"clientId"`
	ClientName           string              `json:"clientName"`
	ClientSessionID      int64               `json:"clientSessionId"`
	AccessToken          string              `json:"accessToken"`
	TokenTTLSeconds      int64               `json:"tokenTtlSeconds"`
	NettyHost            string              `json:"nettyHost"`
	NettyPort            int                 `json:"nettyPort"`
	MaxOnlineInstances   int                 `json:"maxOnlineInstances"`
	Policy               clientPolicy        `json:"policy"`
	TunnelConfigList     []tunnelEndpoint    `json:"tunnelConfigList"`
	HTTPTunnelConfigList []httpRouteEndpoint `json:"httpTunnelConfigList"`
}

type clientPolicy struct {
	Enabled           bool   `json:"enabled"`
	BillingStatus     string `json:"billingStatus"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds"`
}

type tunnelEndpoint struct {
	Port          int    `json:"port"`
	TunnelAddress string `json:"tunnelAddress"`
	TunnelPort    int    `json:"tunnelPort"`
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
	account, err := a.authenticateClientStartup(r.Context(), request)
	if err != nil {
		writeClientAuthError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !account.Enabled {
		writeClientAuthError(w, http.StatusBadRequest, "客户端已停用")
		return
	}
	ttl := time.Duration(a.cfg.Auth.TokenTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	session := a.clientAuth.Create(*account, ttl)
	tunnels, err := a.db.ListEnabledTunnels(r.Context(), account.ID)
	if err != nil {
		writeClientAuthError(w, http.StatusInternalServerError, "加载 TCP 映射失败")
		return
	}
	routes, err := a.db.ListEnabledHTTPRoutes(r.Context(), account.ID)
	if err != nil {
		writeClientAuthError(w, http.StatusInternalServerError, "加载 HTTP 路由失败")
		return
	}
	response := clientAuthLoginResponse{
		TenantID:           "default",
		ClientID:           account.ID,
		ClientName:         account.ClientName,
		ClientSessionID:    session.ID,
		AccessToken:        session.AccessToken,
		TokenTTLSeconds:    int64(ttl / time.Second),
		NettyHost:          a.nettyHost(r.Host),
		NettyPort:          a.cfg.Netty.Port,
		MaxOnlineInstances: 2,
		Policy:             clientPolicy{Enabled: true, BillingStatus: "ACTIVE"},
	}
	for _, item := range tunnels {
		response.TunnelConfigList = append(response.TunnelConfigList, tunnelEndpoint{
			Port:          item.ListenPort,
			TunnelAddress: item.TargetAddress,
			TunnelPort:    item.TargetPort,
		})
	}
	for _, item := range routes {
		response.HTTPTunnelConfigList = append(response.HTTPTunnelConfigList, httpRouteEndpoint{
			Route:         item.Route,
			TargetBaseURL: item.TargetBaseURL,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (a *App) authenticateClientStartup(ctx context.Context, request clientAuthLoginRequest) (*store.ClientAccount, error) {
	authType := strings.TrimSpace(request.AuthType)
	if strings.EqualFold(authType, "password") {
		account, err := a.db.FindClientByName(ctx, strings.TrimSpace(request.Username))
		if err != nil || account == nil {
			return nil, errClientAuth("客户端凭证不存在")
		}
		if auth.HashPassword(request.Password) != account.PasswordHash {
			return nil, errClientAuth("客户端凭证无效")
		}
		return account, nil
	}
	account, err := a.db.FindClientByName(ctx, strings.TrimSpace(request.APIKey))
	if err != nil || account == nil {
		return nil, errClientAuth("客户端凭证不存在")
	}
	if !validAPIKeySignature(request, account.PasswordHash) {
		return nil, errClientAuth("客户端签名无效或已过期")
	}
	return account, nil
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
