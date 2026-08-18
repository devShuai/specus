package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestClientAuthLoginUsesCredentialTenant(t *testing.T) {
	app, ts := newAPIServer(t)
	const (
		apiKey = "ck_tenant_a"
		secret = "tenant-secret"
	)
	insertCredentialForTest(t, app, "tenant-a", "alice", apiKey, secret, 4)
	decoded := clientAuthLoginForTest(t, ts.URL, apiKey, secret, "machine-tenant-a", "alice")

	if decoded.TenantID != "tenant-a" {
		t.Fatalf("tenantId should come from credential, got %q", decoded.TenantID)
	}
	if decoded.MaxOnlineInstances != 4 {
		t.Fatalf("maxOnlineInstances should come from credential, got %d", decoded.MaxOnlineInstances)
	}
	if decoded.ClientName == "" {
		t.Fatal("clientName should be assigned")
	}
	if decoded.NettyTLS == nil || *decoded.NettyTLS {
		t.Fatalf("nettyTls should be present and false for a plaintext listener, got %v", decoded.NettyTLS)
	}
	session := getClientSessionForTest(t, app, decoded.ClientSessionID)
	if session.TenantID != "tenant-a" || session.Status != auth.StatusHTTPAuthenticated {
		t.Fatalf("unexpected persisted http session: tenant=%q status=%q", session.TenantID, session.Status)
	}
	if session.MachineFingerprint != "machine-tenant-a" || session.OSUser != "alice" {
		t.Fatalf("unexpected persisted environment: %+v", session)
	}
	if !session.MessageSendCapable || !session.MessageReceiveCapable || !session.MessageAttachmentsCapable ||
		!session.MessageMediaPreviewCapable || session.MessageMaxAttachmentBytes != 123456 {
		t.Fatalf("client message capabilities were not persisted: %+v", session)
	}
}

func TestClientAuthAdvertisesTLSWhenTerminatedUpstream(t *testing.T) {
	cfg := config.Default()
	cfg.TLS.Mode = "disabled"
	cfg.TLS.TerminatedUpstream = true
	app, ts := newAPIServerWithConfig(t, cfg)
	insertCredentialForTest(t, app, "default", "admin", "ck_upstream_tls", "tls-secret", 2)
	decoded := clientAuthLoginForTest(t, ts.URL, "ck_upstream_tls", "tls-secret", "machine-tls", "alice")
	if decoded.NettyTLS == nil || !*decoded.NettyTLS {
		t.Fatalf("nettyTls should be true for trusted upstream termination, got %v", decoded.NettyTLS)
	}
}

func TestClientAuthDatabaseFailureReturnsInternalServerError(t *testing.T) {
	app, ts := newAPIServer(t)
	if err := app.DB().Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"apiKey":    "unavailable-database",
		"timestamp": strconv.FormatInt(time.Now().UnixMilli(), 10),
		"nonce":     "nonce",
		"signature": "signature",
		"environment": map[string]any{
			"machineFingerprint": "machine",
			"osUser":             "user",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(ts.URL+"/api/client/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("client auth login: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.StatusCode)
	}
	var payload map[string]string
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload["error"] != "客户端认证暂时不可用" {
		t.Fatalf("error = %q", payload["error"])
	}
}

func TestClientAuthLoginUsesClientAuthTokenTTL(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.TokenTTLSeconds = 60
	cfg.ClientAuth.TokenTTLSeconds = 1234
	app, ts := newAPIServerWithConfig(t, cfg)
	const (
		apiKey = "ck_ttl"
		secret = "tenant-secret"
	)
	insertCredentialForTest(t, app, "tenant-a", "alice", apiKey, secret, 4)

	before := time.Now()
	decoded := clientAuthLoginForTest(t, ts.URL, apiKey, secret, "machine-ttl", "alice")
	after := time.Now()

	if decoded.TokenTTLSeconds != 1234 {
		t.Fatalf("tokenTtlSeconds = %d, want 1234", decoded.TokenTTLSeconds)
	}
	session := getClientSessionForTest(t, app, decoded.ClientSessionID)
	minExpiresAt := before.Add(1234*time.Second - 2*time.Second)
	maxExpiresAt := after.Add(1234*time.Second + 2*time.Second)
	if session.ExpiresAt.Before(minExpiresAt) || session.ExpiresAt.After(maxExpiresAt) {
		t.Fatalf("session expiresAt = %s, want around client auth ttl window [%s, %s]",
			session.ExpiresAt.Format(time.RFC3339Nano), minExpiresAt.Format(time.RFC3339Nano),
			maxExpiresAt.Format(time.RFC3339Nano))
	}
}

func TestNettyLoginRejectsDuplicateMachineUserSession(t *testing.T) {
	app, ts := newAPIServer(t)
	const (
		apiKey = "ck_same_machine"
		secret = "tenant-secret"
	)
	insertCredentialForTest(t, app, "tenant-a", "alice", apiKey, secret, 2)

	first := clientAuthLoginForTest(t, ts.URL, apiKey, secret, "machine-1", "alice")
	firstLogin := dialRuntimeAndReadLogin(t, app.ControlPort(), first)
	if !firstLogin.Success {
		t.Fatalf("first netty login failed: %+v", firstLogin)
	}
	if session := getClientSessionForTest(t, app, first.ClientSessionID); session.Status != auth.StatusNettyOnline {
		t.Fatalf("first session should be NETTY_ONLINE, got %q", session.Status)
	}

	second := clientAuthLoginForTest(t, ts.URL, apiKey, secret, "machine-1", "alice")
	secondLogin := dialRuntimeAndReadLogin(t, app.ControlPort(), second)
	if secondLogin.Success {
		t.Fatal("second same-machine netty login should be rejected")
	}
	if secondLogin.Reason == nil || *secondLogin.Reason != "同一台机器和用户已经有在线实例" {
		t.Fatalf("unexpected duplicate-machine reason: %+v", secondLogin.Reason)
	}
}

func TestNettyLoginRejectsCredentialOnlineLimit(t *testing.T) {
	app, ts := newAPIServer(t)
	const (
		apiKey = "ck_online_limit"
		secret = "tenant-secret"
	)
	insertCredentialForTest(t, app, "tenant-a", "alice", apiKey, secret, 1)

	first := clientAuthLoginForTest(t, ts.URL, apiKey, secret, "machine-1", "alice")
	firstLogin := dialRuntimeAndReadLogin(t, app.ControlPort(), first)
	if !firstLogin.Success {
		t.Fatalf("first netty login failed: %+v", firstLogin)
	}

	second := clientAuthLoginForTest(t, ts.URL, apiKey, secret, "machine-2", "alice")
	secondLogin := dialRuntimeAndReadLogin(t, app.ControlPort(), second)
	if secondLogin.Success {
		t.Fatal("second credential netty login should be rejected by maxOnlineInstances")
	}
	if secondLogin.Reason == nil || *secondLogin.Reason != "在线实例数已达上限" {
		t.Fatalf("unexpected online-limit reason: %+v", secondLogin.Reason)
	}
}

type clientAuthLoginForTestResponse struct {
	TenantID           string `json:"tenantId"`
	ClientName         string `json:"clientName"`
	ClientSessionID    int64  `json:"clientSessionId"`
	AccessToken        string `json:"accessToken"`
	TokenTTLSeconds    int64  `json:"tokenTtlSeconds"`
	MaxOnlineInstances int    `json:"maxOnlineInstances"`
	NettyTLS           *bool  `json:"nettyTls"`
}

func insertCredentialForTest(t *testing.T, app *App, tenantID, owner, apiKey, secret string, maxOnline int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	now := time.Now()
	if _, err := app.DB().InsertCredentialIfAbsent(ctx, store.ClientCredential{
		ID:                 auth.NewClientID(),
		TenantID:           tenantID,
		OwnerUsername:      owner,
		APIKey:             apiKey,
		SecretHash:         auth.HashToken(secret),
		Enabled:            true,
		MaxOnlineInstances: maxOnline,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatalf("insert credential: %v", err)
	}
}

func getClientSessionForTest(t *testing.T, app *App, id int64) *store.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := app.DB().GetClientSession(ctx, id)
	if err != nil {
		t.Fatalf("get client session: %v", err)
	}
	return session
}

func clientAuthLoginForTest(t *testing.T, baseURL, apiKey, secret, machineFingerprint, osUser string) clientAuthLoginForTestResponse {
	t.Helper()
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nonce := "nonce-" + machineFingerprint + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	environment := map[string]any{
		"machineFingerprint": machineFingerprint,
		"hostname":           "tenant-host",
		"osUser":             osUser,
		"osName":             "test-os",
		"osArch":             "amd64",
		"localAddresses":     []string{"10.1.2.3"},
		"clientMessageCapabilities": map[string]any{
			"sendMessages": true, "receiveMessages": true, "attachments": true,
			"mediaPreview": true, "maxAttachmentBytes": 123456,
		},
	}
	request := map[string]any{
		"apiKey":      apiKey,
		"timestamp":   timestamp,
		"nonce":       nonce,
		"signature":   signClientAuthForTest(apiKey, timestamp, nonce, machineFingerprint, osUser, secret),
		"environment": environment,
	}
	body, _ := json.Marshal(request)
	resp, err := http.Post(baseURL+"/api/client/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("client auth login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client auth login status %d", resp.StatusCode)
	}
	var decoded clientAuthLoginForTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

func dialRuntimeAndReadLogin(t *testing.T, port int, runtime clientAuthLoginForTestResponse) protocol.LoginResponse {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial control: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := protocol.WritePacket(conn, protocol.LoginRequest{
		ClientName:      runtime.ClientName,
		ClientSessionID: runtime.ClientSessionID,
		AccessToken:     runtime.AccessToken,
		ConnectionRole:  protocol.ConnectionRoleControl,
	}); err != nil {
		t.Fatalf("write login: %v", err)
	}
	resp, ok := readPacket(t, bufio.NewReader(conn)).(protocol.LoginResponse)
	if !ok {
		t.Fatalf("expected LoginResponse, got %T", resp)
	}
	return resp
}

func signClientAuthForTest(apiKey, timestamp, nonce, machineFingerprint, osUser, secret string) string {
	key := sha256.Sum256([]byte(secret))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(apiKey + "\n" + timestamp + "\n" + nonce + "\n" + machineFingerprint + "\n" + osUser))
	return hex.EncodeToString(mac.Sum(nil))
}
