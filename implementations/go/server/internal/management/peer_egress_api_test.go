package management

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// The egress management routes answer a refused request with 4xx and its reason. They used to answer
// every refusal with 500 "服务器内部错误", so a page could only say the server failed.
func TestPeerEgressRoutesAnswerRefusalsWithTheirStatus(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "egress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	for _, user := range []store.ManagementUser{
		{Username: "alice", TenantID: "tenant-a", Role: store.ManagementRoleAdmin},
		{Username: "bob", TenantID: "tenant-a", Role: store.ManagementRoleUser},
	} {
		user.PasswordHash, user.Enabled, user.CreatedAt, user.UpdatedAt = "test-password-hash", true, now, now
		if _, err := db.InsertManagementUser(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	egress := store.ClientAccount{ID: 1002, TenantID: "tenant-a", OwnerUsername: "alice", ClientName: "office-gateway",
		PasswordHash: "unused", Enabled: true, ConnectionRateLimitPerMinute: 60, CreatedAt: now, UpdatedAt: now}
	if err := db.InsertClient(ctx, egress); err != nil {
		t.Fatal(err)
	}
	mesh := peermesh.New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", PublicAddress: "203.0.113.10",
		StunTurnPort: 3478, SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	tokens := security.NewLocalTokenService(config.AuthConfig{JwtSecret: "egress-test-secret"})
	api := NewAPI(db, session.NewRegistry(), tokens, nil, nil, nil,
		config.OidcConfig{}, config.AuthConfig{JwtSecret: "egress-test-secret"},
		config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, mesh, nil, nil, nil, nil)
	mux := http.NewServeMux()
	api.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	admin := tokens.IssueForUser("alice", "tenant-a", store.ManagementRoleAdmin)
	user := tokens.IssueForUser("bob", "tenant-a", store.ManagementRoleUser)

	expect := func(name, method, path, token string, body any, status int, message string) {
		t.Helper()
		response := diagramRequest(t, server, method, path, token, body)
		defer response.Body.Close()
		payload, _ := io.ReadAll(response.Body)
		if response.StatusCode != status || (message != "" && !strings.Contains(string(payload), message)) {
			t.Errorf("%s: %d %s, want %d containing %q", name, response.StatusCode, payload, status, message)
		}
	}
	policies := "/api/admin/peer-mesh/egress/policies"
	expect("switch without enabled", http.MethodPut, "/api/admin/peer-mesh/egress/switch", admin, map[string]any{}, http.StatusBadRequest, "enabled is required")
	expect("switch by a user", http.MethodPut, "/api/admin/peer-mesh/egress/switch", user, map[string]any{"enabled": true}, http.StatusForbidden, "ADMIN")
	expect("policy by a user", http.MethodPost, policies, user, map[string]any{"egressClientId": egress.ID}, http.StatusForbidden, "ADMIN")
	expect("bad scope", http.MethodPost, policies, admin, map[string]any{"egressClientId": egress.ID, "scope": "WORLD"}, http.StatusBadRequest, "invalid scope")
	expect("host bits set", http.MethodPost, policies, admin, map[string]any{"egressClientId": egress.ID,
		"destinationRules": []map[string]any{{"cidr": "203.0.113.1/24", "protocols": []string{"tcp"}, "portRanges": [][]int{{443, 443}}}}},
		http.StatusBadRequest, "destinationRules[0].cidr")
	expect("unknown client", http.MethodPost, policies, admin, map[string]any{"egressClientId": 999999}, http.StatusNotFound, "")
	expect("unknown policy", http.MethodDelete, policies+"/"+strconv.Itoa(424242), admin, nil, http.StatusNotFound, "")
	expect("valid policy", http.MethodPost, policies, admin, map[string]any{"egressClientId": egress.ID,
		"destinationRules": []map[string]any{{"cidr": " 203.0.113.0/24 ", "protocols": []string{"TCP"}, "portRanges": [][]int{{443, 443}}}}},
		http.StatusOK, `"protocols":["tcp"]`)
	expect("address as a domain rule", http.MethodPost, policies, admin, map[string]any{"egressClientId": egress.ID,
		"domainRules": []map[string]any{{"match": "203.0.113.5", "protocols": []string{"tcp"}, "portRanges": [][]int{{443, 443}}}}},
		http.StatusBadRequest, "domainRules[0].match")
	expect("valid domain rule", http.MethodPost, policies, admin, map[string]any{"egressClientId": egress.ID,
		"domainRules": []map[string]any{{"match": " *.CDN.Example. ", "protocols": []string{"UDP"}, "portRanges": [][]int{{443, 443}}}}},
		http.StatusOK, `"domainRules":[{"match":"*.cdn.example","protocols":["udp"],"portRanges":[[443,443]]}]`)
	expect("domain rules kept when omitted", http.MethodPost, policies, admin, map[string]any{"egressClientId": egress.ID,
		"scope": "LAN"}, http.StatusOK, `"domainRules":[{"match":"*.cdn.example"`)
}
