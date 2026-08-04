package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func newDiagramTestServer(t *testing.T) (*httptest.Server, *security.LocalTokenService) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "diagrams.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now()
	for _, user := range []store.ManagementUser{
		{Username: "alice", TenantID: "tenant-a"},
		{Username: "bob", TenantID: "tenant-a"},
		{Username: "carol", TenantID: "tenant-b"},
	} {
		user.PasswordHash = "test-password-hash"
		user.Role = store.ManagementRoleUser
		user.Enabled = true
		user.CreatedAt = now
		user.UpdatedAt = now
		if err := db.InsertManagementUser(context.Background(), user); err != nil {
			t.Fatal(err)
		}
	}
	tokens := security.NewLocalTokenService(config.AuthConfig{JwtSecret: "diagram-test-secret"})
	api := NewAPI(db, session.NewRegistry(), tokens, nil, nil, nil,
		config.OidcConfig{}, config.AuthConfig{JwtSecret: "diagram-test-secret"},
		config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	api.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, tokens
}

func diagramRequest(t *testing.T, server *httptest.Server, method, path, token string,
	body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return response
}

func decodeDiagramResponse[T any](t *testing.T, response *http.Response, wantStatus int) T {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want %d; body=%s", response.StatusCode, wantStatus, payload)
	}
	var decoded T
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

func expectDiagramStatus(t *testing.T, response *http.Response, wantStatus int) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		payload, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want %d; body=%s", response.StatusCode, wantStatus, payload)
	}
}

func TestDiagramDocumentCRUD(t *testing.T) {
	server, tokens := newDiagramTestServer(t)
	token := tokens.IssueForUser("alice", "tenant-a", "USER")
	snapshot := base64.StdEncoding.EncodeToString([]byte("diagram-payload"))

	created := decodeDiagramResponse[diagramDocumentView](t,
		diagramRequest(t, server, http.MethodPost, "/api/admin/diagrams", token,
			diagramDocumentMutation{Name: "流程图一", Update: snapshot}),
		http.StatusCreated)
	if created.Name != "流程图一" || created.Revision != 0 ||
		created.SizeBytes != int64(len("diagram-payload")) || created.CreatedAt == "" {
		t.Fatalf("unexpected created view: %+v", created)
	}
	path := "/api/admin/diagrams/" + strconv.FormatInt(created.ID, 10)

	listed := decodeDiagramResponse[[]diagramDocumentView](t,
		diagramRequest(t, server, http.MethodGet, "/api/admin/diagrams", token, nil), http.StatusOK)
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("unexpected list: %+v", listed)
	}

	detail := decodeDiagramResponse[diagramDocumentDetail](t,
		diagramRequest(t, server, http.MethodGet, path, token, nil), http.StatusOK)
	if detail.Update != snapshot || detail.Document.ID != created.ID {
		t.Fatalf("unexpected detail: %+v", detail)
	}

	staleRevision := int64(7)
	expectDiagramStatus(t,
		diagramRequest(t, server, http.MethodPut, path, token,
			diagramDocumentMutation{Name: "流程图二", Update: snapshot, Revision: &staleRevision}),
		http.StatusConflict)

	revision := int64(0)
	updated := decodeDiagramResponse[diagramDocumentView](t,
		diagramRequest(t, server, http.MethodPut, path, token,
			diagramDocumentMutation{Name: "流程图二", Update: snapshot, Revision: &revision}),
		http.StatusOK)
	if updated.Name != "流程图二" || updated.Revision != 1 {
		t.Fatalf("unexpected updated view: %+v", updated)
	}

	expectDiagramStatus(t, diagramRequest(t, server, http.MethodDelete, path, token, nil),
		http.StatusNoContent)
	expectDiagramStatus(t, diagramRequest(t, server, http.MethodGet, path, token, nil),
		http.StatusNotFound)
}

func TestDiagramDocumentTenantAndOwnerVisibility(t *testing.T) {
	server, tokens := newDiagramTestServer(t)
	alice := tokens.IssueForUser("alice", "tenant-a", "USER")
	bob := tokens.IssueForUser("bob", "tenant-a", "USER")
	carol := tokens.IssueForUser("carol", "tenant-b", "USER")
	snapshot := base64.StdEncoding.EncodeToString([]byte("diagram-payload"))

	created := decodeDiagramResponse[diagramDocumentView](t,
		diagramRequest(t, server, http.MethodPost, "/api/admin/diagrams", alice,
			diagramDocumentMutation{Name: "私有流程图", Update: snapshot}),
		http.StatusCreated)
	path := "/api/admin/diagrams/" + strconv.FormatInt(created.ID, 10)

	for _, outsider := range []string{bob, carol} {
		listed := decodeDiagramResponse[[]diagramDocumentView](t,
			diagramRequest(t, server, http.MethodGet, "/api/admin/diagrams", outsider, nil),
			http.StatusOK)
		if len(listed) != 0 {
			t.Fatalf("outsider must not see the document: %+v", listed)
		}
		expectDiagramStatus(t, diagramRequest(t, server, http.MethodGet, path, outsider, nil),
			http.StatusNotFound)
		revision := int64(0)
		expectDiagramStatus(t,
			diagramRequest(t, server, http.MethodPut, path, outsider,
				diagramDocumentMutation{Name: "劫持", Update: snapshot, Revision: &revision}),
			http.StatusNotFound)
		expectDiagramStatus(t, diagramRequest(t, server, http.MethodDelete, path, outsider, nil),
			http.StatusNotFound)
	}

	expectDiagramStatus(t, diagramRequest(t, server, http.MethodGet, "/api/admin/diagrams", "", nil),
		http.StatusUnauthorized)
}

func TestDiagramDocumentRejectsInvalidSnapshot(t *testing.T) {
	server, tokens := newDiagramTestServer(t)
	token := tokens.IssueForUser("alice", "tenant-a", "USER")
	expectDiagramStatus(t,
		diagramRequest(t, server, http.MethodPost, "/api/admin/diagrams", token,
			diagramDocumentMutation{Name: "bad", Update: "not-base64!!"}),
		http.StatusBadRequest)
	expectDiagramStatus(t,
		diagramRequest(t, server, http.MethodPost, "/api/admin/diagrams", token,
			diagramDocumentMutation{Name: "", Update: base64.StdEncoding.EncodeToString([]byte("x"))}),
		http.StatusBadRequest)
}
