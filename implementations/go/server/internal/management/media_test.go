package management

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/media"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

type manifestTestStorage struct{ objects map[string][]byte }

func (*manifestTestStorage) Ready() bool { return true }
func (*manifestTestStorage) BeginMultipart(context.Context, string, string, string) (media.MultipartUpload, error) {
	return media.MultipartUpload{}, nil
}
func (*manifestTestStorage) UploadPart(context.Context, media.MultipartUpload, int, []byte) (media.CompletedPart, error) {
	return media.CompletedPart{}, nil
}
func (*manifestTestStorage) CompleteMultipart(context.Context, media.MultipartUpload, []media.CompletedPart) (string, error) {
	return "", nil
}
func (*manifestTestStorage) AbortMultipart(context.Context, media.MultipartUpload) error { return nil }
func (s *manifestTestStorage) Open(_ context.Context, key string, start, end int64) (io.ReadCloser, error) {
	data := s.objects[key]
	if start >= 0 && end >= start {
		data = data[start : end+1]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func (s *manifestTestStorage) ReadAll(_ context.Context, key string, _ int64) ([]byte, error) {
	return append([]byte(nil), s.objects[key]...), nil
}
func (s *manifestTestStorage) Delete(context.Context, string) error { return nil }

func TestAdminNestedManifestUsesNestedCaptureAsAssetAnchor(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "nested-media.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if err := db.InsertClient(context.Background(), store.ClientAccount{
		ID: 1, TenantID: "tenant-a", OwnerUsername: "alice", ClientName: "client-a",
		PasswordHash: "hash", Enabled: true, ConnectionRateLimitPerMinute: 60,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertManagementUser(context.Background(), store.ManagementUser{
		Username: "alice", TenantID: "tenant-a", PasswordHash: "test-password-hash",
		Role: store.ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	storage := &manifestTestStorage{objects: map[string][]byte{
		"master": []byte("#EXTM3U\nchild.m3u8\n"),
		"child":  []byte("#EXTM3U\nsegment.ts\n#EXT-X-ENDLIST\n"),
	}}
	insert := func(source, key string, size int64) store.HTTPMediaCapture {
		capture := store.HTTPMediaCapture{
			TenantID: "tenant-a", ClientID: 1, ClientName: "client-a", Route: "media",
			SourceURL: source, ResourceKey: key, Method: "GET", StatusCode: 200,
			MediaKind: media.KindHLSManifest, CapturedBytes: size, ObjectKey: key,
			State: media.StateComplete, CapturedAt: now, CompletedAt: &now, ExpiresAt: now.Add(time.Hour),
		}
		if err := db.InsertHTTPMediaCapture(context.Background(), &capture); err != nil {
			t.Fatal(err)
		}
		return capture
	}
	anchor := insert("/master.m3u8", "master", int64(len(storage.objects["master"])))
	target := insert("/child.m3u8", "child", int64(len(storage.objects["child"])))

	authCfg := config.AuthConfig{JwtSecret: "media-test-secret"}
	tokens := security.NewLocalTokenService(authCfg)
	api := NewAPI(db, session.NewRegistry(), tokens, nil, nil, nil, config.OidcConfig{}, authCfg,
		config.ClientAuthConfig{}, config.TrafficConfig{}, nil, nil, nil, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	mediaCfg := config.Default().MediaCapture
	mediaCfg.Enabled = true
	mediaService := media.NewService(db, mediaCfg, storage, nil)
	api.SetMediaCapture(mediaService)
	mux := http.NewServeMux()
	api.Register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()

	requestURL := server.URL + "/api/admin/traffic/media-captures/" + strconv.FormatInt(anchor.ID, 10) +
		"/asset?url=" + url.QueryEscape(target.SourceURL)
	request, _ := http.NewRequest(http.MethodGet, requestURL, nil)
	request.Header.Set("Authorization", "Bearer "+tokens.IssueForUser("alice", "tenant-a", "USER"))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	expectedBase := "/api/admin/traffic/media-captures/" + strconv.FormatInt(target.ID, 10) + "/asset"
	if !bytes.Contains(body, []byte(expectedBase+"?url=%2Fsegment.ts")) {
		t.Fatalf("nested manifest did not use target id %d as anchor: %s", target.ID, body)
	}

	ticket, err := mediaService.CreateTicket(context.Background(), target, false)
	if err != nil {
		t.Fatalf("create manifest ticket: %v", err)
	}
	headRequest := httptest.NewRequest(http.MethodHead, ticket.ManifestURL, nil)
	headResponse := httptest.NewRecorder()
	mux.ServeHTTP(headResponse, headRequest)
	if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 ||
		headResponse.Header().Get("Content-Length") == "0" {
		t.Fatalf("public HEAD response status=%d body=%q length=%q",
			headResponse.Code, headResponse.Body.String(), headResponse.Header().Get("Content-Length"))
	}
}
