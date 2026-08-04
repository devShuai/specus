package media

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

func TestRustFSStorageMultipartAndRangeRequests(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		requests []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=access/") {
			t.Errorf("missing SigV4 authorization: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-amz-content-sha256") == "" || r.Header.Get("x-amz-date") == "" {
			t.Errorf("missing SigV4 headers")
		}
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.RequestURI()+" range="+r.Header.Get("Range"))
		mu.Unlock()
		switch {
		case r.Method == http.MethodHead && r.URL.Path == "/media":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && r.URL.Query().Get("partNumber") == "1":
			w.Header().Set("ETag", `"part-1"`)
		case r.Method == http.MethodPost && r.URL.Query().Get("uploadId") == "upload-1":
			_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>"object"</ETag></CompleteMultipartUploadResult>`)
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusPartialContent)
			_, _ = io.WriteString(w, "bcd")
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	storage := NewRustFSStorage(config.MediaCaptureConfig{
		Enabled: true, Endpoint: server.URL, Region: "us-east-1", Bucket: "media",
		AccessKeyID: "access", AccessKeySecret: "secret", PathStyle: true,
	})
	if err := storage.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	upload, err := storage.BeginMultipart(context.Background(), "tenant/video file.mp4", "video/mp4", "")
	if err != nil {
		t.Fatalf("BeginMultipart: %v", err)
	}
	part, err := storage.UploadPart(context.Background(), upload, 1, []byte("abcdef"))
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}
	if _, err := storage.CompleteMultipart(context.Background(), upload, []CompletedPart{part}); err != nil {
		t.Fatalf("CompleteMultipart: %v", err)
	}
	input, err := storage.Open(context.Background(), upload.ObjectKey, 1, 3)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, _ := io.ReadAll(input)
	_ = input.Close()
	if string(data) != "bcd" {
		t.Fatalf("range body = %q", data)
	}
	if err := storage.Delete(context.Background(), upload.ObjectKey); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	mu.Lock()
	joined := strings.Join(requests, "\n")
	mu.Unlock()
	if !strings.Contains(joined, "/media/tenant/video%20file.mp4") ||
		!strings.Contains(joined, "range=bytes=1-3") {
		t.Fatalf("unexpected request targets:\n%s", joined)
	}
}

func TestRustFSStorageIncompleteConfigurationIsDisabled(t *testing.T) {
	t.Parallel()
	storage := NewRustFSStorage(config.MediaCaptureConfig{Enabled: true, Endpoint: "http://127.0.0.1:1"})
	if err := storage.Initialize(context.Background()); err != nil {
		t.Fatalf("incomplete config must be a no-op: %v", err)
	}
	if storage.Ready() {
		t.Fatal("incomplete media storage configuration became ready")
	}
}

func TestRustFSStorageRejectsHTTP200EmbeddedCompleteError(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<Error><Code>InternalError</Code><Message>assembly failed</Message></Error>`)
	}))
	defer server.Close()
	storage := NewRustFSStorage(config.MediaCaptureConfig{
		Enabled: true, Endpoint: server.URL, Region: "us-east-1", Bucket: "media",
		AccessKeyID: "access", AccessKeySecret: "secret", PathStyle: true,
	})
	if err := storage.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := storage.CompleteMultipart(context.Background(),
		MultipartUpload{ObjectKey: "movie.mp4", UploadID: "upload-1"},
		[]CompletedPart{{PartNumber: 1, ETag: `"part"`}})
	if err == nil || !strings.Contains(err.Error(), "InternalError") {
		t.Fatalf("embedded completion error = %v", err)
	}
}

func TestRustFSStorageRejectsCompleteResponseWithoutETag(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Location>/media/movie.mp4</Location></CompleteMultipartUploadResult>`)
	}))
	defer server.Close()
	storage := NewRustFSStorage(config.MediaCaptureConfig{
		Enabled: true, Endpoint: server.URL, Region: "us-east-1", Bucket: "media",
		AccessKeyID: "access", AccessKeySecret: "secret", PathStyle: true,
	})
	if err := storage.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := storage.CompleteMultipart(context.Background(),
		MultipartUpload{ObjectKey: "movie.mp4", UploadID: "upload-1"},
		[]CompletedPart{{PartNumber: 1, ETag: `"part"`}})
	if err == nil || !strings.Contains(err.Error(), "did not contain an ETag") {
		t.Fatalf("missing ETag error = %v", err)
	}
}

func TestRustFSStorageRejectsIgnoredRange(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "complete-object")
	}))
	defer server.Close()
	storage := NewRustFSStorage(config.MediaCaptureConfig{
		Enabled: true, Endpoint: server.URL, Region: "us-east-1", Bucket: "media",
		AccessKeyID: "access", AccessKeySecret: "secret", PathStyle: true,
	})
	if err := storage.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	input, err := storage.Open(context.Background(), "movie.mp4", 4, 7)
	if input != nil {
		_ = input.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "ignored requested byte range") {
		t.Fatalf("ignored range error = %v", err)
	}
}
