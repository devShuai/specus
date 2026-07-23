package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestObserveManagementHTTPLogsSafeRequestMetadata(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	app := &App{logger: slog.New(slog.NewTextHandler(&output, nil))}
	handler := app.observeManagementHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Pattern = "POST /api/public/transfer/attachments/{attachmentId}/presign-download"
		http.Error(w, "failed", http.StatusInternalServerError)
	}))
	request := httptest.NewRequest(http.MethodPost,
		"https://example.test/api/public/transfer/downloads/private-token?access_token=private-query", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	logged := output.String()
	if response.Code != http.StatusInternalServerError ||
		!strings.Contains(logged, "status=500") ||
		!strings.Contains(logged, "pattern=\"POST /api/public/transfer/attachments/{attachmentId}/presign-download\"") {
		t.Fatalf("unexpected response or log: status=%d log=%q", response.Code, logged)
	}
	if strings.Contains(logged, "private-token") || strings.Contains(logged, "private-query") {
		t.Fatalf("sensitive URL data leaked into log: %q", logged)
	}
}

func TestObserveManagementHTTPRecoversAndLogsPanic(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	app := &App{logger: slog.New(slog.NewTextHandler(&output, nil))}
	handler := app.observeManagementHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("test panic")
	}))
	request := httptest.NewRequest(http.MethodGet, "https://example.test/health", nil)
	request.Pattern = "GET /health"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	logged := output.String()
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	if !strings.Contains(logged, "management HTTP panic") ||
		!strings.Contains(logged, "panic=\"test panic\"") ||
		!strings.Contains(logged, "status=500") {
		t.Fatalf("panic was not fully logged: %q", logged)
	}
}
