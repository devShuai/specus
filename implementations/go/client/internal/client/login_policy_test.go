package client

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

func TestLoginFailureClassification(t *testing.T) {
	for _, code := range []int{400, 401, 403, 409} {
		failure := loginStatusFailure(code, "120")
		if failure.Retryable || ExitCode(failure) != 3 {
			t.Fatalf("wrong permanent classification: %+v", failure)
		}
	}
	for _, code := range []int{408, 425, 429, 500, 502, 503, 504} {
		if !loginStatusFailure(code, "").Retryable {
			t.Fatalf("must retry %d", code)
		}
	}
	if loginStatusFailure(429, "120").RetryAfter != 120*time.Second {
		t.Fatal("Retry-After ignored")
	}
	if loginStatusFailure(302, "").Retryable {
		t.Fatal("redirect must not repeat credentials")
	}
}

func TestInitialLoginCancellationDoesNotBecomeTimeout(t *testing.T) {
	c := New(Config{ServerBaseURL: "http://127.0.0.1:1", APIKey: "test", Secret: "test"}, log.New(io.Discard, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.login(ctx)
	if err != context.Canceled {
		t.Fatalf("cancelled startup: %v", err)
	}
}

func TestDiagnosticSnapshotProjectsNoCredentials(t *testing.T) {
	c := New(Config{}, log.New(io.Discard, "", 0))
	c.peerMesh.peers = map[int64]*peerMeshPeer{2: {ClientID: 2, ClientName: "peer", VirtualIP: "100.96.0.2", Online: true, PublicKey: "DO_NOT_PRINT_KEY"}}
	c.peerMesh.services = &peerServiceRuntime{roster: map[int64]peerServiceRosterHint{2: {virtualIP: "100.96.0.2", online: true}},
		catalogs: map[peerServiceCatalogKey]peerServiceCatalogSnapshot{{2, 1}: {publisherClientID: 2, publisherClientName: "peer", expiresAt: time.Now().Add(time.Minute),
			services: []peerAdvertisedService{{ServiceID: "web", Name: "web", Application: "http", Transport: "tcp", PublishedPort: 8080, Description: "DO_NOT_PRINT_DESCRIPTION"}}}}}
	c.diagnosticControl.Store(true)
	c.diagnosticReady.Store(true)
	data := c.DiagnosticSnapshot()
	encoded, _ := json.Marshal(data)
	if strings.Contains(string(encoded), "DO_NOT_PRINT") || !strings.Contains(string(encoded), "100.96.0.2") || !strings.Contains(string(encoded), "8080") {
		t.Fatalf("wrong safe view: %s", encoded)
	}
}
