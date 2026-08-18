package management

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestSemanticVersionComparisonFollowsSemVerPrecedence(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"1.0.1", "1.0.0", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0-alpha.2", "1.0.0-alpha.10", -1},
		{"1.0.0+one", "1.0.0+two", 0},
	}
	for _, test := range tests {
		left, err := parseSemanticVersion(test.left)
		if err != nil {
			t.Fatalf("parse %q: %v", test.left, err)
		}
		right, err := parseSemanticVersion(test.right)
		if err != nil {
			t.Fatalf("parse %q: %v", test.right, err)
		}
		got := compareSemanticVersions(left, right)
		if (got < 0 && test.want >= 0) || (got > 0 && test.want <= 0) || (got == 0 && test.want != 0) {
			t.Fatalf("compare %s to %s = %d, want sign %d", test.left, test.right, got, test.want)
		}
	}
	for _, invalid := range []string{"", "1", "1.0", "01.0.0", "1.0.0-01", "1.0.0+"} {
		if _, err := parseSemanticVersion(invalid); err == nil {
			t.Fatalf("invalid semantic version %q accepted", invalid)
		}
	}
}

func TestSelectLatestClientDownloadPrefersExactTargetAndSupportsAndroid(t *testing.T) {
	links := []store.ClientDownloadLink{
		hostedLinkForTest(1, "go", "any", "any", "9.0.0"),
		hostedLinkForTest(2, "go", "linux", "x64", "1.1.0"),
		hostedLinkForTest(3, "android", "android", "any", "2.0.0"),
	}
	if selected := selectLatestClientDownload(links, "go", "linux", "x64"); selected == nil || selected.ID != 2 {
		t.Fatalf("exact Go target not preferred: %+v", selected)
	}
	if selected := selectLatestClientDownload(links, "android", "android", "any"); selected == nil || selected.ID != 3 {
		t.Fatalf("Android universal package not selected: %+v", selected)
	}
}

func hostedLinkForTest(id int64, implementation, platform, arch, version string) store.ClientDownloadLink {
	return store.ClientDownloadLink{
		ID: id, Implementation: implementation, Platform: platform, Arch: arch, Version: version,
		Enabled: true, IsLatest: true, DownloadURL: clientPackageDownloadURL(id),
		SHA256: strings.Repeat("a", 64), FileSize: 1,
	}
}

func TestPublicDownloadRateLimiterIsBoundedAndResets(t *testing.T) {
	limiter := newPublicDownloadRateLimiter()
	now := time.Unix(1_000, 0)
	limiter.now = func() time.Time { return now }
	for index := 0; index < publicDownloadRequests; index++ {
		if allowed, _ := limiter.allow("203.0.113.10"); !allowed {
			t.Fatalf("request %d unexpectedly denied", index+1)
		}
	}
	if allowed, retry := limiter.allow("203.0.113.10"); allowed || retry <= 0 {
		t.Fatalf("request above limit allowed=%t retry=%s", allowed, retry)
	}
	if allowed, _ := limiter.allow("203.0.113.11"); !allowed {
		t.Fatal("one source exhausted another source's quota")
	}
	now = now.Add(publicDownloadWindowLength)
	if allowed, _ := limiter.allow("203.0.113.10"); !allowed {
		t.Fatal("source quota did not reset after the fixed window")
	}
}

func TestClientViewExposesOnlineSessionVersion(t *testing.T) {
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "client-version-view.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	version := "3.2.1"
	now := time.Now()
	account := store.ClientAccount{ID: 42, TenantID: "default", ClientName: "versioned-client",
		Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := db.InsertClientSession(context.Background(), store.ClientSession{
		ID: 1001, TenantID: "default", CredentialID: 1, IdentityID: 2, ClientID: account.ID,
		ClientName: account.ClientName, TokenHash: "hash", Status: "NETTY_ONLINE",
		MachineFingerprint: "machine", OSUser: "user", ClientVersion: &version,
		HTTPLoginAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	registry := session.NewRegistry()
	registry.Replace(clientVersionSession{name: account.ClientName})
	api := &API{db: db, sessions: registry, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	view := api.clientView(context.Background(), account)
	if !view.Online || view.ClientVersion == nil || *view.ClientVersion != version {
		t.Fatalf("client view did not expose active session version: %+v", view)
	}
}

type clientVersionSession struct{ name string }

func (session clientVersionSession) ClientName() string              { return session.name }
func (clientVersionSession) LoginTimeMs() int64                      { return 1 }
func (clientVersionSession) Send(protocol.Packet) error              { return nil }
func (clientVersionSession) Close(string)                            {}
