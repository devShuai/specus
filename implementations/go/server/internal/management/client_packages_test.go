package management

import (
	"context"
	"io"
	"log/slog"
	"os"
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

func TestClientDownloadMutationRequiresVersionedConsistentLatestMetadata(t *testing.T) {
	enabled := true
	latest := true
	sha256 := strings.Repeat("a", 64)
	fileSize := int64(1)
	base := clientDownloadLinkMutation{
		Implementation: "go", Platform: "linux", Arch: "x64",
		DisplayName: "Go Linux", DownloadURL: "https://example.test/client.tar.gz",
		SHA256: &sha256, FileSize: &fileSize, Enabled: &enabled,
	}
	for name, mutate := range map[string]func(*clientDownloadLinkMutation){
		"latest without version": func(request *clientDownloadLinkMutation) {
			request.IsLatest = &latest
		},
		"minimum without version": func(request *clientDownloadLinkMutation) {
			request.MinSupportedVersion = "1.0.0"
		},
		"minimum newer than release": func(request *clientDownloadLinkMutation) {
			request.Version = "1.0.0"
			request.MinSupportedVersion = "1.1.0"
		},
		"android implementation on desktop platform": func(request *clientDownloadLinkMutation) {
			request.Implementation = "android"
			request.Platform = "linux"
			request.Arch = "any"
		},
		"android implementation with concrete architecture": func(request *clientDownloadLinkMutation) {
			request.Implementation = "android"
			request.Platform = "android"
			request.Arch = "arm64"
		},
		"android platform with non-android implementation": func(request *clientDownloadLinkMutation) {
			request.Implementation = "go"
			request.Platform = "android"
			request.Arch = "any"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			link := store.ClientDownloadLink{Enabled: true}
			if err := applyClientDownloadLinkMutation(&link, request); err == nil {
				t.Fatal("invalid catalogue metadata was accepted")
			}
		})
	}

	request := base
	request.Version = "v1.2.0"
	request.MinSupportedVersion = "v1.1.0"
	request.IsLatest = &latest
	link := store.ClientDownloadLink{Enabled: true}
	if err := applyClientDownloadLinkMutation(&link, request); err != nil {
		t.Fatalf("valid versioned latest rejected: %v", err)
	}
	if link.Version == nil || *link.Version != "1.2.0" || link.MinSupportedVersion == nil ||
		*link.MinSupportedVersion != "1.1.0" || !link.IsLatest {
		t.Fatalf("version metadata was not normalized: %+v", link)
	}
}

func TestEnsureClientPackageDirectoryRejectsSymlink(t *testing.T) {
	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "packages")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are unavailable on this platform: %v", err)
	}
	api := &API{packageDirectory: link}
	if _, err := api.ensureClientPackageDirectory(); err == nil {
		t.Fatal("symlinked package directory was accepted")
	}
	if _, err := api.clientPackagePath(1); err == nil {
		t.Fatal("client package path followed a symlinked package directory")
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

func TestPublicCatalogDoesNotResurrectLegacyLinkWhenVersionedTargetIsDisabled(t *testing.T) {
	legacy := store.ClientDownloadLink{
		ID: 1, Implementation: "GO", Platform: " linux ", Arch: "X64",
		Version: nil, Enabled: true, DownloadURL: "https://example.com/legacy",
	}
	versioned := hostedLinkForTest(2, "go", "linux", "x64", "2.0.0")
	versioned.Enabled = false
	versioned.IsLatest = false
	if visible := publicClientDownloadLinks([]store.ClientDownloadLink{legacy, versioned}); len(visible) != 0 {
		t.Fatalf("disabled versioned target resurrected legacy link: %+v", visible)
	}
	versioned.Enabled = true
	versioned.IsLatest = true
	visible := publicClientDownloadLinks([]store.ClientDownloadLink{legacy, versioned})
	if len(visible) != 1 || visible[0].ID != versioned.ID {
		t.Fatalf("public catalog did not expose only latest version: %+v", visible)
	}
}

func TestSelectLatestClientDownloadAcceptsVerifiedExternalLatestAndIgnoresUnpublishedVersions(t *testing.T) {
	external := store.ClientDownloadLink{
		ID: 1, Implementation: "go", Platform: "linux", Arch: "x64", Version: managementVersion("99.0.0"),
		Enabled: true, IsLatest: true, DownloadURL: "https://example.com/untrusted.zip",
		SHA256: strings.Repeat("a", 64), FileSize: 1,
	}
	older := hostedLinkForTest(2, "go", "linux", "x64", "1.0.0")
	newer := hostedLinkForTest(3, "go", "linux", "x64", "1.1.0")
	older.IsLatest = false
	newer.IsLatest = false
	selected := selectLatestClientDownload([]store.ClientDownloadLink{external, older, newer}, "go", "linux", "x64")
	if selected == nil || selected.ID != external.ID {
		t.Fatalf("version check did not select authoritative external latest: %+v", selected)
	}
	external.IsLatest = false
	if selected := selectLatestClientDownload([]store.ClientDownloadLink{external, older, newer}, "go", "linux", "x64"); selected != nil {
		t.Fatalf("version check selected an unpublished version: %+v", selected)
	}
}

func TestExternalClientDistributionRequiresStrictURLAndAuthoritativeMetadata(t *testing.T) {
	valid := store.ClientDownloadLink{
		ID: 1, DownloadURL: "https://github.com/devShuai/specus/releases/download/v1/specus.zip",
		SHA256: strings.Repeat("a", 64), FileSize: 1,
	}
	if !isInstallableClientDistribution(valid) || isHostedClientPackage(valid) {
		t.Fatalf("valid external package classification is wrong: %+v", valid)
	}
	for _, invalid := range []store.ClientDownloadLink{
		{ID: 1, DownloadURL: "http://example.test/client.zip", SHA256: valid.SHA256, FileSize: 1},
		{ID: 1, DownloadURL: "https://user@example.test/client.zip", SHA256: valid.SHA256, FileSize: 1},
		{ID: 1, DownloadURL: "https://example.test/client.zip?token=x", SHA256: valid.SHA256, FileSize: 1},
		{ID: 1, DownloadURL: "https://example.test/client.zip#part", SHA256: valid.SHA256, FileSize: 1},
		{ID: 1, DownloadURL: "https://example.test/client.zip", SHA256: "bad", FileSize: 1},
		{ID: 1, DownloadURL: "https://example.test/client.zip", SHA256: valid.SHA256, FileSize: 0},
	} {
		if isInstallableClientDistribution(invalid) {
			t.Fatalf("invalid external package was installable: %+v", invalid)
		}
	}
}

func TestAndroidClientPackageDownloadNameAppendsAPKOnce(t *testing.T) {
	link := store.ClientDownloadLink{Implementation: "android", Platform: "android", Arch: "any"}
	link.DisplayName = "specus-client-android-2.0.0"
	if got := clientPackageDownloadName(link); got != "specus-client-android-2.0.0.apk" {
		t.Fatalf("download name without extension = %q", got)
	}
	link.DisplayName = "specus-client-android-2.0.0.APK"
	if got := clientPackageDownloadName(link); got != link.DisplayName {
		t.Fatalf("download name duplicated APK extension: %q", got)
	}
}

func hostedLinkForTest(id int64, implementation, platform, arch, version string) store.ClientDownloadLink {
	return store.ClientDownloadLink{
		ID: id, Implementation: implementation, Platform: platform, Arch: arch, Version: managementVersion(version),
		Enabled: true, IsLatest: true, DownloadURL: clientPackageDownloadURL(id),
		SHA256: strings.Repeat("a", 64), FileSize: 1,
	}
}

func managementVersion(value string) *string { return &value }

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

func (session clientVersionSession) ClientName() string { return session.name }
func (clientVersionSession) LoginTimeMs() int64         { return 1 }
func (clientVersionSession) Send(protocol.Packet) error { return nil }
func (clientVersionSession) Close(string)               {}
