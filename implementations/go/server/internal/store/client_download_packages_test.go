package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientDownloadCatalogCompatibilityMigrationBackfillsUniqueVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-client-downloads.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE client_download_link (
		id INTEGER PRIMARY KEY,
		implementation TEXT NOT NULL,
		platform TEXT NOT NULL,
		arch TEXT NOT NULL,
		display_name TEXT NOT NULL,
		download_url TEXT NOT NULL,
		description TEXT,
		display_order INTEGER NOT NULL DEFAULT 0,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)
	if err == nil {
		_, err = legacy.Exec(`INSERT INTO client_download_link
			(id, implementation, platform, arch, display_name, download_url, description,
			 display_order, enabled, created_at, updated_at)
			VALUES
			(101, 'go', 'linux', 'x64', 'legacy one', 'https://example.com/one', NULL, 0, 1,
			 '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z'),
			(102, 'go', 'linux', 'x64', 'legacy two', 'https://example.com/two', NULL, 1, 1,
			 '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z')`)
	}
	if closeErr := legacy.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("upgrade legacy client catalog: %v", err)
	}
	defer db.Close()
	links, err := db.ListClientDownloadLinks(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 || links[0].Version == links[1].Version ||
		!strings.HasPrefix(links[0].Version, "0.0.0-legacy.") ||
		!strings.HasPrefix(links[1].Version, "0.0.0-legacy.") {
		t.Fatalf("legacy versions were not uniquely backfilled: %+v", links)
	}
	for _, column := range []string{"version", "sha256", "file_size", "is_latest", "changelog_url", "min_supported_version"} {
		exists, err := db.columnExists("client_download_link", column)
		if err != nil || !exists {
			t.Fatalf("column %s missing: exists=%t err=%v", column, exists, err)
		}
	}
	var uniqueIndex int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index' AND name = 'uq_client_download_target_version'`).Scan(&uniqueIndex); err != nil || uniqueIndex != 1 {
		t.Fatalf("catalog unique index missing: count=%d err=%v", uniqueIndex, err)
	}
}

func TestClientDownloadLatestSwitchIsAtomicAndTargetScoped(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "client-downloads.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	items := []ClientDownloadLink{
		{ID: 1, Implementation: "go", Platform: "linux", Arch: "x64", Version: "1.0.0",
			DisplayName: "one", DownloadURL: "https://example.com/one", Enabled: true, IsLatest: true,
			CreatedAt: now, UpdatedAt: now},
		{ID: 2, Implementation: "go", Platform: "linux", Arch: "x64", Version: "1.1.0",
			DisplayName: "two", DownloadURL: "https://example.com/two", Enabled: true, IsLatest: true,
			CreatedAt: now, UpdatedAt: now},
		{ID: 3, Implementation: "android", Platform: "android", Arch: "any", Version: "1.0.0",
			DisplayName: "apk", DownloadURL: "https://example.com/app.apk", Enabled: true, IsLatest: true,
			CreatedAt: now, UpdatedAt: now},
	}
	for _, item := range items {
		if err := db.InsertClientDownloadLink(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	links, err := db.ListClientDownloadLinks(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	latest := map[int64]bool{}
	for _, item := range links {
		latest[item.ID] = item.IsLatest
	}
	if latest[1] || !latest[2] || !latest[3] {
		t.Fatalf("latest flags are not target scoped: %#v", latest)
	}
	if _, err := db.SetClientDownloadLinkLatest(context.Background(), 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	links, _ = db.ListClientDownloadLinks(context.Background(), false)
	latest = map[int64]bool{}
	for _, item := range links {
		latest[item.ID] = item.IsLatest
	}
	if !latest[1] || latest[2] || !latest[3] {
		t.Fatalf("explicit latest switch failed: %#v", latest)
	}
}
