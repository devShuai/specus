package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
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
	if len(links) != 2 || links[0].Version != nil || links[1].Version != nil {
		t.Fatalf("legacy versions were not preserved as NULL: %+v", links)
	}
	for _, column := range []string{"version", "sha256", "file_size", "is_latest", "latest_slot", "changelog_url", "min_supported_version"} {
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
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index' AND name = 'uq_client_download_latest_slot'`).Scan(&uniqueIndex); err != nil || uniqueIndex != 1 {
		t.Fatalf("catalog latest-slot unique index missing: count=%d err=%v", uniqueIndex, err)
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
		{ID: 1, Implementation: "go", Platform: "linux", Arch: "x64", Version: storeVersion("1.0.0"),
			DisplayName: "one", DownloadURL: "https://example.com/one", Enabled: true, IsLatest: true,
			CreatedAt: now, UpdatedAt: now},
		{ID: 2, Implementation: "go", Platform: "linux", Arch: "x64", Version: storeVersion("1.1.0"),
			DisplayName: "two", DownloadURL: "https://example.com/two", Enabled: true, IsLatest: true,
			CreatedAt: now, UpdatedAt: now},
		{ID: 3, Implementation: "android", Platform: "android", Arch: "any", Version: storeVersion("1.0.0"),
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

func TestClientDownloadLatestInvariantRejectsDisabledAndMigrationRepairsLegacyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disabled-latest.db")
	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	disabledLatest := ClientDownloadLink{
		ID: 9, Implementation: "go", Platform: "linux", Arch: "x64", Version: storeVersion("1.0.0"),
		DisplayName: "disabled", DownloadURL: "https://example.com/disabled", Enabled: false,
		IsLatest: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.InsertClientDownloadLink(context.Background(), disabledLatest); !errors.Is(err, ErrClientDownloadDisabled) {
		t.Fatalf("disabled latest insert error = %v", err)
	}
	// Simulate a partially upgraded/externally edited legacy database that violates the invariant.
	if _, err := db.sql.Exec(`INSERT INTO client_download_link
		(id, implementation, platform, arch, version, display_name, download_url, description,
		 sha256, file_size, is_latest, latest_slot, changelog_url, min_supported_version,
		 display_order, enabled, created_at, updated_at)
		VALUES (9, 'go', 'linux', 'x64', '1.0.0', 'disabled', 'https://example.com/disabled', NULL,
		 '', 0, 1, 'go|linux|x64', NULL, NULL, 0, 0, ?, ?)`, formatTime(now), formatTime(now)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen and repair disabled latest: %v", err)
	}
	defer db.Close()
	link, err := db.GetClientDownloadLink(context.Background(), 9)
	if err != nil {
		t.Fatal(err)
	}
	if link.Enabled || link.IsLatest {
		t.Fatalf("disabled latest invariant was not repaired: %+v", link)
	}
	var latestSlot sql.NullString
	if err := db.sql.QueryRow(`SELECT latest_slot FROM client_download_link WHERE id = 9`).Scan(&latestSlot); err != nil {
		t.Fatal(err)
	}
	if latestSlot.Valid {
		t.Fatalf("disabled latest slot was not cleared: %q", latestSlot.String)
	}
}

func TestClientDownloadMigrationNormalizesVersionsAndClearsInvalidLatestRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-null-version.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE client_download_link (
		id INTEGER PRIMARY KEY,
		implementation TEXT NOT NULL,
		platform TEXT NOT NULL,
		arch TEXT NOT NULL,
		version TEXT NOT NULL,
		display_name TEXT NOT NULL,
		download_url TEXT NOT NULL,
		description TEXT,
		sha256 TEXT NOT NULL DEFAULT '',
		file_size INTEGER NOT NULL DEFAULT 0,
		is_latest INTEGER NOT NULL DEFAULT 0,
		latest_slot TEXT,
		changelog_url TEXT,
		min_supported_version TEXT,
		display_order INTEGER NOT NULL DEFAULT 0,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)
	if err == nil {
		_, err = legacy.Exec(`INSERT INTO client_download_link
			(id, implementation, platform, arch, version, display_name, download_url,
			 is_latest, latest_slot, enabled, created_at, updated_at)
			VALUES
			(1, 'go', 'linux', 'arm64', '0.0.0-legacy.1', 'synthetic', 'https://example.com/1',
			 1, 'go|linux|arm64', 1, '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z'),
			(2, 'go', 'linux', 'x64', 'v1.2.3', 'published', 'https://example.com/2',
			 1, NULL, 1, '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z'),
			(3, 'go', 'linux', 'x64', '1.2.3', 'duplicate', 'https://example.com/3',
			 0, NULL, 1, '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z'),
			(4, 'java', 'windows', 'x64', 'not-semver', 'invalid', 'https://example.com/4',
			 1, 'java|windows|x64', 1, '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z'),
			(5, 'csharp', 'windows', 'x64', '2.0.0', 'disabled', 'https://example.com/5',
			 1, 'csharp|windows|x64', 0, '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z'),
			(6, 'go', 'linux', 'x64', '0.0.0-legacy.6', 'stale slot', 'https://example.com/6',
			 1, 'go|linux|x64', 1, '2026-08-18T00:00:00.0000000Z', '2026-08-18T00:00:00.0000000Z')`)
	}
	if err == nil {
		_, err = legacy.Exec(`CREATE UNIQUE INDEX uq_client_download_latest_slot ON client_download_link (latest_slot)`)
	}
	if closeErr := legacy.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}

	db, err := Open("sqlite", path)
	if err != nil {
		t.Fatalf("upgrade not-null client catalog: %v", err)
	}
	defer db.Close()
	type migrated struct {
		version    sql.NullString
		isLatest   databaseBoolean
		latestSlot sql.NullString
	}
	got := make(map[int64]migrated)
	rows, err := db.sql.Query(`SELECT id, version, is_latest, latest_slot FROM client_download_link ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		var item migrated
		if err := rows.Scan(&id, &item.version, &item.isLatest, &item.latestSlot); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got[id] = item
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{1, 3, 4, 6} {
		if got[id].version.Valid || bool(got[id].isLatest) || got[id].latestSlot.Valid {
			t.Fatalf("row %d retained invalid/duplicate version or latest state: %+v", id, got[id])
		}
	}
	if !got[2].version.Valid || got[2].version.String != "1.2.3" ||
		!bool(got[2].isLatest) || got[2].latestSlot.String != "go|linux|x64" {
		t.Fatalf("published canonical winner was not retained: %+v", got[2])
	}
	if !got[5].version.Valid || got[5].version.String != "2.0.0" ||
		bool(got[5].isLatest) || got[5].latestSlot.Valid {
		t.Fatalf("disabled row latest state was not repaired: %+v", got[5])
	}
	nullable, err := db.clientDownloadVersionColumnNullable()
	if err != nil || !nullable {
		t.Fatalf("version column nullable=%t err=%v", nullable, err)
	}
	if err := db.InsertClientDownloadLink(context.Background(), ClientDownloadLink{
		ID: 7, Implementation: "go", Platform: "macos", Arch: "arm64", Version: nil,
		DisplayName: "legacy", DownloadURL: "https://example.com/7", Enabled: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("insert nullable legacy version after migration: %v", err)
	}
}

func storeVersion(value string) *string { return &value }
