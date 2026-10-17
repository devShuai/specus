package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func passwordCurrentFixture(t *testing.T, db *DB) ManagementUser {
	t.Helper()
	now := time.Now()
	user, err := db.InsertManagementUser(context.Background(), ManagementUser{Username: "PasswordCurrent", TenantID: "default", PasswordHash: "AbCdPreimage", Role: ManagementRoleAdmin, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	current, err := db.FindManagementUserByAccountKey(context.Background(), user.AccountKey)
	if err != nil || current == nil {
		t.Fatal(err)
	}
	return *current
}

func TestPasswordFinalizationUsesCurrentImmutableIdentity(t *testing.T) {
	for _, scenario := range []string{"unchanged", "disabled", "disabled-and-rotated", "deleted", "replacement", "renamed", "tenant-changed", "rotated", "demoted", "oidc-rebound"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			expected := passwordCurrentFixture(t, db)
			changed := expected
			switch scenario {
			case "disabled":
				changed.Enabled = false
			case "disabled-and-rotated":
				changed.Enabled = false
				changed.PasswordHash = "changed-hash"
			case "rotated":
				changed.PasswordHash = "changed-hash"
			case "demoted":
				changed.Role = ManagementRoleUser
			case "oidc-rebound":
				changed.OIDCIdentityKey = "new-key"
				changed.OIDCIssuer = "new-issuer"
				changed.OIDCSubject = "new-subject"
			case "deleted", "replacement":
				if _, err := db.sql.Exec(`DELETE FROM specus_management_user WHERE username=?`, expected.AccountKey); err != nil {
					t.Fatal(err)
				}
				if scenario == "replacement" {
					changed.AccountKey = "replacement-key"
					if _, err := db.InsertManagementUser(ctx, changed); err != nil {
						t.Fatal(err)
					}
				}
			case "renamed":
				if _, err := db.sql.Exec(`UPDATE specus_management_user SET login_name='renamed',login_name_normalized='renamed' WHERE username=?`, expected.AccountKey); err != nil {
					t.Fatal(err)
				}
			case "tenant-changed":
				if _, err := db.sql.Exec(`UPDATE specus_management_user SET tenant_id='foreign' WHERE username=?`, expected.AccountKey); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "deleted" && scenario != "replacement" && scenario != "renamed" && scenario != "tenant-changed" {
				if err := db.UpdateManagementUser(ctx, changed); err != nil {
					t.Fatal(err)
				}
			}
			current, err := db.CompleteManagementPasswordLogin(ctx, expected)
			switch scenario {
			case "unchanged", "demoted", "oidc-rebound":
				if err != nil || current == nil || current.Role != changed.Role || current.OIDCIdentityKey != changed.OIDCIdentityKey {
					t.Fatalf("current metadata lost: %+v / %v", current, err)
				}
			case "rotated":
				if !errors.Is(err, ErrManagementPasswordHashChanged) || current == nil || current.PasswordHash != changed.PasswordHash {
					t.Fatalf("hash-only change not available for bounded reverification: %+v / %v", current, err)
				}
			default:
				if !errors.Is(err, ErrManagementPasswordLoginChanged) || current != nil {
					t.Fatalf("identity rebound or disabled state accepted: %+v / %v", current, err)
				}
			}
		})
	}
}

func TestPasswordUpgradeWritesOnlyMatchingHashPreimage(t *testing.T) {
	for _, scenario := range []string{"unchanged", "metadata", "disabled", "rotated", "case-only-hash", "case-only-name", "deleted", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			db := provisionTestDB(t)
			ctx := context.Background()
			expected := passwordCurrentFixture(t, db)
			changed := expected
			switch scenario {
			case "metadata":
				changed.Role = ManagementRoleUser
				changed.OIDCIdentityKey = "new-key"
				changed.OIDCIssuer = "new-issuer"
				changed.OIDCSubject = "new-subject"
				changed.UpdatedAt = time.Now().Add(time.Hour)
			case "disabled":
				changed.Enabled = false
			case "rotated":
				changed.PasswordHash = "different-hash"
			case "case-only-hash":
				changed.PasswordHash = strings.ToLower(changed.PasswordHash)
			case "case-only-name":
				if _, err := db.sql.Exec(`UPDATE specus_management_user SET login_name=LOWER(login_name) WHERE username=?`, expected.AccountKey); err != nil {
					t.Fatal(err)
				}
			case "deleted", "replacement":
				if _, err := db.sql.Exec(`DELETE FROM specus_management_user WHERE username=?`, expected.AccountKey); err != nil {
					t.Fatal(err)
				}
				if scenario == "replacement" {
					changed.AccountKey = "replacement-key"
					if _, err := db.InsertManagementUser(ctx, changed); err != nil {
						t.Fatal(err)
					}
				}
			}
			if scenario != "deleted" && scenario != "replacement" && scenario != "case-only-name" {
				if err := db.UpdateManagementUser(ctx, changed); err != nil {
					t.Fatal(err)
				}
			}
			before, err := db.FindManagementUserByAccountKey(ctx, expected.AccountKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.UpgradeManagementPasswordHash(ctx, expected, "upgraded-hash"); err != nil {
				t.Fatal(err)
			}
			after, err := db.FindManagementUserByAccountKey(ctx, expected.AccountKey)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "unchanged" || scenario == "metadata" {
				before.PasswordHash = "upgraded-hash"
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("conditional maintenance changed nonmatching hash or other account fields: %s", scenario)
			}
			if scenario == "replacement" {
				current, err := db.FindManagementUserByAccountKey(ctx, changed.AccountKey)
				if err != nil || current == nil || current.PasswordHash != changed.PasswordHash {
					t.Fatalf("replacement account changed: %v", err)
				}
			}
		})
	}
}

func TestManagementPasswordLoginExternalProvider(t *testing.T) {
	db, ctx := openOwnedStartupProviderDB(t)
	now := time.Now()
	user, err := db.InsertManagementUser(ctx, ManagementUser{Username: "native-password-current", TenantID: "default", PasswordHash: "AbCdPreimage", Role: ManagementRoleAdmin, Enabled: true, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	expected, err := db.FindManagementUserByAccountKey(ctx, user.AccountKey)
	if err != nil || expected == nil {
		t.Fatal(err)
	}
	changed := *expected
	changed.Role = ManagementRoleUser
	changed.OIDCIdentityKey = "native-password-identity"
	changed.OIDCIssuer = "native-issuer"
	changed.OIDCSubject = "native-subject"
	changed.UpdatedAt = now.Add(time.Hour)
	if err := db.UpdateManagementUser(ctx, changed); err != nil {
		t.Fatal(err)
	}
	current, err := db.CompleteManagementPasswordLogin(ctx, *expected)
	if err != nil || current.Role != ManagementRoleUser || current.OIDCIdentityKey != changed.OIDCIdentityKey {
		t.Fatalf("native current login metadata: %+v / %v", current, err)
	}
	before, err := db.FindManagementUserByAccountKey(ctx, user.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpgradeManagementPasswordHash(ctx, *expected, "UpgradedExactHash"); err != nil {
		t.Fatal(err)
	}
	after, err := db.FindManagementUserByAccountKey(ctx, user.AccountKey)
	before.PasswordHash = "UpgradedExactHash"
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("native upgrade changed nonpassword fields: %v", err)
	}
	preimage := *after
	after.PasswordHash = strings.ToLower(after.PasswordHash)
	if err := db.UpdateManagementUser(ctx, *after); err != nil {
		t.Fatal(err)
	}
	if err := db.UpgradeManagementPasswordHash(ctx, preimage, "must-not-revert-case-only-rotation"); err != nil {
		t.Fatal(err)
	}
	current, err = db.FindManagementUserByAccountKey(ctx, user.AccountKey)
	if err != nil || current.PasswordHash != after.PasswordHash {
		t.Fatalf("native case-insensitive collation defeated CAS: %v", err)
	}
	if snapshot, err := db.CompleteManagementPasswordLogin(ctx, preimage); !errors.Is(err, ErrManagementPasswordHashChanged) || snapshot == nil {
		t.Fatalf("native hash changed not detected: %v", err)
	}
	preimage = *current
	current.Enabled = false
	if err := db.UpdateManagementUser(ctx, *current); err != nil {
		t.Fatal(err)
	}
	if current, err := db.CompleteManagementPasswordLogin(ctx, preimage); !errors.Is(err, ErrManagementPasswordLoginChanged) || current != nil {
		t.Fatalf("native disabled login accepted: %v", err)
	}
	if err := db.UpgradeManagementPasswordHash(ctx, preimage, "must-not-enable"); err != nil {
		t.Fatal(err)
	}
	current, err = db.FindManagementUserByAccountKey(ctx, user.AccountKey)
	if err != nil || current.Enabled || current.PasswordHash != preimage.PasswordHash {
		t.Fatalf("native disabled account resurrected: %v", err)
	}
	root := ManagementWriteActor{Username: "admin", TenantID: "default", Admin: true, BuiltIn: true}
	if _, err := db.DeleteManagedUser(ctx, root, *current, now.Unix(), nil); err != nil {
		t.Fatal(err)
	}
	current.AccountKey = ""
	current.Enabled = true
	replacement, err := db.InsertManagementUser(ctx, *current)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := db.CompleteManagementPasswordLogin(ctx, preimage); !errors.Is(err, ErrManagementPasswordLoginChanged) || current != nil {
		t.Fatalf("native reused login rebound: %v", err)
	}
	if err := db.UpgradeManagementPasswordHash(ctx, preimage, "must-not-change-replacement"); err != nil {
		t.Fatal(err)
	}
	current, err = db.FindManagementUserByAccountKey(ctx, replacement.AccountKey)
	if err != nil || current == nil || current.PasswordHash != replacement.PasswordHash {
		t.Fatalf("native replacement mutated: %v", err)
	}
	t.Logf("native password current-state PASS: dialect=%s current-role/binding/exact-hash-only-CAS/case-only-preimage/disable/rotation/replacement", db.dialect)
}
