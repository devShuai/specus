package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveOrProvisionOIDCUserDoesNotOverwriteExistingBinding(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "oidc-binding.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if err := db.InsertManagementUser(context.Background(), ManagementUser{
		Username: "local-user", TenantID: "default", PasswordHash: "password-hash",
		Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	first, err := db.ResolveOrProvisionOIDCUser(context.Background(), "https://issuer-one", "subject-one",
		"identity-one", "local-user", "default", "unused", now.Add(time.Second))
	if err != nil || first == nil || first.OIDCIdentityKey != "identity-one" {
		t.Fatalf("first bind: user=%+v err=%v", first, err)
	}
	if _, err := db.ResolveOrProvisionOIDCUser(context.Background(), "https://issuer-two", "subject-two",
		"identity-two", "local-user", "default", "unused", now.Add(2*time.Second)); !errors.Is(err, ErrOIDCIdentityConflict) {
		t.Fatalf("second identity bind error = %v, want conflict", err)
	}
	stored, err := db.FindManagementUserByUsername(context.Background(), "local-user")
	if err != nil || stored == nil {
		t.Fatalf("read bound user: user=%+v err=%v", stored, err)
	}
	if stored.OIDCIssuer != "https://issuer-one" || stored.OIDCSubject != "subject-one" ||
		stored.OIDCIdentityKey != "identity-one" {
		t.Fatalf("binding was overwritten: %+v", stored)
	}
	if _, err := db.FindManagementUserByOIDCIdentity(context.Background(), "https://wrong-issuer",
		"subject-one", "identity-one"); !errors.Is(err, ErrOIDCIdentityConflict) {
		t.Fatalf("identity hash lookup did not verify original issuer/subject: %v", err)
	}
}

func TestResolveExactOIDCUsernameBindingAcceptsOnlyCommittedExactIdentity(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "oidc-cas-revalidation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	user := ManagementUser{
		Username: "cas-user", TenantID: "default", PasswordHash: "password-hash",
		OIDCIssuer: "https://issuer.example", OIDCSubject: "subject-one", OIDCIdentityKey: "identity-one",
		Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.InsertManagementUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	resolved, err := db.resolveExactOIDCUsernameBinding(context.Background(), user.Username,
		user.OIDCIssuer, user.OIDCSubject, user.OIDCIdentityKey)
	if err != nil || resolved == nil || resolved.Username != user.Username {
		t.Fatalf("resolve exact binding: user=%+v err=%v", resolved, err)
	}
	for name, mismatch := range map[string][3]string{
		"issuer":  {"https://other.example", user.OIDCSubject, user.OIDCIdentityKey},
		"subject": {user.OIDCIssuer, "other-subject", user.OIDCIdentityKey},
		"key":     {user.OIDCIssuer, user.OIDCSubject, "other-key"},
	} {
		issuer, subject, identityKey := mismatch[0], mismatch[1], mismatch[2]
		if _, err := db.resolveExactOIDCUsernameBinding(context.Background(), user.Username,
			issuer, subject, identityKey); !errors.Is(err, ErrOIDCIdentityConflict) {
			t.Errorf("%s mismatch error = %v, want identity conflict", name, err)
		}
	}
	user.Enabled = false
	user.UpdatedAt = now.Add(time.Second)
	if err := db.UpdateManagementUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.resolveExactOIDCUsernameBinding(context.Background(), user.Username,
		user.OIDCIssuer, user.OIDCSubject, user.OIDCIdentityKey); !errors.Is(err, ErrManagementUserDisabled) {
		t.Fatalf("disabled exact binding error = %v, want disabled", err)
	}
}
