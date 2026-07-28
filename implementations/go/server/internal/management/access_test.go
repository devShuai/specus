package management

import (
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestManagementClientAndCredentialVisibilityIsCaseSensitiveLikeJava(t *testing.T) {
	principal := managementPrincipal{Username: "Alice", TenantID: "tenant-a"}
	client := store.ClientAccount{OwnerUsername: "Alice", TenantID: "tenant-a"}
	credential := store.ClientCredential{OwnerUsername: "Alice", TenantID: "tenant-a"}
	if !principal.canAccessClient(client) || !principal.canAccessCredential(credential) {
		t.Fatal("exact tenant/owner identity was rejected")
	}
	client.OwnerUsername = "alice"
	credential.OwnerUsername = "alice"
	if principal.canAccessClient(client) || principal.canAccessCredential(credential) {
		t.Fatal("owner identity was widened with a case-insensitive comparison")
	}
	client.OwnerUsername = "Alice"
	credential.OwnerUsername = "Alice"
	client.TenantID = "TENANT-A"
	credential.TenantID = "TENANT-A"
	if principal.canAccessClient(client) || principal.canAccessCredential(credential) {
		t.Fatal("tenant identity was widened with a case-insensitive comparison")
	}
	principal.Admin = true
	if principal.canAccessClient(client) || principal.canAccessCredential(credential) {
		t.Fatal("admin crossed a case-distinct tenant boundary")
	}
}
