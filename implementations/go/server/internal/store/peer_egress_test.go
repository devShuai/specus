package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerMeshEgressPolicyRoundTrip(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "egress.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	policy := PeerMeshEgressPolicy{
		ID:                       7001,
		TenantID:                 "default",
		OwnerUsername:            "owner",
		EgressClientID:           2002,
		EgressClientName:         "office-gateway",
		Enabled:                  true,
		Scope:                    "PUBLIC",
		AllowedConsumerClientIDs: "1001",
		DestinationRules:         `[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]`,
		MaxConcurrentFlows:       256,
		MaxFlowsPerConsumer:      64,
		IdleTimeoutSeconds:       60,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	if err := db.InsertPeerMeshEgressPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}

	loaded, err := db.FindPeerMeshEgressPolicyByClient(ctx, "default", 2002)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("policy not found by egress client id")
	}
	if loaded.DestinationRules != policy.DestinationRules {
		t.Errorf("destination rules = %s", loaded.DestinationRules)
	}
	if !loaded.Enabled || loaded.Scope != "PUBLIC" || loaded.MaxFlowsPerConsumer != 64 {
		t.Errorf("policy fields did not round trip: %+v", *loaded)
	}

	policy.Enabled = false
	policy.AllowedConsumerClientIDs = "1001,1002"
	policy.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdatePeerMeshEgressPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}

	// A disabled policy must disappear from the enabled-only listing, which is what catalogue
	// building reads: switching the device off has to stop it being offered, not merely stop new
	// flows at the far end.
	enabled, err := db.ListPeerMeshEgressPolicies(ctx, "default", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 0 {
		t.Errorf("disabled policy still listed as enabled: %+v", enabled)
	}
	all, err := db.ListPeerMeshEgressPolicies(ctx, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].AllowedConsumerClientIDs != "1001,1002" {
		t.Errorf("update did not persist: %+v", all)
	}

	if err := db.DeletePeerMeshEgressPolicy(ctx, "default", 7001); err != nil {
		t.Fatal(err)
	}
	gone, err := db.GetPeerMeshEgressPolicy(ctx, "default", 7001)
	if err != nil {
		t.Fatal(err)
	}
	if gone != nil {
		t.Error("policy still present after delete")
	}
}

// A tenant that has never configured egress must read as deny-all rather than as an error.
func TestMissingEgressPolicyReadsAsAbsent(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "egress-empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()

	found, err := db.FindPeerMeshEgressPolicyByClient(ctx, "default", 4242)
	if err != nil {
		t.Fatal(err)
	}
	if found != nil {
		t.Error("expected no policy")
	}
	items, err := db.ListPeerMeshEgressPolicies(ctx, "default", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("expected an empty listing, got %+v", items)
	}
}
