package peermesh

import (
	"context"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/peeregress"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func newEgressTestService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{
		Enabled:           true,
		CIDR:              "100.96.0.0/11",
		PublicAddress:     "203.0.113.10",
		StunTurnPort:      3478,
		SessionTTLSeconds: 3600,
	}, db, session.NewRegistry(), nil)
	return service, db
}

func capableClient() *EgressCapabilities {
	return &EgressCapabilities{Version: 1, ConsumerCapable: true, EgressCapable: true}
}

func upsertTestPolicy(t *testing.T, service *Service, egressID int64, consumers []int64, enabled bool) EgressPolicyView {
	t.Helper()
	scope := peeregress.ScopePublic
	view, err := service.UpsertEgressPolicy(context.Background(),
		AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true},
		EgressPolicyMutation{
			EgressClientID:           &egressID,
			Enabled:                  &enabled,
			Scope:                    &scope,
			AllowedConsumerClientIDs: consumers,
			DestinationRules: []peeregress.DestinationRule{{
				CIDR:       "203.0.113.0/24",
				Protocols:  []string{"tcp"},
				PortRanges: [][]int{{443, 443}},
			}},
		})
	if err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	return view
}

// The point of keeping egress policy separate from the mesh ACL: naming a device in the egress
// allowlist grants nothing unless the base ACL already allows the pair.
func TestBaseMeshAccessIsRequiredOnTopOfTheEgressAllowlist(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)

	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")

	view := upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
	if len(view.EffectiveConsumerClientIDs) != 1 || view.EffectiveConsumerClientIDs[0] != consumer.ID {
		t.Fatalf("same-owner pair should be effective: %+v", view.EffectiveConsumerClientIDs)
	}

	// Move the consumer to a different owner with no explicit ACL. It stays named in the egress
	// allowlist, but the base mesh ACL no longer allows the pair.
	other := insertPeerClient(t, db, 1003, "tenant-a", "bob", "bob-laptop")
	insertPeerDevice(t, db, other, "100.96.0.12", "other-key")
	view = upsertTestPolicy(t, service, egress.ID, []int64{other.ID}, true)
	if len(view.EffectiveConsumerClientIDs) != 0 {
		t.Errorf("cross-owner consumer must not be effective without a mesh ACL: %+v",
			view.EffectiveConsumerClientIDs)
	}
	if len(view.AllowedConsumerClientIDs) != 1 {
		t.Errorf("configured allowlist should still record the request: %+v", view.AllowedConsumerClientIDs)
	}
	_ = ctx
}

// An empty allowlist grants nothing. This is the opposite of the shared-service default, where an
// empty list means "everyone the mesh ACL already allows".
func TestAnEmptyConsumerAllowlistGrantsNothing(t *testing.T) {
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")

	view := upsertTestPolicy(t, service, egress.ID, []int64{}, true)
	if len(view.EffectiveConsumerClientIDs) != 0 {
		t.Errorf("empty allowlist granted %+v", view.EffectiveConsumerClientIDs)
	}
}

func TestDisabledPolicyPushesAnEmptyConfig(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, false)

	message, err := service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if message == nil || message.Enabled == nil || *message.Enabled {
		t.Fatalf("disabled policy must push enabled=false: %+v", message)
	}
	if len(message.DestinationRules) != 0 || len(message.AllowedConsumerClientIDs) != 0 {
		t.Errorf("disabled policy leaked rules or consumers: %+v", message)
	}
}

func TestClientsThatCannotDoEgressAreNeverPushedAPolicy(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")

	for _, capabilities := range []*EgressCapabilities{nil, {Version: 0}} {
		config, err := service.BuildEgressConfig(ctx, egress, capabilities)
		if err != nil {
			t.Fatal(err)
		}
		if config != nil {
			t.Errorf("pushed a config to an incapable client: %+v", config)
		}
		catalog, err := service.BuildEgressCatalog(ctx, egress, capabilities)
		if err != nil {
			t.Fatal(err)
		}
		if catalog != nil {
			t.Errorf("pushed a catalogue to an incapable client: %+v", catalog)
		}
	}
}

func TestEnabledPolicyPushesRulesAndLimits(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)

	message, err := service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if message.Enabled == nil || !*message.Enabled {
		t.Fatal("enabled policy must push enabled=true")
	}
	if message.Scope != peeregress.ScopePublic {
		t.Errorf("scope = %s", message.Scope)
	}
	if len(message.DestinationRules) != 1 || message.DestinationRules[0].CIDR != "203.0.113.0/24" {
		t.Errorf("destination rules = %+v", message.DestinationRules)
	}
	if message.Limits == nil || message.Limits.MaxFlowsPerConsumer != 64 {
		t.Errorf("limits = %+v", message.Limits)
	}
	if message.Revision == nil || *message.Revision <= 0 {
		t.Error("revision must be set so a client can ignore a snapshot it has applied")
	}
}

// A consumer learns which egress nodes exist, never what they are permitted to reach.
func TestCatalogueCarriesNoDestinationAllowlist(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)

	catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Egresses) != 1 || catalog.Egresses[0].ClientID != egress.ID {
		t.Fatalf("catalogue = %+v", catalog.Egresses)
	}
	if len(catalog.Egresses[0].Protocols) != 1 || catalog.Egresses[0].Protocols[0] != "tcp" {
		t.Errorf("protocols = %+v", catalog.Egresses[0].Protocols)
	}
	if catalog.Egresses[0].DomainTargetCapable || catalog.Egresses[0].IPv6TargetCapable {
		t.Error("neither domain nor IPv6 targets ship in this version")
	}
	if catalog.DestinationRules != nil {
		t.Errorf("catalogue leaked the destination allowlist: %+v", catalog.DestinationRules)
	}
}

func TestConsumerOutsideTheAllowlistDoesNotSeeTheEgress(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	elsewhere := insertPeerClient(t, db, 1003, "tenant-a", "alice", "spare")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	insertPeerDevice(t, db, elsewhere, "100.96.0.12", "spare-key")
	upsertTestPolicy(t, service, egress.ID, []int64{elsewhere.ID}, true)

	catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Egresses) != 0 {
		t.Errorf("consumer outside the allowlist saw %+v", catalog.Egresses)
	}
}

func TestDestinationRulesRoundTripAndRejectOversizedInput(t *testing.T) {
	rule := peeregress.DestinationRule{
		CIDR: "203.0.113.0/24", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}},
	}
	encoded, err := EncodeEgressDestinationRules([]peeregress.DestinationRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if decoded := DecodeEgressDestinationRules(encoded, nil); len(decoded) != 1 {
		t.Errorf("round trip = %+v", decoded)
	}

	tooMany := make([]peeregress.DestinationRule, MaxEgressDestinationRules+1)
	for i := range tooMany {
		tooMany[i] = rule
	}
	if _, err := EncodeEgressDestinationRules(tooMany); err == nil {
		t.Error("oversized rule list should be rejected")
	}
}

// An unreadable row must deny everything rather than fall back to something permissive.
func TestUnreadableStoredRulesDenyEverything(t *testing.T) {
	for _, raw := range []string{"{not json", "", "   "} {
		if rules := DecodeEgressDestinationRules(raw, nil); len(rules) != 0 {
			t.Errorf("%q decoded to %+v", raw, rules)
		}
	}
}

func TestNonAdminCannotManageEgressPolicies(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")

	enabled := true
	_, err := service.UpsertEgressPolicy(ctx,
		AccessContext{Username: "alice", TenantID: "tenant-a", Admin: false},
		EgressPolicyMutation{EgressClientID: &egress.ID, Enabled: &enabled})
	if err == nil {
		t.Error("a non-admin must not be able to grant egress")
	}
	if err := service.DeleteEgressPolicy(ctx,
		AccessContext{Username: "alice", TenantID: "tenant-a", Admin: false}, 1); err == nil {
		t.Error("a non-admin must not be able to delete an egress policy")
	}
}
