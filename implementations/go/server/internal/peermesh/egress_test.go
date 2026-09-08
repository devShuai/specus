package peermesh

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/peeregress"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
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

// The tenant switch is off by default, so every fixture that expects a policy to take effect has to
// turn it on. That default is the point: egress is opt-in for the tenant as well as per device.
func enableTenantEgress(t *testing.T, service *Service, tenantID string) {
	t.Helper()
	enabled := true
	if _, err := service.SetEgressSwitch(context.Background(),
		AccessContext{Username: "admin", TenantID: tenantID, Admin: true},
		EgressSwitchMutation{Enabled: &enabled}); err != nil {
		t.Fatalf("enable tenant egress: %v", err)
	}
}

func capableClient() *EgressCapabilities {
	return &EgressCapabilities{Version: 1, ConsumerCapable: true, EgressCapable: true}
}

func upsertTestPolicy(t *testing.T, service *Service, egressID int64, consumers []int64, enabled bool) EgressPolicyView {
	t.Helper()
	enableTenantEgress(t, service, "tenant-a")
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

func insertEgressCapableSession(t *testing.T, db *store.DB, account store.ClientAccount, sessionID int64) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.InsertClientSession(context.Background(), store.ClientSession{
		ID: sessionID, TenantID: account.TenantID, ClientID: account.ID,
		ClientName: account.ClientName, TokenHash: "egress-push-test-" + account.ClientName,
		Status: "NETTY_ONLINE", MachineFingerprint: "machine", OSUser: "user",
		ClientEgressVersion: EgressProtocolVersion,
		HTTPLoginAt:         now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

func egressMessages(t *testing.T, recorded *recordingSession, messageType string) []ControlMessage {
	t.Helper()
	var out []ControlMessage
	for _, message := range recorded.peerMessages(t) {
		if message.Type == messageType {
			out = append(out, message)
		}
	}
	return out
}

// Revoking a grant has to reach the peers now, not at their next login. Building the payload is not
// enough on its own: this is the acceptance condition the builders alone did not satisfy.
func TestPolicyChangeReachesOnlineDevicesImmediately(t *testing.T) {
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{
		Enabled: true, CIDR: "100.96.0.0/11", PublicAddress: "203.0.113.10",
		StunTurnPort: 3478, SessionTTLSeconds: 3600,
	}, db, registry, nil)

	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	insertEgressCapableSession(t, db, consumer, 4101)
	insertEgressCapableSession(t, db, egress, 4102)

	consumerSession := &recordingSession{name: consumer.ClientName}
	egressSession := &recordingSession{name: egress.ClientName}
	registry.Replace(consumerSession)
	registry.Replace(egressSession)

	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)

	configs := egressMessages(t, egressSession, ControlTypeEgressConfig)
	if len(configs) == 0 {
		t.Fatal("granting access pushed no egress-config to the egress device")
	}
	granted := configs[len(configs)-1]
	if granted.Enabled == nil || !*granted.Enabled ||
		len(granted.AllowedConsumerClientIDs) != 1 ||
		granted.AllowedConsumerClientIDs[0] != consumer.ID {
		t.Errorf("egress-config did not name the consumer: %+v", granted)
	}

	catalogs := egressMessages(t, consumerSession, ControlTypeEgressCatalog)
	if len(catalogs) == 0 {
		t.Fatal("granting access pushed no egress-catalog to the consumer")
	}
	offered := catalogs[len(catalogs)-1]
	if len(offered.Egresses) != 1 || offered.Egresses[0].ClientID != egress.ID {
		t.Errorf("egress-catalog did not offer the egress: %+v", offered.Egresses)
	}

	consumerSession.packets = nil
	egressSession.packets = nil
	upsertTestPolicy(t, service, egress.ID, []int64{}, true)

	configs = egressMessages(t, egressSession, ControlTypeEgressConfig)
	if len(configs) == 0 {
		t.Fatal("revoking access pushed no egress-config")
	}
	if revoked := configs[len(configs)-1]; len(revoked.AllowedConsumerClientIDs) != 0 {
		t.Errorf("revoked policy still names consumers: %+v", revoked.AllowedConsumerClientIDs)
	}
	catalogs = egressMessages(t, consumerSession, ControlTypeEgressCatalog)
	if len(catalogs) == 0 {
		t.Fatal("revoking access pushed no egress-catalog")
	}
	if withdrawn := catalogs[len(catalogs)-1]; len(withdrawn.Egresses) != 0 {
		t.Errorf("revoked egress is still catalogued: %+v", withdrawn.Egresses)
	}
}

// A client that announced nothing at login must never be handed an egress payload, even when a
// policy names it.
func TestPushSkipsClientsThatAnnouncedNoEgressCapability(t *testing.T) {
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{
		Enabled: true, CIDR: "100.96.0.0/11", PublicAddress: "203.0.113.10",
		StunTurnPort: 3478, SessionTTLSeconds: 3600,
	}, db, registry, nil)

	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	// Online, but the login carried no clientEgressCapabilities.
	now := time.Now().UTC()
	if err := db.InsertClientSession(context.Background(), store.ClientSession{
		ID: 4103, TenantID: consumer.TenantID, ClientID: consumer.ID,
		ClientName: consumer.ClientName, TokenHash: "no-egress", Status: "NETTY_ONLINE",
		MachineFingerprint: "machine", OSUser: "user",
		HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	consumerSession := &recordingSession{name: consumer.ClientName}
	registry.Replace(consumerSession)

	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)

	if messages := egressMessages(t, consumerSession, ControlTypeEgressCatalog); len(messages) != 0 {
		t.Errorf("pushed an egress payload to a client that cannot read it: %+v", messages)
	}
}

// The server binds the reporter from the authenticated control connection, so a report carrying
// routing or identity of its own is a protocol violation rather than something to sanitise.
func TestEgressReportEnvelopeRejectsClientControlledRoutingAndIdentity(t *testing.T) {
	valid := protocol.MessageRequest{Message: `{"type":"egress-report","revision":1,"activeFlows":3}`}
	if err := validateEgressReportEnvelope(valid); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	targeted := valid
	targeted.ToClientName = "peer-b"
	if err := validateEgressReportEnvelope(targeted); err == nil {
		t.Fatal("targeted egress-report was accepted")
	}
	for _, field := range []string{
		"sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
		"targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
		"sessionId", "token",
	} {
		request := valid
		// An explicit null is a violation too: the field has to be absent.
		request.Message = fmt.Sprintf(`{"type":"egress-report","revision":1,%q:null}`, field)
		if err := validateEgressReportEnvelope(request); err == nil {
			t.Errorf("field %s was accepted", field)
		}
	}
	oversized := valid
	oversized.Message = `{"type":"egress-report","padding":"` + strings.Repeat("x", MaxEgressReportBytes) + `"}`
	if err := validateEgressReportEnvelope(oversized); err == nil {
		t.Fatal("oversized egress-report was accepted")
	}
}

// The rate table is keyed by client-driven session ids, so it needs a ceiling of its own.
func TestEgressReportRateLimitBoundsBothTheWindowAndTheTable(t *testing.T) {
	egressReportStampsMu.Lock()
	egressReportStamps = map[int64][]int64{}
	egressReportStampsMu.Unlock()

	for i := 0; i < EgressReportRateLimit; i++ {
		if err := enforceEgressReportRate(7001); err != nil {
			t.Fatalf("report %d inside the window was refused: %v", i, err)
		}
	}
	if err := enforceEgressReportRate(7001); err == nil {
		t.Error("a session over the window limit was accepted")
	}

	// One slot is already taken above; fill the remainder.
	for session := int64(2); session <= MaxEgressRateTableEntries; session++ {
		if err := enforceEgressReportRate(100000 + session); err != nil {
			t.Fatalf("session %d was refused while the table had room: %v", session, err)
		}
	}
	if err := enforceEgressReportRate(999999); err == nil {
		t.Error("a new session was tracked past the table ceiling")
	}
}

// Refusals are aggregated by result code. A client that invents keys must not grow what is stored.
func TestEgressRefusalCountersKeepOnlyKnownCodes(t *testing.T) {
	encoded := EncodeEgressRejectedFlows(map[string]int64{
		peeregress.CodeDestinationDenied: 4,
		"EGRESS_MADE_UP":                 9,
		peeregress.CodePortDenied:        1,
	})
	decoded := DecodeEgressRejectedFlows(encoded)
	if decoded[peeregress.CodeDestinationDenied] != 4 || decoded[peeregress.CodePortDenied] != 1 {
		t.Errorf("known codes did not round trip: %+v", decoded)
	}
	if _, present := decoded["EGRESS_MADE_UP"]; present {
		t.Error("an invented code was stored")
	}
	if EncodeEgressRejectedFlows(map[string]int64{"EGRESS_MADE_UP": 9}) != "{}" {
		t.Error("a map of only invented codes was stored")
	}
	// A negative counter is a client bug or an attempt to skew the view.
	if EncodeEgressRejectedFlows(map[string]int64{peeregress.CodePortDenied: -3}) != "{}" {
		t.Error("a negative counter was stored")
	}
	if len(DecodeEgressRejectedFlows("not json")) != 0 || len(DecodeEgressRejectedFlows("")) != 0 {
		t.Error("an unreadable stored map must read as no refusals")
	}
}

func TestEgressReportBindsIdentityAndKeepsTheNewestSnapshot(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	registry := session.NewRegistry()
	service := New(config.PeerMeshConfig{
		Enabled: true, CIDR: "100.96.0.0/11", PublicAddress: "203.0.113.10",
		StunTurnPort: 3478, SessionTTLSeconds: 3600,
	}, db, registry, nil)
	egressReportStampsMu.Lock()
	egressReportStamps = map[int64][]int64{}
	egressReportStampsMu.Unlock()

	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	insertEgressCapableSession(t, db, egress, 4201)

	revision := int64(12)
	report := ControlMessage{
		Type: ControlTypeEgressReport, Revision: &revision,
		ActiveFlows: int64Ptr(18), TotalFlows: int64Ptr(2140),
		BytesIn: int64Ptr(10485760), BytesOut: int64Ptr(2097152),
		RejectedFlows: map[string]int64{peeregress.CodeDestinationDenied: 4},
	}
	if err := service.handleEgressReport(ctx, egress, report, 4201); err != nil {
		t.Fatalf("handle report: %v", err)
	}

	views, err := service.ListEgressActivity(ctx, AccessContext{TenantID: "tenant-a", Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].ActiveFlows != 18 || views[0].TotalFlows != 2140 {
		t.Fatalf("activity did not record the report: %+v", views)
	}
	if views[0].RejectedFlows[peeregress.CodeDestinationDenied] != 4 {
		t.Errorf("refusal counters missing: %+v", views[0].RejectedFlows)
	}
	// The device is not bound to the session registry, so it must read as offline rather than
	// staying frozen at whatever it last reported.
	if views[0].Online {
		t.Error("a device with no live control channel was reported online")
	}

	stale := report
	staleRevision := int64(5)
	stale.Revision = &staleRevision
	stale.ActiveFlows = int64Ptr(1)
	if err := service.handleEgressReport(ctx, egress, stale, 4201); err != nil {
		t.Fatalf("stale report: %v", err)
	}
	views, err = service.ListEgressActivity(ctx, AccessContext{TenantID: "tenant-a", Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	if views[0].ActiveFlows != 18 {
		t.Errorf("an older snapshot overwrote a newer one: %+v", views[0])
	}
}

// A session that belongs to someone else, or that never announced the capability, cannot report.
func TestEgressReportRejectsAnUnboundOrIncapableSession(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{
		Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600,
	}, db, session.NewRegistry(), nil)
	egressReportStampsMu.Lock()
	egressReportStamps = map[int64][]int64{}
	egressReportStampsMu.Unlock()

	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	other := insertPeerClient(t, db, 1003, "tenant-a", "bob", "bob-laptop")
	insertEgressCapableSession(t, db, egress, 4301)

	// Another device's session id must not let a client report as this one.
	if err := service.handleEgressReport(ctx, other, ControlMessage{Type: ControlTypeEgressReport}, 4301); err == nil {
		t.Error("a session bound to another client was accepted")
	}

	now := time.Now().UTC()
	if err := db.InsertClientSession(ctx, store.ClientSession{
		ID: 4302, TenantID: other.TenantID, ClientID: other.ID, ClientName: other.ClientName,
		TokenHash: "no-egress-report", Status: "NETTY_ONLINE",
		MachineFingerprint: "machine", OSUser: "user",
		HTTPLoginAt: now, NettyConnectedAt: &now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.handleEgressReport(ctx, other, ControlMessage{Type: ControlTypeEgressReport}, 4302); err == nil {
		t.Error("a client that announced no egress capability was allowed to report")
	}
}

func int64Ptr(value int64) *int64 { return &value }

// The tenant switch and the per-device flag are two separate gates; both must be on.
func TestTenantSwitchGatesEveryPolicyWithoutErasingThem(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")

	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
	admin := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}

	status, err := service.EgressSwitchStatus(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if !status.ConfiguredEnabled || !status.EffectiveEnabled || status.EnabledPolicyCount != 1 {
		t.Fatalf("switch status after enabling: %+v", status)
	}

	config, err := service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil || config == nil || config.Enabled == nil || !*config.Enabled {
		t.Fatalf("an enabled tenant must push an enabled config: %+v", config)
	}

	disabled := false
	if _, err := service.SetEgressSwitch(ctx, admin, EgressSwitchMutation{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	config, err = service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil || config == nil || config.Enabled == nil || *config.Enabled {
		t.Errorf("a disabled tenant must push a disabled config: %+v", config)
	}
	catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
	if err != nil || catalog == nil || len(catalog.Egresses) != 0 {
		t.Errorf("a disabled tenant must offer no egresses: %+v", catalog)
	}

	// The policies survive the switch, so turning it back on restores what was configured rather
	// than making the operator rebuild it.
	status, err = service.EgressSwitchStatus(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if status.EnabledPolicyCount != 1 {
		t.Errorf("switching the tenant off erased policies: %+v", status)
	}
	views, err := service.ListEgressPolicies(ctx, admin)
	if err != nil || len(views) != 1 || len(views[0].AllowedConsumerClientIDs) != 1 {
		t.Errorf("stored policy did not survive the switch: %+v", views)
	}
}

// A non-admin cannot flip the tenant switch, same as every other egress mutation.
func TestOnlyAdminsCanFlipTheTenantSwitch(t *testing.T) {
	service, _ := newEgressTestService(t)
	enabled := true
	if _, err := service.SetEgressSwitch(context.Background(),
		AccessContext{Username: "someone", TenantID: "tenant-a"},
		EgressSwitchMutation{Enabled: &enabled}); err == nil {
		t.Error("a non-admin flipped the tenant switch")
	}
}
