package peermesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/peeregress"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
)

type egressDomainPolicyVector struct {
	Limits struct {
		Rules             int `json:"rules"`
		PortRangesPerRule int `json:"portRangesPerRule"`
		StoredJSONBytes   int `json:"storedJsonBytes"`
	} `json:"limits"`
	Management struct {
		Accept []struct {
			Name        string                  `json:"name"`
			DomainRules []peeregress.DomainRule `json:"domainRules"`
			Stored      json.RawMessage         `json:"stored"`
		} `json:"accept"`
		Reject []struct {
			Name        string            `json:"name"`
			DomainRules []json.RawMessage `json:"domainRules"`
		} `json:"reject"`
	} `json:"management"`
}

func loadEgressDomainPolicyVector(t *testing.T) egressDomainPolicyVector {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "peer-egress-domain-policy-v1.json"))
		if err == nil {
			var vector egressDomainPolicyVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			return vector
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("cannot locate peer-egress-domain-policy-v1.json")
	return egressDomainPolicyVector{}
}

func compactJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// Saved through the service, each accepted request stores exactly the vector's rules -- byte for
// byte, since the size limit is counted on that form -- and the view returns them; each refused one
// is a request error that saves nothing, whether the policy exists already or not.
func TestEgressPolicyDomainRulesMatchTheSharedVector(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	fresh := insertPeerClient(t, db, 1003, "tenant-a", "alice", "spare-gateway")
	admin := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true}
	vector := loadEgressDomainPolicyVector(t)
	if vector.Limits.Rules != MaxEgressDomainRules || vector.Limits.PortRangesPerRule != MaxEgressPortRangesPerRule ||
		vector.Limits.StoredJSONBytes != MaxEgressDomainRulesBytes {
		t.Fatalf("vector limits %+v differ from this build", vector.Limits)
	}
	if len(vector.Management.Accept) == 0 || len(vector.Management.Reject) == 0 {
		t.Fatal("the vector carries no management cases")
	}

	for _, c := range vector.Management.Accept {
		view, err := service.UpsertEgressPolicy(ctx, admin,
			EgressPolicyMutation{EgressClientID: &egress.ID, DomainRules: c.DomainRules})
		if err != nil {
			t.Errorf("%s: refused: %v", c.Name, err)
			continue
		}
		var want []peeregress.DomainRule
		if err := json.Unmarshal(c.Stored, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(view.DomainRules, want) {
			t.Errorf("%s: view %+v, want %+v", c.Name, view.DomainRules, want)
		}
		row, err := db.FindPeerMeshEgressPolicyByClient(ctx, "tenant-a", egress.ID)
		if err != nil || row == nil {
			t.Fatalf("%s: stored policy: %+v %v", c.Name, row, err)
		}
		if got, wantRaw := row.DomainRules, compactJSON(t, c.Stored); got != wantRaw {
			t.Errorf("%s: stored %s, want %s", c.Name, got, wantRaw)
		}
	}

	baseline, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID,
		DomainRules: []peeregress.DomainRule{{Match: "example.com", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Management.Reject {
		// Decoded rule by rule, the way the API's JSON decoder delivers them.
		rules := make([]peeregress.DomainRule, 0, len(c.DomainRules))
		for _, raw := range c.DomainRules {
			var rule peeregress.DomainRule
			if err := json.Unmarshal(raw, &rule); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			rules = append(rules, rule)
		}
		var invalid EgressRequestError
		_, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, DomainRules: rules})
		if !errors.As(err, &invalid) {
			t.Errorf("%s: want a request error, got %v", c.Name, err)
		}
		_, err = service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &fresh.ID, DomainRules: rules})
		if !errors.As(err, &invalid) {
			t.Errorf("%s: new policy: want a request error, got %v", c.Name, err)
		}
		views, listErr := service.ListEgressPolicies(ctx, admin)
		if listErr != nil || len(views) != 1 || !reflect.DeepEqual(views[0].DomainRules, baseline.DomainRules) {
			t.Errorf("%s: a refused request saved something: %+v %v", c.Name, views, listErr)
		}
	}
}

// The API's rule that omitted fields keep their value holds for domain rules too, and a policy
// created without them stores, returns and pushes an empty list.
func TestEgressPolicyDomainRulesAreKeptWhenOmittedAndEmptyByDefault(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	admin := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true}

	created, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID})
	if err != nil {
		t.Fatal(err)
	}
	if created.DomainRules == nil || len(created.DomainRules) != 0 {
		t.Errorf("a new policy returned domain rules %#v, want []", created.DomainRules)
	}
	encoded, err := json.Marshal(created)
	if err != nil || !strings.Contains(string(encoded), `"domainRules":[]`) {
		t.Errorf("view JSON %s lacks an empty domainRules: %v", encoded, err)
	}
	if row, err := db.FindPeerMeshEgressPolicyByClient(ctx, "tenant-a", egress.ID); err != nil || row == nil || row.DomainRules != "[]" {
		t.Errorf("a new policy stored %+v %v, want []", row, err)
	}

	rules := []peeregress.DomainRule{{Match: "*.CDN.example.", Protocols: []string{"TCP"}, PortRanges: [][]int{{443, 443}}}}
	if _, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, DomainRules: rules}); err != nil {
		t.Fatal(err)
	}
	scope := peeregress.ScopeLAN
	kept, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, Scope: &scope})
	if err != nil {
		t.Fatal(err)
	}
	want := []peeregress.DomainRule{{Match: "*.cdn.example", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}}}
	if !reflect.DeepEqual(kept.DomainRules, want) {
		t.Errorf("an update without domainRules left %+v, want %+v", kept.DomainRules, want)
	}

	cleared, err := service.UpsertEgressPolicy(ctx, admin,
		EgressPolicyMutation{EgressClientID: &egress.ID, DomainRules: []peeregress.DomainRule{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cleared.DomainRules) != 0 {
		t.Errorf("an explicit [] left %+v", cleared.DomainRules)
	}
}

// The egress-config an enabled egress receives carries the saved domain rules next to the
// destination rules, and [] when there are none. The disabling push keeps its shape, and the
// catalogue never carries them.
func TestEgressConfigCarriesTheSavedDomainRules(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	consumer := insertPeerClient(t, db, 1001, "tenant-a", "alice", "alice-laptop")
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	insertPeerDevice(t, db, consumer, "100.96.0.10", "consumer-key")
	insertPeerDevice(t, db, egress, "100.96.0.11", "egress-key")
	admin := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true}
	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)

	message, err := service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if message.DomainRules == nil || len(*message.DomainRules) != 0 {
		t.Fatalf("enabled push without domain rules carried %#v, want []", message.DomainRules)
	}
	if encoded, _ := json.Marshal(message); !strings.Contains(string(encoded), `"domainRules":[]`) {
		t.Errorf("enabled push %s lacks domainRules: []", encoded)
	}

	rules := []peeregress.DomainRule{
		{Match: "example.com", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}},
		{Match: "*.cdn.example", Protocols: []string{"tcp", "udp"}, PortRanges: [][]int{{443, 443}}},
	}
	if _, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, DomainRules: rules}); err != nil {
		t.Fatal(err)
	}
	message, err = service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if message.DomainRules == nil || !reflect.DeepEqual(*message.DomainRules, rules) {
		t.Errorf("enabled push carried %#v, want %+v", message.DomainRules, rules)
	}
	if len(message.DestinationRules) != 1 {
		t.Errorf("destination rules = %+v", message.DestinationRules)
	}

	catalog, err := service.BuildEgressCatalog(ctx, consumer, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if encoded, _ := json.Marshal(catalog); strings.Contains(string(encoded), "domainRules") || strings.Contains(string(encoded), "cdn.example") {
		t.Errorf("catalogue leaked the domain rules: %s", encoded)
	}

	disabled := false
	if _, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	message, err = service.BuildEgressConfig(ctx, egress, capableClient())
	if err != nil {
		t.Fatal(err)
	}
	if encoded, _ := json.Marshal(message); strings.Contains(string(encoded), "domainRules") {
		t.Errorf("the disabling push changed shape: %s", encoded)
	}
}

// What actually goes over the control channel when a policy is saved: the raw egress-config the
// egress device receives names the domain rules.
func TestSavingDomainRulesPushesThemToTheOnlineEgress(t *testing.T) {
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
	insertEgressCapableSession(t, db, egress, 4102)
	egressSession := &recordingSession{name: egress.ClientName}
	registry.Replace(egressSession)

	upsertTestPolicy(t, service, egress.ID, []int64{consumer.ID}, true)
	if raw := lastEgressConfig(t, egressSession); !strings.Contains(raw, `"domainRules":[]`) {
		t.Errorf("egress-config without domain rules: %s", raw)
	}

	egressSession.packets = nil
	_, err := service.UpsertEgressPolicy(context.Background(),
		AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true},
		EgressPolicyMutation{EgressClientID: &egress.ID, DomainRules: []peeregress.DomainRule{
			{Match: " Example.COM. ", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `"domainRules":[{"match":"example.com","protocols":["tcp"],"portRanges":[[443,443]]}]`
	if raw := lastEgressConfig(t, egressSession); !strings.Contains(raw, want) {
		t.Errorf("egress-config %s does not carry %s", raw, want)
	}
}

func lastEgressConfig(t *testing.T, recorded *recordingSession) string {
	t.Helper()
	last := ""
	for _, packet := range recorded.packets {
		response, ok := packet.(protocol.MessageResponse)
		if !ok || !strings.Contains(response.Message, `"type":"egress-config"`) {
			continue
		}
		last = response.Message
	}
	if last == "" {
		t.Fatal("no egress-config was pushed")
	}
	return last
}
