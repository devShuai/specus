package peermesh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/peeregress"
)

type egressManagementVector struct {
	Accept []struct {
		Name             string                       `json:"name"`
		DestinationRules []peeregress.DestinationRule `json:"destinationRules"`
		Stored           []peeregress.DestinationRule `json:"stored"`
	} `json:"accept"`
	Reject []struct {
		Name             string            `json:"name"`
		DestinationRules []json.RawMessage `json:"destinationRules"`
	} `json:"reject"`
}

func loadEgressManagementVector(t *testing.T) egressManagementVector {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "peer-egress-management-v1.json"))
		if err == nil {
			var vector egressManagementVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			return vector
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("cannot locate peer-egress-management-v1.json")
	return egressManagementVector{}
}

// Saved through the service, each accepted request stores exactly the vector's rules and returns
// them; each refused one is a request error and leaves the stored policy as it was.
func TestEgressPolicyDestinationRulesMatchTheSharedVector(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	admin := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true}
	vector := loadEgressManagementVector(t)

	for _, c := range vector.Accept {
		view, err := service.UpsertEgressPolicy(ctx, admin,
			EgressPolicyMutation{EgressClientID: &egress.ID, DestinationRules: c.DestinationRules})
		if err != nil {
			t.Errorf("%s: refused: %v", c.Name, err)
			continue
		}
		if !reflect.DeepEqual(view.DestinationRules, c.Stored) {
			t.Errorf("%s: stored %+v, want %+v", c.Name, view.DestinationRules, c.Stored)
		}
	}

	baseline, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID,
		DestinationRules: []peeregress.DestinationRule{{CIDR: "203.0.113.0/24", Protocols: []string{"tcp"}, PortRanges: [][]int{{443, 443}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Reject {
		// Decoded rule by rule so a case such as a one-element port pair reaches the check the
		// way the API's JSON decoder would deliver it.
		rules := make([]peeregress.DestinationRule, 0, len(c.DestinationRules))
		for _, raw := range c.DestinationRules {
			var rule peeregress.DestinationRule
			if err := json.Unmarshal(raw, &rule); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			rules = append(rules, rule)
		}
		_, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, DestinationRules: rules})
		var invalid EgressRequestError
		if !errors.As(err, &invalid) {
			t.Errorf("%s: want a request error, got %v", c.Name, err)
		}
		views, listErr := service.ListEgressPolicies(ctx, admin)
		if listErr != nil || len(views) != 1 || !reflect.DeepEqual(views[0].DestinationRules, baseline.DestinationRules) {
			t.Errorf("%s: a refused request changed the stored rules: %+v", c.Name, views)
		}
	}
}

// Each kind of refusal carries the type the API maps to its status code.
func TestEgressManagementErrorsCarryTheirKind(t *testing.T) {
	ctx := context.Background()
	service, db := newEgressTestService(t)
	egress := insertPeerClient(t, db, 1002, "tenant-a", "alice", "office-gateway")
	user := AccessContext{Username: "bob", TenantID: "tenant-a", Admin: false}
	admin := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: true}

	var forbidden ForbiddenError
	if _, err := service.UpsertEgressPolicy(ctx, user, EgressPolicyMutation{EgressClientID: &egress.ID}); !errors.As(err, &forbidden) {
		t.Errorf("non-admin upsert: %v", err)
	}
	enabled := true
	if _, err := service.SetEgressSwitch(ctx, user, EgressSwitchMutation{Enabled: &enabled}); !errors.As(err, &forbidden) {
		t.Errorf("non-admin switch: %v", err)
	}
	var invalid EgressRequestError
	if _, err := service.SetEgressSwitch(ctx, admin, EgressSwitchMutation{}); !errors.As(err, &invalid) {
		t.Errorf("switch without enabled: %v", err)
	}
	scope := "WORLD"
	if _, err := service.UpsertEgressPolicy(ctx, admin, EgressPolicyMutation{EgressClientID: &egress.ID, Scope: &scope}); !errors.As(err, &invalid) {
		t.Errorf("bad scope: %v", err)
	}
	if err := service.DeleteEgressPolicy(ctx, admin, 424242); errors.As(err, &invalid) || errors.As(err, &forbidden) || err == nil {
		t.Errorf("unknown policy should be a not-found error: %v", err)
	}
}
