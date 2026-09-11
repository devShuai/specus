package client

import "testing"

// Binds the egress-config decoder to protocol/test-vectors/peer-egress-control-v1.json.
//
// The push is produced by three server implementations and read by three clients, so what a client
// makes of it is a contract. The parts most likely to drift are the ones a JSON library decides
// rather than the protocol: what an absent field becomes, and whether a value is normalised before
// it is compared.
//
// The vector's expectations come from an independent reference decoder in the generator, not from
// this package.

type egressControlVector struct {
	EgressConfig struct {
		Accept []struct {
			Name    string `json:"name"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
			Expect  struct {
				Revision int64 `json:"revision"`
				Policy   struct {
					Enabled                  bool    `json:"enabled"`
					Scope                    string  `json:"scope"`
					AllowedConsumerClientIDs []int64 `json:"allowedConsumerClientIds"`
					DestinationRules         []struct {
						CIDR       string   `json:"cidr"`
						Protocols  []string `json:"protocols"`
						PortRanges [][]int  `json:"portRanges"`
					} `json:"destinationRules"`
					Limits struct {
						MaxConcurrentFlows  int `json:"maxConcurrentFlows"`
						MaxFlowsPerConsumer int `json:"maxFlowsPerConsumer"`
						IdleTimeoutSeconds  int `json:"idleTimeoutSeconds"`
					} `json:"limits"`
				} `json:"policy"`
			} `json:"expect"`
		} `json:"accept"`
		Reject []struct {
			Name    string `json:"name"`
			Message string `json:"message"`
		} `json:"reject"`
	} `json:"egressConfig"`
	DeploymentEndpoints struct {
		Cases []struct {
			Name  string `json:"name"`
			Input struct {
				ServerBaseURL string `json:"serverBaseUrl"`
				StunHost      string `json:"stunHost"`
				TurnHost      string `json:"turnHost"`
				RelayAddress  string `json:"relayAddress"`
			} `json:"input"`
			Expect []string `json:"expect"`
		} `json:"cases"`
	} `json:"deploymentEndpoints"`
}

func TestEgressConfigDecodeMatchesSharedVector(t *testing.T) {
	var vector egressControlVector
	readEgressVector(t, "peer-egress-control-v1.json", &vector)
	if len(vector.EgressConfig.Accept) == 0 || len(vector.EgressConfig.Reject) == 0 {
		t.Fatal("control vector carried no egress-config cases")
	}

	for _, testCase := range vector.EgressConfig.Accept {
		policy, revision, ok := decodeEgressConfig([]byte(testCase.Message))
		if !ok {
			t.Errorf("%s: the message was refused", testCase.Name)
			continue
		}
		want := testCase.Expect
		if revision != want.Revision {
			t.Errorf("%s: revision = %d, want %d", testCase.Name, revision, want.Revision)
		}
		if policy.Enabled != want.Policy.Enabled {
			t.Errorf("%s: enabled = %v, want %v", testCase.Name, policy.Enabled, want.Policy.Enabled)
		}
		if policy.Scope != want.Policy.Scope {
			t.Errorf("%s: scope = %q, want %q", testCase.Name, policy.Scope, want.Policy.Scope)
		}
		if len(policy.AllowedConsumerClientIDs) != len(want.Policy.AllowedConsumerClientIDs) {
			t.Errorf("%s: %d consumers, want %d", testCase.Name,
				len(policy.AllowedConsumerClientIDs), len(want.Policy.AllowedConsumerClientIDs))
		}
		if len(policy.DestinationRules) != len(want.Policy.DestinationRules) {
			t.Errorf("%s: %d destination rules, want %d", testCase.Name,
				len(policy.DestinationRules), len(want.Policy.DestinationRules))
			continue
		}
		for index, rule := range policy.DestinationRules {
			expected := want.Policy.DestinationRules[index]
			if rule.CIDR != expected.CIDR || len(rule.Protocols) != len(expected.Protocols) ||
				len(rule.PortRanges) != len(expected.PortRanges) {
				t.Errorf("%s: rule %d = %+v, want %+v", testCase.Name, index, rule, expected)
			}
		}
		if policy.Limits.MaxConcurrentFlows != want.Policy.Limits.MaxConcurrentFlows ||
			policy.Limits.MaxFlowsPerConsumer != want.Policy.Limits.MaxFlowsPerConsumer ||
			policy.Limits.IdleTimeoutSeconds != want.Policy.Limits.IdleTimeoutSeconds {
			t.Errorf("%s: limits = %+v, want %+v", testCase.Name, policy.Limits, want.Policy.Limits)
		}
	}

	for _, testCase := range vector.EgressConfig.Reject {
		if _, _, ok := decodeEgressConfig([]byte(testCase.Message)); ok {
			t.Errorf("%s: the message was accepted", testCase.Name)
		}
	}
}

// The forced-deny list has to include this deployment's own endpoints, or a consumer could reach the
// infrastructure through the egress it is only supposed to reach the internet through. Three clients
// holding the same configuration must derive the same list.
func TestEgressDeploymentDenyCIDRsMatchSharedVector(t *testing.T) {
	var vector egressControlVector
	readEgressVector(t, "peer-egress-control-v1.json", &vector)
	if len(vector.DeploymentEndpoints.Cases) == 0 {
		t.Fatal("control vector carried no deployment endpoint cases")
	}

	for _, testCase := range vector.DeploymentEndpoints.Cases {
		got := egressDeploymentDenyCIDRs(testCase.Input.ServerBaseURL, testCase.Input.StunHost,
			testCase.Input.TurnHost, testCase.Input.RelayAddress)
		if len(got) != len(testCase.Expect) {
			t.Errorf("%s: derived %v, want %v", testCase.Name, got, testCase.Expect)
			continue
		}
		for index, want := range testCase.Expect {
			if got[index] != want {
				t.Errorf("%s: entry %d = %q, want %q", testCase.Name, index, got[index], want)
			}
		}
	}
}
