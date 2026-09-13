package client

import (
	"encoding/json"
	"testing"
)

// The login environment has to announce egress, or no server will ever make this device an egress.
//
// All four servers gate egress-config and egress-catalog on
// environment.clientEgressCapabilities.version being at least 1. Nothing sent it, so in a real
// deployment no policy ever reached a client and the egress data plane was reachable only from tests
// that handed it a policy directly. Asserted on the wire JSON rather than the struct, because the
// field names are the part the servers read and the part that went wrong.
func TestLoginEnvironmentAnnouncesEgressCapabilities(t *testing.T) {
	encoded, err := json.Marshal(collectEnvironment())
	if err != nil {
		t.Fatalf("marshal environment: %v", err)
	}
	var wire struct {
		Capabilities *struct {
			Version             *int  `json:"version"`
			ConsumerCapable     *bool `json:"consumerCapable"`
			EgressCapable       *bool `json:"egressCapable"`
			DomainTargetCapable *bool `json:"domainTargetCapable"`
			IPv6TargetCapable   *bool `json:"ipv6TargetCapable"`
		} `json:"clientEgressCapabilities"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("unmarshal environment: %v", err)
	}
	caps := wire.Capabilities
	if caps == nil {
		t.Fatal("the login environment carries no clientEgressCapabilities")
	}
	if caps.Version == nil {
		t.Fatal("clientEgressCapabilities carries no version; every server treats that as 0")
	}
	if *caps.Version < 1 {
		t.Fatalf("clientEgressCapabilities.version = %d; every server skips egress-config below 1",
			*caps.Version)
	}
	if caps.EgressCapable == nil || !*caps.EgressCapable {
		t.Error("egressCapable is not true, but an egress needs only ordinary sockets")
	}
	if caps.ConsumerCapable == nil || *caps.ConsumerCapable != egressRouteTakeoverSupported {
		t.Errorf("consumerCapable = %v, but this build's route takeover support is %v",
			caps.ConsumerCapable, egressRouteTakeoverSupported)
	}
	// Phase one carries address targets only; claiming more would invite a server to send what
	// this build refuses.
	if caps.DomainTargetCapable == nil || *caps.DomainTargetCapable {
		t.Error("domainTargetCapable must be present and false in phase one")
	}
	if caps.IPv6TargetCapable == nil || *caps.IPv6TargetCapable {
		t.Error("ipv6TargetCapable must be present and false in phase one")
	}
}
