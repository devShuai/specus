package client

import (
	"net"
	"testing"
)

var (
	natPrimaryEndpoint = &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 3478}
	natOtherEndpoint   = &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 3479}
	natMappedEndpoint  = &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 52000}
)

func TestNatBehaviorDiscoveryEndpointIndependent(t *testing.T) {
	discovery := &natBehaviorDiscovery{}
	started, err := discovery.begin(natPrimaryEndpoint, natMappedEndpoint, natOtherEndpoint)
	if err != nil {
		t.Fatalf("begin discovery: %v", err)
	}
	filter := requireNextNatProbe(t, started, natProbeFilterChangeIPAndPort)
	if !sameNatEndpoint(filter.ExpectedResponseEndpoint, natOtherEndpoint) {
		t.Fatalf("filter expected response = %v, want %v", filter.ExpectedResponseEndpoint, natOtherEndpoint)
	}

	mappingIP := requireNextNatProbe(t,
		discovery.succeeded(filter.Generation, filter.Probe, natMappedEndpoint),
		natProbeMappingAlternateIP)
	if mappingIP.TargetEndpoint.Port != natPrimaryEndpoint.Port ||
		!mappingIP.TargetEndpoint.IP.Equal(natOtherEndpoint.IP) {
		t.Fatalf("mapping alternate-ip target = %v", mappingIP.TargetEndpoint)
	}
	mappingIPPort := requireNextNatProbe(t,
		discovery.succeeded(mappingIP.Generation, mappingIP.Probe, natMappedEndpoint),
		natProbeMappingAlternateIPPort)
	completed := discovery.succeeded(
		mappingIPPort.Generation,
		mappingIPPort.Probe,
		natMappedEndpoint).Snapshot

	if !completed.Complete ||
		completed.MappingBehavior != natBehaviorEndpointIndependent ||
		completed.FilteringBehavior != natBehaviorEndpointIndependent {
		t.Fatalf("unexpected snapshot: %+v", completed)
	}
}

func TestNatBehaviorDiscoveryAddressDependent(t *testing.T) {
	discovery := &natBehaviorDiscovery{}
	started, _ := discovery.begin(natPrimaryEndpoint, natMappedEndpoint, natOtherEndpoint)
	filterBoth := requireNextNatProbe(t, started, natProbeFilterChangeIPAndPort)
	filterPort := requireNextNatProbe(t,
		discovery.timedOut(filterBoth.Generation, filterBoth.Probe),
		natProbeFilterChangePort)
	if filterPort.ExpectedResponseEndpoint.Port != natOtherEndpoint.Port ||
		!filterPort.ExpectedResponseEndpoint.IP.Equal(natPrimaryEndpoint.IP) {
		t.Fatalf("change-port expected response = %v", filterPort.ExpectedResponseEndpoint)
	}
	mappingIP := requireNextNatProbe(t,
		discovery.succeeded(filterPort.Generation, filterPort.Probe, natMappedEndpoint),
		natProbeMappingAlternateIP)
	mappedII := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 52010}
	mappingIPPort := requireNextNatProbe(t,
		discovery.succeeded(mappingIP.Generation, mappingIP.Probe, mappedII),
		natProbeMappingAlternateIPPort)
	completed := discovery.succeeded(mappingIPPort.Generation, mappingIPPort.Probe, mappedII).Snapshot

	if completed.MappingBehavior != natBehaviorAddressDependent ||
		completed.FilteringBehavior != natBehaviorAddressDependent {
		t.Fatalf("unexpected snapshot: %+v", completed)
	}
}

func TestNatBehaviorDiscoveryAddressAndPortDependent(t *testing.T) {
	discovery := &natBehaviorDiscovery{}
	started, _ := discovery.begin(natPrimaryEndpoint, natMappedEndpoint, natOtherEndpoint)
	filterBoth := requireNextNatProbe(t, started, natProbeFilterChangeIPAndPort)
	filterPort := requireNextNatProbe(t,
		discovery.timedOut(filterBoth.Generation, filterBoth.Probe),
		natProbeFilterChangePort)
	mappingIP := requireNextNatProbe(t,
		discovery.timedOut(filterPort.Generation, filterPort.Probe),
		natProbeMappingAlternateIP)
	mappingIPPort := requireNextNatProbe(t,
		discovery.succeeded(mappingIP.Generation, mappingIP.Probe,
			&net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 52010}),
		natProbeMappingAlternateIPPort)
	completed := discovery.succeeded(mappingIPPort.Generation, mappingIPPort.Probe,
		&net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 52020}).Snapshot

	if completed.MappingBehavior != natBehaviorAddressAndPortDependent ||
		completed.FilteringBehavior != natBehaviorAddressAndPortDependent {
		t.Fatalf("unexpected snapshot: %+v", completed)
	}
}

func TestNatBehaviorDiscoveryUnsupportedFilteringStillMaps(t *testing.T) {
	discovery := &natBehaviorDiscovery{}
	started, _ := discovery.begin(natPrimaryEndpoint, natMappedEndpoint, natOtherEndpoint)
	filter := requireNextNatProbe(t, started, natProbeFilterChangeIPAndPort)
	mappingIP := requireNextNatProbe(t,
		discovery.failed(filter.Generation, filter.Probe, true),
		natProbeMappingAlternateIP)
	mappingIPPort := requireNextNatProbe(t,
		discovery.succeeded(mappingIP.Generation, mappingIP.Probe, natMappedEndpoint),
		natProbeMappingAlternateIPPort)
	completed := discovery.succeeded(mappingIPPort.Generation, mappingIPPort.Probe, natMappedEndpoint).Snapshot

	if completed.MappingBehavior != natBehaviorEndpointIndependent ||
		completed.FilteringBehavior != natBehaviorUnsupported {
		t.Fatalf("unexpected snapshot: %+v", completed)
	}
}

func requireNextNatProbe(
	t *testing.T,
	transition natBehaviorTransition,
	expected natBehaviorProbe,
) *natBehaviorProbeRequest {
	t.Helper()
	if !transition.Accepted || transition.NextProbe == nil || transition.NextProbe.Probe != expected {
		t.Fatalf("transition = %+v, want next probe %q", transition, expected)
	}
	return transition.NextProbe
}
