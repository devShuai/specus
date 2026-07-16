package client

import (
	"fmt"
	"net"
	"sync"
)

const (
	natDiscoveryRFC5780 = "RFC5780"
	natDiscoveryBasic   = "BASIC"

	natBehaviorEndpointIndependent     = "ENDPOINT_INDEPENDENT"
	natBehaviorAddressDependent        = "ADDRESS_DEPENDENT"
	natBehaviorAddressAndPortDependent = "ADDRESS_AND_PORT_DEPENDENT"
	natBehaviorUnknown                 = "UNKNOWN"
	natBehaviorUnsupported             = "UNSUPPORTED"
)

type natBehaviorProbe string

const (
	natProbeFilterChangeIPAndPort  natBehaviorProbe = "rfc5780-filter-change-ip-port"
	natProbeFilterChangePort       natBehaviorProbe = "rfc5780-filter-change-port"
	natProbeMappingAlternateIP     natBehaviorProbe = "rfc5780-mapping-alternate-ip"
	natProbeMappingAlternateIPPort natBehaviorProbe = "rfc5780-mapping-alternate-ip-port"
)

type natBehaviorProbeRequest struct {
	Generation               int
	Probe                    natBehaviorProbe
	TargetEndpoint           *net.UDPAddr
	ExpectedResponseEndpoint *net.UDPAddr
	ChangeIP                 bool
	ChangePort               bool
}

type natBehaviorSnapshot struct {
	Generation        int
	Discovery         string
	MappingBehavior   string
	FilteringBehavior string
	MappedEndpoint    *net.UDPAddr
	Complete          bool
}

type natBehaviorTransition struct {
	Accepted  bool
	NextProbe *natBehaviorProbeRequest
	Snapshot  natBehaviorSnapshot
}

type natBehaviorDiscovery struct {
	mu                        sync.Mutex
	generation                int
	pendingProbe              natBehaviorProbe
	primaryEndpoint           *net.UDPAddr
	otherEndpoint             *net.UDPAddr
	primaryMappedEndpoint     *net.UDPAddr
	alternateIPMappedEndpoint *net.UDPAddr
	mappingBehavior           string
	filteringBehavior         string
	complete                  bool
}

func (discovery *natBehaviorDiscovery) begin(
	primaryEndpoint *net.UDPAddr,
	primaryMappedEndpoint *net.UDPAddr,
	otherEndpoint *net.UDPAddr,
) (natBehaviorTransition, error) {
	discovery.mu.Lock()
	defer discovery.mu.Unlock()

	if err := requireNatEndpoint(primaryEndpoint, "primaryEndpoint"); err != nil {
		return natBehaviorTransition{}, err
	}
	if err := requireNatEndpoint(primaryMappedEndpoint, "primaryMappedEndpoint"); err != nil {
		return natBehaviorTransition{}, err
	}
	if err := requireNatEndpoint(otherEndpoint, "otherEndpoint"); err != nil {
		return natBehaviorTransition{}, err
	}
	if primaryEndpoint.IP.Equal(otherEndpoint.IP) || primaryEndpoint.Port == otherEndpoint.Port {
		return natBehaviorTransition{}, fmt.Errorf(
			"RFC 5780 discovery requires another IP address and another UDP port")
	}

	discovery.generation++
	discovery.primaryEndpoint = cloneUDPAddr(primaryEndpoint)
	discovery.primaryMappedEndpoint = cloneUDPAddr(primaryMappedEndpoint)
	discovery.otherEndpoint = cloneUDPAddr(otherEndpoint)
	discovery.alternateIPMappedEndpoint = nil
	discovery.mappingBehavior = ""
	discovery.filteringBehavior = ""
	discovery.complete = false
	return discovery.nextLocked(natProbeFilterChangeIPAndPort), nil
}

func (discovery *natBehaviorDiscovery) succeeded(
	expectedGeneration int,
	probe natBehaviorProbe,
	mappedEndpoint *net.UDPAddr,
) natBehaviorTransition {
	discovery.mu.Lock()
	defer discovery.mu.Unlock()

	if !discovery.acceptsLocked(expectedGeneration, probe) {
		return discovery.ignoredLocked()
	}
	if requireNatEndpoint(mappedEndpoint, "mappedEndpoint") != nil {
		return discovery.failedMappingLocked()
	}
	switch probe {
	case natProbeFilterChangeIPAndPort:
		discovery.filteringBehavior = natBehaviorEndpointIndependent
		return discovery.nextLocked(natProbeMappingAlternateIP)
	case natProbeFilterChangePort:
		discovery.filteringBehavior = natBehaviorAddressDependent
		return discovery.nextLocked(natProbeMappingAlternateIP)
	case natProbeMappingAlternateIP:
		discovery.alternateIPMappedEndpoint = cloneUDPAddr(mappedEndpoint)
		return discovery.nextLocked(natProbeMappingAlternateIPPort)
	case natProbeMappingAlternateIPPort:
		return discovery.finishMappingLocked(mappedEndpoint)
	default:
		return discovery.ignoredLocked()
	}
}

func (discovery *natBehaviorDiscovery) timedOut(
	expectedGeneration int,
	probe natBehaviorProbe,
) natBehaviorTransition {
	discovery.mu.Lock()
	defer discovery.mu.Unlock()

	if !discovery.acceptsLocked(expectedGeneration, probe) {
		return discovery.ignoredLocked()
	}
	switch probe {
	case natProbeFilterChangeIPAndPort:
		return discovery.nextLocked(natProbeFilterChangePort)
	case natProbeFilterChangePort:
		discovery.filteringBehavior = natBehaviorAddressAndPortDependent
		return discovery.nextLocked(natProbeMappingAlternateIP)
	case natProbeMappingAlternateIP, natProbeMappingAlternateIPPort:
		return discovery.failedMappingLocked()
	default:
		return discovery.ignoredLocked()
	}
}

func (discovery *natBehaviorDiscovery) failed(
	expectedGeneration int,
	probe natBehaviorProbe,
	unsupported bool,
) natBehaviorTransition {
	discovery.mu.Lock()
	defer discovery.mu.Unlock()

	if !discovery.acceptsLocked(expectedGeneration, probe) {
		return discovery.ignoredLocked()
	}
	switch probe {
	case natProbeFilterChangeIPAndPort, natProbeFilterChangePort:
		if unsupported {
			discovery.filteringBehavior = natBehaviorUnsupported
		} else {
			discovery.filteringBehavior = natBehaviorUnknown
		}
		return discovery.nextLocked(natProbeMappingAlternateIP)
	case natProbeMappingAlternateIP, natProbeMappingAlternateIPPort:
		return discovery.failedMappingLocked()
	default:
		return discovery.ignoredLocked()
	}
}

func (discovery *natBehaviorDiscovery) snapshot() natBehaviorSnapshot {
	discovery.mu.Lock()
	defer discovery.mu.Unlock()
	return discovery.snapshotLocked()
}

func (discovery *natBehaviorDiscovery) finishMappingLocked(
	alternateIPAndPortMappedEndpoint *net.UDPAddr,
) natBehaviorTransition {
	if sameNatEndpoint(discovery.primaryMappedEndpoint, discovery.alternateIPMappedEndpoint) {
		discovery.mappingBehavior = natBehaviorEndpointIndependent
	} else if sameNatEndpoint(discovery.alternateIPMappedEndpoint, alternateIPAndPortMappedEndpoint) {
		discovery.mappingBehavior = natBehaviorAddressDependent
	} else {
		discovery.mappingBehavior = natBehaviorAddressAndPortDependent
	}
	discovery.pendingProbe = ""
	discovery.complete = true
	return discovery.acceptedLocked(nil)
}

func (discovery *natBehaviorDiscovery) failedMappingLocked() natBehaviorTransition {
	discovery.mappingBehavior = natBehaviorUnknown
	if discovery.filteringBehavior != natBehaviorEndpointIndependent &&
		discovery.filteringBehavior != natBehaviorUnsupported {
		discovery.filteringBehavior = natBehaviorUnknown
	}
	discovery.pendingProbe = ""
	discovery.complete = true
	return discovery.acceptedLocked(nil)
}

func (discovery *natBehaviorDiscovery) nextLocked(
	probe natBehaviorProbe,
) natBehaviorTransition {
	discovery.pendingProbe = probe
	request := discovery.requestLocked(probe)
	return discovery.acceptedLocked(&request)
}

func (discovery *natBehaviorDiscovery) requestLocked(
	probe natBehaviorProbe,
) natBehaviorProbeRequest {
	alternateIPPrimaryPort := &net.UDPAddr{
		IP:   append(net.IP(nil), discovery.otherEndpoint.IP...),
		Port: discovery.primaryEndpoint.Port,
	}
	primaryIPAlternatePort := &net.UDPAddr{
		IP:   append(net.IP(nil), discovery.primaryEndpoint.IP...),
		Port: discovery.otherEndpoint.Port,
	}
	request := natBehaviorProbeRequest{
		Generation: discovery.generation,
		Probe:      probe,
	}
	switch probe {
	case natProbeFilterChangeIPAndPort:
		request.TargetEndpoint = cloneUDPAddr(discovery.primaryEndpoint)
		request.ExpectedResponseEndpoint = cloneUDPAddr(discovery.otherEndpoint)
		request.ChangeIP = true
		request.ChangePort = true
	case natProbeFilterChangePort:
		request.TargetEndpoint = cloneUDPAddr(discovery.primaryEndpoint)
		request.ExpectedResponseEndpoint = primaryIPAlternatePort
		request.ChangePort = true
	case natProbeMappingAlternateIP:
		request.TargetEndpoint = alternateIPPrimaryPort
		request.ExpectedResponseEndpoint = cloneUDPAddr(alternateIPPrimaryPort)
	case natProbeMappingAlternateIPPort:
		request.TargetEndpoint = cloneUDPAddr(discovery.otherEndpoint)
		request.ExpectedResponseEndpoint = cloneUDPAddr(discovery.otherEndpoint)
	}
	return request
}

func (discovery *natBehaviorDiscovery) acceptsLocked(
	expectedGeneration int,
	probe natBehaviorProbe,
) bool {
	return expectedGeneration == discovery.generation &&
		probe != "" &&
		discovery.pendingProbe == probe &&
		!discovery.complete
}

func (discovery *natBehaviorDiscovery) acceptedLocked(
	nextProbe *natBehaviorProbeRequest,
) natBehaviorTransition {
	return natBehaviorTransition{
		Accepted:  true,
		NextProbe: nextProbe,
		Snapshot:  discovery.snapshotLocked(),
	}
}

func (discovery *natBehaviorDiscovery) ignoredLocked() natBehaviorTransition {
	return natBehaviorTransition{Snapshot: discovery.snapshotLocked()}
}

func (discovery *natBehaviorDiscovery) snapshotLocked() natBehaviorSnapshot {
	return natBehaviorSnapshot{
		Generation:        discovery.generation,
		Discovery:         natDiscoveryRFC5780,
		MappingBehavior:   discovery.mappingBehavior,
		FilteringBehavior: discovery.filteringBehavior,
		MappedEndpoint:    cloneUDPAddr(discovery.primaryMappedEndpoint),
		Complete:          discovery.complete,
	}
}

func requireNatEndpoint(endpoint *net.UDPAddr, name string) error {
	if endpoint == nil || endpoint.IP == nil || endpoint.IP.IsUnspecified() || endpoint.Port <= 0 {
		return fmt.Errorf("%s must be a resolved UDP endpoint", name)
	}
	return nil
}

func sameNatEndpoint(first, second *net.UDPAddr) bool {
	return first != nil &&
		second != nil &&
		first.Port == second.Port &&
		first.IP != nil &&
		second.IP != nil &&
		first.IP.Equal(second.IP)
}
