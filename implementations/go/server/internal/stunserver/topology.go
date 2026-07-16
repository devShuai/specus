package stunserver

import (
	"fmt"
	"net"
	"strings"
)

type EndpointID string

const (
	Primary              EndpointID = "primary-primary"
	PrimaryAlternatePort EndpointID = "primary-alternate"
	AlternatePrimaryPort EndpointID = "alternate-primary"
	Alternate            EndpointID = "alternate-alternate"
)

type Endpoint struct {
	ID         EndpointID
	Bind       *net.UDPAddr
	Advertised *net.UDPAddr
}

type Topology struct {
	endpoints map[EndpointID]Endpoint
	order     []EndpointID
	rfc5780   bool
}

func NewBasicTopology(primary Endpoint, alternatePort *Endpoint) (Topology, error) {
	if err := validateEndpoint(primary, Primary); err != nil {
		return Topology{}, err
	}
	result := Topology{
		endpoints: map[EndpointID]Endpoint{Primary: cloneEndpoint(primary)},
		order:     []EndpointID{Primary},
	}
	if alternatePort != nil {
		if err := validateEndpoint(*alternatePort, PrimaryAlternatePort); err != nil {
			return Topology{}, err
		}
		if !primary.Bind.IP.Equal(alternatePort.Bind.IP) ||
			!primary.Advertised.IP.Equal(alternatePort.Advertised.IP) ||
			primary.Bind.Port == alternatePort.Bind.Port {
			return Topology{}, fmt.Errorf("basic topology alternate endpoint must use the primary IP and a distinct port")
		}
		result.endpoints[PrimaryAlternatePort] = cloneEndpoint(*alternatePort)
		result.order = append(result.order, PrimaryAlternatePort)
	}
	return result, nil
}

func NewRFC5780Topology(primary, primaryAlternate, alternatePrimary, alternate Endpoint) (Topology, error) {
	items := []struct {
		endpoint Endpoint
		id       EndpointID
	}{
		{primary, Primary},
		{primaryAlternate, PrimaryAlternatePort},
		{alternatePrimary, AlternatePrimaryPort},
		{alternate, Alternate},
	}
	result := Topology{
		endpoints: make(map[EndpointID]Endpoint, 4),
		order:     []EndpointID{Primary, PrimaryAlternatePort, AlternatePrimaryPort, Alternate},
		rfc5780:   true,
	}
	for _, item := range items {
		if err := validateEndpoint(item.endpoint, item.id); err != nil {
			return Topology{}, err
		}
		result.endpoints[item.id] = cloneEndpoint(item.endpoint)
	}
	if primary.Bind.IP.IsUnspecified() || alternatePrimary.Bind.IP.IsUnspecified() {
		return Topology{}, fmt.Errorf("RFC 5780 requires two explicit bind IP addresses")
	}
	if primary.Bind.IP.Equal(alternatePrimary.Bind.IP) ||
		primary.Advertised.IP.Equal(alternatePrimary.Advertised.IP) {
		return Topology{}, fmt.Errorf("RFC 5780 requires two distinct bind and advertised IP addresses")
	}
	if addressFamily(primary.Advertised.IP) != addressFamily(alternatePrimary.Advertised.IP) {
		return Topology{}, fmt.Errorf("RFC 5780 endpoints must use the same address family")
	}
	if !primary.Bind.IP.Equal(primaryAlternate.Bind.IP) ||
		!primary.Advertised.IP.Equal(primaryAlternate.Advertised.IP) ||
		!alternatePrimary.Bind.IP.Equal(alternate.Bind.IP) ||
		!alternatePrimary.Advertised.IP.Equal(alternate.Advertised.IP) {
		return Topology{}, fmt.Errorf("RFC 5780 endpoints in each address slot must share an IP")
	}
	if primary.Bind.Port != alternatePrimary.Bind.Port ||
		primaryAlternate.Bind.Port != alternate.Bind.Port ||
		primary.Bind.Port == primaryAlternate.Bind.Port {
		return Topology{}, fmt.Errorf("RFC 5780 requires the same two distinct ports on both IP addresses")
	}
	return result, nil
}

func (t Topology) SupportsRFC5780() bool {
	return t.rfc5780
}

func (t Topology) Endpoint(id EndpointID) (Endpoint, bool) {
	value, ok := t.endpoints[id]
	return cloneEndpoint(value), ok
}

func (t Topology) Endpoints() []Endpoint {
	result := make([]Endpoint, 0, len(t.order))
	for _, id := range t.order {
		result = append(result, cloneEndpoint(t.endpoints[id]))
	}
	return result
}

func (t Topology) ResponseEndpoint(incoming EndpointID, request ChangeRequest) (EndpointID, error) {
	if _, ok := t.endpoints[incoming]; !ok {
		return "", fmt.Errorf("unknown incoming endpoint %s", incoming)
	}
	if !t.rfc5780 || (!request.ChangeIP && !request.ChangePort) {
		return incoming, nil
	}
	addressAlternate := incoming == AlternatePrimaryPort || incoming == Alternate
	portAlternate := incoming == PrimaryAlternatePort || incoming == Alternate
	if request.ChangeIP {
		addressAlternate = !addressAlternate
	}
	if request.ChangePort {
		portAlternate = !portAlternate
	}
	return endpointID(addressAlternate, portAlternate), nil
}

func (t Topology) OtherEndpoint(incoming EndpointID) (EndpointID, bool) {
	if !t.rfc5780 {
		return "", false
	}
	addressAlternate := incoming == AlternatePrimaryPort || incoming == Alternate
	portAlternate := incoming == PrimaryAlternatePort || incoming == Alternate
	id := endpointID(!addressAlternate, !portAlternate)
	_, ok := t.endpoints[id]
	return id, ok
}

func (t Topology) LegacyAlternatePortEndpoint(incoming EndpointID) (EndpointID, bool) {
	switch incoming {
	case Primary:
		_, ok := t.endpoints[PrimaryAlternatePort]
		return PrimaryAlternatePort, ok
	case PrimaryAlternatePort:
		_, ok := t.endpoints[Primary]
		return Primary, ok
	case AlternatePrimaryPort:
		_, ok := t.endpoints[Alternate]
		return Alternate, ok
	case Alternate:
		_, ok := t.endpoints[AlternatePrimaryPort]
		return AlternatePrimaryPort, ok
	default:
		return "", false
	}
}

func (t Topology) Describe() string {
	values := make([]string, 0, len(t.order))
	for _, id := range t.order {
		value := t.endpoints[id]
		values = append(values, fmt.Sprintf("%s[bind=%s, advertised=%s]", id, value.Bind, value.Advertised))
	}
	return strings.Join(values, ", ")
}

func endpointID(alternateAddress, alternatePort bool) EndpointID {
	switch {
	case alternateAddress && alternatePort:
		return Alternate
	case alternateAddress:
		return AlternatePrimaryPort
	case alternatePort:
		return PrimaryAlternatePort
	default:
		return Primary
	}
}

func validateEndpoint(endpoint Endpoint, expected EndpointID) error {
	if endpoint.ID != expected {
		return fmt.Errorf("expected endpoint %s but got %s", expected, endpoint.ID)
	}
	if endpoint.Bind == nil || endpoint.Advertised == nil ||
		endpoint.Bind.IP == nil || endpoint.Advertised.IP == nil {
		return fmt.Errorf("endpoint %s addresses are required", expected)
	}
	if endpoint.Bind.Port <= 0 || endpoint.Bind.Port > 65535 ||
		endpoint.Advertised.Port != endpoint.Bind.Port {
		return fmt.Errorf("endpoint %s ports are invalid", expected)
	}
	if addressFamily(endpoint.Bind.IP) != addressFamily(endpoint.Advertised.IP) {
		return fmt.Errorf("endpoint %s bind and advertised addresses must use the same family", expected)
	}
	if endpoint.Advertised.IP.IsUnspecified() {
		return fmt.Errorf("endpoint %s advertised address cannot be wildcard", expected)
	}
	return nil
}

func addressFamily(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	if ip.To16() != nil {
		return 6
	}
	return 0
}

func cloneEndpoint(value Endpoint) Endpoint {
	if value.Bind == nil || value.Advertised == nil {
		return value
	}
	value.Bind = &net.UDPAddr{IP: cloneIP(value.Bind.IP), Port: value.Bind.Port, Zone: value.Bind.Zone}
	value.Advertised = &net.UDPAddr{IP: cloneIP(value.Advertised.IP), Port: value.Advertised.Port, Zone: value.Advertised.Zone}
	return value
}
