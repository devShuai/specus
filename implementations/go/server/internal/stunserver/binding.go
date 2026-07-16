package stunserver

import (
	"encoding/binary"
	"fmt"
	"net"
)

type BindingService struct {
	topology        Topology
	software        string
	legacy          bool
	maxPaddingBytes int
}

type BindingResult struct {
	ResponseEndpoint EndpointID
	ResponseTarget   *net.UDPAddr
	Response         Message
}

func NewBindingService(topology Topology, software string, legacy bool, maxPaddingBytes int) *BindingService {
	if software == "" {
		software = defaultSoftware
	}
	return &BindingService{
		topology:        topology,
		software:        software,
		legacy:          legacy,
		maxPaddingBytes: max(0, min(65503, maxPaddingBytes)),
	}
}

func (s *BindingService) Process(request Message, remote *net.UDPAddr, incoming EndpointID, receivedBytes int) (BindingResult, error) {
	if request.Type != BindingRequest {
		return BindingResult{}, fmt.Errorf("only STUN Binding requests are supported")
	}
	if remote == nil || remote.IP == nil {
		return BindingResult{}, fmt.Errorf("remote endpoint is required")
	}
	responseTarget := cloneUDPAddr(remote)
	hasResponsePort := request.Has(AttrResponsePort)
	hasPadding := request.Has(AttrPadding)
	if hasResponsePort && hasPadding {
		return s.error(incoming, remote, request, 400, "response-port-and-padding-are-mutually-exclusive"), nil
	}
	if hasResponsePort {
		attr, _ := request.First(AttrResponsePort)
		port, ok := request.ResponsePort()
		if len(attr.Value) != 2 || !ok || port == 0 {
			return s.error(incoming, remote, request, 400, "invalid-response-port"), nil
		}
		responseTarget.Port = port
	}

	change := ChangeRequest{}
	if request.Has(AttrChangeRequest) {
		attr, _ := request.First(AttrChangeRequest)
		if len(attr.Value) != 4 {
			return s.error(incoming, responseTarget, request, 400, "invalid-change-request"), nil
		}
		flags := binary.BigEndian.Uint32(attr.Value)
		if flags&^uint32(changeRequestMask) != 0 {
			return s.error(incoming, responseTarget, request, 400, "invalid-change-request-flags"), nil
		}
		change, _ = request.ChangeRequest()
		if !s.topology.SupportsRFC5780() {
			return s.error(
				incoming,
				responseTarget,
				request,
				420,
				"unsupported-change-request",
				UnknownAttributesAttribute(AttrChangeRequest),
			), nil
		}
	}

	responseEndpoint, err := s.topology.ResponseEndpoint(incoming, change)
	if err != nil {
		return BindingResult{}, err
	}
	endpoint, ok := s.topology.Endpoint(responseEndpoint)
	if !ok {
		return BindingResult{}, fmt.Errorf("response endpoint %s is unavailable", responseEndpoint)
	}
	attrs := []Attribute{
		MappedAddressAttribute(remote),
		XorMappedAddressAttribute(remote, request.TransactionID),
		SoftwareAttribute(s.software),
	}
	if s.topology.SupportsRFC5780() {
		attrs = append(attrs, ResponseOriginAttribute(endpoint.Advertised))
		if otherID, found := s.topology.OtherEndpoint(incoming); found {
			if other, available := s.topology.Endpoint(otherID); available {
				attrs = append(attrs, OtherAddressAttribute(other.Advertised))
			}
		}
	} else if s.legacy {
		attrs = append(attrs, Attribute{
			Type:  AttrResponseOrigin,
			Value: encodeXorAddress(endpoint.Advertised, request.TransactionID),
		})
		if alternateID, found := s.topology.LegacyAlternatePortEndpoint(incoming); found {
			if alternate, available := s.topology.Endpoint(alternateID); available {
				attrs = append(attrs, Attribute{
					Type:  AttrOtherAddress,
					Value: encodeXorAddress(alternate.Advertised, request.TransactionID),
				})
			}
		}
	} else {
		attrs = append(attrs, ResponseOriginAttribute(endpoint.Advertised))
	}
	if hasPadding {
		padding, _ := request.First(AttrPadding)
		boundedByDatagram := max(0, receivedBytes-stunHeaderBytes)
		attrs = append(attrs, PaddingAttribute(min(len(padding.Value), min(s.maxPaddingBytes, boundedByDatagram))))
	}
	return BindingResult{
		ResponseEndpoint: responseEndpoint,
		ResponseTarget:   responseTarget,
		Response: Message{
			Type:          BindingSuccess,
			TransactionID: request.TransactionID,
			Attributes:    attrs,
		},
	}, nil
}

func (s *BindingService) error(
	endpoint EndpointID,
	target *net.UDPAddr,
	request Message,
	code int,
	reason string,
	extras ...Attribute,
) BindingResult {
	attrs := []Attribute{ErrorCodeAttribute(code, reason), SoftwareAttribute(s.software)}
	attrs = append(attrs, extras...)
	return BindingResult{
		ResponseEndpoint: endpoint,
		ResponseTarget:   cloneUDPAddr(target),
		Response: Message{
			Type:          BindingError,
			TransactionID: request.TransactionID,
			Attributes:    attrs,
		},
	}
}

func cloneUDPAddr(value *net.UDPAddr) *net.UDPAddr {
	if value == nil {
		return nil
	}
	return &net.UDPAddr{IP: cloneIP(value.IP), Port: value.Port, Zone: value.Zone}
}
