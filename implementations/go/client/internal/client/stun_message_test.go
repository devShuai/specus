package client

import (
	"net"
	"testing"
)

func TestStunRFC5780AttributesRoundTrip(t *testing.T) {
	tx := newStunTransactionID()
	origin := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 3478}
	other := &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 3479}
	message := newStunMessage(
		stunBindingSuccess,
		tx,
		stunAttrResponseOriginValue(origin),
		stunAttrOtherAddressValue(other),
		stunAttrChangeRequestValue(true, true),
		stunAttrUnknownAttributesValue(stunAttrChangeRequest))

	parsed, err := parseStunMessage(message.bytes())
	if err != nil {
		t.Fatalf("parse STUN message: %v", err)
	}
	if decoded, ok := parsed.responseOrigin(); !ok || !sameNatEndpoint(decoded, origin) {
		t.Fatalf("response origin = %v, ok=%v", decoded, ok)
	}
	if decoded, ok := parsed.otherAddress(); !ok || !sameNatEndpoint(decoded, other) {
		t.Fatalf("other address = %v, ok=%v", decoded, ok)
	}
	changeIP, changePort, ok := parsed.changeRequest()
	if !ok || !changeIP || !changePort {
		t.Fatalf("change request = ip:%v port:%v ok:%v", changeIP, changePort, ok)
	}
	unknown := parsed.unknownAttributes()
	if len(unknown) != 1 || unknown[0] != stunAttrChangeRequest {
		t.Fatalf("unknown attributes = %v", unknown)
	}
}
