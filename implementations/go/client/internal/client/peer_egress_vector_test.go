package client

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Binds the client-side egress layer to the shared vectors under protocol/test-vectors, the same
// fixtures the four server runtimes read. The client keeps its own copy of the judgment layer
// because it is a separate Go module with no third-party dependencies; these vectors are what keep
// that copy from drifting.

func readEgressVector(t *testing.T, name string, target any) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(dir, "protocol", "test-vectors", name)
		if data, err := os.ReadFile(candidate); err == nil {
			if err := json.Unmarshal(data, target); err != nil {
				t.Fatalf("decode %s: %v", name, err)
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("cannot locate %s", name)
}

type egressFrameVector struct {
	Accept []struct {
		Name                 string `json:"name"`
		FrameHex             string `json:"frameHex"`
		Type                 int    `json:"type"`
		Flags                int    `json:"flags"`
		InnerPacketHex       string `json:"innerPacketHex"`
		InnerSourceIP        string `json:"innerSourceIp"`
		InnerDestinationIP   string `json:"innerDestinationIp"`
		InnerProtocol        string `json:"innerProtocol"`
		InnerSourcePort      int    `json:"innerSourcePort"`
		InnerDestinationPort int    `json:"innerDestinationPort"`
		ControlJSON          *struct {
			Type            string   `json:"type"`
			Protocol        string   `json:"protocol"`
			SourceIP        string   `json:"sourceIp"`
			SourcePort      int      `json:"sourcePort"`
			DestinationIP   string   `json:"destinationIp"`
			DestinationPort int      `json:"destinationPort"`
			Destinations    []string `json:"destinations"`
			Code            string   `json:"code"`
		} `json:"controlJson"`
		ControlCanonicalUTF8Hex string `json:"controlCanonicalUtf8Hex"`
	} `json:"accept"`
	Reject []struct {
		Name     string `json:"name"`
		FrameHex string `json:"frameHex"`
		Code     string `json:"code"`
	} `json:"reject"`
}

func TestEgressFrameAcceptsSharedVector(t *testing.T) {
	var vector egressFrameVector
	readEgressVector(t, "peer-egress-frame-v1.json", &vector)
	if len(vector.Accept) == 0 {
		t.Fatal("frame vector carried no accept cases")
	}
	for _, testCase := range vector.Accept {
		raw, err := hex.DecodeString(testCase.FrameHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", testCase.Name, err)
		}
		if !looksLikePeerEgressFrame(raw) {
			t.Errorf("%s: not recognised as an SPEG1 frame", testCase.Name)
			continue
		}
		frame, code := parsePeerEgressFrame(raw)
		if code != "" {
			t.Errorf("%s: rejected with %s", testCase.Name, code)
			continue
		}
		if int(frame.Type) != testCase.Type {
			t.Errorf("%s: type = %d, want %d", testCase.Name, frame.Type, testCase.Type)
		}
		if frame.Hop != (testCase.Flags&peerEgressFlagHop != 0) {
			t.Errorf("%s: hop = %v", testCase.Name, frame.Hop)
		}
		if testCase.InnerPacketHex != "" {
			if got := hex.EncodeToString(frame.Body); got != testCase.InnerPacketHex {
				t.Errorf("%s: body = %s", testCase.Name, got)
			}
			if frame.Inner.SourceIP != testCase.InnerSourceIP ||
				frame.Inner.DestinationIP != testCase.InnerDestinationIP {
				t.Errorf("%s: inner addresses = %s -> %s", testCase.Name,
					frame.Inner.SourceIP, frame.Inner.DestinationIP)
			}
			if frame.Inner.SourcePort != testCase.InnerSourcePort ||
				frame.Inner.DestinationPort != testCase.InnerDestinationPort {
				t.Errorf("%s: inner ports = %d -> %d", testCase.Name,
					frame.Inner.SourcePort, frame.Inner.DestinationPort)
			}
			wantProtocol := map[string]int{"tcp": ipv4ProtocolTCP, "udp": ipv4ProtocolUDP}[testCase.InnerProtocol]
			if wantProtocol != 0 && frame.Inner.Protocol != wantProtocol {
				t.Errorf("%s: inner protocol = %d, want %d", testCase.Name, frame.Inner.Protocol, wantProtocol)
			}
		}
		if frame.Type == peerEgressTypeControl {
			if _, ok := decodePeerEgressControl(frame.Body); !ok {
				t.Errorf("%s: control body did not decode", testCase.Name)
			}
		}
	}
}

// The assertions check the returned code, not just accept versus reject: a runtime that refuses for
// the wrong reason still leaves an operator unable to tell a malformed frame from an unsupported one.
func TestEgressFrameRejectsSharedVector(t *testing.T) {
	var vector egressFrameVector
	readEgressVector(t, "peer-egress-frame-v1.json", &vector)
	if len(vector.Reject) == 0 {
		t.Fatal("frame vector carried no reject cases")
	}
	for _, testCase := range vector.Reject {
		raw, err := hex.DecodeString(testCase.FrameHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", testCase.Name, err)
		}
		_, code := parsePeerEgressFrame(raw)
		if code != testCase.Code {
			t.Errorf("%s: code = %q, want %q", testCase.Name, code, testCase.Code)
		}
	}
}

type egressAuthzVector struct {
	ForcedDenyCIDRs []string     `json:"forcedDenyCidrs"`
	Policy          egressPolicy `json:"policy"`
	Cases           []struct {
		Name    string `json:"name"`
		Request struct {
			ConsumerClientID       int64    `json:"consumerClientId"`
			DestinationIP          string   `json:"destinationIp"`
			DestinationPort        int      `json:"destinationPort"`
			Protocol               string   `json:"protocol"`
			Hop                    bool     `json:"hop"`
			ActiveFlowsForConsumer int      `json:"activeFlowsForConsumer"`
			ActiveFlowsTotal       int      `json:"activeFlowsTotal"`
			LocalInterfaceCIDRs    []string `json:"localInterfaceCidrs"`
		} `json:"request"`
		Expect struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	} `json:"cases"`
	CrossLanguageCases []struct {
		Name    string `json:"name"`
		Request struct {
			ConsumerClientID       int64    `json:"consumerClientId"`
			DestinationIP          string   `json:"destinationIp"`
			DestinationPort        int      `json:"destinationPort"`
			Protocol               string   `json:"protocol"`
			Hop                    bool     `json:"hop"`
			ActiveFlowsForConsumer int      `json:"activeFlowsForConsumer"`
			ActiveFlowsTotal       int      `json:"activeFlowsTotal"`
			LocalInterfaceCIDRs    []string `json:"localInterfaceCidrs"`
		} `json:"request"`
		Expect struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	} `json:"crossLanguageCases"`
}

// The mesh network reaches the implementation through the deployment context rather than the static
// list, so it is lifted back out of the vector's forced-deny set by its prefix length.
func egressContextFor(vector egressAuthzVector) egressContext {
	context := newEgressContext()
	for _, text := range vector.ForcedDenyCIDRs {
		if cidr, ok := parseEgressCIDR(text); ok && cidr.prefixLen == 11 {
			context.MeshCIDR = text
		}
	}
	return context
}

func TestEgressAuthorizationMatchesSharedVector(t *testing.T) {
	var vector egressAuthzVector
	readEgressVector(t, "peer-egress-authz-v1.json", &vector)
	if len(vector.Cases) == 0 {
		t.Fatal("authorization vector carried no cases")
	}
	context := egressContextFor(vector)
	for _, testCase := range vector.Cases {
		request := egressRequest{
			ConsumerClientID:       testCase.Request.ConsumerClientID,
			DestinationIP:          testCase.Request.DestinationIP,
			DestinationPort:        testCase.Request.DestinationPort,
			Protocol:               testCase.Request.Protocol,
			Hop:                    testCase.Request.Hop,
			ActiveFlowsForConsumer: testCase.Request.ActiveFlowsForConsumer,
			ActiveFlowsTotal:       testCase.Request.ActiveFlowsTotal,
			LocalInterfaceCIDRs:    testCase.Request.LocalInterfaceCIDRs,
		}
		decision := authorizeEgressFlow(request, vector.Policy, true, context)
		if decision.Code != testCase.Expect.Code || decision.Allowed != testCase.Expect.Allowed {
			t.Errorf("%s: got %s/%v, want %s/%v", testCase.Name, decision.Code, decision.Allowed,
				testCase.Expect.Code, testCase.Expect.Allowed)
		}
	}
}

func TestEgressCrossLanguageSweepMatchesSharedVector(t *testing.T) {
	var vector egressAuthzVector
	readEgressVector(t, "peer-egress-authz-v1.json", &vector)
	if len(vector.CrossLanguageCases) < 100 {
		t.Fatalf("cross-language sweep carried only %d cases", len(vector.CrossLanguageCases))
	}
	context := egressContextFor(vector)
	for _, testCase := range vector.CrossLanguageCases {
		request := egressRequest{
			ConsumerClientID:       testCase.Request.ConsumerClientID,
			DestinationIP:          testCase.Request.DestinationIP,
			DestinationPort:        testCase.Request.DestinationPort,
			Protocol:               testCase.Request.Protocol,
			Hop:                    testCase.Request.Hop,
			ActiveFlowsForConsumer: testCase.Request.ActiveFlowsForConsumer,
			ActiveFlowsTotal:       testCase.Request.ActiveFlowsTotal,
			LocalInterfaceCIDRs:    testCase.Request.LocalInterfaceCIDRs,
		}
		decision := authorizeEgressFlow(request, vector.Policy, true, context)
		if decision.Code != testCase.Expect.Code || decision.Allowed != testCase.Expect.Allowed {
			t.Errorf("%s: got %s/%v, want %s/%v", testCase.Name, decision.Code, decision.Allowed,
				testCase.Expect.Code, testCase.Expect.Allowed)
		}
	}
}

// Control messages have to encode to the same bytes everywhere.
//
// The vector carries the canonical body for each one, and until this test existed nothing checked
// it in any runtime -- the claim that two implementations produce byte-identical frames rested on
// three separate readings of the same field order. Key order is not something a JSON library owes
// anyone, so it is asserted rather than assumed.
func TestEgressControlEncodingMatchesSharedVector(t *testing.T) {
	var vector egressFrameVector
	readEgressVector(t, "peer-egress-frame-v1.json", &vector)

	checked := 0
	for _, testCase := range vector.Accept {
		if testCase.ControlJSON == nil || testCase.ControlCanonicalUTF8Hex == "" {
			continue
		}
		checked++
		control := peerEgressControl{
			Type:            testCase.ControlJSON.Type,
			Protocol:        testCase.ControlJSON.Protocol,
			SourceIP:        testCase.ControlJSON.SourceIP,
			SourcePort:      testCase.ControlJSON.SourcePort,
			DestinationIP:   testCase.ControlJSON.DestinationIP,
			DestinationPort: testCase.ControlJSON.DestinationPort,
			Destinations:    testCase.ControlJSON.Destinations,
			Code:            testCase.ControlJSON.Code,
		}
		body, err := encodePeerEgressControl(control)
		if err != nil {
			t.Errorf("%s: encode: %v", testCase.Name, err)
			continue
		}
		if got := hex.EncodeToString(body); got != testCase.ControlCanonicalUTF8Hex {
			t.Errorf("%s: canonical body = %s, want %s", testCase.Name, got,
				testCase.ControlCanonicalUTF8Hex)
			continue
		}

		// And the whole frame, so the header the body travels in is pinned too.
		frame := encodePeerEgressFrame(peerEgressTypeControl, false, body)
		if got := hex.EncodeToString(frame); got != testCase.FrameHex {
			t.Errorf("%s: frame = %s, want %s", testCase.Name, got, testCase.FrameHex)
		}

		decoded, ok := decodePeerEgressControl(body)
		if !ok {
			t.Errorf("%s: the canonical body did not decode", testCase.Name)
			continue
		}
		if decoded.Type != control.Type || decoded.Code != control.Code ||
			decoded.DestinationIP != control.DestinationIP ||
			decoded.DestinationPort != control.DestinationPort {
			t.Errorf("%s: decoded = %+v, want %+v", testCase.Name, decoded, control)
		}
	}
	if checked == 0 {
		t.Fatal("frame vector carried no control cases")
	}
}
