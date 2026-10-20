package client

import (
	"encoding/hex"
	"strconv"
	"testing"
)

// The egress side of the IPv6 data plane against protocol/test-vectors/peer-egress-ipv6-v1.json: the
// derived device address, and the frames an egress that announces ipv6PacketCapable reads.

type egressIPv6PlaneVector struct {
	MeshAddress struct {
		Prefix string `json:"prefix"`
		Derive []struct {
			MeshIPv4 string `json:"meshIpv4"`
			IPv6     string `json:"ipv6"`
		} `json:"derive"`
		Underive []struct {
			IPv6     string  `json:"ipv6"`
			MeshIPv4 *string `json:"meshIpv4"`
		} `json:"underive"`
	} `json:"meshAddress"`
	Frames struct {
		Accept []struct {
			Name                 string `json:"name"`
			Direction            string `json:"direction"`
			FrameHex             string `json:"frameHex"`
			InnerSourceIP        string `json:"innerSourceIp"`
			InnerDestinationIP   string `json:"innerDestinationIp"`
			InnerNextHeader      int    `json:"innerNextHeader"`
			InnerSourcePort      int    `json:"innerSourcePort"`
			InnerDestinationPort int    `json:"innerDestinationPort"`
			EgressCode           string `json:"egressCode"`
		} `json:"accept"`
		Reject []struct {
			Name     string `json:"name"`
			FrameHex string `json:"frameHex"`
			Code     string `json:"code"`
		} `json:"reject"`
	} `json:"frames"`
	Failure struct {
		ResetOnPacket struct {
			Cases []struct {
				Name      string `json:"name"`
				PacketHex string `json:"packetHex"`
				Expect    struct {
					PacketHex string `json:"packetHex"`
				} `json:"expect"`
			} `json:"cases"`
		} `json:"resetOnPacket"`
	} `json:"failure"`
}

func readEgressIPv6PlaneVector(t *testing.T) egressIPv6PlaneVector {
	t.Helper()
	var vector egressIPv6PlaneVector
	readEgressVector(t, "peer-egress-ipv6-v1.json", &vector)
	return vector
}

func decodeEgressHex(t *testing.T, name, text string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", name, err)
	}
	return raw
}

func TestEgressIPv6MeshAddressMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6PlaneVector(t)
	section := vector.MeshAddress
	if section.Prefix != egressMeshPrefix6 {
		t.Fatalf("prefix = %s, this build derives in %s", section.Prefix, egressMeshPrefix6)
	}
	if len(section.Derive) == 0 || len(section.Underive) == 0 {
		t.Fatal("the vector carried no meshAddress cases")
	}
	for _, testCase := range section.Derive {
		derived, ok := egressDeviceAddress6(testCase.MeshIPv4)
		if !ok {
			t.Errorf("%s: did not derive", testCase.MeshIPv4)
			continue
		}
		if got := formatEgressAddress6(derived); got != testCase.IPv6 {
			t.Errorf("%s: derived %s, want %s", testCase.MeshIPv4, got, testCase.IPv6)
		}
	}
	for _, testCase := range section.Underive {
		address, ok := parseEgressAddress6(testCase.IPv6)
		if !ok {
			t.Errorf("%s: does not parse", testCase.IPv6)
			continue
		}
		meshIPv4, inside := egressMeshIPv4From6(address)
		switch {
		case testCase.MeshIPv4 == nil && inside:
			t.Errorf("%s: read back %s, want nothing: it is outside the prefix", testCase.IPv6,
				formatEgressAddress(meshIPv4))
		case testCase.MeshIPv4 != nil && !inside:
			t.Errorf("%s: read back nothing, want %s", testCase.IPv6, *testCase.MeshIPv4)
		case testCase.MeshIPv4 != nil && formatEgressAddress(meshIPv4) != *testCase.MeshIPv4:
			t.Errorf("%s: read back %s, want %s", testCase.IPv6, formatEgressAddress(meshIPv4), *testCase.MeshIPv4)
		}
	}
}

// An egress with the data plane reads every accepted frame's tuple; one that refuses by protocol is
// refused by the runtime with the vector's code, and nothing is dialled for it.
func TestEgressIPv6FramesAcceptSharedVector(t *testing.T) {
	vector := readEgressIPv6PlaneVector(t)
	if len(vector.Frames.Accept) == 0 {
		t.Fatal("the vector carried no accepted frames")
	}
	refusals := 0
	for _, testCase := range vector.Frames.Accept {
		raw := decodeEgressHex(t, testCase.Name, testCase.FrameHex)
		frame, code := parsePeerEgressFrameFor(raw, true)
		if code != "" {
			t.Errorf("%s: rejected with %s", testCase.Name, code)
			continue
		}
		inner := frame.Inner
		if !inner.IPv6 || inner.SourceIP != testCase.InnerSourceIP || inner.DestinationIP != testCase.InnerDestinationIP ||
			inner.Protocol != testCase.InnerNextHeader || inner.SourcePort != testCase.InnerSourcePort ||
			inner.DestinationPort != testCase.InnerDestinationPort {
			t.Errorf("%s: parsed %+v", testCase.Name, inner)
		}
		// Without the data plane the same frame is refused as before.
		if _, code := parsePeerEgressFrame(raw); code != egressCodeIPv6Unsupported {
			t.Errorf("%s: without the data plane the code is %q, want %s", testCase.Name, code, egressCodeIPv6Unsupported)
		}
		if testCase.EgressCode == "" {
			continue
		}
		refusals++
		harness := newEgressHarness(t, "::/0")
		harness.runtime.handleFrameFrom(7, "100.96.0.1", raw, flowEpoch)
		if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != testCase.EgressCode {
			t.Errorf("%s: the runtime refused with %v, want %s", testCase.Name, codes, testCase.EgressCode)
		}
		if harness.dialCount() != 0 {
			t.Errorf("%s: a refused packet was dialled", testCase.Name)
		}
	}
	if refusals == 0 {
		t.Fatal("the vector carried no frame the runtime refuses")
	}
}

// The consumer-to-egress frames the runtime does not refuse open a flow to the IPv6 destination.
func TestEgressIPv6VectorFramesOpenFlows(t *testing.T) {
	vector := readEgressIPv6PlaneVector(t)
	opened := 0
	for _, testCase := range vector.Frames.Accept {
		if testCase.Direction != "consumer-to-egress" || testCase.EgressCode != "" {
			continue
		}
		opened++
		harness := newEgressHarness(t, "2001:db8:1::/48")
		harness.runtime.handleFrameFrom(7, "100.96.0.1", decodeEgressHex(t, testCase.Name, testCase.FrameHex), flowEpoch)
		harness.waitFor(testCase.Name+" to open", func() bool { return harness.runtime.flows.size() == 1 })
		harness.mu.Lock()
		dialed := append([]string(nil), harness.dialed...)
		harness.mu.Unlock()
		want := "[" + testCase.InnerDestinationIP + "]:" + strconv.Itoa(testCase.InnerDestinationPort)
		if len(dialed) != 1 || dialed[0] != want {
			t.Errorf("%s: dialled %v, want %s", testCase.Name, dialed, want)
		}
		if codes := harness.rejectCodes(); len(codes) != 0 {
			t.Errorf("%s: refused with %v", testCase.Name, codes)
		}
	}
	if opened == 0 {
		t.Fatal("the vector carried no consumer-to-egress frame to open")
	}
}

func TestEgressIPv6FramesRejectSharedVector(t *testing.T) {
	vector := readEgressIPv6PlaneVector(t)
	if len(vector.Frames.Reject) == 0 {
		t.Fatal("the vector carried no rejected frames")
	}
	for _, testCase := range vector.Frames.Reject {
		_, code := parsePeerEgressFrameFor(decodeEgressHex(t, testCase.Name, testCase.FrameHex), true)
		if code != testCase.Code {
			t.Errorf("%s: code = %q, want %q", testCase.Name, code, testCase.Code)
		}
	}
}

// The returning SYN-ACK in the vector is exactly what the codec writes for the same segment: header
// fields, hop limit and the checksum over the RFC 8200 pseudo-header.
func TestEgressIPv6SegmentEncodingMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6PlaneVector(t)
	for _, testCase := range vector.Frames.Accept {
		if testCase.Direction != "egress-to-consumer" {
			continue
		}
		raw := decodeEgressHex(t, testCase.Name, testCase.FrameHex)
		frame, code := parsePeerEgressFrameFor(raw, true)
		if code != "" {
			t.Fatalf("%s: rejected with %s", testCase.Name, code)
		}
		segment, ok := parseTCPSegment6(frame.Body)
		if !ok {
			t.Fatalf("%s: the segment does not parse, or its checksum is wrong", testCase.Name)
		}
		if got := hex.EncodeToString(buildTCPSegment(segment)); got != hex.EncodeToString(frame.Body) {
			t.Errorf("%s: rebuilt %s, want %s", testCase.Name, got, hex.EncodeToString(frame.Body))
		}
	}
}

// The egress resets an unwanted IPv6 segment by the same RFC 793 rule the consumer does, so the
// vector's consumer-side resets are what buildTCPReset writes too.
func TestEgressIPv6ResetMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6PlaneVector(t)
	cases := vector.Failure.ResetOnPacket.Cases
	if len(cases) == 0 {
		t.Fatal("the vector carried no reset cases")
	}
	for _, testCase := range cases {
		segment, ok := parseTCPSegment6(decodeEgressHex(t, testCase.Name, testCase.PacketHex))
		if !ok {
			t.Fatalf("%s: the packet does not parse", testCase.Name)
		}
		if got := hex.EncodeToString(buildTCPReset(segment)); got != testCase.Expect.PacketHex {
			t.Errorf("%s: reset %s, want %s", testCase.Name, got, testCase.Expect.PacketHex)
		}
	}
}

func TestEgressIPv6DatagramRoundTrips(t *testing.T) {
	original := udpDatagram{
		IPv6:            true,
		SourceIP6:       egressMeshAddress6(testAddr(t, "100.96.0.1")),
		DestinationIP6:  mustEgressAddress6(t, "2001:db8:1::35"),
		SourcePort:      51000,
		DestinationPort: 53,
		Payload:         []byte("query"),
	}
	packet := buildUDPDatagram(original)
	if packet[0] != 0x60 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0 || packet[7] != ipv6HopLimit {
		t.Fatalf("header = %x", packet[:8])
	}
	parsed, ok := parseUDPDatagram6(packet)
	if !ok {
		t.Fatal("a datagram the codec wrote does not parse")
	}
	if parsed.SourceIP6 != original.SourceIP6 || parsed.DestinationIP6 != original.DestinationIP6 ||
		parsed.SourcePort != original.SourcePort || parsed.DestinationPort != original.DestinationPort ||
		string(parsed.Payload) != "query" {
		t.Errorf("round trip = %+v", parsed)
	}
	// IPv6 has no optional UDP checksum.
	zeroed := append([]byte(nil), packet...)
	zeroed[ipv6HeaderLen+6], zeroed[ipv6HeaderLen+7] = 0, 0
	if _, ok := parseUDPDatagram6(zeroed); ok {
		t.Error("a datagram without a checksum was accepted")
	}
	damaged := append([]byte(nil), packet...)
	damaged[len(damaged)-1] ^= 0xff
	if _, ok := parseUDPDatagram6(damaged); ok {
		t.Error("a datagram with a wrong checksum was accepted")
	}
}

func mustEgressAddress6(t *testing.T, text string) [16]byte {
	t.Helper()
	address, ok := parseEgressAddress6(text)
	if !ok {
		t.Fatalf("%s did not parse", text)
	}
	return address
}
