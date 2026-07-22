package client

import (
	"testing"
	"time"
)

func TestPeerPathMTUWireShape(t *testing.T) {
	var vector struct {
		Nonce          uint64 `json:"nonce"`
		InnerMTU       int    `json:"innerMtu"`
		ProbeLength    int    `json:"probeLength"`
		ProbeHeaderHex string `json:"probeHeaderHex"`
		AckHex         string `json:"ackHex"`
	}
	readRepositoryJSON(t, "protocol/test-vectors/peer-path-mtu-v2.json", &vector)
	probe := encodePeerPathMTUProbe(vector.Nonce, vector.InnerMTU)
	if len(probe) != vector.ProbeLength {
		t.Fatalf("probe length = %d", len(probe))
	}
	expectedProbeHeader := decodeVectorHex(t, vector.ProbeHeaderHex)
	if string(probe[:len(expectedProbeHeader)]) != string(expectedProbeHeader) {
		t.Fatalf("probe header = %x", probe[:len(expectedProbeHeader)])
	}
	decoded, ok := decodePeerPathMTU(probe)
	if !ok || !decoded.Probe || decoded.Nonce != vector.Nonce || decoded.InnerMTU != vector.InnerMTU {
		t.Fatalf("unexpected probe: %+v ok=%v", decoded, ok)
	}
	ack := encodePeerPathMTUAck(vector.Nonce, vector.InnerMTU)
	expectedAck := decodeVectorHex(t, vector.AckHex)
	if string(ack) != string(expectedAck) {
		t.Fatalf("ack = %x", ack)
	}
	decoded, ok = decodePeerPathMTU(ack)
	if !ok || decoded.Probe || decoded.Nonce != vector.Nonce || decoded.InnerMTU != vector.InnerMTU {
		t.Fatalf("unexpected ack: %+v ok=%v", decoded, ok)
	}
	if _, ok := decodePeerPathMTU(probe[:len(probe)-1]); ok {
		t.Fatal("truncated probe was accepted")
	}
}

func TestPeerPathMTUDiscoveryRetriesAndReduces(t *testing.T) {
	state := &peerPathMTUDiscovery{}
	transition := state.activate("direct|127.0.0.1:7000", 1280, nil, time.UnixMilli(1000))
	if transition.Probe == nil || transition.Probe.InnerMTU != 1280 {
		t.Fatalf("unexpected initial transition: %+v", transition)
	}
	nonce := transition.Probe.Nonce
	for attempt := 0; attempt < 2; attempt++ {
		transition = state.timeout(nonce, time.UnixMilli(int64(2000+attempt)))
		if transition.Probe == nil || transition.Probe.InnerMTU != 1280 {
			t.Fatalf("unexpected retry %d: %+v", attempt, transition)
		}
	}
	transition = state.timeout(nonce, time.UnixMilli(4000))
	if transition.Probe == nil || transition.Probe.InnerMTU >= 1280 {
		t.Fatalf("black-hole search did not reduce: %+v", transition)
	}
	if effective := state.effectiveMTU(1280); effective >= 1280 {
		t.Fatalf("effective MTU was not reduced: %d", effective)
	}
}

func TestPeerPathMTUSuccessCachesCeiling(t *testing.T) {
	state := &peerPathMTUDiscovery{}
	probe := state.activate("relay|target", 1280, nil, time.UnixMilli(1000)).Probe
	transition := state.acknowledge(probe.Nonce, probe.InnerMTU, time.UnixMilli(1050))
	if transition.CompletedMTU != 1280 || state.effectiveMTU(1280) != 1280 {
		t.Fatalf("unexpected completion: %+v", transition)
	}
}
