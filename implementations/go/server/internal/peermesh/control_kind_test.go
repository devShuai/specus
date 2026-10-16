package peermesh

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSignalTargetsPeerMatchesServerAdmissionKinds(t *testing.T) {
	for _, kind := range []string{TypePathReport, TypeTrafficReport, TypeDeviceReport, TypeServiceReport, ControlTypeEgressReport, TypeClose, TypeConfig, TypeRoster, TypeSessionGrant, TypeServiceCatalog, ControlTypeEgressConfig, ControlTypeEgressCatalog} {
		t.Run(kind, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"type": kind})
			if err != nil || SignalTargetsPeer(string(body)) {
				t.Fatalf("server operation leased client-requested target: %s / %v", body, err)
			}
		})
	}
	for _, kind := range []string{TypeCandidates, "offer", "answer", "peer-probe"} {
		body, _ := json.Marshal(map[string]any{"type": kind})
		if !SignalTargetsPeer(string(body)) {
			t.Fatalf("forwarded signal omitted target lifecycle gate: %s", body)
		}
	}
	for _, body := range []string{"{", `[]`, `{"type":1}`, `{}`, `{"type":" "}`, `{"type":"candidates","type":"roster"}`, `{"type":"\u0072oster"}`} {
		if SignalTargetsPeer(body) {
			t.Fatalf("invalid/server-only input acquired target gate: %s", body)
		}
	}
}

func TestServerOnlyControlTypeRejectsCaseAndSpaceVariants(t *testing.T) {
	for _, kind := range []string{TypeConfig, TypeRoster, TypeSessionGrant, TypeServiceCatalog, ControlTypeEgressConfig, ControlTypeEgressCatalog} {
		for _, variant := range []string{kind, strings.ToUpper(kind), " " + kind + " "} {
			if !serverOnlyControlType(variant) {
				t.Fatalf("server-only type became client-forwardable: %q", variant)
			}
		}
	}
	if serverOnlyControlType(TypeCandidates) || serverOnlyControlType(TypeClose) {
		t.Fatal("client negotiation/close was classified as server-only")
	}
}
