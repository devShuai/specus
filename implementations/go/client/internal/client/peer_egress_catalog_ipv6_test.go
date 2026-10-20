package client

import "testing"

// ipv6PacketCapable in egress-catalog (protocol/spec/peer-egress.md, IPv6 数据面, 能力): read like
// domainTargetCapable, so only a JSON true says an egress takes IPv6 packets.
func TestEgressCatalogReadsIPv6PacketCapable(t *testing.T) {
	reader := newEgressCatalogReader()
	payload := `{"type":"egress-catalog","revision":1,"egresses":[` +
		`{"clientId":2,"ipv6PacketCapable":true},{"clientId":3,"ipv6PacketCapable":"true"},` +
		`{"clientId":4,"ipv6PacketCapable":1},{"clientId":5},{"clientId":6,"ipv6TargetCapable":true}]}`
	if !reader.read([]byte(payload)) {
		t.Fatal("the catalogue was refused")
	}
	view := reader.view()
	for id, want := range map[int64]bool{2: true, 3: false, 4: false, 5: false, 6: false} {
		if got := view.Listed[id].IPv6PacketCapable; got != want {
			t.Errorf("egress %d: ipv6PacketCapable = %v, want %v", id, got, want)
		}
	}
	if ids := reader.ipv6CapableIDs(); len(ids) != 1 || ids[0] != 2 {
		t.Errorf("ipv6CapableIDs = %v", ids)
	}
}
