package client

import (
	"container/list"
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Phase two of peer egress on the egress side: the names consumers bind to their fake addresses,
// and the choice of the address a named flow is dialled to. See protocol/spec/peer-egress-dns.md.

// normalizeEgressName is how a query name, a rule match and a bound name are compared: no trailing
// dots, lower case.
func normalizeEgressName(name string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
}

// validEgressName reports whether a name is one this implementation will resolve: ASCII labels of
// 1-63 bytes from a-z, 0-9 and '-', not starting or ending with '-', at least two labels, at most
// 253 bytes, and not all digits (which would be an address). IDN must arrive as punycode.
func validEgressName(name string) bool {
	text := normalizeEgressName(name)
	if text == "" || len(text) > 253 {
		return false
	}
	labels := strings.Split(text, ".")
	if len(labels) < 2 {
		return false
	}
	numeric := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c == '-':
				numeric = false
			case c >= '0' && c <= '9':
			default:
				return false
			}
		}
	}
	return !numeric
}

// egressNameCapacity bounds the bindings one egress keeps. A binding is a few bytes, and it is only
// ever read when a flow opens, so the cap is there to bound memory against a consumer that binds
// without end rather than to be reached in use.
const (
	egressNameCapacity            = 65536
	egressNameCapacityPerConsumer = 4096
)

type egressNameKey struct {
	consumer int64
	address  uint32
}

type egressNameEntry struct {
	key  egressNameKey
	name string
}

// egressNameTable holds the names consumers bound to their fake addresses with name-bind, kept by
// most recent use. Not safe for concurrent use; the runtime's lock covers it.
type egressNameTable struct {
	entries     map[egressNameKey]*list.Element
	order       *list.List // front is the most recently used
	perConsumer map[int64]int
}

func newEgressNameTable() *egressNameTable {
	return &egressNameTable{entries: map[egressNameKey]*list.Element{}, order: list.New(), perConsumer: map[int64]int{}}
}

// bind records or replaces a consumer's name for an address. The name must already be valid.
func (t *egressNameTable) bind(consumer int64, address uint32, name string) {
	key := egressNameKey{consumer, address}
	if element, ok := t.entries[key]; ok {
		element.Value.(*egressNameEntry).name = name
		t.order.MoveToFront(element)
		return
	}
	for t.perConsumer[consumer] >= egressNameCapacityPerConsumer {
		t.evictOldest(func(entry *egressNameEntry) bool { return entry.key.consumer == consumer })
	}
	for t.order.Len() >= egressNameCapacity {
		t.evictOldest(func(*egressNameEntry) bool { return true })
	}
	t.entries[key] = t.order.PushFront(&egressNameEntry{key: key, name: name})
	t.perConsumer[consumer]++
}

func (t *egressNameTable) evictOldest(selects func(*egressNameEntry) bool) {
	for element := t.order.Back(); element != nil; element = element.Prev() {
		if entry := element.Value.(*egressNameEntry); selects(entry) {
			t.remove(element)
			return
		}
	}
}

func (t *egressNameTable) remove(element *list.Element) {
	entry := element.Value.(*egressNameEntry)
	t.order.Remove(element)
	delete(t.entries, entry.key)
	if remaining := t.perConsumer[entry.key.consumer] - 1; remaining > 0 {
		t.perConsumer[entry.key.consumer] = remaining
	} else {
		delete(t.perConsumer, entry.key.consumer)
	}
}

// lookup returns the name a consumer bound to an address, refreshing it.
func (t *egressNameTable) lookup(consumer int64, address uint32) (string, bool) {
	element, ok := t.entries[egressNameKey{consumer, address}]
	if !ok {
		return "", false
	}
	t.order.MoveToFront(element)
	return element.Value.(*egressNameEntry).name, true
}

// dropConsumer forgets every binding of a consumer, for when it is revoked.
func (t *egressNameTable) dropConsumer(consumer int64) {
	for element := t.order.Front(); element != nil; {
		next := element.Next()
		if element.Value.(*egressNameEntry).key.consumer == consumer {
			t.remove(element)
		}
		element = next
	}
}

func (t *egressNameTable) size() int { return t.order.Len() }

// egressResolveFunc resolves a name to the addresses a flow to it may be dialled to, in the order
// they should be tried.
type egressResolveFunc func(name string) ([]netip.Addr, error)

// egressIPv6TargetCapable says this egress connects to IPv6 targets, and so announces
// ipv6TargetCapable: a name with no A record is dialled over its AAAA records
// (protocol/spec/peer-egress-dns.md). Only the egress's own socket is IPv6; the consumer still
// reaches the flow at its IPv4 fake address.
const egressIPv6TargetCapable = true

// egressNameResolveTimeout bounds a lookup. It is charged against the flow's own connect, which
// the consumer's application is waiting on either way.
const egressNameResolveTimeout = 5 * time.Second

// defaultEgressResolve uses this device's own resolver: the egress resolves in its own network,
// which is the point of sending the name rather than an address.
//
// A records first; AAAA only for a name that has none. An address of either family then goes
// through the same authorization, so a name rebound to an IPv6 loopback or private address is
// refused like an IPv4 one.
func defaultEgressResolve(name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), egressNameResolveTimeout)
	defer cancel()
	found, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	a := make([]netip.Addr, 0, len(found))
	for _, address := range found {
		if address = address.Unmap(); address.Is4() {
			a = append(a, address)
		}
	}
	if len(a) > 0 || !egressIPv6TargetCapable {
		return a, err
	}
	found, err6 := net.DefaultResolver.LookupNetIP(ctx, "ip6", name)
	aaaa := make([]netip.Addr, 0, len(found))
	for _, address := range found {
		// An IPv4-mapped answer stays mapped: the forced-deny list refuses it as such rather than
		// letting an AAAA record stand in for an IPv4 address.
		if address.Is6() {
			aaaa = append(aaaa, address)
		}
	}
	if len(aaaa) == 0 && err != nil {
		return nil, err
	}
	return aaaa, err6
}

// egressDialCandidates is the order a name's addresses are tried in: its A records, or, when it has
// none and this egress connects to IPv6 targets, its AAAA records.
func egressDialCandidates(a, aaaa []netip.Addr, ipv6Capable bool) []netip.Addr {
	if len(a) > 0 || !ipv6Capable {
		return a
	}
	return aaaa
}

// formatEgressNetAddr writes an address the way the judgment reads it: dotted for IPv4 and RFC 5952
// for IPv6, never the dotted form net/netip uses for an IPv4-mapped address.
func formatEgressNetAddr(address netip.Addr) string {
	if address.Is4() {
		return address.String()
	}
	return formatEgressAddress6(address.As16())
}

// chooseEgressAddress picks the address a named flow is dialled to: the first resolved address the
// authorization allows. With none allowed, the first address's refusal is the answer, so the code
// the consumer sees is about the address it would have gone to. With nothing resolved, the name
// did not resolve.
func chooseEgressAddress(addresses []netip.Addr, authorize func(netip.Addr) string) (netip.Addr, string) {
	if len(addresses) == 0 {
		return netip.Addr{}, egressCodeNameUnresolved
	}
	first := ""
	for _, address := range addresses {
		code := authorize(address)
		if code == egressCodeAllowed {
			return address, egressCodeAllowed
		}
		if first == "" {
			first = code
		}
	}
	return netip.Addr{}, first
}
