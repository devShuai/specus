package client

import (
	"sort"
	"time"
)

// The egress flow table: what is open right now, who opened it, and when it stops being allowed.
//
// TCP announces its own beginning and end, so its state machine could in principle track itself.
// UDP announces neither, so a session exists only because this table says it does, and ends only
// because an idle timer says it does. Both protocols share one table anyway, because the limits in
// the policy count flows rather than TCP flows: a consumer must not be able to exceed its quota by
// splitting traffic across protocols.
//
// Like the TCP state machine this holds no sockets and reads no clock. Time arrives as an argument
// so expiry is deterministic under test, and the caller keeps whatever handle it needs in Handle,
// which this file never inspects.

// egressFlowKey identifies one flow by its full inner four-tuple.
//
// Keying on the consumer's source port alone would be wrong, not merely coarse. Two datagrams
// leaving the same consumer port for different destinations are separate sessions; collapsing them
// onto one socket would send the second destination's traffic to the first.
type egressFlowKey struct {
	protocol     int
	consumerIP   uint32
	consumerPort uint16
	remoteIP     uint32
	remotePort   uint16
}

func (k egressFlowKey) protocolName() string { return egressProtocolName(k.protocol) }

// egressFlow is one live flow's accounting. The data plane owns the socket; this owns the fact that
// the socket is allowed to exist.
type egressFlow struct {
	Key      egressFlowKey
	Consumer int64
	OpenedAt time.Time
	LastSeen time.Time

	BytesToRemote   int64
	BytesFromRemote int64

	// Handle is whatever the caller attached: a tcpConn, a UDP socket, a cancel function. The
	// table stores it so that everything needed to tear a flow down travels with the entry that
	// authorises it, and never reads it.
	Handle any
}

// egressFlowTable holds every flow this node is currently forwarding.
//
// Not safe for concurrent use. The data plane serialises access through its own loop, and a mutex
// here would invite callers to hold a flow pointer past the point where the table still vouches
// for it.
type egressFlowTable struct {
	idleTimeout time.Duration
	flows       map[egressFlowKey]*egressFlow
	perConsumer map[int64]int
}

func newEgressFlowTable(idleTimeout time.Duration) *egressFlowTable {
	if idleTimeout <= 0 {
		idleTimeout = egressDefaultIdleTimeout
	}
	return &egressFlowTable{
		idleTimeout: idleTimeout,
		flows:       make(map[egressFlowKey]*egressFlow),
		perConsumer: make(map[int64]int),
	}
}

// egressDefaultIdleTimeout applies when the policy names no timeout. Five minutes is long enough
// not to cut a QUIC connection between its own keepalives, and short enough that a consumer that
// vanished stops holding a socket and a quota slot.
const egressDefaultIdleTimeout = 5 * time.Minute

func (t *egressFlowTable) size() int { return len(t.flows) }

// counts feeds the two limit checks in authorizeEgressFlow. It is read before the flow opens, so it
// deliberately excludes the flow being considered.
func (t *egressFlowTable) counts(consumer int64) (forConsumer int, total int) {
	return t.perConsumer[consumer], len(t.flows)
}

func (t *egressFlowTable) lookup(key egressFlowKey) (*egressFlow, bool) {
	flow, ok := t.flows[key]
	return flow, ok
}

// touch records activity. Idle expiry is measured from the last packet in either direction, so a
// flow that is only receiving stays alive.
func (t *egressFlowTable) touch(key egressFlowKey, now time.Time) {
	if flow, ok := t.flows[key]; ok {
		flow.LastSeen = now
	}
}

// open records an authorised flow. It returns false if the key is already present, which the caller
// must treat as "use the existing flow" rather than as an error: a retransmitted SYN or a second
// datagram arriving before the first finished opening is normal traffic, not an attack.
func (t *egressFlowTable) open(key egressFlowKey, consumer int64, now time.Time) (*egressFlow, bool) {
	if existing, ok := t.flows[key]; ok {
		existing.LastSeen = now
		return existing, false
	}
	flow := &egressFlow{Key: key, Consumer: consumer, OpenedAt: now, LastSeen: now}
	t.flows[key] = flow
	t.perConsumer[consumer]++
	return flow, true
}

// close removes a flow and returns it so the caller can release the socket it carries. Closing an
// unknown key is not an error; teardown races are ordinary.
func (t *egressFlowTable) close(key egressFlowKey) (*egressFlow, bool) {
	flow, ok := t.flows[key]
	if !ok {
		return nil, false
	}
	t.remove(flow)
	return flow, true
}

func (t *egressFlowTable) remove(flow *egressFlow) {
	delete(t.flows, flow.Key)
	if remaining := t.perConsumer[flow.Consumer] - 1; remaining > 0 {
		t.perConsumer[flow.Consumer] = remaining
	} else {
		// Dropping the entry rather than leaving a zero keeps the map bounded by live
		// consumers instead of by every consumer that ever connected.
		delete(t.perConsumer, flow.Consumer)
	}
}

// expire removes every flow idle for longer than the timeout and returns them for the caller to
// release. Without this a UDP session would never end, because nothing in UDP says it has.
func (t *egressFlowTable) expire(now time.Time) []*egressFlow {
	return t.reap(func(flow *egressFlow) bool {
		return now.Sub(flow.LastSeen) >= t.idleTimeout
	})
}

// revokeConsumer closes every flow belonging to one consumer, for the moment its authorization is
// withdrawn. A revoked consumer must stop being forwarded immediately, not when it next happens to
// open something.
func (t *egressFlowTable) revokeConsumer(consumer int64) []*egressFlow {
	return t.reap(func(flow *egressFlow) bool { return flow.Consumer == consumer })
}

// purgeDestinations closes every flow whose remote address falls inside one of the given prefixes.
// This serves the flow-purge control message, which a consumer sends when its own routing rules
// change and it wants the matching flows torn down rather than left to time out.
//
// An unparseable prefix is skipped rather than treated as matching everything. A malformed purge
// should close nothing, not the whole table.
func (t *egressFlowTable) purgeDestinations(destinations []string) []*egressFlow {
	return t.purgeConsumerDestinations(0, destinations)
}

// purgeConsumerDestinations restricts the same purge to one consumer's flows. A flow-purge arrives
// over a consumer's own session and speaks only for that consumer; applying it to everyone would
// let any peer tear down every other peer's traffic with one message. A zero consumer means no
// restriction, which is for local teardown rather than for anything that arrives on the wire.
func (t *egressFlowTable) purgeConsumerDestinations(consumer int64, destinations []string) []*egressFlow {
	prefixes := make([]egressCIDR, 0, len(destinations))
	for _, text := range destinations {
		if cidr, ok := parseEgressCIDR(text); ok {
			prefixes = append(prefixes, cidr)
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	return t.reap(func(flow *egressFlow) bool {
		if consumer != 0 && flow.Consumer != consumer {
			return false
		}
		for _, prefix := range prefixes {
			if prefix.contains(flow.Key.remoteIP) {
				return true
			}
		}
		return false
	})
}

// hasReturnPath reports whether a packet arriving from the real network belongs to a flow this node
// actually opened.
//
// The spec requires this on the egress-to-consumer direction: without it a peer could inject a
// packet with any source address it likes and have the egress relay it into the mesh as though the
// egress had fetched it.
func (t *egressFlowTable) hasReturnPath(key egressFlowKey) bool {
	_, ok := t.flows[key]
	return ok
}

// drain closes everything, for egress shutdown or for the tenant switch being turned off.
func (t *egressFlowTable) drain() []*egressFlow {
	return t.reap(func(*egressFlow) bool { return true })
}

// reauthorize runs the judgment layer again over every live flow against a policy that has just
// changed, and returns the flows that are no longer allowed.
//
// A policy change that only governs new flows is not a revocation. An operator who deletes a
// destination rule expects that traffic to stop, and would reasonably read a connection that keeps
// running until its peer closes it as the rule having failed to apply.
//
// The limit fields are deliberately not re-checked here. Lowering a quota should stop the next
// flow, not pick live ones to kill, and a limit breach is not a permission the flow lost.
func (t *egressFlowTable) reauthorize(policy egressPolicy, peerACLAllows func(consumer int64) bool,
	context egressContext, localInterfaceCIDRs []string) []egressRevocation {
	codes := make(map[egressFlowKey]string)
	reaped := t.reap(func(flow *egressFlow) bool {
		allowed := true
		if peerACLAllows != nil {
			allowed = peerACLAllows(flow.Consumer)
		}
		decision := authorizeEgressFlow(egressRequest{
			ConsumerClientID:    flow.Consumer,
			DestinationIP:       formatEgressAddress(flow.Key.remoteIP),
			DestinationPort:     int(flow.Key.remotePort),
			Protocol:            flow.Key.protocolName(),
			LocalInterfaceCIDRs: localInterfaceCIDRs,
		}, policy, allowed, context)
		if decision.Allowed {
			return false
		}
		codes[flow.Key] = decision.Code
		return true
	})
	revoked := make([]egressRevocation, 0, len(reaped))
	for _, flow := range reaped {
		revoked = append(revoked, egressRevocation{Flow: flow, Code: codes[flow.Key]})
	}
	return revoked
}

// egressRevocation pairs a closed flow with why it closed.
//
// Carried per flow rather than per batch because one policy push can close flows for different
// reasons at once: a destination rule dropped for one, a consumer removed from the allow list for
// another. Collapsing them onto a single code would put a reason in the consumer's flow-reject that
// does not match what actually happened to that flow.
type egressRevocation struct {
	Flow *egressFlow
	Code string
}

// egressRevocationsFor labels a batch that really does share one reason, such as a shutdown or an
// ACL withdrawal. An empty code means the flow ended normally and owes the consumer no explanation.
func egressRevocationsFor(flows []*egressFlow, code string) []egressRevocation {
	revoked := make([]egressRevocation, 0, len(flows))
	for _, flow := range flows {
		revoked = append(revoked, egressRevocation{Flow: flow, Code: code})
	}
	return revoked
}

// reap removes and returns the flows a predicate selects, in a stable order.
//
// Sorted rather than in map order because the caller emits one rejection record per closed flow.
// Ordering that changes run to run would make those records, and the conformance suite that reads
// them, non-reproducible.
func (t *egressFlowTable) reap(selects func(*egressFlow) bool) []*egressFlow {
	var reaped []*egressFlow
	for _, flow := range t.flows {
		if selects(flow) {
			reaped = append(reaped, flow)
		}
	}
	sortEgressFlows(reaped)
	for _, flow := range reaped {
		t.remove(flow)
	}
	return reaped
}

func sortEgressFlows(flows []*egressFlow) {
	sort.Slice(flows, func(i, j int) bool {
		left, right := flows[i].Key, flows[j].Key
		switch {
		case left.protocol != right.protocol:
			return left.protocol < right.protocol
		case left.consumerIP != right.consumerIP:
			return left.consumerIP < right.consumerIP
		case left.consumerPort != right.consumerPort:
			return left.consumerPort < right.consumerPort
		case left.remoteIP != right.remoteIP:
			return left.remoteIP < right.remoteIP
		default:
			return left.remotePort < right.remotePort
		}
	})
}
