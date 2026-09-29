package client

import (
	"sort"
	"strings"
	"time"
)

// Phase two on the consumer: when it runs, and the fake-IP pool it hands names out of. See
// protocol/spec/peer-egress-dns.md, sections 二 and 四, and the phaseTwo, poolConfig and pool cases
// of protocol/test-vectors/peer-egress-dns-v1.json.
//
// A domain rule cannot become a route: a route selects on an address, and the name's addresses are
// the egress's to know. So a name a domain rule claims is answered with an address from a pool this
// node owns, and traffic arriving at that address is steered by the name it was handed out for. The
// pool is therefore the one place a name turns into an address on the consumer, and nothing here
// resolves anything.
//
// Like the rule engine this holds no clock: time arrives as an argument, so the shared cases drive it
// step by step.

// egressDefaultFakeIPCIDR is the pool unless peerEgressFakeIpCidr names another: RFC 2544's
// benchmarking block, which nothing on a real network is meant to use.
const egressDefaultFakeIPCIDR = "198.18.0.0/15"

const (
	// egressFakeIPMinLifetime is how long a mapping survives without use. It has nothing to do
	// with the one-second TTL of the answer: how long an application caches an address is not
	// ours to decide, and reclaiming at the TTL would push every long cache into "no mapping".
	egressFakeIPMinLifetime = 6 * time.Hour
	// egressFakeIPQuarantine keeps an evicted address from going to another name at once, so a
	// connection still open to the old name does not land on the new one.
	egressFakeIPQuarantine = 30 * time.Minute
	// The pool's accepted sizes. Narrower leaves too few addresses to be worth the takeover, wider
	// swallows more of the address space than any set of names needs.
	egressFakeIPMinPrefix = 8
	egressFakeIPMaxPrefix = 24
)

// effectiveEgressFakeIPCIDR is the configured pool, or the default when none is configured.
func effectiveEgressFakeIPCIDR(configured string) string {
	if trimmed := strings.TrimSpace(configured); trimmed != "" {
		return trimmed
	}
	return egressDefaultFakeIPCIDR
}

// validateEgressFakeIPPool reports why a pool cannot be used, or "" when it can: an IPv4 prefix with
// its host bits clear, /8 to /24, clear of the mesh. Overlap with this device's own networks is
// checked separately, at startup, since it depends on the machine rather than on the configuration.
func validateEgressFakeIPPool(cidr, meshCIDR string) string {
	pool, ok := parseEgressCIDR(strings.TrimSpace(cidr))
	if !ok || pool.prefixLen < egressFakeIPMinPrefix || pool.prefixLen > egressFakeIPMaxPrefix ||
		overlapsEgressMesh(pool, meshCIDR) {
		return egressCodeFakeIPPoolInvalid
	}
	return ""
}

// evaluateEgressPhaseTwo says whether phase two runs: asked for, on top of phase one, with a usable
// pool. An unusable pool stops phase two alone: phase one carries on, and domain rules read as if
// takeover were off. The code is set only when the pool is what stopped it.
func evaluateEgressPhaseTwo(consumerEnabled, takeover bool, cidr, meshCIDR string) (active bool, code string) {
	if !consumerEnabled || !takeover {
		return false, ""
	}
	if code := validateEgressFakeIPPool(effectiveEgressFakeIPCIDR(cidr), meshCIDR); code != "" {
		return false, code
	}
	return true, ""
}

// egressPhaseTwo is phase two's state on this node, as the status reports it.
type egressPhaseTwo struct {
	// CIDR is the pool as configured, with the default filled in.
	CIDR   string
	Active bool
	// Code is set when the pool is what keeps phase two from running.
	Code string
}

// pool is the fake-IP pool the rule engine and the consumer are given: the pool while phase two
// runs, "" while it does not.
func (p egressPhaseTwo) pool() string {
	if p.Active {
		return p.CIDR
	}
	return ""
}

// egressFakeIPPoolOverlapsLocal reports whether the pool shares addresses with any network this
// device sits on. Routing the pool into the tunnel would then take those neighbours away, and a
// name answered with one of their addresses would reach the neighbour instead of the egress.
func egressFakeIPPoolOverlapsLocal(cidr string, networks []string) bool {
	pool, ok := parseEgressCIDR(strings.TrimSpace(cidr))
	if !ok {
		return false
	}
	for _, text := range networks {
		if network, parsed := parseEgressCIDR(text); parsed && egressCIDRsOverlap(pool, network) {
			return true
		}
	}
	return false
}

// egressFakeIPMapping is one name's address and when it was last used.
type egressFakeIPMapping struct {
	address  uint32
	lastUsed time.Time
}

// egressFakeIPPool hands out the pool's addresses to names.
//
// Every address except the network, the broadcast and the responder's own is available. The same
// name keeps its address for as long as the mapping lives, and different names never share one, so
// two names behind one CDN address cannot be told apart by address and are never confused. Not
// safe for concurrent use; the consumer's lock covers it.
type egressFakeIPPool struct {
	cidr egressCIDR
	// listen is the responder's address, the pool's first. first and last bound what is handed
	// out, and cursor is where the next search starts.
	listen, first, last, cursor uint32

	byName    map[string]*egressFakeIPMapping
	byAddress map[uint32]string
	// quarantine holds evicted addresses and when each is free again.
	quarantine map[uint32]time.Time
}

func newEgressFakeIPPool(cidr egressCIDR) *egressFakeIPPool {
	broadcast := cidr.network | ^egressMaskFor(cidr.prefixLen)
	pool := &egressFakeIPPool{
		cidr:       cidr,
		listen:     cidr.network + 1,
		first:      cidr.network + 2,
		last:       broadcast - 1,
		byName:     map[string]*egressFakeIPMapping{},
		byAddress:  map[uint32]string{},
		quarantine: map[uint32]time.Time{},
	}
	// The search starts just past the responder, so a fresh pool hands out addresses in order.
	pool.cursor = pool.first
	return pool
}

func (p *egressFakeIPPool) contains(address uint32) bool { return p.cidr.contains(address) }

func (p *egressFakeIPPool) span() uint32 { return p.last - p.first + 1 }

// egressFakeIPAssignment is what one query gets from the pool: an address, or exhausted. Evicted
// lists the idle mappings reclaimed to make room, in address order.
type egressFakeIPAssignment struct {
	Address   uint32
	Exhausted bool
	Evicted   []egressFakeIPEviction
}

type egressFakeIPEviction struct {
	Name    string
	Address uint32
}

// assign returns the address for a name, handing out a new one when the name has none.
//
// A full pool first evicts every mapping idle for the minimum lifetime and quarantines their
// addresses, then looks again. The addresses it just freed are quarantined, so that second look can
// still find nothing; the query is then answered as exhausted and every mapping still alive is left
// alone. Better one name that cannot be answered than a live connection moved to another name.
func (p *egressFakeIPPool) assign(name string, now time.Time) egressFakeIPAssignment {
	name = normalizeEgressName(name)
	if mapping, known := p.byName[name]; known {
		mapping.lastUsed = now
		return egressFakeIPAssignment{Address: mapping.address}
	}
	address, found := p.scan(now)
	var evicted []egressFakeIPEviction
	if !found {
		evicted = p.evictIdle(now)
		address, found = p.scan(now)
	}
	if !found {
		return egressFakeIPAssignment{Exhausted: true, Evicted: evicted}
	}
	p.byName[name] = &egressFakeIPMapping{address: address, lastUsed: now}
	p.byAddress[address] = name
	return egressFakeIPAssignment{Address: address, Evicted: evicted}
}

// scan finds the first free address from the cursor on, in address order, wrapping once, and moves
// the cursor past it. Walking on rather than reusing the lowest free address keeps an address that
// was just given up from going straight to the next name.
func (p *egressFakeIPPool) scan(now time.Time) (uint32, bool) {
	span := p.span()
	if uint64(len(p.byAddress))+uint64(len(p.quarantine)) >= uint64(span) {
		// Nothing can be free unless a quarantine ended. Checked before the walk, which on a
		// wide pool is millions of steps to learn the same thing.
		p.pruneQuarantine(now)
		if uint64(len(p.byAddress))+uint64(len(p.quarantine)) >= uint64(span) {
			return 0, false
		}
	}
	for step := uint32(0); step < span; step++ {
		candidate := p.first + (p.cursor-p.first+step)%span
		if p.free(candidate, now) {
			p.cursor = p.first + (candidate-p.first+1)%span
			return candidate, true
		}
	}
	return 0, false
}

func (p *egressFakeIPPool) free(address uint32, now time.Time) bool {
	if until, quarantined := p.quarantine[address]; quarantined {
		if now.Before(until) {
			return false
		}
		delete(p.quarantine, address)
	}
	_, taken := p.byAddress[address]
	return !taken
}

func (p *egressFakeIPPool) pruneQuarantine(now time.Time) {
	for address, until := range p.quarantine {
		if !now.Before(until) {
			delete(p.quarantine, address)
		}
	}
}

// evictIdle removes every mapping idle for at least the minimum lifetime, quarantining its address.
func (p *egressFakeIPPool) evictIdle(now time.Time) []egressFakeIPEviction {
	var evicted []egressFakeIPEviction
	for name, mapping := range p.byName {
		if now.Sub(mapping.lastUsed) >= egressFakeIPMinLifetime {
			evicted = append(evicted, egressFakeIPEviction{Name: name, Address: mapping.address})
		}
	}
	sort.Slice(evicted, func(i, j int) bool { return evicted[i].Address < evicted[j].Address })
	for _, entry := range evicted {
		delete(p.byName, entry.Name)
		delete(p.byAddress, entry.Address)
		p.quarantine[entry.Address] = now.Add(egressFakeIPQuarantine)
	}
	return evicted
}

// nameFor is the name an address was handed out for. touch refreshes the mapping, which traffic
// does and a rule change re-examining a flow does not: a rule change is not use.
func (p *egressFakeIPPool) nameFor(address uint32, now time.Time, touch bool) (string, bool) {
	name, mapped := p.byAddress[address]
	if !mapped {
		return "", false
	}
	if touch {
		p.byName[name].lastUsed = now
	}
	return name, true
}

// counts are the live mappings and the addresses still in quarantine, as of now.
func (p *egressFakeIPPool) counts(now time.Time) (mappings, quarantined int) {
	p.pruneQuarantine(now)
	return len(p.byName), len(p.quarantine)
}
