package client

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Turning the hosts the tunnel's transport talks to into addresses a bypass route can pin.
//
// The forced-deny list the egress role enforces takes literals only, because a resolution taken at
// policy time can differ from the one a connect uses and a block that looks enforced is worse than
// none. A bypass is the other way round. Its failure mode is a missing route, which sends the
// control connection into the tunnel it carries; an extra /32 for an address the server no longer
// answers on costs nothing. So hostnames are resolved here, and every address they resolve to is
// pinned.
//
// Resolution is cached for a minute. The list is recomputed every few seconds, and asking the
// resolver each time would turn a periodic tick into a periodic DNS query for every endpoint.

// egressBypassResolveTTL is how long a lookup's answer, or its failure, stands in for the next.
const egressBypassResolveTTL = 60 * time.Second

type egressBypassLookup struct {
	addresses []string
	failed    bool
	at        time.Time
}

// egressBypassResolver resolves hosts to IPv4 literals with a short cache.
type egressBypassResolver struct {
	lookup func(host string) ([]net.IP, error)
	mu     sync.Mutex
	cache  map[string]egressBypassLookup
}

func newEgressBypassResolver(lookup func(host string) ([]net.IP, error)) *egressBypassResolver {
	if lookup == nil {
		lookup = net.LookupIP
	}
	return &egressBypassResolver{lookup: lookup, cache: make(map[string]egressBypassLookup)}
}

// resolve returns the IPv4 addresses behind each entry, in input order without duplicates, and the
// hosts whose lookup failed so the caller can say so once.
//
// An entry may be a URL, a host with a port, or a bare host or literal. Anything unreadable is
// skipped rather than refused: the list comes from runtime discovery, not from configuration, and
// one unreadable entry must not cost the others their route.
func (r *egressBypassResolver) resolve(entries []string, now time.Time) (addresses, failed []string) {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		host := egressBypassHost(entry)
		if host == "" {
			continue
		}
		var resolved []string
		if _, literal := parseEgressAddress(host); literal {
			resolved = []string{host}
		} else {
			answer := r.lookupCached(host, now)
			if answer.failed {
				failed = append(failed, host)
			}
			resolved = answer.addresses
		}
		for _, address := range resolved {
			if _, duplicate := seen[address]; duplicate {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	return addresses, failed
}

func (r *egressBypassResolver) lookupCached(host string, now time.Time) egressBypassLookup {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.cache[host]; ok && now.Sub(cached.at) < egressBypassResolveTTL {
		return cached
	}
	answer := egressBypassLookup{at: now}
	ips, err := r.lookup(host)
	if err != nil {
		answer.failed = true
	}
	for _, ip := range ips {
		// IPv4 only: the rules are IPv4 and so are the routes they install, so an IPv6 answer
		// has nothing to be routed around.
		if v4 := ip.To4(); v4 != nil {
			answer.addresses = append(answer.addresses, v4.String())
		}
	}
	// A failure is cached too. Retrying a name that does not resolve on every tick would be the
	// same query storm the cache exists to prevent, and the next tick after the TTL will ask again.
	r.cache[host] = answer
	return answer
}

// egressBypassHost extracts the host from a URL, a host:port pair, or a bare host. Empty when
// there is nothing to resolve, which includes IPv6 literals: the routes are IPv4.
func egressBypassHost(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	if strings.Contains(entry, "://") {
		parsed, err := url.Parse(entry)
		if err != nil {
			return ""
		}
		entry = parsed.Host
	}
	if host, _, err := net.SplitHostPort(entry); err == nil {
		entry = host
	}
	if entry == "" || strings.Contains(entry, ":") || strings.HasPrefix(entry, "[") {
		return ""
	}
	return entry
}
