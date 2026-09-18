package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turning the hosts the tunnel's transport talks to into addresses a bypass route can pin.
 *
 * <p>The forced-deny list the egress role enforces takes literals only, because a resolution taken
 * at policy time can differ from the one a connect uses and a block that looks enforced is worse
 * than none. A bypass is the other way round. Its failure mode is a missing route, which sends the
 * control connection into the tunnel it carries; an extra /32 for an address the server no longer
 * answers on costs nothing. So hostnames are resolved here, and every address they resolve to is
 * pinned.
 *
 * <p>Resolution is cached for a minute. The list is recomputed every few seconds, and asking the
 * resolver each time would turn a periodic tick into a periodic DNS query for every endpoint.
 */
final class PeerEgressBypassResolver {

    /** How long a lookup's answer, or its failure, stands in for the next. */
    static final long RESOLVE_TTL_MILLIS = 60_000L;

    /** How a name is resolved. Injected so the cache can be driven without a network. */
    interface Lookup {
        InetAddress[] lookup(String host) throws UnknownHostException;
    }

    /** The addresses behind the entries, and the hosts whose lookup failed. */
    record Resolution(List<String> addresses, List<String> failed) {
    }

    private record Answer(List<String> addresses, boolean failed, long atMillis) {
    }

    private final Lookup lookup;
    private final Map<String, Answer> cache = new HashMap<>();

    PeerEgressBypassResolver(Lookup lookup) {
        this.lookup = lookup == null ? InetAddress::getAllByName : lookup;
    }

    /**
     * Returns the IPv4 addresses behind each entry, in input order without duplicates, and the
     * hosts whose lookup failed so the caller can say so once.
     *
     * <p>An entry may be a URL, a host with a port, or a bare host or literal. Anything unreadable
     * is skipped rather than refused: the list comes from runtime discovery, not from
     * configuration, and one unreadable entry must not cost the others their route.
     */
    synchronized Resolution resolve(List<String> entries, long nowMillis) {
        Set<String> addresses = new LinkedHashSet<>();
        List<String> failed = new ArrayList<>();
        for (String entry : entries == null ? List.<String>of() : entries) {
            String host = hostOf(entry);
            if (host.isEmpty()) {
                continue;
            }
            if (Ipv4Cidr.parseAddress(host) != null) {
                addresses.add(host);
                continue;
            }
            Answer answer = lookupCached(host, nowMillis);
            if (answer.failed()) {
                failed.add(host);
            }
            addresses.addAll(answer.addresses());
        }
        return new Resolution(List.copyOf(addresses), List.copyOf(failed));
    }

    private Answer lookupCached(String host, long nowMillis) {
        Answer cached = cache.get(host);
        if (cached != null && nowMillis - cached.atMillis() < RESOLVE_TTL_MILLIS) {
            return cached;
        }
        List<String> resolved = new ArrayList<>();
        boolean failed = false;
        try {
            for (InetAddress address : lookup.lookup(host)) {
                // IPv4 only: the rules are IPv4 and so are the routes they install, so an IPv6
                // answer has nothing to be routed around.
                if (address instanceof Inet4Address) {
                    resolved.add(address.getHostAddress());
                }
            }
        } catch (UnknownHostException | RuntimeException unresolved) {
            failed = true;
        }
        // A failure is cached too. Retrying a name that does not resolve on every tick would be
        // the same query storm the cache exists to prevent, and the next tick after the TTL will
        // ask again.
        Answer answer = new Answer(List.copyOf(resolved), failed, nowMillis);
        cache.put(host, answer);
        return answer;
    }

    /**
     * The host in a URL, a host:port pair, or a bare host. Empty when there is nothing to resolve,
     * which includes IPv6 literals: the routes are IPv4.
     */
    static String hostOf(String entry) {
        String trimmed = entry == null ? "" : entry.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        if (trimmed.contains("://")) {
            try {
                String host = URI.create(trimmed).getHost();
                trimmed = host == null ? "" : host;
            } catch (IllegalArgumentException notAUrl) {
                return "";
            }
        }
        if (trimmed.isEmpty() || trimmed.startsWith("[")) {
            return "";
        }
        int colon = trimmed.indexOf(':');
        if (colon < 0) {
            return trimmed;
        }
        if (trimmed.indexOf(':', colon + 1) >= 0) {
            // More than one colon is an unbracketed IPv6 literal, not a host and port.
            return "";
        }
        return trimmed.substring(0, colon);
    }
}
