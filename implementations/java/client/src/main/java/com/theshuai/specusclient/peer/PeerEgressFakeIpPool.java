package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressNames;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import lombok.extern.slf4j.Slf4j;

/**
 * The fake-IP pool of phase two: which address stands for which name.
 *
 * <p>A name that a domain rule sends to an egress (or blocks) is not resolved here; the DNS answer
 * is an address from this pool, and traffic to that address is steered by the name it stands for.
 * So the mapping is what every later decision rests on, and its rules are the spec's
 * ({@code protocol/spec/peer-egress-dns.md}, "fake-IP mapping"), replayed by the {@code pool}
 * section of {@code peer-egress-dns-v1.json}:
 *
 * <ul>
 *   <li>one name, one address, for as long as the mapping lives; different names, different
 *       addresses;</li>
 *   <li>allocation walks the pool in address order from a cursor, skipping addresses in use or in
 *       quarantine, and leaves the cursor after what it took;</li>
 *   <li>a mapping is kept while it was used (queried or sent to) within the last six hours,
 *       however short the answer's TTL, because how long an application caches is not ours;</li>
 *   <li>a full pool evicts every mapping idle for six hours, quarantines their addresses for thirty
 *       minutes, and tries once more; failing that the query is answered as exhausted and no
 *       mapping is touched.</li>
 * </ul>
 *
 * <p>Not reachable are the network address, the broadcast address and the responder's own address,
 * the first after the network one.
 *
 * <p>Thread-safe on its own lock, because it has two callers on different threads: the consumer,
 * which reads and refreshes mappings for traffic under its own monitor, and the DNS responder (step
 * four), which creates them. Nothing here calls out, so the consumer can hold its monitor while
 * taking this lock.
 */
@Slf4j
final class PeerEgressFakeIpPool {

    /** What a query got. */
    record Answer(Integer address, boolean exhausted, List<String> evicted) {
        /** The address as text, or null when the pool was exhausted. */
        String addressText() {
            return address == null ? null : Ipv4Cidr.format(address);
        }
    }

    private static final class Mapping {
        final int address;
        long lastUsedMs;

        Mapping(int address, long lastUsedMs) {
            this.address = address;
            this.lastUsedMs = lastUsedMs;
        }
    }

    private final Ipv4Cidr cidr;
    private final LongSupplier clock;
    /** Unsigned, as longs: the pool can sit on either side of 128.0.0.0. */
    private final long first;
    private final long last;
    private final int listen;
    private long cursor;
    private final Map<String, Mapping> byName = new HashMap<>();
    private final Map<Integer, String> byAddress = new HashMap<>();
    /** Evicted addresses and when they may be handed out again. */
    private final Map<Integer, Long> quarantine = new HashMap<>();
    /** Said once until an allocation succeeds again, rather than once per refused query. */
    private boolean exhaustedLogged;

    PeerEgressFakeIpPool(Ipv4Cidr cidr) {
        this(cidr, System::currentTimeMillis);
    }

    /**
     * @param cidr  the pool. A configured one has passed {@link PeerEgressDns#poolProblem}, which
     *              bounds it to /8-/24; anything up to /30, which leaves one address to hand out,
     *              works here, so the shared cases can fill a pool in a handful of queries
     * @param clock for the calls that do not pass the time themselves
     */
    PeerEgressFakeIpPool(Ipv4Cidr cidr, LongSupplier clock) {
        if (cidr == null || cidr.prefixLength() > 30) {
            throw new IllegalArgumentException("not a usable fake-IP pool: " + cidr);
        }
        this.cidr = cidr;
        this.clock = clock;
        long network = Integer.toUnsignedLong(cidr.network());
        long broadcast = network + (1L << (32 - cidr.prefixLength())) - 1;
        this.listen = (int) (network + 1);
        this.first = network + 2;
        this.last = broadcast - 1;
        // Starts after the responder's address, which is never handed out.
        this.cursor = first;
    }

    /** The pool as configured, in canonical form. */
    String cidr() {
        return cidr.toString();
    }

    /** Whether an address is in the pool at all, mapped or not. */
    boolean contains(int address) {
        return cidr.contains(address);
    }

    /** The responder's address, the first after the network address; step four listens on it. */
    int listenAddress() {
        return listen;
    }

    /** {@link #query(String, long)} at the clock's time: the DNS responder's entry point. */
    Answer query(String name) {
        return query(name, clock.getAsLong());
    }

    /**
     * The address for a name, allocating one when it has none. A name already mapped is refreshed,
     * so an application querying it again keeps its address.
     */
    synchronized Answer query(String name, long nowMs) {
        String normalized = PeerEgressNames.normalize(name);
        Mapping mapping = byName.get(normalized);
        if (mapping != null) {
            mapping.lastUsedMs = nowMs;
            return new Answer(mapping.address, false, List.of());
        }
        Integer address = scan(nowMs);
        List<String> evicted = new ArrayList<>();
        if (address == null) {
            evicted = evictIdle(nowMs);
            address = scan(nowMs);
        }
        if (address == null) {
            if (!exhaustedLogged) {
                exhaustedLogged = true;
                log.warn("[peer-egress-consumer] fake-IP pool exhausted: {} addresses in use, none idle for {} h",
                        byName.size(), PeerEgressDns.MIN_MAPPING_LIFETIME_MS / 3_600_000L);
            }
            return new Answer(null, true, List.copyOf(evicted));
        }
        exhaustedLogged = false;
        byName.put(normalized, new Mapping(address, nowMs));
        byAddress.put(address, normalized);
        return new Answer(address, false, List.copyOf(evicted));
    }

    /**
     * The name a packet's destination stands for, refreshing the mapping as traffic does; null when
     * the address has no mapping, which the consumer blocks as {@code fake-ip-unmapped}.
     */
    synchronized String traffic(int address, long nowMs) {
        String name = byAddress.get(address);
        if (name != null) {
            byName.get(name).lastUsedMs = nowMs;
        }
        return name;
    }

    /**
     * The name an address stands for without refreshing it. A rule change re-deciding established
     * flows is not traffic, and must not keep a mapping alive.
     */
    synchronized String nameOf(int address) {
        return byAddress.get(address);
    }

    /** The mappings held now, for the status. */
    synchronized int mappings() {
        return byName.size();
    }

    /** The addresses still in quarantine at this moment, for the status. */
    synchronized int quarantined(long nowMs) {
        quarantine.values().removeIf(until -> nowMs >= until);
        return quarantine.size();
    }

    /** The first free address from the cursor on, moving the cursor past it; null when none is. */
    private Integer scan(long nowMs) {
        long span = last - first + 1;
        for (long step = 0; step < span; step++) {
            long candidate = first + (cursor - first + step) % span;
            int address = (int) candidate;
            if (free(address, nowMs)) {
                cursor = first + (candidate - first + 1) % span;
                return address;
            }
        }
        return null;
    }

    private boolean free(int address, long nowMs) {
        Long until = quarantine.get(address);
        if (until != null && nowMs >= until) {
            quarantine.remove(address);
            until = null;
        }
        return until == null && !byAddress.containsKey(address);
    }

    /**
     * Evicts every mapping idle for the minimum lifetime, in address order, and quarantines the
     * addresses so a connection still aimed at the old name does not land on a new one. Each is
     * logged by its address and idle time; the name stays out of the log, which would otherwise be
     * a record of what this user looked up.
     */
    private List<String> evictIdle(long nowMs) {
        record Idle(String name, Mapping mapping) {
        }
        List<Idle> idle = new ArrayList<>();
        for (Map.Entry<String, Mapping> entry : byName.entrySet()) {
            if (nowMs - entry.getValue().lastUsedMs >= PeerEgressDns.MIN_MAPPING_LIFETIME_MS) {
                idle.add(new Idle(entry.getKey(), entry.getValue()));
            }
        }
        idle.sort((left, right) -> Integer.compareUnsigned(left.mapping().address, right.mapping().address));
        List<String> evicted = new ArrayList<>(idle.size());
        for (Idle entry : idle) {
            Mapping mapping = entry.mapping();
            byName.remove(entry.name());
            byAddress.remove(mapping.address);
            quarantine.put(mapping.address, nowMs + PeerEgressDns.QUARANTINE_MS);
            evicted.add(entry.name());
            log.info("[peer-egress-consumer] fake-IP mapping {} evicted after {} s idle",
                    Ipv4Cidr.format(mapping.address), (nowMs - mapping.lastUsedMs) / 1000L);
        }
        return evicted;
    }
}
