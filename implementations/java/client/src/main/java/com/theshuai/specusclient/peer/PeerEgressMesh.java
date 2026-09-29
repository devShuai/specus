package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressConfigMessage;
import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;

/**
 * Wiring the egress data plane into Peer Mesh.
 *
 * <p>Three joins. SPEG1 frames are demultiplexed out of the decrypted payload stream, the pushed
 * {@code egress-config} becomes the policy the plane enforces, and a closing session revokes that
 * peer's flows. For the consumer's phase two it also reads the pushed {@code egress-catalog} and
 * owns the fake-IP pool.
 *
 * <p>Lock ordering is the constraint that shapes this class. The mesh takes its own lock and the
 * egress plane takes its own, and the plane holds its lock while emitting frames. So frames are
 * queued rather than sent inline: sending inline would mean the plane's lock is held while the
 * mesh's is taken, and the mesh already takes its lock on paths that reach into the plane, which is
 * a cycle. Everything here either queues or is called with no mesh lock held.
 */
@Slf4j
final class PeerEgressMesh implements AutoCloseable {

    /**
     * Bounds frames waiting for encryption. Egress TCP retains rejected payload/FIN until a
     * writable notification. UDP and untracked control frames remain best effort; no caller blocks.
     */
    private static final int SEND_QUEUE_DEPTH = 512;

    /**
     * Drives retransmission and idle expiry. Well under the minimum RTO, so a retransmit is never
     * delayed by more than a fraction of the interval it waited for.
     */
    private static final long TICK_INTERVAL_MS = 100;

    /** What the mesh client provides. Every method is called with no mesh lock held. */
    interface Host {
        /** Encrypts and sends one frame to a peer. False means it did not go. */
        boolean sendToPeer(long peerId, byte[] frame);

        /** Writes one packet to the local virtual device. */
        void writeToDevice(byte[] packet);

        /** The tunnel interface name, for the route commander. */
        String tunName();

        /** This deployment's mesh prefix. */
        String meshCidr();

        /** This node's own mesh address. */
        String virtualIp();

        /** This deployment's control, STUN and TURN endpoints, as /32 prefixes. */
        List<String> deploymentDenyCidrs();

        /** Every peer's own endpoint address, which must keep reaching the physical network. */
        List<String> peerEndpointAddresses();

        /** The measured path budget for one peer, or null when nothing has measured it. */
        Integer pathMtuForPeer(long peerId);

        /** Where the route journal lives, or null for the default location. */
        default Path routeJournalPath() {
            return null;
        }

        /** This node's own consumer rules, fixed for the life of the process. */
        default List<PeerEgressRule> consumerRules() {
            return List.of();
        }

        /**
         * The consumer's master switch, {@code peerEgressEnabled}. Off, the rules are kept and none
         * is applied. True by default so a host built only to drive the plane applies what it is given.
         */
        default boolean consumerEnabled() {
            return true;
        }

        /**
         * {@code peerEgressDnsTakeover}, the switch for phase two (protocol/spec/peer-egress-dns.md).
         * Off by default; phase one is then exactly as it was.
         */
        default boolean dnsTakeover() {
            return false;
        }

        /** {@code peerEgressFakeIpCidr}, the fake-IP pool phase two hands addresses out of. */
        default String fakeIpCidr() {
            return PeerEgressDns.DEFAULT_FAKE_IP_CIDR;
        }

        /**
         * The networks of this device's interfaces, which the pool must stay clear of: an address
         * handed out for a name would otherwise shadow a real host on an attached network.
         */
        default List<String> localInterfaceCidrs() {
            return PeerEgressEndpoints.localInterfaceCidrs();
        }

        /**
         * This device's own interface addresses: besides the mesh address, the only sources the DNS
         * responder answers.
         */
        default List<String> localInterfaceAddresses() {
            return PeerEgressEndpoints.localInterfaceAddresses();
        }

        /**
         * The upstreams the DNS responder forwards to, in order: literal addresses with an optional
         * port. Step five supplies the ones it recorded; until then none, and a forwarded query is
         * answered SERVFAIL.
         */
        default List<String> dnsUpstreams() {
            return List.of();
        }

        /** Complete snapshot of reachable egress peers; omitted peers are offline. */
        default Map<Long, Boolean> egressAvailability() {
            return Map.of();
        }

        /**
         * What carries frames to each peer now: {@code direct}, {@code relay}, or absent when
         * there is neither. Read for status only.
         */
        default Map<Long, String> egressPaths() {
            return Map.of();
        }

        /** Whether there is an interface to route into: a real device that started. */
        default boolean deviceReady() {
            return true;
        }

        /** What the device is instead, for the line that says the routes are waiting on it. */
        default String deviceStatus() {
            return "absent";
        }

        /**
         * The hosts the tunnel's transport talks to, as URLs, host:port pairs or bare hosts: the
         * control connection, the login server, STUN and TURN, the relay. Resolved by the plane,
         * so a hostname is fine here.
         */
        default List<String> bypassHosts() {
            return List.of();
        }
    }

    private record Outbound(long consumer, byte[] frame) {
    }

    private final Host host;
    /**
     * How the egress role opens its real sockets. Injected so this class can be driven without a
     * network: with the real dialer a test that pushes a policy and sends a SYN spends the whole
     * connect timeout reaching an address nobody routes.
     */
    private final PeerEgressRuntime.Dialer dialer;
    /**
     * How the consumer role changes the routing table, or null to build the platform's own.
     * Injected for the same reason the dialer is: a test that applies rules must not run
     * {@code ip route} on the machine it is running on.
     */
    private final PeerEgressRouteInstaller.Commander commander;
    private final BlockingQueue<Outbound> queue = new ArrayBlockingQueue<>(SEND_QUEUE_DEPTH);
    private final AtomicBoolean closed = new AtomicBoolean();
    private Thread sendLoop;
    private Thread tickLoop;

    private volatile PeerEgressRuntime runtime;
    private volatile PeerEgressConsumer consumer;
    private volatile PeerEgressRouteInstaller routes;

    /**
     * What the last route apply left behind that cannot be recomputed: which prefixes were refused
     * because somebody else already owned them, and whether the plan had to be rolled back.
     */
    private volatile PeerEgressStatus.ApplyOutcome applied = PeerEgressStatus.ApplyOutcome.none();

    /** What the server's egress-catalog said about which egresses resolve names. */
    private final PeerEgressCatalog catalog = new PeerEgressCatalog();
    /**
     * The fake-IP pool while phase two runs and there is a consumer to steer by it; null
     * otherwise. Owned here rather than by the consumer so that the mappings outlive a
     * reconfiguration, and so the DNS responder (step four) answers from the same pool.
     */
    private volatile PeerEgressFakeIpPool fakeIps;
    /** The DNS responder over that pool, started and stopped with it. */
    private volatile PeerEgressDnsResponder responder;
    /**
     * How the responder reaches its upstreams. Replaceable before the first reconcile, so a test
     * forwards to a fake instead of the network.
     */
    PeerEgressDnsResponder.Forwarder dnsForwarder = new PeerEgressDnsForwarder();
    /** What every responder of this process did, which the status reports running or not. */
    private final PeerEgressDnsResponder.Counters dnsCounters = new PeerEgressDnsResponder.Counters();
    /**
     * This device's interface addresses, for the responder's source check. Read at most every few
     * seconds: the check runs on the TUN read path, and enumerating interfaces per query would put
     * a system call behind every lookup that does not come from the mesh address.
     */
    private final Object localAddressLock = new Object();
    private java.util.Set<Integer> localAddresses = java.util.Set.of();
    private long localAddressesAtMillis;
    private boolean localAddressesLoaded;
    private static final long LOCAL_ADDRESSES_TTL_MILLIS = 5_000L;
    /**
     * The pool checked against this device's interfaces, once: the check is made at startup, not on
     * every tick, and a pool only changes with the configuration.
     */
    private final Object phaseLock = new Object();
    private String interfacesCheckedFor;
    private boolean interfacesOverlap;
    private String phaseLogged = "";

    /**
     * The consumer's route plan, kept true on the mesh's own tick. Guarded by {@link #planLock},
     * which is never held while anything that can wait on the mesh runs: a reconcile resolves
     * hostnames and runs route commands, and the mesh's own thread must never queue behind it.
     */
    private final Object planLock = new Object();
    private final PeerEgressBypassResolver bypass;
    private PeerEgressRoutePlanner.PlanAttempt lastPlan;
    private String consumerKey = "";
    private String refusalsLogged = "";
    private String conflictsLogged = "";
    private String errorLogged = "";
    private String bypassFailedLogged = "";
    private boolean deviceWaitLogged;
    /** The last check of the table against the plan, and whether it left a reinstall undone. */
    private long repairAtMillis;
    private boolean repairTroubled;
    private String tableErrorLogged = "";

    PeerEgressMesh(Host host) {
        this(host, new PeerEgressSocketDialer(PeerEgressSocketBinder.forPlatform(() -> host.tunName())),
                null, null);
    }

    PeerEgressMesh(Host host, PeerEgressRuntime.Dialer dialer,
            PeerEgressRouteInstaller.Commander commander) {
        this(host, dialer, commander, null);
    }

    /** @param lookup how bypass hostnames are resolved, or null for the system resolver */
    PeerEgressMesh(Host host, PeerEgressRuntime.Dialer dialer,
            PeerEgressRouteInstaller.Commander commander, PeerEgressBypassResolver.Lookup lookup) {
        this.host = host;
        this.dialer = dialer;
        this.commander = commander;
        this.bypass = new PeerEgressBypassResolver(lookup);
    }

    /**
     * Builds the plane and the threads that carry its frames and its clock, on first use.
     *
     * <p>Lazy on purpose. Building it on first contact would let any peer turn an unconfigured
     * device into an egress by sending it a frame.
     */
    private PeerEgressRuntime ensureRuntime() {
        PeerEgressRuntime existing = runtime;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (runtime != null) {
                return runtime;
            }
            PeerEgressRuntime built = new PeerEgressRuntime(
                    (consumerId, frame) -> queue.offer(new Outbound(consumerId, frame)),
                    dialer);
            built.trySend = (consumerId, frame) -> !closed.get() && queue.offer(new Outbound(consumerId, frame));
            runtime = built;
            startLoops(built);
            return built;
        }
    }

    private void startLoops(PeerEgressRuntime plane) {
        sendLoop = Thread.ofVirtual().name("peer-egress-send").start(() -> {
            while (!closed.get()) {
                Outbound outbound;
                try {
                    outbound = queue.poll(TICK_INTERVAL_MS, TimeUnit.MILLISECONDS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                if (outbound != null) { plane.sendReady(System.currentTimeMillis()); }
                if (outbound != null && !host.sendToPeer(outbound.consumer(), outbound.frame())) {
                    log.debug("Peer Mesh egress send failed: peer={}", outbound.consumer());
                }
            }
        });
        tickLoop = Thread.ofVirtual().name("peer-egress-tick").start(() -> {
            while (!closed.get()) {
                try {
                    Thread.sleep(TICK_INTERVAL_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
                plane.onTick(System.currentTimeMillis());
            }
        });
    }

    /**
     * Builds the consumer side on first use.
     *
     * <p>Its sender is synchronous, unlike the egress role's. It is called from the TUN read path
     * with no plane lock held, and the caller needs to know whether the packet left: a send that
     * failed means the rule's destination has to be blocked, not allowed out locally.
     */
    private PeerEgressConsumer ensureConsumer() {
        PeerEgressConsumer existing = consumer;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (consumer == null) {
                PeerEgressConsumer built = new PeerEgressConsumer(host::sendToPeer, host::writeToDevice);
                built.setLocalAddresses(this::isLocalAddress);
                consumer = built;
            }
            return consumer;
        }
    }

    /**
     * Demultiplexes SPEG1 out of the decrypted payload stream.
     *
     * <p>Belongs after the application-message check and before the bare IPv4 endpoint check: a
     * frame carrying the SPEG1 magic is addressed to the egress path and must be refused with its
     * own code rather than dropped as an unrecognised mesh packet.
     *
     * <p>The consumer role is offered the frame first. A node can be both, and both roles receive
     * type=1 frames; the consumer claims only what is addressed to its own virtual IP, so trying it
     * first costs nothing and keeps a reply from being judged as an egress request.
     */
    boolean handleInboundFrame(long peerId, byte[] payload) {
        if (!PeerEgressFrame.looksLikeFrame(payload)) {
            return false;
        }
        long nowMs = System.currentTimeMillis();
        PeerEgressConsumer consumerRole = consumer;
        if (consumerRole != null) {
            synchronized (consumerRole) {
                if (consumerRole.handleInbound(payload, peerId, nowMs)) { return true; }
            }
        }
        PeerEgressRuntime plane = runtime;
        if (plane == null) {
            // Nothing has enabled the egress on this node, so there is no policy to judge against.
            // The frame is dropped rather than answered with a refusal: a reply would need the rate
            // limiting only the plane provides, and a peer that never got an egress in the first
            // place learns from its own timeout.
            return true;
        }
        // A returning segment travels inside an SPEG1 frame, so the frame header has to come out of
        // the budget the stack sizes segments against.
        Integer pathMtu = host.pathMtuForPeer(peerId);
        if (pathMtu != null) {
            plane.setPathMtu(pathMtu - PeerEgressFrame.HEADER_BYTES);
        }
        return plane.handleFrame(peerId, payload, nowMs);
    }

    /**
     * Offers a packet read from the TUN to the consumer rules, and reports whether the consumer
     * claimed it.
     *
     * <p>Sits at the top of the TUN read path, because a destination a rule claims is not a mesh
     * peer and the existing path would drop it as such: silently, and as though nothing had been
     * configured.
     */
    boolean handleOutbound(byte[] packet) {
        PeerEgressConsumer consumerRole = consumer;
        if (consumerRole == null) {
            return false;
        }
        PeerEgressConsumer.Outcome outcome;
        synchronized (consumerRole) {
            outcome = consumerRole.handleOutbound(packet, System.currentTimeMillis());
        }
        if (outcome == PeerEgressConsumer.Outcome.NOT_MINE) {
            return false;
        }
        if (outcome != PeerEgressConsumer.Outcome.FORWARDED && outcome != PeerEgressConsumer.Outcome.DNS) {
            // Logged without the destination: a per-destination record of what a user was blocked
            // from reaching is their own browsing history.
            log.debug("[peer-egress-consumer] packet not forwarded: {}", outcome);
        }
        return true;
    }

    /**
     * Installs a pushed {@code egress-config}.
     *
     * <p>The revision guard is the spec's: a snapshot at or below the last accepted one is ignored,
     * so a reordered or replayed push cannot walk the policy backwards.
     */
    void applyEgressConfig(String payload) {
        PeerEgressConfigMessage message = PeerEgressConfigMessage.decode(payload);
        if (message == null) {
            log.warn("decode egress-config failed");
            return;
        }
        PeerEgressRuntime plane = ensureRuntime();
        if (!plane.acceptRevision(message.revision())) {
            return;
        }
        List<String> denied = new ArrayList<>(host.deploymentDenyCidrs());
        // An egress whose own configuration runs phase two refuses to dial its own pool: such a
        // flow would be routed into this node's tunnel and steered by this node's own names. Judged
        // from the configuration and the mesh rather than the last reconcile, which may not have
        // run when the policy arrives.
        String ownPool = PeerEgressDns.effectivePool(host.fakeIpCidr());
        if (PeerEgressDns.phaseTwo(host.consumerEnabled(), host.dnsTakeover(), ownPool, meshCidrOrDefault()).active()) {
            denied.add(ownPool);
        }
        PeerEgressAuthorization.Context context = new PeerEgressAuthorization.Context(
                meshCidrOrDefault(), List.copyOf(denied));
        plane.setLocalInterfaceCidrs(PeerEgressEndpoints.localInterfaceCidrs());
        plane.applyPolicy(message.policy(), context, System.currentTimeMillis());
        log.info("[peer-egress] policy applied enabled={} revision={} rules={}",
                message.policy().isEnabled(), message.revision(),
                message.policy().getDestinationRules().size());
    }

    /**
     * Takes a pushed {@code egress-catalog}: which egresses resolve names. A domain rule sends
     * nothing to an egress that does not, so a change here can end flows to fake addresses, and
     * their egresses are told to close their side.
     *
     * <p>Kept even while no consumer exists, so the one built later starts from what the server
     * last said rather than from nothing.
     */
    void applyEgressCatalog(String payload) {
        if (!catalog.read(payload)) {
            log.debug("[peer-egress-consumer] egress-catalog ignored: unreadable or not newer");
            return;
        }
        log.info("[peer-egress-consumer] egress catalogue applied revision={} domainTargetCapable={}",
                catalog.revision(), catalog.domainCapableIds());
        PeerEgressConsumer consumerRole = consumer;
        if (consumerRole == null) {
            return;
        }
        Map<Long, List<String>> purge;
        synchronized (consumerRole) {
            // Read inside the monitor, so of two racing updates the later one is the one applied.
            purge = consumerRole.setDomainCapable(catalog.domainCapable(), System.currentTimeMillis());
        }
        deliverPurges(purge);
    }

    /**
     * A new control session: the server numbers its catalogues afresh. Only the revision floor is
     * reset; what the last catalogue said stands until the next one replaces it.
     */
    void newControlSession() {
        catalog.newSession();
    }

    /** The pool phase two answers from, or null while it does not run; for the DNS responder. */
    PeerEgressFakeIpPool fakeIpPool() {
        return fakeIps;
    }

    /** The egresses the last accepted catalogue says resolve names, sorted. */
    List<Long> domainCapableEgresses() {
        return catalog.domainCapableIds();
    }

    /**
     * Whether phase two runs, from the configuration, the actual mesh network and, once, this
     * device's interfaces. An unusable pool stops phase two alone and is said once.
     */
    PeerEgressDns.PhaseTwo phaseTwo() {
        String cidr = PeerEgressDns.effectivePool(host.fakeIpCidr());
        PeerEgressDns.PhaseTwo phase = PeerEgressDns.phaseTwo(
                host.consumerEnabled(), host.dnsTakeover(), cidr, meshCidrOrDefault());
        synchronized (phaseLock) {
            if (phase.active() && overlapsInterface(cidr)) {
                phase = new PeerEgressDns.PhaseTwo(false, PeerEgressCodes.FAKE_IP_POOL_INVALID);
            }
            String state = phase.active() + "|" + phase.code() + "|" + cidr;
            if (host.dnsTakeover() && !state.equals(phaseLogged)) {
                phaseLogged = state;
                // Without the pool itself: configuration values stay out of the log, as a rule's
                // match does.
                if (phase.active()) {
                    log.info("[peer-egress-consumer] phase two running");
                } else if (phase.code() != null) {
                    // Phase one carries on; domain rules read as though takeover were off.
                    log.warn("[peer-egress-consumer] phase two not started: {} (peerEgressFakeIpCidr must be"
                            + " an IPv4 /8 to /24 clear of the Peer Mesh network and of this device's networks)",
                            phase.code());
                }
            }
        }
        return phase;
    }

    /** Whether the pool overlaps a network of this device's own, checked once per pool. */
    private boolean overlapsInterface(String cidr) {
        if (!cidr.equals(interfacesCheckedFor)) {
            interfacesCheckedFor = cidr;
            interfacesOverlap = false;
            Ipv4Cidr pool = Ipv4Cidr.parse(cidr);
            List<String> networks = host.localInterfaceCidrs();
            for (String network : networks == null ? List.<String>of() : networks) {
                Ipv4Cidr parsed = Ipv4Cidr.parse(network);
                if (pool != null && parsed != null && parsed.overlaps(pool)) {
                    interfacesOverlap = true;
                    break;
                }
            }
        }
        return interfacesOverlap;
    }

    /**
     * The pool for a usable CIDR, kept across calls so its mappings survive a reconfiguration, and
     * the DNS responder that answers from it, started with it.
     */
    private PeerEgressFakeIpPool poolFor(String cidr) {
        Ipv4Cidr parsed = Ipv4Cidr.parse(cidr.trim());
        synchronized (phaseLock) {
            PeerEgressFakeIpPool existing = fakeIps;
            if (existing != null && existing.cidr().equals(parsed.toString())) {
                return existing;
            }
            PeerEgressFakeIpPool created = new PeerEgressFakeIpPool(parsed);
            PeerEgressDnsResponder previous = responder;
            responder = PeerEgressDnsResponder.start(created, dnsForwarder, host::writeToDevice, dnsCounters);
            fakeIps = created;
            if (previous != null) {
                previous.close();
            }
            return created;
        }
    }

    /** Phase two is not running: no pool, and no responder answering from one. */
    private void stopPhaseTwo() {
        synchronized (phaseLock) {
            fakeIps = null;
            PeerEgressDnsResponder previous = responder;
            responder = null;
            if (previous != null) {
                previous.close();
            }
        }
    }

    /** The DNS responder while phase two runs, or null. */
    PeerEgressDnsResponder dnsResponder() {
        return responder;
    }

    /**
     * Whether an address is one of this device's own, from an interface list at most a few seconds
     * old.
     */
    private boolean isLocalAddress(int address) {
        long now = System.currentTimeMillis();
        synchronized (localAddressLock) {
            if (!localAddressesLoaded || now - localAddressesAtMillis >= LOCAL_ADDRESSES_TTL_MILLIS
                    || now < localAddressesAtMillis) {
                java.util.Set<Integer> fresh = new java.util.HashSet<>();
                List<String> listed = host.localInterfaceAddresses();
                for (String text : listed == null ? List.<String>of() : listed) {
                    Integer parsed = Ipv4Cidr.parseAddress(text);
                    if (parsed != null) {
                        fresh.add(parsed);
                    }
                }
                localAddresses = java.util.Set.copyOf(fresh);
                localAddressesAtMillis = now;
                localAddressesLoaded = true;
            }
            return localAddresses.contains(address);
        }
    }

    /**
     * The egress section of the diagnostic snapshot.
     *
     * <p>The consumer's half is read under its monitor because the consumer has no lock of its
     * own; the runtime's half takes the runtime's own lock.
     */
    public Map<String, Object> status() {
        PeerEgressConsumer consumerRole = consumer;
        PeerEgressRouteInstaller installer = routes;
        PeerEgressRuntime plane = runtime;
        PeerEgressStatus.ConsumerSnapshot consumerSnapshot = null;
        if (consumerRole != null) {
            synchronized (consumerRole) {
                consumerSnapshot = consumerRole.statusSnapshot(System.currentTimeMillis());
            }
        }
        if (consumerSnapshot != null) {
            consumerSnapshot = consumerSnapshot.withPaths(host.egressPaths());
        }
        PeerEgressStatus.Dns dns = null;
        if (host.dnsTakeover()) {
            PeerEgressDns.PhaseTwo phase = phaseTwo();
            PeerEgressDnsResponder answering = responder;
            List<String> upstreams = new ArrayList<>();
            List<String> configured = host.dnsUpstreams();
            for (String text : configured == null ? List.<String>of() : configured) {
                if (PeerEgressDnsForwarder.parseUpstream(text) != null) {
                    upstreams.add(text.trim());
                }
            }
            dns = new PeerEgressStatus.Dns(PeerEgressDns.effectivePool(host.fakeIpCidr()), phase.active(), phase.code(),
                    phase.active() && answering != null ? Ipv4Cidr.format(answering.listenAddress()) : null,
                    List.copyOf(upstreams), dnsCounters.answered(), dnsCounters.forwarded(), dnsCounters.failed());
        }
        return PeerEgressStatus.section(consumerSnapshot,
                installer == null ? List.of() : installer.installed(), applied,
                plane == null ? null : plane.statusSnapshot(), host.consumerEnabled(), host.consumerRules(),
                dns);
    }

    /**
     * Installs the consumer's own rules and the routes they need, now.
     *
     * <p>Refused rules are reported and skipped; the rest take effect. A rule set is rarely wrong
     * all at once, and refusing to apply any of it would leave a user with one typo sending
     * everything out locally, which is the failure this feature exists to prevent.
     */
    void applyRules(List<PeerEgressRule> rules) {
        reconcile(rules == null ? List.of() : rules, System.currentTimeMillis());
    }

    /**
     * Recomputes the consumer's routes from what the host knows now and applies them if that is
     * due: once the virtual device is up, and on the mesh's own tick from then on.
     *
     * <p>The rules are fixed for the life of the process, but what they need installed is not. A
     * bypass exists for an address a rule covers, and those addresses move: peers connect and
     * drop, the relay is reassigned, the control connection is re-established.
     */
    void reconcileRoutes() {
        // With the master switch off nothing is taken over. The plan is then empty, which withdraws
        // whatever a previous run left installed, and the consumer is not built.
        reconcile(host.consumerEnabled() ? host.consumerRules() : List.of(), System.currentTimeMillis());
    }

    void reconcile(List<PeerEgressRule> rules, long nowMs) {
        if (closed.get()) { return; }
        // While phase two runs the pool is routed and the consumer exists whether or not there are
        // rules: an address in the pool has to reach something that answers it, even if all it can
        // be told is that the address stands for nothing.
        PeerEgressDns.PhaseTwo phase = phaseTwo();
        PeerEgressFakeIpPool pool = null;
        PeerEgressDnsResponder dns = null;
        if (phase.active()) {
            pool = poolFor(PeerEgressDns.effectivePool(host.fakeIpCidr()));
            dns = responder;
            if (dns != null) {
                dns.setUpstreams(host.dnsUpstreams());
            }
        } else {
            stopPhaseTwo();
        }
        // Consumer sends can reach the mesh. Never wait for its monitor while holding
        // planLock: mesh shutdown acquires planLock to withdraw routes.
        //
        // A consumer that exists is reconfigured even with nothing left for it to do: phase two
        // stopping (the mesh network moving over the pool, say) with no rules would otherwise leave
        // it holding the pool and a stopped responder, steering by a pool nothing routes any more.
        Map<Long, List<String>> purge = rules.isEmpty() && pool == null && consumer == null ? Map.of()
                : configureConsumer(rules, meshCidrOrDefault(), pool, dns, nowMs);
        synchronized (planLock) {
            if (closed.get()) {
                return;
            }
            reconcileLocked(rules, pool == null ? null : pool.cidr(), nowMs);
        }
        // Delivered outside the plan lock. A purge reaches a peer through the mesh, and nothing
        // that can wait on the mesh may run while a lock the mesh itself may need is held.
        deliverPurges(purge);
        syncEgressAvailability(host.egressAvailability());
    }

    /** @param fakeIpCidr the pool phase two runs with, whose route the plan then carries; or null */
    private void reconcileLocked(List<PeerEgressRule> rules, String fakeIpCidr, long nowMs) {
        String meshCidr = meshCidrOrDefault();

        // Without a device there is nothing to route into. A rule's route pointed at an interface
        // that is not there is a black hole rather than the local fallback the user would get
        // with no route at all, so the plan is empty until the device is up, and empties again if
        // it goes.
        List<PeerEgressRoutePlanner.Route> desired = List.of();
        if (host.deviceReady()) {
            deviceWaitLogged = false;
            PeerEgressRoutePlanner.Plan plan =
                    PeerEgressRoutePlanner.plan(rules, bypassAddresses(nowMs), meshCidr, fakeIpCidr);
            logRefusals(plan.refused());
            desired = plan.routes();
        } else if ((!rules.isEmpty() || fakeIpCidr != null) && !deviceWaitLogged) {
            deviceWaitLogged = true;
            log.warn("[peer-egress-consumer] routes not installed: virtual device is {}",
                    host.deviceStatus());
        }

        PeerEgressRouteInstaller installer = ensureRouteInstaller();
        if (!PeerEgressRoutePlanner.reconcileDue(lastPlan, desired, nowMs)) {
            // The common tick: the plan has nothing to do, so the table is checked against it.
            if (host.deviceReady()) {
                repairDrift(installer, nowMs);
            }
            return;
        }
        PeerEgressRouteInstaller.ApplyResult result = installer.apply(desired);
        lastPlan = new PeerEgressRoutePlanner.PlanAttempt(nowMs, desired,
                !result.conflicts().isEmpty() || result.error() != null);
        repairAtMillis = 0;
        repairTroubled = false;

        // Remembered before it is logged. A conflict is the one part of this outcome nothing can
        // recompute -- the answer came from the platform's routing table at this moment -- and
        // writing it only to the log is what left an operator with no way to see that a rule they
        // wrote is not in force.
        String error = result.error() == null ? "" : String.valueOf(result.error().getMessage());
        applied = new PeerEgressStatus.ApplyOutcome(nowMs, List.copyOf(result.conflicts()), error,
                result.rolledBack(), true);

        // Logged when they change, not on every retry. A conflict is retried every minute for as
        // long as the other route is there, and repeating the same line each time would bury the
        // one that says it went away.
        List<String> conflicts = new ArrayList<>();
        for (PeerEgressRouteInstaller.RouteConflict conflict : result.conflicts()) {
            conflicts.add(conflict.route().cidr() + "=" + conflict.existing());
        }
        String joined = String.join(";", conflicts);
        if (!joined.equals(conflictsLogged)) {
            conflictsLogged = joined;
            for (PeerEgressRouteInstaller.RouteConflict conflict : result.conflicts()) {
                // Not preempted and not compared by metric. The operator is told which of their
                // own routes is in the way, so they can decide rather than discover it later.
                log.warn("[peer-egress-consumer] route {} not installed, already present: {}",
                        conflict.route().cidr(), conflict.existing());
            }
        }
        if (!error.equals(errorLogged)) {
            errorLogged = error;
            if (result.error() != null) {
                log.warn("[peer-egress-consumer] route install failed: {} rolledBack={}",
                        result.error().getMessage(), result.rolledBack());
            }
        }
        if (!result.added().isEmpty() || !result.removed().isEmpty()) {
            log.info("[peer-egress-consumer] routes added={} removed={}",
                    result.added().size(), result.removed().size());
        }
    }

    /**
     * Puts back what the routing table lost since the plan was applied: a route dropped with its
     * interface, a bypass still naming a gateway the machine left behind. Called under the plan
     * lock on the ticks the plan itself has nothing to do.
     */
    private void repairDrift(PeerEgressRouteInstaller installer, long nowMs) {
        if (repairTroubled && nowMs - repairAtMillis < PeerEgressRoutePlanner.RETRY_AFTER_MILLIS) {
            return;
        }
        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        if (result.tableError() != null) {
            // Said once per failure. Without the table nothing can be compared, and a machine
            // whose `ip` is missing would otherwise say so every five seconds.
            String text = String.valueOf(result.tableError().getMessage());
            if (!text.equals(tableErrorLogged)) {
                tableErrorLogged = text;
                log.warn("[peer-egress-consumer] cannot read the routing table to check the routes: {}", text);
            }
            repairAtMillis = nowMs;
            repairTroubled = true;
            return;
        }
        tableErrorLogged = "";
        repairAtMillis = nowMs;
        repairTroubled = result.error() != null;

        for (PeerEgressSocketBinding.Drift drift : result.repaired()) {
            // Each one is a real event -- the machine changed networks -- so each one is said.
            log.info("[peer-egress-consumer] route {} put back, it was {}", drift.route().cidr(), drift.reason());
        }
        if (!result.lost().isEmpty()) {
            // Reported the way an apply reports a conflict, and remembered the same way, so the
            // status lists the prefix as not installed with what holds it. The plan still wants
            // it: marked troubled, it asks again after the interval and reports the conflict if
            // it is still there.
            List<PeerEgressRouteInstaller.RouteConflict> merged = new ArrayList<>(applied.conflicts());
            for (PeerEgressRouteInstaller.RouteConflict lost : result.lost()) {
                merged.removeIf(existing -> existing.route().cidr().equals(lost.route().cidr()));
                merged.add(lost);
                log.warn("[peer-egress-consumer] route {} lost to another route, not taken back: {}",
                        lost.route().cidr(), lost.existing());
            }
            applied = new PeerEgressStatus.ApplyOutcome(nowMs, List.copyOf(merged), applied.error(),
                    applied.rolledBack(), true);
            if (lastPlan != null) {
                lastPlan = new PeerEgressRoutePlanner.PlanAttempt(nowMs, lastPlan.desired(), true);
            }
        }
        if (result.error() != null) {
            String text = String.valueOf(result.error().getMessage());
            if (!text.equals(errorLogged)) {
                errorLogged = text;
                log.warn("[peer-egress-consumer] route repair failed: {}", text);
            }
        }
    }

    /**
     * Gives the consumer its rules, once per distinct configuration.
     *
     * <p>Reconfiguring purges the flows the new rules no longer cover, and with the same rules that
     * is every flow being re-examined for nothing on every tick; with a change of virtual IP it is
     * what has to happen.
     */
    private Map<Long, List<String>> configureConsumer(List<PeerEgressRule> rules, String meshCidr,
            PeerEgressFakeIpPool pool, PeerEgressDnsResponder dns, long nowMs) {
        String virtualIp = host.virtualIp() == null ? "" : host.virtualIp().trim();
        StringBuilder key = new StringBuilder(meshCidr).append('|').append(virtualIp)
                .append('|').append(pool == null ? "" : pool.cidr())
                .append('|').append(dns == null ? 0 : System.identityHashCode(dns));
        for (PeerEgressRule rule : rules) {
            key.append('|').append(rule.getMatch()).append(' ').append(rule.getAction())
                    .append(' ').append(rule.getEgressClientId()).append(' ').append(rule.getPort());
        }
        PeerEgressConsumer consumerRole = ensureConsumer();
        synchronized (consumerRole) {
            // A consumer built after the catalogue arrived starts from it. Cheap when nothing
            // changed, and read inside the monitor like every other update of it.
            Map<Long, List<String>> purge = consumerRole.setDomainCapable(catalog.domainCapable(), nowMs);
            if (key.toString().equals(consumerKey)) { return purge; }
            consumerKey = key.toString();
            return mergePurges(purge, consumerRole.configure(rules, meshCidr, virtualIp, pool, dns, nowMs));
        }
    }

    /** Two sets of purges as one, each egress's destinations once and in order. */
    private static Map<Long, List<String>> mergePurges(Map<Long, List<String>> first,
            Map<Long, List<String>> second) {
        if (first.isEmpty()) {
            return second;
        }
        if (second.isEmpty()) {
            return first;
        }
        Map<Long, java.util.TreeSet<String>> merged = new java.util.TreeMap<>();
        for (Map<Long, List<String>> part : List.of(first, second)) {
            part.forEach((egress, destinations) ->
                    merged.computeIfAbsent(egress, unused -> new java.util.TreeSet<>()).addAll(destinations));
        }
        Map<Long, List<String>> out = new java.util.LinkedHashMap<>();
        merged.forEach((egress, destinations) -> out.put(egress, List.copyOf(destinations)));
        return out;
    }

    /**
     * Reports the rules that were thrown out, once per distinct set. The rules do not change while
     * the process runs, so in practice this is once.
     */
    private void logRefusals(List<PeerEgressRoutePlanner.Refusal> refused) {
        List<String> keys = new ArrayList<>();
        for (PeerEgressRoutePlanner.Refusal refusal : refused) {
            keys.add(refusal.index() + ":" + refusal.code());
        }
        String joined = String.join(",", keys);
        if (joined.equals(refusalsLogged)) {
            return;
        }
        refusalsLogged = joined;
        for (PeerEgressRoutePlanner.Refusal refusal : refused) {
            // The index and the code, not the match: configuration values stay out of the log.
            log.warn("[peer-egress-consumer] rule {} refused: {}",
                    refusal.index(), refusal.code());
        }
    }

    /**
     * The addresses that must keep reaching the physical network: the host's transport endpoints,
     * resolved, and every peer's own endpoint. Without them a rule broad enough to cover one would
     * route the tunnel's transport into the tunnel.
     */
    private List<String> bypassAddresses(long nowMs) {
        PeerEgressBypassResolver.Resolution resolution = bypass.resolve(host.bypassHosts(), nowMs);
        String failed = String.join(",", resolution.failed());
        if (!failed.equals(bypassFailedLogged)) {
            bypassFailedLogged = failed;
            for (String hostName : resolution.failed()) {
                // Said once per failure, not per tick: the cache retries after its TTL and the
                // next line is the one that says it resolved.
                log.warn("[peer-egress-consumer] bypass host {} did not resolve; a rule covering it would capture it",
                        hostName);
            }
        }
        List<String> addresses = new ArrayList<>(resolution.addresses());
        addresses.addAll(host.peerEndpointAddresses());
        return addresses;
    }

    /**
     * Builds the installer and takes back whatever a previous run left in the journal.
     *
     * <p>Taken back rather than adopted. A journal outlives the process that wrote it, and that
     * process's interface is gone with it, so the routes it describes are either gone too or
     * pointing at nothing; what is still wanted is put back by the apply that follows. This is
     * also what clears a crash's leftovers when the rules have since been removed: there is no rule
     * set so small that the journal is not read.
     */
    private PeerEgressRouteInstaller ensureRouteInstaller() {
        PeerEgressRouteInstaller existing = routes;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (routes != null) {
                return routes;
            }
            Path journal = host.routeJournalPath() == null
                    ? Path.of(System.getProperty("user.home", "."), ".specus", "egress-routes.json")
                    : host.routeJournalPath();
            PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(
                    commander == null
                            ? PeerEgressRouteCommanders.forPlatform(host.tunName())
                            : commander,
                    journal);
            try {
                installer.load();
            } catch (Exception unusable) {
                log.warn("[peer-egress-consumer] route journal unusable, starting empty: {}",
                        unusable.getMessage());
            }
            List<PeerEgressRoutePlanner.Route> leftover = installer.withdrawAll();
            if (!leftover.isEmpty()) {
                log.info("[peer-egress-consumer] took back {} routes left by a previous run", leftover.size());
            }
            routes = installer;
            return installer;
        }
    }

    /**
     * Tells the consumer which egresses can take a flow, and delivers the purges a peer going
     * offline produces.
     */
    void syncEgressAvailability(Map<Long, Boolean> online) {
        PeerEgressConsumer consumerRole = consumer;
        if (consumerRole == null) {
            return;
        }
        long nowMs = System.currentTimeMillis();
        Map<Long, List<String>> purge = new java.util.LinkedHashMap<>();
        synchronized (consumerRole) {
            var peers = new java.util.HashSet<>(consumerRole.statusSnapshot(nowMs).online().keySet());
            peers.addAll(online.keySet());
            for (long peer : peers) {
                purge.putAll(consumerRole.setEgressOnline(peer,
                        Boolean.TRUE.equals(online.get(peer)), nowMs));
            }
        }
        deliverPurges(purge);
    }

    /**
     * Sends one flow-purge per affected egress.
     *
     * <p>Best effort by design. The message is what closes the far side promptly, but the egress
     * reclaims the flow on its own idle timer regardless, so a purge that cannot be delivered
     * delays cleanup rather than losing it.
     */
    private void deliverPurges(Map<Long, List<String>> purge) {
        for (Map.Entry<Long, List<String>> entry : purge.entrySet()) {
            if (entry.getValue().isEmpty()) {
                continue;
            }
            byte[] body = PeerEgressFrame.encodeControl(PeerEgressFrame.Control.flowPurge(
                    entry.getValue(), PeerEgressCodes.DISABLED));
            host.sendToPeer(entry.getKey(),
                    PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false, body));
        }
    }

    /**
     * Closes a peer's flows when its session ends.
     *
     * <p>The plane cannot poll for this: asking the mesh whether a peer is still authorised would
     * mean taking the mesh lock from under the plane's own, so revocation is delivered as an event
     * instead.
     */
    void revokeConsumer(long peerId) {
        PeerEgressRuntime plane = runtime;
        if (plane != null && peerId > 0) {
            plane.revokeConsumer(peerId, System.currentTimeMillis());
        }
    }

    /**
     * Takes back every route this feature installed and forgets the plan, so the next reconcile
     * starts from nothing. Safe to call with the mesh's own lock held: nothing here waits on it.
     */
    void withdrawRoutes() {
        synchronized (planLock) {
            PeerEgressRouteInstaller installer;
            synchronized (this) {
                installer = routes;
                routes = null;
            }
            lastPlan = null;
            repairAtMillis = 0;
            repairTroubled = false;
            // What was logged belongs to the routes that are going; the next start says its own.
            conflictsLogged = "";
            errorLogged = "";
            deviceWaitLogged = false;
            tableErrorLogged = "";
            if (installer != null) {
                installer.withdrawAll();
            }
        }
    }

    /**
     * Stops forwarding. The plane closes sockets under its own lock, and the loops are stopped by
     * their own flag rather than by closing the queue: a reader thread can still be between
     * releasing the plane's lock and queuing its last frame.
     */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        stopPhaseTwo();
        PeerEgressRuntime plane = runtime;
        if (plane != null) {
            plane.shutdown(System.currentTimeMillis());
        }
        if (sendLoop != null) {
            sendLoop.interrupt();
        }
        if (tickLoop != null) {
            tickLoop.interrupt();
        }
    }

    private String meshCidrOrDefault() {
        String configured = host.meshCidr();
        return configured == null || configured.isBlank()
                ? PeerEgressRules.DEFAULT_MESH_CIDR
                : configured.trim();
    }

    /** Visible for tests: how many frames are waiting to be encrypted and sent. */
    int queuedFrames() {
        return queue.size();
    }
}
