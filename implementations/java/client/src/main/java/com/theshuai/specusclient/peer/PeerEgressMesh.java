package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressConfigMessage;
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
 * peer's flows.
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
     * Bounds frames waiting to be encrypted and sent. A full queue drops, which is safe here in a
     * way it would not be elsewhere: TCP retransmits what is lost and UDP is lossy by contract,
     * whereas blocking would stall every flow on the node.
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
                consumer = new PeerEgressConsumer(host::sendToPeer, host::writeToDevice);
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
        if (consumerRole != null && consumerRole.handleInbound(payload, peerId, nowMs)) {
            return true;
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
        PeerEgressConsumer.Outcome outcome =
                consumerRole.handleOutbound(packet, System.currentTimeMillis());
        if (outcome == PeerEgressConsumer.Outcome.NOT_MINE) {
            return false;
        }
        if (outcome != PeerEgressConsumer.Outcome.FORWARDED) {
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
        PeerEgressAuthorization.Context context = new PeerEgressAuthorization.Context(
                meshCidrOrDefault(), List.copyOf(host.deploymentDenyCidrs()));
        plane.setLocalInterfaceCidrs(PeerEgressEndpoints.localInterfaceCidrs());
        plane.applyPolicy(message.policy(), context, System.currentTimeMillis());
        log.info("[peer-egress] policy applied enabled={} revision={} rules={}",
                message.policy().isEnabled(), message.revision(),
                message.policy().getDestinationRules().size());
    }

    /**
     * The egress section of the diagnostic snapshot.
     *
     * <p>The consumer's half is read under this monitor because the consumer has no lock of its
     * own; the runtime's half takes the runtime's own lock.
     */
    public Map<String, Object> status() {
        PeerEgressConsumer consumerRole = consumer;
        PeerEgressRouteInstaller installer = routes;
        PeerEgressRuntime plane = runtime;
        PeerEgressStatus.ConsumerSnapshot consumerSnapshot = null;
        if (consumerRole != null) {
            synchronized (this) {
                consumerSnapshot = consumerRole.statusSnapshot();
            }
        }
        return PeerEgressStatus.section(consumerSnapshot,
                installer == null ? List.of() : installer.installed(), applied,
                plane == null ? null : plane.statusSnapshot());
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
        reconcile(host.consumerRules(), System.currentTimeMillis());
    }

    void reconcile(List<PeerEgressRule> rules, long nowMs) {
        Map<Long, List<String>> purge;
        synchronized (planLock) {
            if (closed.get()) {
                return;
            }
            purge = reconcileLocked(rules, nowMs);
        }
        // Delivered outside the plan lock. A purge reaches a peer through the mesh, and nothing
        // that can wait on the mesh may run while a lock the mesh itself may need is held.
        deliverPurges(purge);
    }

    private Map<Long, List<String>> reconcileLocked(List<PeerEgressRule> rules, long nowMs) {
        String meshCidr = meshCidrOrDefault();
        // The consumer exists only when there are rules for it to apply. Building it for an empty
        // set would report a consumer with nothing to do.
        Map<Long, List<String>> purge = rules.isEmpty() ? Map.of() : configureConsumer(rules, meshCidr, nowMs);

        // Without a device there is nothing to route into. A rule's route pointed at an interface
        // that is not there is a black hole rather than the local fallback the user would get
        // with no route at all, so the plan is empty until the device is up, and empties again if
        // it goes.
        List<PeerEgressRoutePlanner.Route> desired = List.of();
        if (host.deviceReady()) {
            deviceWaitLogged = false;
            PeerEgressRoutePlanner.Plan plan =
                    PeerEgressRoutePlanner.plan(rules, bypassAddresses(nowMs), meshCidr);
            logRefusals(plan.refused());
            desired = plan.routes();
        } else if (!rules.isEmpty() && !deviceWaitLogged) {
            deviceWaitLogged = true;
            log.warn("[peer-egress-consumer] routes not installed: virtual device is {}",
                    host.deviceStatus());
        }

        PeerEgressRouteInstaller installer = ensureRouteInstaller();
        if (!PeerEgressRoutePlanner.reconcileDue(lastPlan, desired, nowMs)) {
            return purge;
        }
        PeerEgressRouteInstaller.ApplyResult result = installer.apply(desired);
        lastPlan = new PeerEgressRoutePlanner.PlanAttempt(nowMs, desired,
                !result.conflicts().isEmpty() || result.error() != null);

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
        return purge;
    }

    /**
     * Gives the consumer its rules, once per distinct configuration.
     *
     * <p>Reconfiguring purges the flows the new rules no longer cover, and with the same rules that
     * is every flow being re-examined for nothing on every tick; with a change of virtual IP it is
     * what has to happen.
     */
    private Map<Long, List<String>> configureConsumer(List<PeerEgressRule> rules, String meshCidr, long nowMs) {
        String virtualIp = host.virtualIp() == null ? "" : host.virtualIp().trim();
        StringBuilder key = new StringBuilder(meshCidr).append('|').append(virtualIp);
        for (PeerEgressRule rule : rules) {
            key.append('|').append(rule.getMatch()).append(' ').append(rule.getAction())
                    .append(' ').append(rule.getEgressClientId()).append(' ').append(rule.getPort());
        }
        if (key.toString().equals(consumerKey)) {
            return Map.of();
        }
        consumerKey = key.toString();
        return ensureConsumer().configure(rules, meshCidr, virtualIp, nowMs);
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
            log.warn("[peer-egress-consumer] rule {} ({}) refused: {}",
                    refusal.index(), refusal.match(), refusal.code());
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
        for (Map.Entry<Long, Boolean> entry : online.entrySet()) {
            deliverPurges(consumerRole.setEgressOnline(entry.getKey(),
                    Boolean.TRUE.equals(entry.getValue()), nowMs));
        }
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
            // What was logged belongs to the routes that are going; the next start says its own.
            conflictsLogged = "";
            errorLogged = "";
            deviceWaitLogged = false;
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
