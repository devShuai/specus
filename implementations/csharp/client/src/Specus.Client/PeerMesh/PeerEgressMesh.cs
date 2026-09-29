using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Logging;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>What the mesh client provides. Every member is called with no mesh lock held.</summary>
internal interface IPeerEgressMeshHost
{
    /// <summary>
    /// Whether a peer can be reached right now, without sending anything.
    /// </summary>
    /// <remarks>
    /// Split out from the send because the consumer needs an answer synchronously: a packet its
    /// rules claimed must be blocked rather than allowed out locally when the egress is gone, and
    /// that decision cannot wait on a socket. The rest of the send is asynchronous and its outcome
    /// changes nothing the consumer could act on -- a frame lost after this point is one TCP will
    /// retransmit.
    /// </remarks>
    bool CanReach(long peerId);

    /// <summary>Encrypts and sends one frame to a peer.</summary>
    Task<bool> SendToPeerAsync(long peerId, byte[] frame);

    /// <summary>Writes one packet to the local virtual device.</summary>
    Task WriteToDeviceAsync(byte[] packet);

    /// <summary>The tunnel interface name, for the route commander.</summary>
    string TunName { get; }

    /// <summary>This deployment's mesh prefix.</summary>
    string MeshCidr { get; }

    /// <summary>This node's own mesh address.</summary>
    string VirtualIp { get; }

    /// <summary>This deployment's control, STUN and TURN endpoints, as /32 prefixes.</summary>
    IReadOnlyList<string> DeploymentDenyCidrs();

    /// <summary>Every peer's own endpoint address, which must keep reaching the physical network.</summary>
    IReadOnlyList<string> PeerEndpointAddresses();

    /// <summary>The measured path budget for one peer, or null when nothing has measured it.</summary>
    int? PathMtuForPeer(long peerId);

    /// <summary>Where the route journal lives, or null for the default location.</summary>
    string? RouteJournalPath => null;

    /// <summary>This node's own consumer rules, fixed for the life of the process.</summary>
    IReadOnlyList<PeerEgressRule> ConsumerRules => [];

    /// <summary>
    /// The consumer's master switch, <c>peerEgressEnabled</c>. Off, the rules are kept and none is
    /// applied. True by default so a host built only to drive the plane applies what it is given.
    /// </summary>
    bool ConsumerEnabled => true;

    /// <summary>
    /// Phase two's switch, <c>peerEgressDnsTakeover</c>: domain rules through the fake-IP pool.
    /// Off by default, which is phase one exactly.
    /// </summary>
    bool DnsTakeover => false;

    /// <summary>The fake-IP pool as configured, <c>peerEgressFakeIpCidr</c>.</summary>
    string FakeIpCidr => PeerEgressRules.DefaultFakeIpCidr;

    /// <summary>
    /// The IPv4 networks of this device's own interfaces, which the pool must stay clear of. Read
    /// once, when phase two first starts.
    /// </summary>
    IReadOnlyList<string> LocalInterfaceNetworks() => PeerEgressEndpoints.LocalInterfaceCidrs();

    /// <summary>
    /// This device's own interface addresses: besides the mesh address, the only sources the DNS
    /// responder answers.
    /// </summary>
    IReadOnlyList<string> LocalInterfaceAddresses() => PeerEgressEndpoints.LocalInterfaceAddresses();

    /// <summary>
    /// Where the DNS responder forwards what it does not answer itself: addresses, each with an
    /// optional port. Step five records the system's own resolvers here; until then it is empty,
    /// and every forwarded query is answered SERVFAIL.
    /// </summary>
    IReadOnlyList<string> DnsUpstreams => [];

    /// <summary>Complete snapshot; omitted peers are offline.</summary>
    IReadOnlyDictionary<long, bool> EgressAvailability => new Dictionary<long, bool>();

    /// <summary>
    /// What carries frames to each peer now: <c>direct</c>, <c>relay</c>, or absent when there is
    /// neither. Read for status only.
    /// </summary>
    IReadOnlyDictionary<long, string> EgressPaths => new Dictionary<long, string>();

    /// <summary>Whether there is an interface to route into: a real device that started.</summary>
    bool DeviceReady => true;

    /// <summary>What the device is instead, for the line that says the routes are waiting on it.</summary>
    string DeviceStatus => "absent";

    /// <summary>
    /// The hosts the tunnel's transport talks to, as URLs, host:port pairs or bare hosts: the
    /// control connection, the login server, STUN and TURN, the relay. Resolved by the plane, so a
    /// hostname is fine here.
    /// </summary>
    IReadOnlyList<string?> BypassHosts() => [];
}

/// <summary>
/// Wiring the egress data plane into Peer Mesh.
/// </summary>
/// <remarks>
/// Four joins. SPEG1 frames are demultiplexed out of the decrypted payload stream, the pushed
/// <c>egress-config</c> becomes the policy the plane enforces, the pushed <c>egress-catalog</c>
/// says which egresses the consumer may send names to, and a closing session revokes that peer's
/// flows.
///
/// <para>Lock ordering is the constraint that shapes this class. The mesh takes its own lock and
/// the egress plane takes its own, and the plane holds its lock while emitting frames. So frames
/// are queued rather than sent inline: sending inline would mean the plane's lock is held while the
/// mesh's is taken, and the mesh already takes its lock on paths that reach into the plane, which
/// is a cycle. Everything here either queues or is called with no mesh lock held.</para>
/// </remarks>
/// <param name="dialer">
/// How the egress role opens its real sockets. Injected so this class can be driven without a
/// network: with the real dialer a test that pushes a policy and sends a SYN spends the whole
/// connect timeout reaching an address nobody routes.
/// </param>
/// <param name="commander">
/// How the consumer role changes the routing table, or null to build the platform's own. Injected
/// for the same reason the dialer is: a test that applies rules must not run <c>ip route</c> on the
/// machine it is running on.
/// </param>
/// <param name="lookup">How bypass hostnames are resolved, or null for the system resolver.</param>
/// <param name="dnsForwarder">
/// How the DNS responder reaches its upstreams, or null for real sockets. Injected so a test can
/// answer in place of a resolver.
/// </param>
internal sealed class PeerEgressMesh(
    IPeerEgressMeshHost host,
    ILogger? logger = null,
    IPeerEgressDialer? dialer = null,
    IPeerEgressRouteCommander? commander = null,
    Func<string, IPAddress[]>? lookup = null,
    IPeerEgressDnsForwarder? dnsForwarder = null) : IDisposable
{
    /// <summary>
    /// Drives the DNS responder's TCP retransmission and idle close. Well under the one-second
    /// retransmission interval, so a retransmission is never late by much of it.
    /// </summary>
    private const int DnsTickIntervalMs = 100;

    /// <summary>
    /// Bounds frames waiting for encryption. Egress TCP retains rejected payload/FIN until a
    /// writable notification. UDP and untracked control frames remain best effort; no caller blocks.
    /// </summary>
    private const int SendQueueDepth = 512;

    /// <summary>
    /// Drives retransmission and idle expiry. Well under the minimum RTO, so a retransmit is never
    /// delayed by more than a fraction of the interval it waited for.
    /// </summary>
    private const int TickIntervalMs = 100;

    private readonly BlockingCollection<(long Consumer, byte[] Frame)> _queue =
        new(new ConcurrentQueue<(long, byte[])>(), SendQueueDepth);

    /// <summary>
    /// Packets waiting to be written to the local device, on their own queue and their own loop.
    /// </summary>
    /// <remarks>
    /// Separate from the send queue because a node can be both roles at once, and sharing one loop
    /// would let an egress's outbound congestion stall the consumer's inbound delivery, which are
    /// different directions serving different peers.
    /// </remarks>
    private readonly BlockingCollection<byte[]> _deviceQueue =
        new(new ConcurrentQueue<byte[]>(), SendQueueDepth);

    private readonly CancellationTokenSource _stopping = new();
    private readonly object _gate = new();

    private PeerEgressRuntime? _runtime;
    private PeerEgressConsumer? _consumer;
    private PeerEgressRouteInstaller? _routes;

    /// <summary>
    /// What the last route apply left behind that cannot be recomputed: which prefixes were
    /// refused because somebody else already owned them, and whether the plan was rolled back.
    /// </summary>
    private volatile PeerEgressApplyOutcome _applied = PeerEgressApplyOutcome.None;
    private Thread? _sendLoop;
    private Thread? _tickLoop;
    private Thread? _deviceLoop;
    private bool _closed;

    /// <summary>
    /// The consumer's route plan, kept true on the mesh's own tick. Guarded by <see cref="_planLock"/>,
    /// which is never held while anything that can wait on the mesh runs: a reconcile resolves
    /// hostnames and runs route commands, and the mesh's own thread must never queue behind it.
    /// </summary>
    private readonly object _planLock = new();
    private readonly PeerEgressBypassResolver _bypass = new(lookup);
    private PeerEgressPlanAttempt? _lastPlan;
    private string _consumerKey = "";
    private string _refusalsLogged = "";
    private string _conflictsLogged = "";
    private string _errorLogged = "";
    private string _bypassFailedLogged = "";
    private bool _deviceWaitLogged;

    /// <summary>The last check of the table against the plan, and whether it left a reinstall undone.</summary>
    private long _repairAtMillis;
    private bool _repairTroubled;
    private string _tableErrorLogged = "";

    /// <summary>Which egresses resolve names, from <c>egress-catalog</c>; locked on its own.</summary>
    private readonly PeerEgressCatalog _catalog = new();

    /// <summary>
    /// Guards phase two's state below. Never held while anything that can wait on the mesh runs.
    /// </summary>
    private readonly object _phaseLock = new();

    /// <summary>
    /// The fake-IP pool, built the first time phase two runs and kept from then on. Its mappings
    /// are answers applications hold, so a reconcile that finds phase two still running must hand
    /// the consumer the same pool rather than a fresh one.
    /// </summary>
    private PeerEgressFakeIpPool? _fakeIpPool;

    /// <summary>The last decision on phase two, for the status; null before the first.</summary>
    private PeerEgressPhaseTwo? _phaseTwo;

    /// <summary>The pool whose overlap with this device's interfaces was checked, and the answer.</summary>
    private string? _interfacesCheckedFor;
    private bool _clearOfInterfaces;
    private string _phaseTwoLogged = "";

    /// <summary>
    /// The DNS responder, built the first time phase two runs and kept, like the pool, so its
    /// counters describe the whole run. Guarded by <see cref="_phaseLock"/>.
    /// </summary>
    private PeerEgressDnsResponder? _dnsResponder;
    private Timer? _dnsTick;
    private string _upstreamsRefusedLogged = "";

    /// <summary>
    /// Builds the plane and the threads that carry its frames and its clock, on first use.
    /// </summary>
    /// <remarks>
    /// Lazy on purpose. Building it on first contact would let any peer turn an unconfigured device
    /// into an egress by sending it a frame.
    /// </remarks>
    private PeerEgressRuntime EnsureRuntime()
    {
        if (_runtime is { } existing)
        {
            return existing;
        }
        lock (_gate)
        {
            if (_runtime is not null)
            {
                return _runtime;
            }
            var built = new PeerEgressRuntime(
                (consumer, frame) =>
                {
                    // Best effort for untracked control and UDP; TCP data uses TrySend below.
                    _queue.TryAdd((consumer, frame));
                },
                dialer ?? new PeerEgressSocketDialer(PeerEgressSocketBinder.ForPlatform(() => host.TunName)),
                logger: logger);
            built.TrySend = (consumer, frame) => !_stopping.IsCancellationRequested && _queue.TryAdd((consumer, frame));
            _runtime = built;
            EnsureLoops();
            // The tick only exists for the egress role: retransmission and idle expiry belong to
            // flows this node opened on somebody else's behalf.
            _tickLoop ??= Start(() =>
            {
                while (!_stopping.IsCancellationRequested)
                {
                    if (_stopping.Token.WaitHandle.WaitOne(TickIntervalMs))
                    {
                        return;
                    }
                    built.OnTick(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                }
            });
            return built;
        }
    }

    /// <summary>
    /// Starts the two loops that carry queued work, whichever role needed them first.
    /// </summary>
    /// <remarks>
    /// Both roles queue, so a node that is only a consumer needs these as much as one that is only
    /// an egress. Called under the gate.
    /// </remarks>
    private void EnsureLoops()
    {
        _sendLoop ??= Start(() =>
        {
            foreach (var outbound in _queue.GetConsumingEnumerable(_stopping.Token))
            {
                // One frame that fails to go out is a lost datagram. Letting its exception leave
                // this loop ended the thread and, unobserved on a thread of its own, the process:
                // every flow of every consumer went with it.
                try
                {
                    _runtime?.SendReady(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
                    // Blocking on the task is what this thread is for. It is not a pool thread, so
                    // waiting here costs nothing anyone else needs.
                    if (!host.SendToPeerAsync(outbound.Consumer, outbound.Frame).GetAwaiter().GetResult())
                    {
                        logger?.LogDebug("Peer Mesh egress send failed: peer={Peer}", outbound.Consumer);
                    }
                }
                catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
                {
                    logger?.LogDebug(ex, "Peer Mesh egress send failed: peer={Peer}", outbound.Consumer);
                }
            }
        });
        _deviceLoop ??= Start(() =>
        {
            foreach (var packet in _deviceQueue.GetConsumingEnumerable(_stopping.Token))
            {
                // As above: one packet the device would not take must not end the loop.
                try
                {
                    host.WriteToDeviceAsync(packet).GetAwaiter().GetResult();
                }
                catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
                {
                    logger?.LogDebug(ex, "Peer Mesh egress device write failed");
                }
            }
        });
    }

    /// <summary>
    /// A dedicated thread, not the pool. These loops block for the life of the node, and a pool
    /// thread parked like that is one everything else on the process cannot have.
    /// </summary>
    private static Thread Start(Action work)
    {
        var thread = new Thread(() =>
        {
            try
            {
                work();
            }
            catch (OperationCanceledException)
            {
                // Shutdown.
            }
        })
        { IsBackground = true };
        thread.Start();
        return thread;
    }

    /// <summary>
    /// Builds the consumer side on first use.
    /// </summary>
    /// <remarks>
    /// Its sender is synchronous, unlike the egress role's. It is called from the TUN read path
    /// with no plane lock held, and the caller needs to know whether the packet left: a send that
    /// failed means the rule's destination has to be blocked, not allowed out locally.
    /// </remarks>
    private PeerEgressConsumer EnsureConsumer()
    {
        if (_consumer is { } existing)
        {
            return existing;
        }
        lock (_gate)
        {
            // The consumer asks whether the peer is reachable and then queues. It gets a true
            // answer to the question it can act on -- whether the destination still has an egress
            // -- without waiting on a socket, and a frame dropped by a full queue is one TCP
            // retransmits, which is the same trade the egress role already makes.
            EnsureLoops();
            _consumer ??= new PeerEgressConsumer(
                (peerId, frame) => host.CanReach(peerId) && _queue.TryAdd((peerId, frame)),
                packet => _deviceQueue.TryAdd(packet),
                logger);
            return _consumer;
        }
    }

    /// <summary>
    /// Demultiplexes SPEG1 out of the decrypted payload stream.
    /// </summary>
    /// <remarks>
    /// Belongs after the application-message check and before the bare IPv4 endpoint check: a frame
    /// carrying the SPEG1 magic is addressed to the egress path and must be refused with its own
    /// code rather than dropped as an unrecognised mesh packet.
    ///
    /// <para>The consumer role is offered the frame first. A node can be both, and both roles
    /// receive type=1 frames; the consumer claims only what is addressed to its own virtual IP, so
    /// trying it first costs nothing and keeps a reply from being judged as an egress request.</para>
    /// </remarks>
    public bool HandleInboundFrame(long peerId, byte[] payload)
    {
        if (!PeerEgressFrame.LooksLikeFrame(payload))
        {
            return false;
        }
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (_consumer is { } consumerRole)
        {
            lock (consumerRole)
            {
                if (consumerRole.HandleInbound(payload, peerId, nowMs)) { return true; }
            }
        }
        if (_runtime is not { } plane)
        {
            // Nothing has enabled the egress on this node, so there is no policy to judge against.
            // The frame is dropped rather than answered with a refusal: a reply would need the rate
            // limiting only the plane provides, and a peer that never got an egress in the first
            // place learns from its own timeout.
            return true;
        }
        // A returning segment travels inside an SPEG1 frame, so the frame header has to come out of
        // the budget the stack sizes segments against.
        if (host.PathMtuForPeer(peerId) is { } pathMtu)
        {
            plane.SetPathMtu(pathMtu - PeerEgressFrame.HeaderBytes);
        }
        return plane.HandleFrame(peerId, payload, nowMs);
    }

    /// <summary>
    /// Offers a packet read from the TUN to the consumer rules, and reports whether the consumer
    /// claimed it.
    /// </summary>
    /// <remarks>
    /// Sits at the top of the TUN read path, because a destination a rule claims is not a mesh peer
    /// and the existing path would drop it as such: silently, and as though nothing had been
    /// configured.
    /// </remarks>
    public bool HandleOutbound(byte[] packet)
    {
        if (_consumer is not { } consumerRole)
        {
            return false;
        }
        PeerEgressConsumerOutcome outcome;
        lock (consumerRole)
        {
            outcome = consumerRole.HandleOutbound(packet, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        }
        if (outcome == PeerEgressConsumerOutcome.NotMine)
        {
            return false;
        }
        if (outcome is not (PeerEgressConsumerOutcome.Forwarded or PeerEgressConsumerOutcome.DnsQuery))
        {
            // Logged without the destination: a per-destination record of what a user was blocked
            // from reaching is their own browsing history.
            logger?.LogDebug("[peer-egress-consumer] packet not forwarded: {Outcome}", outcome);
        }
        return true;
    }

    /// <summary>
    /// Installs a pushed <c>egress-config</c>.
    /// </summary>
    /// <remarks>
    /// The revision guard is the spec's: a snapshot at or below the last accepted one is ignored, so
    /// a reordered or replayed push cannot walk the policy backwards.
    /// </remarks>
    public void ApplyEgressConfig(string? payload)
    {
        var message = PeerEgressConfigMessage.Decode(payload);
        if (message is null)
        {
            logger?.LogWarning("decode egress-config failed");
            return;
        }
        var plane = EnsureRuntime();
        if (!plane.AcceptRevision(message.Revision))
        {
            return;
        }
        var meshCidr = MeshCidrOrDefault();
        var context = new PeerEgressContext
        {
            MeshCidr = meshCidr,
            DeploymentDenyCidrs = [.. host.DeploymentDenyCidrs(), .. OwnFakeIpPool(meshCidr)],
        };
        plane.SetLocalInterfaceCidrs(PeerEgressEndpoints.LocalInterfaceCidrs());
        plane.ApplyPolicy(message.Policy, context, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        logger?.LogInformation(
            "[peer-egress] policy applied enabled={Enabled} revision={Revision} rules={Rules}",
            message.Policy.Enabled, message.Revision, message.Policy.DestinationRules.Count);
    }

    /// <summary>
    /// This node's own fake-IP pool when its configuration runs phase two, for the egress role's
    /// forced-deny list (protocol/spec/peer-egress-dns.md, section five). A consumer's flow dialled
    /// into it would be routed into this node's own tunnel and steered by this node's own names.
    /// </summary>
    /// <remarks>
    /// Judged from the configuration and the mesh prefix rather than from the last reconcile, which
    /// may not have run when the policy arrives; denying a range that turns out not to be routed
    /// here costs a destination nobody should be dialling anyway.
    /// </remarks>
    private IEnumerable<string> OwnFakeIpPool(string meshCidr)
    {
        var phase = PeerEgressRules.PhaseTwo(host.ConsumerEnabled, host.DnsTakeover, host.FakeIpCidr, meshCidr);
        return phase.Active ? [phase.Pool.ToString()] : [];
    }

    /// <summary>
    /// Takes a pushed <c>egress-catalog</c>: which egresses resolve names.
    /// </summary>
    /// <remarks>
    /// Its revision is guarded as <c>egress-config</c>'s is, per control session. An accepted
    /// catalogue can take away an egress's capability, and the flows to pool addresses it carried
    /// are then closed at once rather than left to fail: the consumer re-decides them and the purges
    /// go out here.
    /// </remarks>
    public void ApplyEgressCatalog(string? payload)
    {
        if (!_catalog.Read(payload))
        {
            logger?.LogDebug("[peer-egress-consumer] egress-catalog ignored: unreadable, or not newer than the last one");
            return;
        }
        logger?.LogInformation(
            "[peer-egress-consumer] egress catalog applied revision={Revision} domainTargetCapable=[{Capable}]",
            _catalog.Revision, string.Join(",", _catalog.CapableIds()));
        if (_consumer is not { } consumerRole)
        {
            // Nothing built yet; the consumer reads the catalogue when it is.
            return;
        }
        IReadOnlyDictionary<long, IReadOnlyList<string>> purge;
        lock (consumerRole)
        {
            // Read inside the consumer's lock, as ConfigureConsumer reads it, so whichever of the two
            // runs last hands the consumer the newest catalogue.
            purge = consumerRole.SetEgressCapabilities(_catalog.Capabilities(),
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        }
        DeliverPurges(purge);
    }

    /// <summary>
    /// A new control session is starting: the next <c>egress-catalog</c> is accepted whatever its
    /// revision, since the revision counts within one session. What the last one said is kept.
    /// </summary>
    public void NewControlSession() => _catalog.NewSession();

    /// <summary>The egress section of the diagnostic snapshot.</summary>
    /// <remarks>
    /// The consumer's half is read under this mesh's gate because the consumer has no lock of its
    /// own; the runtime's half takes the runtime's own lock.
    /// </remarks>
    public Dictionary<string, object?> Status()
    {
        var consumerRole = _consumer;
        var installer = _routes;
        var plane = _runtime;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        PeerEgressConsumerStatus? consumerStatus = null;
        if (consumerRole is not null)
        {
            lock (consumerRole)
            {
                consumerStatus = consumerRole.StatusSnapshot(nowMs);
            }
        }
        if (consumerStatus is not null) consumerStatus = consumerStatus with { Paths = host.EgressPaths };
        return PeerEgressStatus.Section(consumerStatus,
            installer?.Installed ?? [], _applied, plane?.StatusSnapshot(), host.ConsumerEnabled, host.ConsumerRules,
            DnsStatus(nowMs));
    }

    /// <summary>
    /// <c>consumer.dns</c>, only while <c>peerEgressDnsTakeover</c> is on. The counts are taken now
    /// rather than remembered, so an address whose rest ended a minute ago is not reported resting.
    /// </summary>
    private PeerEgressDnsStatus? DnsStatus(long nowMs)
    {
        if (!host.DnsTakeover)
        {
            return null;
        }
        PeerEgressPhaseTwo phase;
        PeerEgressFakeIpPool? pool;
        PeerEgressDnsResponder? responder;
        lock (_phaseLock)
        {
            phase = _phaseTwo ?? DecidePhaseTwoLocked(MeshCidrOrDefault()).Phase;
            pool = phase.Active ? _fakeIpPool : null;
            responder = _dnsResponder;
        }
        // The upstreams and the counters are there whenever the switch is on, so a node whose phase
        // two stopped still says where it would forward and what it did while it ran; the listen
        // address only while something answers on it.
        List<string> upstreams;
        lock (_phaseLock)
        {
            upstreams = [.. DnsUpstreams().Select(upstream => upstream.ToString())];
        }
        return new PeerEgressDnsStatus(phase.Active, host.FakeIpCidr?.Trim() ?? string.Empty,
            pool?.Mappings ?? 0, pool?.Quarantined(nowMs) ?? 0, phase.Code)
        {
            Listen = pool is not null && responder is not null ? Ipv4Cidr.FormatAddress(pool.Listen) : null,
            Upstreams = upstreams,
            Queries = responder?.Counters ?? new PeerEgressDnsCounters(0, 0, 0),
        };
    }

    /// <summary>
    /// Whether phase two runs now, and the pool it runs over.
    /// </summary>
    /// <remarks>
    /// Decided on every reconcile, because one of its inputs moves: the mesh prefix arrives from the
    /// server and a pool that overlaps it stops phase two. The overlap with this device's own
    /// interfaces is checked once, when the pool is first considered: the spec makes it a startup
    /// check, and following every address change is step five's work, together with the system DNS
    /// it has to hand back. An unusable pool stops phase two alone; phase one carries on.
    /// </remarks>
    private (PeerEgressPhaseTwo Phase, PeerEgressFakeIpPool? Pool) DecidePhaseTwo(string meshCidr)
    {
        lock (_phaseLock)
        {
            return DecidePhaseTwoLocked(meshCidr);
        }
    }

    private (PeerEgressPhaseTwo Phase, PeerEgressFakeIpPool? Pool) DecidePhaseTwoLocked(string meshCidr)
    {
        var phase = PeerEgressRules.PhaseTwo(host.ConsumerEnabled, host.DnsTakeover, host.FakeIpCidr, meshCidr);
        var reason = phase.Code is null ? "" : "peerEgressFakeIpCidr is not an IPv4 prefix of /8 to /24 clear of the mesh";
        if (phase.Active && !ClearOfInterfacesLocked(phase.Pool))
        {
            phase = new PeerEgressPhaseTwo(false, PeerEgressCodes.FakeIpPoolInvalid, default);
            reason = "peerEgressFakeIpCidr overlaps a network of this device's own interfaces";
        }
        _phaseTwo = phase;
        var said = phase.Active ? "on" : phase.Code ?? "off";
        if (!string.Equals(said, _phaseTwoLogged, StringComparison.Ordinal))
        {
            _phaseTwoLogged = said;
            if (phase.Active)
            {
                logger?.LogInformation("[peer-egress-consumer] phase two running: domain rules steer through the fake-IP pool");
            }
            else if (phase.Code is not null)
            {
                // The reason and not the value, as for rules: configuration stays out of the log.
                logger?.LogWarning("[peer-egress-consumer] phase two not started: {Code} ({Reason}); phase one carries on",
                    phase.Code, reason);
            }
        }
        if (!phase.Active)
        {
            return (phase, null);
        }
        if (_fakeIpPool is null || _fakeIpPool.Cidr != phase.Pool)
        {
            _fakeIpPool = new PeerEgressFakeIpPool(phase.Pool, logger: logger);
        }
        return (phase, _fakeIpPool);
    }

    /// <summary>Whether the pool is clear of this device's own interface networks, asked once per pool.</summary>
    private bool ClearOfInterfacesLocked(Ipv4Cidr pool)
    {
        var key = pool.ToString();
        if (string.Equals(_interfacesCheckedFor, key, StringComparison.Ordinal))
        {
            return _clearOfInterfaces;
        }
        _interfacesCheckedFor = key;
        _clearOfInterfaces = true;
        foreach (var text in host.LocalInterfaceNetworks())
        {
            if (Ipv4Cidr.TryParse(text, out var network) && network.Overlaps(pool))
            {
                // A pool route over a network this device is on would take part of that network
                // away from it, and an address handed out there could be a real neighbour's.
                _clearOfInterfaces = false;
                break;
            }
        }
        return _clearOfInterfaces;
    }

    /// <summary>
    /// Installs the consumer's own rules and the routes they need, now.
    /// </summary>
    /// <remarks>
    /// Refused rules are reported and skipped; the rest take effect. A rule set is rarely wrong all
    /// at once, and refusing to apply any of it would leave a user with one typo sending everything
    /// out locally, which is the failure this feature exists to prevent.
    /// </remarks>
    public void ApplyRules(IReadOnlyList<PeerEgressRule> rules) =>
        Reconcile(rules, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    /// <summary>
    /// Recomputes the consumer's routes from what the host knows now and applies them if that is
    /// due: once the virtual device is up, and on the mesh's own tick from then on.
    /// </summary>
    /// <remarks>
    /// The rules are fixed for the life of the process, but what they need installed is not. A
    /// bypass exists for an address a rule covers, and those addresses move: peers connect and
    /// drop, the relay is reassigned, the control connection is re-established.
    /// </remarks>
    public void ReconcileRoutes() =>
        // With the master switch off nothing is taken over. The plan is then empty, which withdraws
        // whatever a previous run left installed, and the consumer is not built.
        Reconcile(host.ConsumerEnabled ? host.ConsumerRules : [], DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    public void Reconcile(IReadOnlyList<PeerEgressRule> rules, long nowMs)
    {
        lock (_gate) { if (_closed) { return; } }
        var meshCidr = MeshCidrOrDefault();
        // Phase two needs the consumer even with no rules yet: the pool's route sends its addresses
        // into the TUN, and whatever arrives there is refused as unmapped rather than dropped
        // unaccounted for by the mesh path.
        var (_, pool) = DecidePhaseTwo(meshCidr);
        var responder = pool is null ? null : DnsResponderFor(rules, meshCidr, pool);
        // Consumer callbacks may reach the mesh. Do not wait for their lock while
        // holding _planLock, which mesh shutdown needs when withdrawing routes.
        var purge = rules.Count == 0 && pool is null
            ? new Dictionary<long, IReadOnlyList<string>>()
            : ConfigureConsumer(rules, meshCidr, pool, responder, nowMs);
        lock (_planLock)
        {
            lock (_gate)
            {
                if (_closed)
                {
                    return;
                }
            }
            ReconcileLocked(rules, pool?.Cidr, nowMs);
        }
        // Delivered outside the plan lock. A purge reaches a peer through the mesh, and nothing
        // that can wait on the mesh may run while a lock the mesh itself may need is held.
        DeliverPurges(purge);
        SyncEgressAvailability(host.EgressAvailability);
    }

    private void ReconcileLocked(
        IReadOnlyList<PeerEgressRule> rules, Ipv4Cidr? fakeIpPool, long nowMs)
    {
        var meshCidr = MeshCidrOrDefault();

        // Without a device there is nothing to route into. A rule's route pointed at an interface
        // that is not there is a black hole rather than the local fallback the user would get with
        // no route at all, so the plan is empty until the device is up, and empties again if it
        // goes.
        IReadOnlyList<PeerEgressRoute> desired = [];
        if (host.DeviceReady)
        {
            _deviceWaitLogged = false;
            var plan = PeerEgressRoutePlanner.Plan(rules, BypassAddresses(nowMs), meshCidr, fakeIpPool);
            LogRefusals(plan.Refused);
            desired = plan.Routes;
        }
        else if ((rules.Count > 0 || fakeIpPool is not null) && !_deviceWaitLogged)
        {
            _deviceWaitLogged = true;
            logger?.LogWarning("[peer-egress-consumer] routes not installed: virtual device is {Status}",
                host.DeviceStatus);
        }

        var installer = EnsureRouteInstaller();
        if (!PeerEgressRoutePlanner.ReconcileDue(_lastPlan, desired, nowMs))
        {
            // The common tick: the plan has nothing to do, so the table is checked against it.
            if (host.DeviceReady)
            {
                RepairDrift(installer, nowMs);
            }
            return;
        }
        var result = installer.Apply(desired);
        _lastPlan = new PeerEgressPlanAttempt(nowMs, desired, result.Conflicts.Count > 0 || result.Error is not null);
        _repairAtMillis = 0;
        _repairTroubled = false;

        // Remembered before it is logged. A conflict is the one part of this outcome nothing can
        // recompute -- the answer came from the platform's routing table at this moment -- and
        // writing it only to the log is what left an operator with no way to see that a rule they
        // wrote is not in force.
        var error = result.Error?.Message ?? string.Empty;
        _applied = new PeerEgressApplyOutcome(nowMs, result.Conflicts.ToList(), error, result.RolledBack, true);

        // Logged when they change, not on every retry. A conflict is retried every minute for as
        // long as the other route is there, and repeating the same line each time would bury the
        // one that says it went away.
        var conflicts = string.Join(";", result.Conflicts.Select(c => c.Route.Cidr + "=" + c.Existing));
        if (!string.Equals(conflicts, _conflictsLogged, StringComparison.Ordinal))
        {
            _conflictsLogged = conflicts;
            foreach (var conflict in result.Conflicts)
            {
                // Not preempted and not compared by metric. The operator is told which of their
                // own routes is in the way, so they can decide rather than discover it later.
                logger?.LogWarning(
                    "[peer-egress-consumer] route {Cidr} not installed, already present: {Existing}",
                    conflict.Route.Cidr, conflict.Existing);
            }
        }
        if (!string.Equals(error, _errorLogged, StringComparison.Ordinal))
        {
            _errorLogged = error;
            if (result.Error is not null)
            {
                logger?.LogWarning("[peer-egress-consumer] route install failed: {Error} rolledBack={RolledBack}",
                    result.Error.Message, result.RolledBack);
            }
        }
        if (result.Added.Count > 0 || result.Removed.Count > 0)
        {
            logger?.LogInformation("[peer-egress-consumer] routes added={Added} removed={Removed}",
                result.Added.Count, result.Removed.Count);
        }
    }

    /// <summary>
    /// Puts back what the routing table lost since the plan was applied: a route dropped with its
    /// interface, a bypass still naming a gateway the machine left behind. Called under the plan
    /// lock on the ticks the plan itself has nothing to do.
    /// </summary>
    private void RepairDrift(PeerEgressRouteInstaller installer, long nowMs)
    {
        if (_repairTroubled && nowMs - _repairAtMillis < PeerEgressRoutePlanner.RetryAfterMillis)
        {
            return;
        }
        var result = installer.Repair();
        if (result.TableError is not null)
        {
            // Said once per failure. Without the table nothing can be compared, and a machine
            // whose `ip` is missing would otherwise say so every five seconds.
            var text = result.TableError.Message;
            if (!string.Equals(text, _tableErrorLogged, StringComparison.Ordinal))
            {
                _tableErrorLogged = text;
                logger?.LogWarning("[peer-egress-consumer] cannot read the routing table to check the routes: {Error}", text);
            }
            _repairAtMillis = nowMs;
            _repairTroubled = true;
            return;
        }
        _tableErrorLogged = "";
        _repairAtMillis = nowMs;
        _repairTroubled = result.Error is not null;

        foreach (var drift in result.Repaired)
        {
            // Each one is a real event -- the machine changed networks -- so each one is said.
            logger?.LogInformation("[peer-egress-consumer] route {Cidr} put back, it was {Reason}",
                drift.Route.Cidr, drift.Reason);
        }
        if (result.Lost.Count > 0)
        {
            // Reported the way an apply reports a conflict, and remembered the same way, so the
            // status lists the prefix as not installed with what holds it. The plan still wants
            // it: marked troubled, it asks again after the interval and reports the conflict if
            // it is still there.
            var previous = _applied;
            var merged = previous.Conflicts.ToList();
            foreach (var lost in result.Lost)
            {
                merged.RemoveAll(existing => existing.Route.Cidr == lost.Route.Cidr);
                merged.Add(lost);
                logger?.LogWarning("[peer-egress-consumer] route {Cidr} lost to another route, not taken back: {Existing}",
                    lost.Route.Cidr, lost.Existing);
            }
            _applied = new PeerEgressApplyOutcome(nowMs, merged, previous.Error, previous.RolledBack, true);
            if (_lastPlan is { } plan)
            {
                _lastPlan = new PeerEgressPlanAttempt(nowMs, plan.Desired, true);
            }
        }
        if (result.Error is not null)
        {
            var text = result.Error.Message;
            if (!string.Equals(text, _errorLogged, StringComparison.Ordinal))
            {
                _errorLogged = text;
                logger?.LogWarning("[peer-egress-consumer] route repair failed: {Error}", text);
            }
        }
    }

    /// <summary>
    /// Gives the consumer its rules, once per distinct configuration.
    /// </summary>
    /// <remarks>
    /// Reconfiguring purges the flows the new rules no longer cover, and with the same rules that is
    /// every flow being re-examined for nothing on every tick; with a change of virtual IP it is
    /// what has to happen.
    /// </remarks>
    private IReadOnlyDictionary<long, IReadOnlyList<string>> ConfigureConsumer(
        IReadOnlyList<PeerEgressRule> rules, string meshCidr, PeerEgressFakeIpPool? fakeIpPool,
        PeerEgressDnsResponder? responder, long nowMs)
    {
        var virtualIp = host.VirtualIp?.Trim() ?? string.Empty;
        // Phase two starting or stopping changes which rules are in force, so it is part of what
        // makes a configuration distinct.
        var key = meshCidr + "|" + virtualIp + "|" + (fakeIpPool?.Cidr.ToString() ?? "-") + "|" + string.Join("|",
            rules.Select(rule => $"{rule.Match} {rule.Action} {rule.EgressClientId} {rule.Port}"));
        var consumerRole = EnsureConsumer();
        lock (consumerRole)
        {
            // Queries to the listen address reach the responder only while phase two runs.
            consumerRole.DnsResponder = responder;
            if (string.Equals(key, _consumerKey, StringComparison.Ordinal))
            {
                return new Dictionary<long, IReadOnlyList<string>>();
            }
            _consumerKey = key;
            // A consumer built after the catalogue arrived has not heard it yet. Read inside the
            // consumer's lock, as ApplyEgressCatalog reads it, so the newest catalogue wins.
            var purge = Merge(
                consumerRole.SetEgressCapabilities(_catalog.Capabilities(), nowMs),
                consumerRole.Configure(rules, meshCidr, virtualIp, nowMs, fakeIpPool));
            return purge;
        }
    }

    /// <summary>
    /// The DNS responder, built the first time phase two runs, and brought up to date with the rules,
    /// the pool, this node's mesh address and the upstreams on every reconcile.
    /// </summary>
    private PeerEgressDnsResponder DnsResponderFor(IReadOnlyList<PeerEgressRule> rules, string meshCidr,
        PeerEgressFakeIpPool pool)
    {
        PeerEgressDnsResponder responder;
        lock (_phaseLock)
        {
            if (_dnsResponder is null)
            {
                lock (_gate)
                {
                    // Its answers go out on the device loop, like the consumer's.
                    EnsureLoops();
                }
                var built = new PeerEgressDnsResponder(packet => _deviceQueue.TryAdd(packet), dnsForwarder,
                    localAddresses: host.LocalInterfaceAddresses, logger: logger);
                _dnsTick = new Timer(_ => built.OnTick(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
                    null, DnsTickIntervalMs, DnsTickIntervalMs);
                _dnsResponder = built;
            }
            responder = _dnsResponder;
            responder.Configure(rules, meshCidr, pool, host.VirtualIp, DnsUpstreams());
        }
        return responder;
    }

    /// <summary>
    /// The upstreams the host names, as addresses. One that does not read as an address, with an
    /// optional port, is left out and said once: forwarding to a guess would be worse than to fewer.
    /// Called under <see cref="_phaseLock"/>.
    /// </summary>
    private List<PeerEgressDnsUpstream> DnsUpstreams()
    {
        var upstreams = new List<PeerEgressDnsUpstream>();
        var refused = 0;
        foreach (var text in host.DnsUpstreams)
        {
            if (PeerEgressDnsUpstream.TryParse(text, out var upstream))
            {
                upstreams.Add(upstream);
            }
            else
            {
                refused++;
            }
        }
        var said = refused.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (refused > 0 && !string.Equals(said, _upstreamsRefusedLogged, StringComparison.Ordinal))
        {
            logger?.LogWarning("[peer-egress-dns] {Count} DNS upstream(s) are not an address with an optional port and are not used",
                refused);
        }
        _upstreamsRefusedLogged = refused > 0 ? said : "";
        return upstreams;
    }

    /// <summary>The DNS responder while phase two runs, for tests and the status.</summary>
    internal PeerEgressDnsResponder? DnsResponder
    {
        get
        {
            lock (_phaseLock)
            {
                return _phaseTwo is { Active: true } ? _dnsResponder : null;
            }
        }
    }

    /// <summary>Two sets of purges as one, a destination named by both sent once.</summary>
    private static Dictionary<long, IReadOnlyList<string>> Merge(
        IReadOnlyDictionary<long, IReadOnlyList<string>> first, IReadOnlyDictionary<long, IReadOnlyList<string>> second)
    {
        var merged = new Dictionary<long, IReadOnlyList<string>>();
        foreach (var (egress, destinations) in first.Concat(second))
        {
            merged[egress] = merged.TryGetValue(egress, out var known)
                ? known.Union(destinations, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList()
                : destinations;
        }
        return merged;
    }

    /// <summary>
    /// Reports the rules that were thrown out, once per distinct set. The rules do not change while
    /// the process runs, so in practice this is once.
    /// </summary>
    private void LogRefusals(IReadOnlyList<PeerEgressRuleRefusal> refused)
    {
        var joined = string.Join(",", refused.Select(r => r.Index + ":" + r.Code));
        if (string.Equals(joined, _refusalsLogged, StringComparison.Ordinal))
        {
            return;
        }
        _refusalsLogged = joined;
        foreach (var refusal in refused)
        {
            // The index and the code, not the match: configuration values stay out of the log.
            logger?.LogWarning("[peer-egress-consumer] rule {Index} refused: {Code}",
                refusal.Index, refusal.Code);
        }
    }

    /// <summary>
    /// The addresses that must keep reaching the physical network: the host's transport endpoints,
    /// resolved, and every peer's own endpoint. Without them a rule broad enough to cover one would
    /// route the tunnel's transport into the tunnel.
    /// </summary>
    private List<string> BypassAddresses(long nowMs)
    {
        var resolution = _bypass.Resolve(host.BypassHosts(), nowMs);
        var failed = string.Join(",", resolution.Failed);
        if (!string.Equals(failed, _bypassFailedLogged, StringComparison.Ordinal))
        {
            _bypassFailedLogged = failed;
            foreach (var hostName in resolution.Failed)
            {
                // Said once per failure, not per tick: the cache retries after its TTL and the
                // next line is the one that says it resolved.
                logger?.LogWarning(
                    "[peer-egress-consumer] bypass host {Host} did not resolve; a rule covering it would capture it",
                    hostName);
            }
        }
        var addresses = new List<string>(resolution.Addresses);
        addresses.AddRange(host.PeerEndpointAddresses());
        return addresses;
    }

    /// <summary>
    /// Builds the installer and takes back whatever a previous run left in the journal.
    /// </summary>
    /// <remarks>
    /// Taken back rather than adopted. A journal outlives the process that wrote it, and that
    /// process's interface is gone with it, so the routes it describes are either gone too or
    /// pointing at nothing; what is still wanted is put back by the apply that follows. This is
    /// also what clears a crash's leftovers when the rules have since been removed: there is no
    /// rule set so small that the journal is not read.
    /// </remarks>
    private PeerEgressRouteInstaller EnsureRouteInstaller()
    {
        if (_routes is { } existing)
        {
            return existing;
        }
        lock (_gate)
        {
            if (_routes is not null)
            {
                return _routes;
            }
            var journal = host.RouteJournalPath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".specus", "egress-routes.json");
            var installer = new PeerEgressRouteInstaller(
                commander ?? PeerEgressRouteCommanders.ForPlatform(host.TunName), journal);
            try
            {
                installer.Load();
            }
            catch (Exception unusable)
            {
                logger?.LogWarning(
                    "[peer-egress-consumer] route journal unusable, starting empty: {Error}",
                    unusable.Message);
            }
            var leftover = installer.WithdrawAll();
            if (leftover.Count > 0)
            {
                logger?.LogInformation("[peer-egress-consumer] took back {Count} routes left by a previous run",
                    leftover.Count);
            }
            _routes = installer;
            return installer;
        }
    }

    /// <summary>
    /// Tells the consumer which egresses can take a flow, and delivers the purges a peer going
    /// offline produces.
    /// </summary>
    public void SyncEgressAvailability(IReadOnlyDictionary<long, bool> online)
    {
        if (_consumer is not { } consumerRole)
        {
            return;
        }
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var purge = new Dictionary<long, IReadOnlyList<string>>();
        lock (consumerRole)
        {
            var peers = consumerRole.StatusSnapshot(nowMs).Online.Keys.Concat(online.Keys).Distinct().ToArray();
            foreach (var peer in peers)
            {
                foreach (var (egress, destinations) in consumerRole.SetEgressOnline(peer,
                             online.TryGetValue(peer, out var up) && up, nowMs))
                {
                    purge[egress] = destinations;
                }
            }
        }
        DeliverPurges(purge);
    }

    /// <summary>
    /// Sends one flow-purge per affected egress.
    /// </summary>
    /// <remarks>
    /// Best effort by design. The message is what closes the far side promptly, but the egress
    /// reclaims the flow on its own idle timer regardless, so a purge that cannot be delivered
    /// delays cleanup rather than losing it.
    /// </remarks>
    private void DeliverPurges(IReadOnlyDictionary<long, IReadOnlyList<string>> purge)
    {
        foreach (var (egress, destinations) in purge)
        {
            if (destinations.Count == 0)
            {
                continue;
            }
            _queue.TryAdd((egress, PurgeFrame(destinations)));
        }
    }

    /// <summary>The flow-purge frame sent to an egress for these destinations.</summary>
    internal static byte[] PurgeFrame(IReadOnlyList<string> destinations) =>
        PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, PeerEgressFrame.EncodeControl(
            PeerEgressFrame.Control.FlowPurge(destinations, PeerEgressCodes.Disabled)));

    /// <summary>
    /// The fake-IP pool while phase two runs, null otherwise. The DNS responder (step four of
    /// protocol/spec/peer-egress-dns.md) answers from it: <see cref="PeerEgressFakeIpPool.Query(string)"/>
    /// for a name, <see cref="PeerEgressFakeIpPool.NameFor"/> for a reverse lookup.
    /// </summary>
    internal PeerEgressFakeIpPool? FakeIpPool
    {
        get
        {
            lock (_phaseLock)
            {
                return _phaseTwo is { Active: true } ? _fakeIpPool : null;
            }
        }
    }

    /// <summary>
    /// Closes a peer's flows when its session ends.
    /// </summary>
    /// <remarks>
    /// The plane cannot poll for this: asking the mesh whether a peer is still authorised would mean
    /// taking the mesh lock from under the plane's own, so revocation is delivered as an event
    /// instead.
    /// </remarks>
    public void RevokeConsumer(long peerId)
    {
        if (_runtime is { } plane && peerId > 0)
        {
            plane.RevokeConsumer(peerId, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        }
    }

    /// <summary>
    /// Takes back every route this feature installed and forgets the plan, so the next reconcile
    /// starts from nothing. Safe to call with the mesh's own lock held: nothing here waits on it.
    /// </summary>
    /// <summary>
    /// Stops serving other consumers, and leaves everything this node installed for its own
    /// traffic where it is.
    /// </summary>
    /// <remarks>
    /// For a control connection that has gone away and is about to come back. An egress that
    /// cannot hear a revocation should not be taking new flows, but the routes this node's own
    /// rules claimed are still the truth about where that traffic goes, and withdrawing them for
    /// the length of a reconnect puts it back on the machine's own default route. The loops and
    /// the queue stay, so the next policy push rebuilds the plane without restarting them.
    /// </remarks>
    public void ShutdownServing()
    {
        PeerEgressRuntime? plane;
        lock (_gate)
        {
            plane = _runtime;
            _runtime = null;
        }
        plane?.Shutdown(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    public void WithdrawRoutes()
    {
        lock (_planLock)
        {
            PeerEgressRouteInstaller? installer;
            lock (_gate)
            {
                installer = _routes;
                _routes = null;
            }
            _lastPlan = null;
            _repairAtMillis = 0;
            _repairTroubled = false;
            // What was logged belongs to the routes that are going; the next start says its own.
            _conflictsLogged = "";
            _errorLogged = "";
            _deviceWaitLogged = false;
            _tableErrorLogged = "";
            installer?.WithdrawAll();
        }
    }

    /// <summary>
    /// Stops forwarding. The plane closes sockets under its own lock, and the loops are stopped by
    /// their own signal rather than by completing the queue: a reader thread can still be between
    /// releasing the plane's lock and queuing its last frame.
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
        }
        _runtime?.Shutdown(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        lock (_phaseLock)
        {
            _dnsTick?.Dispose();
            _dnsTick = null;
        }
        _stopping.Cancel();
        _sendLoop?.Join(TimeSpan.FromSeconds(1));
        _tickLoop?.Join(TimeSpan.FromSeconds(1));
        _deviceLoop?.Join(TimeSpan.FromSeconds(1));
        _stopping.Dispose();
    }

    private string MeshCidrOrDefault() =>
        string.IsNullOrWhiteSpace(host.MeshCidr) ? PeerEgressRules.DefaultMeshCidr : host.MeshCidr.Trim();

    /// <summary>Visible for tests: how many frames are waiting to be encrypted and sent.</summary>
    public int QueuedFrames => _queue.Count;
}
