using System.Collections.Concurrent;
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
}

/// <summary>
/// Wiring the egress data plane into Peer Mesh.
/// </summary>
/// <remarks>
/// Three joins. SPEG1 frames are demultiplexed out of the decrypted payload stream, the pushed
/// <c>egress-config</c> becomes the policy the plane enforces, and a closing session revokes that
/// peer's flows.
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
internal sealed class PeerEgressMesh(
    IPeerEgressMeshHost host,
    ILogger? logger = null,
    IPeerEgressDialer? dialer = null,
    IPeerEgressRouteCommander? commander = null) : IDisposable
{
    /// <summary>
    /// Bounds frames waiting to be encrypted and sent. A full queue drops, which is safe here in a
    /// way it would not be elsewhere: TCP retransmits what is lost and UDP is lossy by contract,
    /// whereas blocking would stall every flow on the node.
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
    private Thread? _sendLoop;
    private Thread? _tickLoop;
    private Thread? _deviceLoop;
    private bool _closed;

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
                    // TryAdd rather than Add: a full queue drops, it never blocks the plane.
                    _queue.TryAdd((consumer, frame));
                },
                dialer ?? new PeerEgressSocketDialer(),
                logger: logger);
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
                // Blocking on the task is what this thread is for. It is not a pool thread, so
                // waiting here costs nothing anyone else needs.
                if (!host.SendToPeerAsync(outbound.Consumer, outbound.Frame).GetAwaiter().GetResult())
                {
                    logger?.LogDebug("Peer Mesh egress send failed: peer={Peer}", outbound.Consumer);
                }
            }
        });
        _deviceLoop ??= Start(() =>
        {
            foreach (var packet in _deviceQueue.GetConsumingEnumerable(_stopping.Token))
            {
                host.WriteToDeviceAsync(packet).GetAwaiter().GetResult();
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
        if (_consumer is { } consumerRole && consumerRole.HandleInbound(payload, peerId, nowMs))
        {
            return true;
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
        var outcome = consumerRole.HandleOutbound(packet, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        if (outcome == PeerEgressConsumerOutcome.NotMine)
        {
            return false;
        }
        if (outcome != PeerEgressConsumerOutcome.Forwarded)
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
        var context = new PeerEgressContext
        {
            MeshCidr = MeshCidrOrDefault(),
            DeploymentDenyCidrs = host.DeploymentDenyCidrs(),
        };
        plane.SetLocalInterfaceCidrs(PeerEgressEndpoints.LocalInterfaceCidrs());
        plane.ApplyPolicy(message.Policy, context, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        logger?.LogInformation(
            "[peer-egress] policy applied enabled={Enabled} revision={Revision} rules={Rules}",
            message.Policy.Enabled, message.Revision, message.Policy.DestinationRules.Count);
    }

    /// <summary>
    /// Installs the consumer's own rules and the routes they need.
    /// </summary>
    /// <remarks>
    /// Refused rules are reported and skipped; the rest take effect. A rule set is rarely wrong all
    /// at once, and refusing to apply any of it would leave a user with one typo sending everything
    /// out locally, which is the failure this feature exists to prevent.
    /// </remarks>
    public void ApplyRules(IReadOnlyList<PeerEgressRule> rules)
    {
        var consumerRole = EnsureConsumer();
        var meshCidr = MeshCidrOrDefault();
        DeliverPurges(consumerRole.Configure(rules, meshCidr, host.VirtualIp,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));

        var plan = PeerEgressRoutePlanner.Plan(rules, host.PeerEndpointAddresses(), meshCidr);
        foreach (var refusal in plan.Refused)
        {
            logger?.LogWarning("[peer-egress-consumer] rule {Index} ({Match}) refused: {Code}",
                refusal.Index, refusal.Match, refusal.Code);
        }

        var installer = EnsureRouteInstaller();
        var result = installer.Apply(plan.Routes);
        foreach (var conflict in result.Conflicts)
        {
            // Not preempted and not compared by metric. The operator is told which of their own
            // routes is in the way, so they can decide rather than discover it later.
            logger?.LogWarning(
                "[peer-egress-consumer] route {Cidr} not installed, already present: {Existing}",
                conflict.Route.Cidr, conflict.Existing);
        }
        if (result.Error is not null)
        {
            logger?.LogWarning("[peer-egress-consumer] route install failed: {Error} rolledBack={RolledBack}",
                result.Error.Message, result.RolledBack);
        }
        if (result.Added.Count > 0 || result.Removed.Count > 0)
        {
            logger?.LogInformation("[peer-egress-consumer] routes added={Added} removed={Removed}",
                result.Added.Count, result.Removed.Count);
        }
    }

    /// <summary>
    /// Builds the installer and adopts any journal a previous run left.
    /// </summary>
    /// <remarks>
    /// Adoption comes first so a process that was killed has its routes taken back rather than left
    /// for a user to find and wonder about.
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
                commander ?? LinuxPeerEgressRouteCommander.ForPlatform(host.TunName), journal);
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
        foreach (var (egress, up) in online)
        {
            DeliverPurges(consumerRole.SetEgressOnline(egress, up, nowMs));
        }
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
            var body = PeerEgressFrame.EncodeControl(
                PeerEgressFrame.Control.FlowPurge(destinations, PeerEgressCodes.Disabled));
            _queue.TryAdd((egress, PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body)));
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

    /// <summary>Takes back every route this feature installed.</summary>
    public void WithdrawRoutes()
    {
        PeerEgressRouteInstaller? installer;
        lock (_gate)
        {
            installer = _routes;
            _routes = null;
        }
        installer?.WithdrawAll();
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
