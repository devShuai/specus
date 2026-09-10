using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The egress flow table: what is open right now, who opened it, and when it stops being allowed.
/// </summary>
/// <remarks>
/// TCP announces its own beginning and end, so its state machine could in principle track itself.
/// UDP announces neither, so a session exists only because this table says it does, and ends only
/// because an idle timer says it does. Both protocols share one table anyway, because the limits in
/// the policy count flows rather than TCP flows: a consumer must not be able to exceed its quota by
/// splitting traffic across protocols.
///
/// <para>Like the TCP state machine this holds no sockets and reads no clock. Time arrives as an
/// argument so expiry is deterministic under test, and the caller keeps whatever handle it needs in
/// <see cref="Flow.Handle"/>, which this class never inspects.</para>
///
/// <para>Not safe for concurrent use. The data plane serialises access through its own loop, and a
/// lock here would invite callers to hold a flow past the point where the table still vouches for
/// it.</para>
/// </remarks>
internal sealed class PeerEgressFlowTable
{
    /// <summary>
    /// Applies when the policy names no timeout. Long enough not to cut a QUIC connection between
    /// its own keepalives, short enough that a consumer that vanished stops holding a socket.
    /// </summary>
    public const long DefaultIdleTimeoutMs = 5 * 60 * 1000L;

    /// <summary>
    /// Identifies one flow by its full inner four-tuple.
    /// </summary>
    /// <remarks>
    /// Keying on the consumer's source port alone would be wrong, not merely coarse. Two datagrams
    /// leaving the same consumer port for different destinations are separate sessions; collapsing
    /// them onto one socket would send the second destination's traffic to the first.
    /// </remarks>
    internal readonly record struct Key(
        int Protocol, uint ConsumerIp, ushort ConsumerPort, uint RemoteIp, ushort RemotePort)
    {
        public string ProtocolName() => Protocol switch
        {
            PeerEgressSegment.Ipv4ProtocolTcp => "tcp",
            PeerEgressDatagram.Ipv4ProtocolUdp => "udp",
            // Anything else yields a name no destination rule can match, so an unsupported
            // protocol is refused rather than defaulting to one a rule might allow.
            _ => ""
        };
    }

    /// <summary>One live flow's accounting. The data plane owns the socket; this owns the fact that it may exist.</summary>
    internal sealed class Flow(Key key, long consumer, long nowMs)
    {
        public Key Key { get; } = key;
        public long Consumer { get; } = consumer;
        public long OpenedAtMs { get; } = nowMs;
        public long LastSeenMs { get; set; } = nowMs;
        public long BytesToRemote { get; set; }
        public long BytesFromRemote { get; set; }

        /// <summary>
        /// Whatever the caller attached: a connection, a socket, a cancellation handle. Stored so
        /// that everything needed to tear a flow down travels with the entry that authorises it,
        /// and never read here.
        /// </summary>
        public object? Handle { get; set; }
    }

    /// <summary>
    /// Pairs a closed flow with why it closed.
    /// </summary>
    /// <remarks>
    /// Carried per flow rather than per batch because one policy push can close flows for different
    /// reasons at once: a destination rule dropped for one, a consumer removed from the allow list
    /// for another. Collapsing them onto a single code would put a reason in the consumer's
    /// flow-reject that does not match what actually happened to that flow.
    /// </remarks>
    internal sealed record Revocation(Flow Flow, string? Code);

    private readonly long _idleTimeoutMs;
    private readonly Dictionary<Key, Flow> _flows = [];
    private readonly Dictionary<long, int> _perConsumer = [];

    public PeerEgressFlowTable(long idleTimeoutMs) =>
        _idleTimeoutMs = idleTimeoutMs > 0 ? idleTimeoutMs : DefaultIdleTimeoutMs;

    public int Count => _flows.Count;

    /// <summary>Feeds the two limit checks in the judgment layer, so it excludes the flow being considered.</summary>
    public int CountFor(long consumer) => _perConsumer.GetValueOrDefault(consumer, 0);

    public Flow? Lookup(Key key) => _flows.GetValueOrDefault(key);

    /// <summary>
    /// Records activity. Idle expiry is measured from the last packet in either direction, so a
    /// flow that is only receiving stays alive.
    /// </summary>
    public void Touch(Key key, long nowMs)
    {
        if (_flows.TryGetValue(key, out var flow))
        {
            flow.LastSeenMs = nowMs;
        }
    }

    /// <summary>
    /// Records an authorised flow, returning null when the key is already present.
    /// </summary>
    /// <remarks>
    /// A caller must treat that as "use the existing flow" rather than as an error: a retransmitted
    /// SYN, or a second datagram arriving before the first finished opening, is normal traffic and
    /// not an attack.
    /// </remarks>
    public Flow? Open(Key key, long consumer, long nowMs)
    {
        if (_flows.TryGetValue(key, out var existing))
        {
            existing.LastSeenMs = nowMs;
            return null;
        }
        var flow = new Flow(key, consumer, nowMs);
        _flows[key] = flow;
        _perConsumer[consumer] = _perConsumer.GetValueOrDefault(consumer, 0) + 1;
        return flow;
    }

    /// <summary>
    /// Removes a flow and returns it so the caller can release the socket it carries. Closing an
    /// unknown key is not an error; teardown races are ordinary.
    /// </summary>
    public Flow? Close(Key key)
    {
        if (!_flows.Remove(key, out var flow))
        {
            return null;
        }
        Release(flow.Consumer);
        return flow;
    }

    private void Release(long consumer)
    {
        if (!_perConsumer.TryGetValue(consumer, out var remaining))
        {
            return;
        }
        if (remaining <= 1)
        {
            // Dropping the entry rather than leaving a zero keeps the map bounded by live consumers
            // instead of by every consumer that ever connected.
            _perConsumer.Remove(consumer);
        }
        else
        {
            _perConsumer[consumer] = remaining - 1;
        }
    }

    /// <summary>
    /// Removes every flow idle for longer than the timeout. Without this a UDP session would never
    /// end, because nothing in UDP says it has.
    /// </summary>
    public List<Flow> Expire(long nowMs) => Reap(flow => nowMs - flow.LastSeenMs >= _idleTimeoutMs);

    /// <summary>
    /// Closes every flow belonging to one consumer, for the moment its authorization is withdrawn.
    /// A revoked consumer must stop being forwarded immediately, not when it next opens something.
    /// </summary>
    public List<Flow> RevokeConsumer(long consumer) => Reap(flow => flow.Consumer == consumer);

    /// <summary>Closes everything, for egress shutdown or for the tenant switch being turned off.</summary>
    public List<Flow> Drain() => Reap(_ => true);

    /// <summary>
    /// Closes every flow of one consumer whose remote address falls inside one of the given
    /// prefixes, which serves the flow-purge control message.
    /// </summary>
    /// <remarks>
    /// Scoped to its sender: a purge arrives over one consumer's session and speaks only for that
    /// consumer, so applying it to everyone would let any peer tear down every other peer's traffic
    /// with one message. A consumer of zero means no restriction, which is for local teardown
    /// rather than for anything that arrives on the wire.
    ///
    /// <para>An unparseable prefix is skipped rather than treated as matching everything: a
    /// malformed purge should close nothing, not the whole table.</para>
    /// </remarks>
    public List<Flow> PurgeDestinations(long consumer, IReadOnlyList<string>? destinations)
    {
        var prefixes = new List<Ipv4Cidr>();
        foreach (var text in destinations ?? [])
        {
            if (Ipv4Cidr.TryParse(text, out var cidr))
            {
                prefixes.Add(cidr);
            }
        }
        if (prefixes.Count == 0)
        {
            return [];
        }
        return Reap(flow =>
        {
            if (consumer != 0 && flow.Consumer != consumer)
            {
                return false;
            }
            foreach (var prefix in prefixes)
            {
                if (prefix.Contains(flow.Key.RemoteIp))
                {
                    return true;
                }
            }
            return false;
        });
    }

    /// <summary>
    /// Reports whether a packet arriving from the real network belongs to a flow this node opened.
    /// </summary>
    /// <remarks>
    /// Without it a peer could inject a packet with any source address it liked and have the egress
    /// relay it into the mesh as though the egress had fetched it.
    /// </remarks>
    public bool HasReturnPath(Key key) => _flows.ContainsKey(key);

    /// <summary>
    /// Runs the judgment layer again over every live flow against a policy that has just changed,
    /// and returns the flows that are no longer allowed together with why.
    /// </summary>
    /// <remarks>
    /// A policy change that only governs new flows is not a revocation. An operator who deletes a
    /// destination rule expects that traffic to stop, and would reasonably read a connection that
    /// keeps running until its peer closes it as the rule having failed to apply.
    ///
    /// <para>The limit fields are deliberately not re-checked. Lowering a quota should stop the
    /// next flow, not pick live ones to kill, and a limit breach is not a permission the flow
    /// lost.</para>
    /// </remarks>
    public List<Revocation> Reauthorize(
        PeerEgressPolicy policy,
        Func<long, bool>? peerAclAllows,
        PeerEgressContext context,
        IReadOnlyList<string>? localInterfaceCidrs)
    {
        var codes = new Dictionary<Key, string>();
        var reaped = Reap(flow =>
        {
            var allowed = peerAclAllows is null || peerAclAllows(flow.Consumer);
            var decision = PeerEgressAuthorization.Authorize(
                new PeerEgressRequest
                {
                    ConsumerClientId = flow.Consumer,
                    DestinationIp = Ipv4Cidr.FormatAddress(flow.Key.RemoteIp),
                    DestinationPort = flow.Key.RemotePort,
                    Protocol = flow.Key.ProtocolName(),
                    LocalInterfaceCidrs = localInterfaceCidrs ?? []
                },
                policy, allowed, context);
            if (decision.Allowed)
            {
                return false;
            }
            codes[flow.Key] = decision.Code;
            return true;
        });

        var revoked = new List<Revocation>(reaped.Count);
        foreach (var flow in reaped)
        {
            revoked.Add(new Revocation(flow, codes.GetValueOrDefault(flow.Key)));
        }
        return revoked;
    }

    /// <summary>
    /// Labels a batch that really does share one reason, such as a shutdown or an ACL withdrawal.
    /// A null code means the flow ended normally and owes the consumer no explanation.
    /// </summary>
    public static List<Revocation> RevocationsFor(List<Flow> reaped, string? code)
    {
        var revoked = new List<Revocation>(reaped.Count);
        foreach (var flow in reaped)
        {
            revoked.Add(new Revocation(flow, code));
        }
        return revoked;
    }

    /// <summary>
    /// Removes and returns the flows a predicate selects, in a stable order.
    /// </summary>
    /// <remarks>
    /// Sorted rather than in dictionary order because the caller emits one rejection record per
    /// closed flow. Ordering that changed run to run would make those records, and any test reading
    /// them, non-reproducible.
    /// </remarks>
    private List<Flow> Reap(Func<Flow, bool> selects)
    {
        var reaped = new List<Flow>();
        foreach (var flow in _flows.Values)
        {
            if (selects(flow))
            {
                reaped.Add(flow);
            }
        }
        Sort(reaped);
        foreach (var flow in reaped)
        {
            _flows.Remove(flow.Key);
            Release(flow.Consumer);
        }
        return reaped;
    }

    public static void Sort(List<Flow> entries) =>
        entries.Sort((left, right) =>
        {
            var order = left.Key.Protocol.CompareTo(right.Key.Protocol);
            if (order != 0)
            {
                return order;
            }
            // Addresses are unsigned; comparing them as signed would order 10.x above 200.x.
            order = left.Key.ConsumerIp.CompareTo(right.Key.ConsumerIp);
            if (order != 0)
            {
                return order;
            }
            order = left.Key.ConsumerPort.CompareTo(right.Key.ConsumerPort);
            if (order != 0)
            {
                return order;
            }
            order = left.Key.RemoteIp.CompareTo(right.Key.RemoteIp);
            return order != 0 ? order : left.Key.RemotePort.CompareTo(right.Key.RemotePort);
        });
}
