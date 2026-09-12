using Microsoft.Extensions.Logging;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>What happened to one packet.</summary>
internal enum PeerEgressConsumerOutcome
{
    /// <summary>
    /// No rule claims this destination, so the caller carries on with its own handling. This is not
    /// a decision about the packet, it is the absence of one.
    /// </summary>
    NotMine,

    Forwarded,

    /// <summary>A rule that says block.</summary>
    BlockedByRule,

    /// <summary>A rule that says egress, for an egress that cannot take it.</summary>
    BlockedNoEgress,

    /// <summary>A packet this version cannot carry, such as IPv6 or ICMP.</summary>
    Unsupported
}

/// <summary>
/// The consumer data plane: packets leaving the TUN, and the replies coming back.
/// </summary>
/// <remarks>
/// The rule that shapes this class is that a destination matched by an egress rule must never
/// quietly go out locally. If the egress is offline, its authorization has been withdrawn, or the
/// flow cannot be opened, the packet is dropped. Falling back to the local stack would send the
/// user's traffic from the address they arranged for it not to come from, which is worse than the
/// connection failing, because it fails silently and in the direction they were guarding against.
///
/// <para>Time arrives as an argument. Not safe for concurrent use on its own; the caller serialises
/// access the same way the Go consumer's mutex does.</para>
/// </remarks>
internal sealed class PeerEgressConsumer(
    Func<long, byte[], bool>? send, Action<byte[]>? toTun, ILogger? logger = null)
{
    private const int Ipv4MinHeaderBytes = 20;

    /// <summary>
    /// One flow this node opened through an egress, tracked so a reply can be matched to something
    /// we actually asked for, and so a rule change can close exactly the flows it invalidates.
    /// </summary>
    private sealed class Flow(long egress, long lastSeenMs)
    {
        public long Egress { get; } = egress;
        public long LastSeenMs { get; set; } = lastSeenMs;
    }

    private IReadOnlyList<PeerEgressRule> _rules = [];
    private string _meshCidr = PeerEgressRules.DefaultMeshCidr;

    /// <summary>This node's mesh address, which every reply must be addressed to.</summary>
    private string _virtualIp = string.Empty;

    /// <summary>Which egress peers can currently take a flow. Absent means no.</summary>
    private readonly Dictionary<long, bool> _online = [];

    private readonly Dictionary<PeerEgressFlowTable.Key, Flow> _flows = [];
    private readonly SortedDictionary<string, long> _blocked = [];

    /// <summary>
    /// Installs a rule set and closes the flows it invalidates.
    /// </summary>
    /// <remarks>
    /// Established flows survive a rule change unless their rule stopped saying egress or stopped
    /// matching. The returned purge messages tell each affected egress to close its side; without
    /// them the egress would hold the socket until its own idle timer, and the user would see a
    /// connection that is dead at one end and open at the other.
    /// </remarks>
    /// <summary>What an operator can read, for the status surface.</summary>
    /// <remarks>
    /// No lock here, for the same reason nothing else in this class has one: the caller serialises
    /// access. Copies of the collections, because the caller is a diagnostic reader and this
    /// consumer goes on mutating its own.
    /// </remarks>
    public PeerEgressConsumerStatus StatusSnapshot() => new(
        _rules.ToList(), _meshCidr, new Dictionary<long, bool>(_online), _flows.Count,
        new Dictionary<string, long>(_blocked));

    public IReadOnlyDictionary<long, IReadOnlyList<string>> Configure(
        IReadOnlyList<PeerEgressRule>? rules, string? meshCidr, string? virtualIp, long nowMs)
    {
        _rules = rules ?? [];
        if (!string.IsNullOrWhiteSpace(meshCidr))
        {
            _meshCidr = meshCidr.Trim();
        }
        _virtualIp = virtualIp?.Trim() ?? string.Empty;
        return PurgeInvalidated(nowMs);
    }

    /// <summary>
    /// Records whether an egress peer can take flows.
    /// </summary>
    /// <remarks>
    /// Going offline closes its flows rather than leaving them to time out, because every packet
    /// they would carry in the meantime is one the rule says must not go out locally.
    /// </remarks>
    public IReadOnlyDictionary<long, IReadOnlyList<string>> SetEgressOnline(
        long egress, bool online, long nowMs)
    {
        _online[egress] = online;
        return online
            ? new Dictionary<long, IReadOnlyList<string>>()
            : PurgeInvalidated(nowMs);
    }

    /// <summary>
    /// Drops flows whose rule no longer sends them to the egress they are using, and returns the
    /// destinations to purge per egress.
    /// </summary>
    /// <remarks>
    /// The destinations are sorted. The flows they came from live in a dictionary, so without it
    /// the same rule change would produce them in a different order every run, and an operator
    /// comparing two flow-purge messages could not tell a real difference from iteration order.
    /// </remarks>
    private IReadOnlyDictionary<long, IReadOnlyList<string>> PurgeInvalidated(long nowMs)
    {
        var purge = new SortedDictionary<long, SortedSet<string>>();
        var dropped = new List<PeerEgressFlowTable.Key>();
        foreach (var (key, flow) in _flows)
        {
            var match = PeerEgressRules.Match(_rules, Ipv4Cidr.FormatAddress(key.RemoteIp), _meshCidr);
            var stillOurs = match.Action == PeerEgressRules.ActionEgress
                && match.EgressClientId == flow.Egress
                && _online.GetValueOrDefault(flow.Egress);
            if (stillOurs)
            {
                continue;
            }
            dropped.Add(key);
            if (!purge.TryGetValue(flow.Egress, out var destinations))
            {
                destinations = new SortedSet<string>(StringComparer.Ordinal);
                purge[flow.Egress] = destinations;
            }
            destinations.Add(Ipv4Cidr.FormatAddress(key.RemoteIp) + "/32");
        }
        foreach (var key in dropped)
        {
            _flows.Remove(key);
        }

        var result = new Dictionary<long, IReadOnlyList<string>>(purge.Count);
        foreach (var (egress, destinations) in purge)
        {
            result[egress] = destinations.ToList();
        }
        return result;
    }

    /// <summary>
    /// Decides what happens to one packet read from the TUN.
    /// </summary>
    /// <remarks>
    /// A destination no rule claims returns <see cref="PeerEgressConsumerOutcome.NotMine"/>, so the
    /// caller falls through to its own handling. That is what keeps this from claiming the mesh's
    /// own traffic, which shares the device.
    /// </remarks>
    public PeerEgressConsumerOutcome HandleOutbound(byte[] packet, long nowMs)
    {
        if (packet is null || packet.Length < Ipv4MinHeaderBytes)
        {
            return PeerEgressConsumerOutcome.NotMine;
        }
        if (packet[0] >> 4 != 4)
        {
            // IPv6 has no rules in this version, so nothing can claim it and it is not ours.
            return PeerEgressConsumerOutcome.NotMine;
        }
        var destination = PeerIpPacket.DestinationIPv4(packet);
        if (string.IsNullOrEmpty(destination))
        {
            return PeerEgressConsumerOutcome.NotMine;
        }

        var match = PeerEgressRules.Match(_rules, destination, _meshCidr);
        if (!match.Matched
            || match.Action is not (PeerEgressRules.ActionEgress or PeerEgressRules.ActionBlock))
        {
            return PeerEgressConsumerOutcome.NotMine;
        }
        if (match.Action == PeerEgressRules.ActionBlock)
        {
            RecordBlocked("rule");
            return PeerEgressConsumerOutcome.BlockedByRule;
        }

        int protocol = packet[9];
        if (protocol != PeerEgressSegment.Ipv4ProtocolTcp && protocol != PeerEgressDatagram.Ipv4ProtocolUdp)
        {
            // ICMP and anything else this version does not carry. The rule says this destination
            // must not go out locally, so it is dropped rather than handed back.
            RecordBlocked("unsupported-protocol");
            return PeerEgressConsumerOutcome.Unsupported;
        }
        if (match.EgressClientId is not { } egress || !_online.GetValueOrDefault(egress))
        {
            RecordBlocked("egress-unavailable");
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }

        if (FlowKeyFor(packet, protocol) is { } key)
        {
            if (_flows.TryGetValue(key, out var existing))
            {
                existing.LastSeenMs = nowMs;
            }
            else
            {
                _flows[key] = new Flow(egress, nowMs);
            }
        }

        if (send is null)
        {
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }
        // hop stays clear: this node is acting as a consumer, not forwarding on behalf of another
        // egress. An egress that receives it set refuses, which is what stops multi-hop chains.
        var frame = PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet);
        if (!send(egress, frame))
        {
            RecordBlocked("send-failed");
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }
        return PeerEgressConsumerOutcome.Forwarded;
    }

    /// <summary>
    /// Builds the four-tuple as the consumer sees it, which is the mirror of what the egress
    /// recorded, so a reply can be matched against it.
    /// </summary>
    private static PeerEgressFlowTable.Key? FlowKeyFor(byte[] packet, int protocol)
    {
        var ihl = (packet[0] & 0x0f) * 4;
        if (ihl < Ipv4MinHeaderBytes || packet.Length < ihl + 4)
        {
            return null;
        }
        return new PeerEgressFlowTable.Key(
            protocol,
            ReadUInt32(packet, 12),
            ReadUInt16(packet, ihl),
            ReadUInt32(packet, 16),
            ReadUInt16(packet, ihl + 2));
    }

    private static uint ReadUInt32(byte[] data, int offset) =>
        ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16)
        | ((uint)data[offset + 2] << 8) | data[offset + 3];

    private static ushort ReadUInt16(byte[] data, int offset) =>
        (ushort)((data[offset] << 8) | data[offset + 1]);

    /// <summary>
    /// Takes one SPEG1 frame addressed to this node as a consumer and writes the packet to the TUN.
    /// Reports whether the frame was this node's to handle.
    /// </summary>
    /// <remarks>
    /// A node can be a consumer and an egress at once, and both roles receive type=1 frames, so the
    /// two have to be told apart before either acts. A reply is addressed to this node's own virtual
    /// IP; a frame for the egress role is addressed to the wider network. Control messages split by
    /// type: flow-reject travels egress to consumer, flow-purge the other way. Anything not ours is
    /// left for the egress runtime rather than counted as an abuse of the return path.
    /// </remarks>
    public bool HandleInbound(byte[] frame, long fromEgress, long nowMs)
    {
        if (!PeerEgressFrame.LooksLikeFrame(frame))
        {
            return false;
        }
        var parsed = PeerEgressFrame.Parse(frame);
        if (!parsed.Accepted)
        {
            // A frame nobody can read is not claimed. The egress runtime refuses it with its own
            // code, which is the one an operator needs, and counting it here as well would report
            // one malformed frame twice.
            return false;
        }
        if (parsed.Type == PeerEgressFrame.TypeControl)
        {
            var control = PeerEgressFrame.DecodeControl(parsed.Body);
            if (control is null || control.Type != PeerEgressFrame.ControlFlowReject)
            {
                return false;
            }
            HandleFlowReject(control, fromEgress);
            return true;
        }
        if (parsed.Type != PeerEgressFrame.TypeIpPacket)
        {
            return false;
        }

        if (_virtualIp.Length == 0 || parsed.Inner.DestinationIp != _virtualIp)
        {
            // Not addressed to us as a consumer, so it belongs to the egress role if this node has
            // one. Refusing it here would break a node that is both.
            return false;
        }
        if (!Ipv4Cidr.TryParseAddress(parsed.Inner.SourceIp, out var source)
            || (Ipv4Cidr.TryParse(_meshCidr, out var mesh) && mesh.Contains(source)))
        {
            // A reply claiming a mesh address would let an egress speak as another peer.
            RecordBlocked("return-mesh-source");
            return true;
        }
        if (!HasReturnFlow(parsed.Inner, fromEgress, nowMs))
        {
            RecordBlocked("return-no-flow");
            return true;
        }
        toTun?.Invoke(parsed.Body);
        return true;
    }

    /// <summary>
    /// Reports whether a reply belongs to a flow this node opened through this egress. The tuple is
    /// mirrored, since the reply travels the other way.
    /// </summary>
    private bool HasReturnFlow(PeerEgressFrame.Inner inner, long fromEgress, long nowMs)
    {
        if (!Ipv4Cidr.TryParseAddress(inner.SourceIp, out var remote)
            || !Ipv4Cidr.TryParseAddress(inner.DestinationIp, out var local))
        {
            return false;
        }
        var key = new PeerEgressFlowTable.Key(
            inner.Protocol, local, (ushort)inner.DestinationPort, remote, (ushort)inner.SourcePort);
        if (!_flows.TryGetValue(key, out var flow) || flow.Egress != fromEgress)
        {
            return false;
        }
        flow.LastSeenMs = nowMs;
        return true;
    }

    /// <summary>
    /// Reads a flow-reject. It is diagnostic: the application learns the flow is dead from the reset
    /// the egress user-space stack sends, and this only supplies a readable reason.
    /// </summary>
    private void HandleFlowReject(PeerEgressFrame.Control control, long fromEgress)
    {
        RecordBlocked("rejected-" + control.Code.ToLowerInvariant());
        if (Ipv4Cidr.TryParseAddress(control.DestinationIp, out var remote)
            && Ipv4Cidr.TryParseAddress(control.SourceIp, out var local))
        {
            _flows.Remove(new PeerEgressFlowTable.Key(
                ProtocolNumberFor(control.Protocol),
                local, (ushort)control.SourcePort, remote, (ushort)control.DestinationPort));
        }
        logger?.LogInformation(
            "[peer-egress-consumer] egress={Egress} refused {Destination}:{Port} code={Code}",
            fromEgress, control.DestinationIp, control.DestinationPort, control.Code);
    }

    private static int ProtocolNumberFor(string? name) => name?.Trim().ToLowerInvariant() switch
    {
        "udp" => PeerEgressDatagram.Ipv4ProtocolUdp,
        "tcp" => PeerEgressSegment.Ipv4ProtocolTcp,
        _ => 0
    };

    /// <summary>
    /// Counts why traffic did not go out. Aggregated by reason and never by destination, for the
    /// same reason the egress report is: a per-destination record is a browsing history, and this
    /// one would be the user's own.
    /// </summary>
    private void RecordBlocked(string reason) =>
        _blocked[reason] = _blocked.GetValueOrDefault(reason) + 1;

    public IReadOnlyDictionary<string, long> BlockedCounts() => new Dictionary<string, long>(_blocked);

    public int FlowCount => _flows.Count;
}
