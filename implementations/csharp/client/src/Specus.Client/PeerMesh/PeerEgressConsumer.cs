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
    Unsupported,

    /// <summary>
    /// Sent into the fake-IP pool at an address no rule steers now: one with no mapping, or one
    /// whose name no rule claims any more or <c>direct</c> claims.
    /// </summary>
    BlockedFakeIp,

    /// <summary>A DNS query to the listen address, taken by the responder.</summary>
    DnsQuery,

    /// <summary>A DNS query to the listen address from a source that is not this machine.</summary>
    BlockedDnsNotLocal
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
/// <para>Phase two (protocol/spec/peer-egress-dns.md) adds a second way in. A destination inside the
/// fake-IP pool is decided by the name it was handed out for, never by an address rule, and every
/// refusal on that path is answered, because the application asked a name and must be sent back to
/// ask again rather than left to time out. Before a packet to a pool address goes out, the egress is
/// told which name the address stands for.</para>
///
/// <para>Time arrives as an argument. Not safe for concurrent use on its own; the caller serialises
/// access the same way the Go consumer's mutex does.</para>
/// </remarks>
internal sealed class PeerEgressConsumer(
    Func<long, byte[], bool>? send, Action<byte[]>? toTun, ILogger? logger = null,
    int flowCapacity = PeerEgressConsumer.DefaultFlowCapacity)
{
    private const int Ipv4MinHeaderBytes = 20;

    /// <summary>A datagram flow is forgotten after this long without a packet either way.</summary>
    internal const long UdpIdleMs = 180_000;

    /// <summary>
    /// A TCP flow that has not closed is forgotten after this long without a packet either way. The
    /// egress's own idle timeout (60 seconds by default) has usually ended the flow long before;
    /// this only bounds what a consumer holds when that end never reaches it.
    /// </summary>
    internal const long TcpIdleMs = 7_200_000;

    /// <summary>
    /// A TCP flow is forgotten this long after it closed: an RST either way, or a FIN both ways.
    /// Long enough for the last ACK and any retransmitted FIN to still find the flow.
    /// </summary>
    internal const long TcpClosedLingerMs = 120_000;

    /// <summary>How many flows the consumer remembers at most; protocol/spec/peer-egress.md.</summary>
    internal const int DefaultFlowCapacity = 65536;

    private readonly int _flowCapacity = flowCapacity > 0
        ? flowCapacity
        : throw new ArgumentOutOfRangeException(nameof(flowCapacity), "the flow table must hold at least one flow");

    /// <summary>
    /// One flow this node opened through an egress, tracked so a reply can be matched to something
    /// we actually asked for, and so a rule change can close exactly the flows it invalidates.
    /// </summary>
    private sealed class Flow
    {
        public Flow(PeerEgressFlowTable.Key key, long egress, long registered, long nowMs)
        {
            Key = key;
            Egress = egress;
            Registered = registered;
            LastSeenMs = nowMs;
            // Allocated once with the flow and moved between lists from then on, so a packet
            // touching a flow allocates nothing.
            RecencyNode = new LinkedListNode<Flow>(this);
            DeadlineNode = new LinkedListNode<Flow>(this);
        }

        public PeerEgressFlowTable.Key Key { get; }

        public long Egress { get; }

        /// <summary>
        /// When the flow was registered relative to the others. A full table evicts the flow with
        /// the oldest last packet, and among flows last seen at the same moment the one registered
        /// first, as the shared vector does.
        /// </summary>
        public long Registered { get; }

        public long LastSeenMs { get; set; }

        /// <summary>
        /// Whether a packet from the egress has been accepted on this flow. Until one has, every
        /// datagram of a UDP flow to a pool address carries its name-bind: UDP retransmits nothing
        /// on its own, so a lost binding would otherwise never be repeated.
        /// </summary>
        public bool Replied { get; set; }

        public bool IsTcp => Key.Protocol == PeerEgressSegment.Ipv4ProtocolTcp;

        private bool _finOut;
        private bool _finIn;

        /// <summary>When a TCP flow closed, an RST either way or a FIN both ways; null while open.</summary>
        public long? ClosedAtMs { get; private set; }

        /// <summary>This flow's place in the consumer's recency list.</summary>
        public LinkedListNode<Flow> RecencyNode { get; }

        /// <summary>This flow's place in the deadline list for its protocol and state.</summary>
        public LinkedListNode<Flow> DeadlineNode { get; }

        /// <summary>The moment the flow is forgotten. At that moment, not after it.</summary>
        public long DeadlineMs => !IsTcp
            ? LastSeenMs + UdpIdleMs
            : ClosedAtMs is { } closedAt ? closedAt + TcpClosedLingerMs : LastSeenMs + TcpIdleMs;

        /// <summary>
        /// Records the flags of a TCP segment on this flow. The close time is set once: the last ACK
        /// or a retransmitted FIN after it must not keep a finished flow around.
        /// </summary>
        public void NoteTcpFlags(int flags, bool outbound, long nowMs)
        {
            if ((flags & PeerEgressSegment.FlagRst) != 0)
            {
                ClosedAtMs ??= nowMs;
            }
            if ((flags & PeerEgressSegment.FlagFin) != 0)
            {
                if (outbound)
                {
                    _finOut = true;
                }
                else
                {
                    _finIn = true;
                }
            }
            if (_finOut && _finIn)
            {
                ClosedAtMs ??= nowMs;
            }
        }

        /// <summary>
        /// What the application last said on a TCP flow, kept so the flow can be reset without
        /// waiting for it to speak again. Its acknowledgement number is its receive-next, the one
        /// sequence number a stack accepts a reset at (RFC 5961); its next sequence number is what
        /// the reset acknowledges. Unknown until the application has sent a segment carrying ACK.
        /// </summary>
        public bool AppAckKnown { get; private set; }

        public uint AppAck { get; private set; }

        public uint AppSeqNext { get; private set; }

        /// <summary>
        /// Records where the application is on a TCP flow from a segment it sent. Read from the
        /// header directly rather than through the parser: this runs on every forwarded packet,
        /// and a checksum over the whole segment for two numbers would be paid on every one.
        /// </summary>
        public void NoteApplicationProgress(byte[] packet)
        {
            var ihl = (packet[0] & 0x0f) * 4;
            if (packet.Length < ihl + 20)
            {
                return;
            }
            var dataOffset = (packet[ihl + 12] >> 4) * 4;
            if (dataOffset < 20)
            {
                return;
            }
            var total = Math.Min((packet[2] << 8) | packet[3], packet.Length);
            var payload = Math.Max(total - ihl - dataOffset, 0);
            int flags = packet[ihl + 13];
            var next = ReadUInt32(packet, ihl + 4) + (uint)payload;
            if ((flags & PeerEgressSegment.FlagSyn) != 0)
            {
                next++;
            }
            if ((flags & PeerEgressSegment.FlagFin) != 0)
            {
                next++;
            }
            AppSeqNext = next;
            if ((flags & PeerEgressSegment.FlagAck) != 0)
            {
                AppAck = ReadUInt32(packet, ihl + 8);
                AppAckKnown = true;
            }
        }
    }

    private IReadOnlyList<PeerEgressRule> _rules = [];
    private string _meshCidr = PeerEgressRules.DefaultMeshCidr;

    /// <summary>This node's mesh address, which every reply must be addressed to.</summary>
    private string _virtualIp = string.Empty;

    /// <summary>Which egress peers can currently take a flow. Absent means no.</summary>
    private readonly Dictionary<long, bool> _online = [];

    /// <summary>
    /// What <c>egress-catalog</c> says: whether one arrived in this control session, which egresses
    /// the last one listed, the version each announced, and which resolve names. An egress the
    /// catalogue does not list is not sent names, and once a catalogue has arrived in this session it
    /// is not sent flows either (protocol/spec/peer-egress.md, 能力不支持).
    /// </summary>
    private PeerEgressCatalogSnapshot _catalog = PeerEgressCatalogSnapshot.None;

    /// <summary>The fake-IP pool while phase two runs; null otherwise, which is phase one exactly.</summary>
    private PeerEgressFakeIpPool? _pool;

    /// <summary>
    /// The DNS responder, which queries to port 53 of the pool's listen address go to while phase
    /// two runs. Set by the caller under the same serialisation as every other call.
    /// </summary>
    public PeerEgressDnsResponder? DnsResponder { get; set; }

    /// <summary>
    /// The flows this node remembers, bounded by time and by count (protocol/spec/peer-egress.md,
    /// shared vector <c>peer-egress-consumer-flows-v1.json</c>). Unbounded, every flow ever made
    /// stayed here, and the status's active flows only ever grew.
    /// </summary>
    private readonly Dictionary<PeerEgressFlowTable.Key, Flow> _flows = [];

    /// <summary>Every remembered flow, least recently seen first: the order a full table evicts in.</summary>
    private readonly LinkedList<Flow> _byRecency = new();

    // One list per expiry rule. Within a rule a flow's deadline moves only forward, and the list is
    // appended to as it does -- on each packet for UDP and open TCP, once at close for closed TCP --
    // so each list stays in deadline order and finding what has expired means looking at three
    // heads. That lets every packet sweep, as the reference does, at a constant cost. A single list
    // would not do: a closed TCP flow expires two minutes after its close however recently it was
    // seen, and an open one two hours after its last packet.
    private readonly LinkedList<Flow> _udpByDeadline = new();
    private readonly LinkedList<Flow> _tcpOpenByDeadline = new();
    private readonly LinkedList<Flow> _tcpClosedByDeadline = new();
    private long _registrations;

    private readonly SortedDictionary<string, long> _blocked = [];

    /// <summary>What an operator can read, for the status surface.</summary>
    /// <remarks>
    /// No lock here, for the same reason nothing else in this class has one: the caller serialises
    /// access. Copies of the collections, because the caller is a diagnostic reader and this
    /// consumer goes on mutating its own. Expired flows are forgotten first, so an idle consumer
    /// does not report the flows it had when traffic stopped.
    /// </remarks>
    public PeerEgressConsumerStatus StatusSnapshot(long nowMs)
    {
        ExpireFlows(nowMs);
        return new(
            _rules.ToList(), _meshCidr, new Dictionary<long, bool>(_online), _flows.Count,
            new Dictionary<string, long>(_blocked),
            _flows.Values.GroupBy(flow => flow.Egress).ToDictionary(group => group.Key, group => group.Count()))
        {
            Capable = _catalog.Listed.ToDictionary(entry => entry.Key, entry => entry.Value.DomainTargetCapable),
            Catalog = _catalog,
            FakeIpPool = _pool?.Cidr,
        };
    }

    /// <summary>
    /// Installs a rule set and closes the flows it invalidates.
    /// </summary>
    /// <remarks>
    /// Established flows survive a rule change unless their rule stopped saying egress or stopped
    /// matching. The returned purge messages tell each affected egress to close its side; without
    /// them the egress would hold the socket until its own idle timer, and the user would see a
    /// connection that is dead at one end and open at the other.
    ///
    /// <para><paramref name="fakeIpPool"/> is the pool while phase two runs and null while it does
    /// not. The pool is the caller's and outlives a reconfiguration: its mappings are answers
    /// applications already hold, and a rule change is no reason to take them back.</para>
    /// </remarks>
    public IReadOnlyDictionary<long, IReadOnlyList<string>> Configure(
        IReadOnlyList<PeerEgressRule>? rules, string? meshCidr, string? virtualIp, long nowMs,
        PeerEgressFakeIpPool? fakeIpPool = null)
    {
        _rules = rules ?? [];
        if (!string.IsNullOrWhiteSpace(meshCidr))
        {
            _meshCidr = meshCidr.Trim();
        }
        _virtualIp = virtualIp?.Trim() ?? string.Empty;
        _pool = fakeIpPool;
        return PurgeInvalidated(nowMs);
    }

    /// <summary>
    /// Records what the catalogue says -- whether one arrived in this control session, which
    /// egresses the last one listed, their versions and which resolve names -- and closes the flows
    /// an egress can no longer take.
    /// </summary>
    /// <remarks>
    /// The whole picture is replaced, the way the catalogue replaces it. A standing that turns to
    /// not-offered or unsupported closes every flow to that egress, as its going offline does; an
    /// egress that stops resolving names loses only its flows to pool addresses.
    /// </remarks>
    public IReadOnlyDictionary<long, IReadOnlyList<string>> SetCatalog(PeerEgressCatalogSnapshot catalog, long nowMs)
    {
        _catalog = catalog;
        return PurgeInvalidated(nowMs);
    }

    /// <summary>The catalogue standing of one egress (<see cref="PeerEgressStanding"/>).</summary>
    public string StandingOf(long egress) => _catalog.StandingOf(egress);

    /// <summary>Whether the last catalogue says this egress resolves names. Not listed means no.</summary>
    private bool Capable(long egress) =>
        _catalog.Listed.TryGetValue(egress, out var listing) && listing.DomainTargetCapable;

    /// <summary>
    /// Whether the egress can take a flow at all: online, and not stopped by its catalogue standing.
    /// One decision for the flows a change re-examines; a new packet reaches the same answer step by
    /// step, because each step is counted under its own reason.
    /// </summary>
    private bool CanTake(long egress) =>
        _online.GetValueOrDefault(egress) && PeerEgressStanding.BlockedReason(StandingOf(egress)) is null;

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
        // A flow already forgotten is not reset or purged: its application finished with it, or
        // stopped using it, long enough ago that a reset now would only be noise.
        ExpireFlows(nowMs);
        var purge = new SortedDictionary<long, SortedSet<string>>();
        var dropped = new List<Flow>();
        var resets = new List<byte[]>();
        foreach (var (key, flow) in _flows)
        {
            if (StillOurs(key.RemoteIp, flow.Egress))
            {
                continue;
            }
            dropped.Add(flow);
            if (!purge.TryGetValue(flow.Egress, out var destinations))
            {
                destinations = new SortedSet<string>(StringComparer.Ordinal);
                purge[flow.Egress] = destinations;
            }
            destinations.Add(Ipv4Cidr.FormatAddress(key.RemoteIp) + "/32");
            if (FlowResetPacket(key, flow) is { } reset)
            {
                resets.Add(reset);
            }
        }
        foreach (var flow in dropped)
        {
            Forget(flow);
        }
        // The application is told each flow is over, so it fails now rather than at its own
        // timeout; the egress is told through the purge messages returned.
        foreach (var reset in resets)
        {
            toTun?.Invoke(reset);
        }

        var result = new Dictionary<long, IReadOnlyList<string>>(purge.Count);
        foreach (var (egress, destinations) in purge)
        {
            result[egress] = destinations.ToList();
        }
        return result;
    }

    /// <summary>
    /// Whether a flow's destination still goes to the egress carrying it, by the same decision a new
    /// packet would get.
    /// </summary>
    /// <remarks>
    /// A pool address is decided by its name, looked up without refreshing the mapping: a rule
    /// change, an egress going offline or a new catalogue is not traffic, and counting it as use
    /// would keep alive a mapping nobody is using. The purge then names the fake address itself,
    /// because that is what the egress keeps in its flow key.
    /// </remarks>
    private bool StillOurs(uint remote, long egress)
    {
        if (_pool is { } pool && pool.Contains(remote))
        {
            if (pool.NameFor(remote) is not { } name)
            {
                return false;
            }
            var index = PeerEgressRules.SelectDomainRule(_rules, name, _meshCidr, pool.Cidr);
            if (index < 0)
            {
                return false;
            }
            var rule = _rules[index];
            return (rule.Action?.Trim() ?? string.Empty) == PeerEgressRules.ActionEgress
                && rule.EgressClientId == egress
                && CanTake(egress)
                && Capable(egress);
        }
        var match = PeerEgressRules.Match(_rules, Ipv4Cidr.FormatAddress(remote), _meshCidr, _pool?.Cidr);
        return match.Action == PeerEgressRules.ActionEgress
            && match.EgressClientId == egress
            && CanTake(egress);
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
        int protocol = packet[9];
        var address = ReadUInt32(packet, 16);

        long egress;
        // The name a pool address stands for; null for every destination outside the pool.
        string? name = null;
        if (_pool is { } pool && pool.Contains(address))
        {
            if (address == pool.Listen && IsDnsQuery(packet, protocol))
            {
                // Port 53 of the listen address belongs to the responder, ahead of any steering;
                // anything else sent to the listen address is refused below as unmapped.
                if (DnsResponder is not { } responder)
                {
                    return PeerEgressConsumerOutcome.NotMine;
                }
                if (responder.Handle(packet, nowMs) == PeerEgressDnsIntake.NotLocal)
                {
                    // Dropped unanswered: this machine is routing somebody else's query, and phase
                    // two does not resolve names on anybody else's behalf.
                    RecordBlocked("dns-not-local");
                    return PeerEgressConsumerOutcome.BlockedDnsNotLocal;
                }
                return PeerEgressConsumerOutcome.DnsQuery;
            }
            // Using the address keeps its mapping alive, whatever is decided next.
            name = pool.Use(address, nowMs);
            if (name is null)
            {
                // The one real leak of the fake-IP scheme. Sent to the egress or let out locally,
                // this traffic would go wherever the address happens to lead rather than where a
                // rule said; it can only be refused.
                return Refuse(packet, protocol, "fake-ip-unmapped", PeerEgressConsumerOutcome.BlockedFakeIp);
            }
            var index = PeerEgressRules.SelectDomainRule(_rules, name, _meshCidr, pool.Cidr);
            var action = index < 0 ? PeerEgressRules.ActionDirect : _rules[index].Action?.Trim() ?? string.Empty;
            if (action == PeerEgressRules.ActionDirect)
            {
                // Handed out under rules that no longer claim the name. Its real address is not
                // known here, so letting it out would mean guessing; answered, the application asks
                // again, and the fresh query goes wherever the rules say now.
                return Refuse(packet, protocol, "fake-ip-stale", PeerEgressConsumerOutcome.BlockedFakeIp);
            }
            if (action == PeerEgressRules.ActionBlock)
            {
                RecordBlocked("rule");
                return PeerEgressConsumerOutcome.BlockedByRule;
            }
            egress = _rules[index].EgressClientId ?? 0;
        }
        else
        {
            // Address rules only. With phase two running, one reaching into the pool was refused
            // in validation, so no pool address is ever decided here.
            var match = PeerEgressRules.Match(_rules, destination, _meshCidr, _pool?.Cidr);
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
            egress = match.EgressClientId ?? 0;
        }

        if (protocol != PeerEgressSegment.Ipv4ProtocolTcp && protocol != PeerEgressDatagram.Ipv4ProtocolUdp)
        {
            // ICMP and anything else this version does not carry. The rule says this destination
            // must not go out locally, so it is dropped rather than handed back.
            RecordBlocked("unsupported-protocol");
            return PeerEgressConsumerOutcome.Unsupported;
        }
        if (egress <= 0 || !_online.GetValueOrDefault(egress))
        {
            // Answered, not just dropped. The rule is doing what it should, but the application
            // would only learn that from its own timeout; a reset or an unreachable lets it fail
            // now and retry when the egress is back. A failed send, by contrast, stays silent:
            // the session may be re-establishing and the flow may yet recover.
            return Refuse(packet, protocol, "egress-unavailable", PeerEgressConsumerOutcome.BlockedNoEgress);
        }
        if (PeerEgressStanding.BlockedReason(StandingOf(egress)) is { } standingReason)
        {
            // Online, but the catalogue says it will not take this device's flows: it is not offered
            // here, or its client does not support peer egress and would drop the frame unread.
            // Answered like an offline egress, for the same reason -- the application fails now
            // instead of at its timeout -- and the destination still does not go out locally.
            return Refuse(packet, protocol, standingReason, PeerEgressConsumerOutcome.BlockedNoEgress);
        }
        if (name is not null && !Capable(egress))
        {
            // Online, but the catalogue does not say it resolves names: sending it a name-bind
            // would be refused, and the packet would open a flow to the fake address itself.
            return Refuse(packet, protocol, "egress-no-domain", PeerEgressConsumerOutcome.BlockedNoEgress);
        }

        if (FlowKeyFor(packet, protocol) is { } key)
        {
            var flow = Remembered(key, nowMs);
            // A SYN on a four-tuple whose flow has closed is a new connection reusing the port.
            // Kept on the old entry, it would inherit the old close time and be forgotten two
            // minutes in, with its replies refused from then on.
            if (flow is { ClosedAtMs: not null } && IsBareSyn(packet))
            {
                Forget(flow);
                flow = null;
            }
            var fresh = flow is null;
            flow ??= Register(key, egress, nowMs);
            Touch(flow, packet, outbound: true, nowMs);
            if (protocol == PeerEgressSegment.Ipv4ProtocolTcp)
            {
                flow.NoteApplicationProgress(packet);
            }
            if (name is not null && !NeedsNameBind(flow, fresh, packet, protocol))
            {
                // The egress already has the name for this flow; only the packet goes.
                name = null;
            }
        }

        if (send is null)
        {
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }
        if (name is not null)
        {
            // Ahead of the packet on the same queue, so the egress knows the name before the packet
            // opens anything. Not sent at all when it cannot be: the packet would open a flow to the
            // fake address, which is worse than the retransmission this costs.
            var binding = PeerEgressFrame.EncodeControl(
                PeerEgressFrame.Control.NameBind(Ipv4Cidr.FormatAddress(address), name));
            if (!send(egress, PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, binding)))
            {
                RecordBlocked("send-failed");
                return PeerEgressConsumerOutcome.BlockedNoEgress;
            }
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
    /// Counts a refusal and answers the application with <see cref="FailurePacket"/>, so it fails
    /// now rather than at its own timeout. The refusals that are answered -- no egress, an egress not
    /// offered to this device or whose client does not support peer egress, an egress that does not
    /// resolve names, an unmapped and a stale pool address -- all come here and are answered alike.
    /// </summary>
    private PeerEgressConsumerOutcome Refuse(byte[] packet, int protocol, string reason, PeerEgressConsumerOutcome outcome)
    {
        RecordBlocked(reason);
        if (FailurePacket(packet, protocol) is { } answer)
        {
            toTun?.Invoke(answer);
        }
        return outcome;
    }

    /// <summary>
    /// Whether a packet to a pool address has to be preceded by its name-bind
    /// (protocol/spec/peer-egress-dns.md, vector <c>steering</c>): it opened a new flow, it is a TCP
    /// SYN without ACK, retransmissions included, or its UDP flow has had no reply yet.
    /// </summary>
    /// <remarks>
    /// Control messages are not delivered reliably, so one binding per flow is not enough. TCP
    /// repeats its SYN until the egress answers, and each repeat carries the binding again; UDP
    /// repeats nothing, so every datagram carries it until the egress has spoken on the flow. After
    /// that the egress plainly has the name, and repeating it would only cost bandwidth.
    /// </remarks>
    private static bool NeedsNameBind(Flow flow, bool fresh, byte[] packet, int protocol) =>
        fresh
        || (protocol == PeerEgressSegment.Ipv4ProtocolTcp && IsBareSyn(packet))
        || (protocol == PeerEgressDatagram.Ipv4ProtocolUdp && !flow.Replied);

    /// <summary>Whether a TCP or UDP packet is addressed to port 53.</summary>
    private static bool IsDnsQuery(byte[] packet, int protocol)
    {
        if (protocol != PeerEgressSegment.Ipv4ProtocolTcp && protocol != PeerEgressDatagram.Ipv4ProtocolUdp)
        {
            return false;
        }
        var ihl = (packet[0] & 0x0f) * 4;
        return packet.Length >= ihl + 4 && ReadUInt16(packet, ihl + 2) == 53;
    }

    /// <summary>
    /// Answers a packet the consumer refused to forward, the way an unreachable host would: a TCP
    /// reset placed where the application's stack accepts it (RFC 793), or an ICMP host-unreachable
    /// for a datagram. Null when there is nothing an application could act on. Shared vector:
    /// <c>protocol/test-vectors/peer-egress-failure-v1.json</c>.
    /// </summary>
    public static byte[]? FailurePacket(byte[] packet, int protocol) => protocol switch
    {
        PeerEgressSegment.Ipv4ProtocolTcp => PeerEgressSegment.Parse(packet) is { } segment
            ? PeerEgressSegment.BuildReset(segment)
            : null,
        PeerEgressDatagram.Ipv4ProtocolUdp => PeerIpPacket.IcmpHostUnreachableFor(packet),
        _ => null,
    };

    /// <summary>
    /// The reset for a flow the consumer closed, or null when there is none to build: a datagram
    /// flow, or a TCP flow on which the application has not yet sent an acknowledgement, whose
    /// retransmitted SYN will be answered when it arrives.
    /// </summary>
    private static byte[]? FlowResetPacket(PeerEgressFlowTable.Key key, Flow flow)
    {
        if (key.Protocol != PeerEgressSegment.Ipv4ProtocolTcp || !flow.AppAckKnown)
        {
            return null;
        }
        return PeerEgressSegment.Build(new PeerEgressSegment.Segment(
            key.RemoteIp, key.ConsumerIp, key.RemotePort, key.ConsumerPort,
            flow.AppAck, flow.AppSeqNext, PeerEgressSegment.FlagRst | PeerEgressSegment.FlagAck, 0, 0, []));
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

    /// <summary>
    /// The TCP flags of an IPv4 packet, or zero when it is too short to carry them. Read from the
    /// header directly, like <see cref="Flow.NoteApplicationProgress"/>, because it runs on every
    /// packet either way.
    /// </summary>
    private static int TcpFlags(byte[] packet)
    {
        var ihl = (packet[0] & 0x0f) * 4;
        return packet.Length > ihl + 13 ? packet[ihl + 13] : 0;
    }

    private static bool IsBareSyn(byte[] packet) =>
        (TcpFlags(packet) & (PeerEgressSegment.FlagSyn | PeerEgressSegment.FlagAck)) == PeerEgressSegment.FlagSyn;

    /// <summary>
    /// The flow remembered for a four-tuple, or null. Everything already expired is forgotten
    /// first, which is what releases the memory of flows nobody asks about again.
    /// </summary>
    /// <remarks>
    /// The deadline is checked here as well. The deadline lists are in order only while the clock
    /// runs forward; after the wall clock steps back an expired flow can sit behind one that has
    /// not, and it must not answer for its four-tuple in the meantime.
    /// </remarks>
    private Flow? Remembered(PeerEgressFlowTable.Key key, long nowMs)
    {
        ExpireFlows(nowMs);
        if (!_flows.TryGetValue(key, out var flow))
        {
            return null;
        }
        if (nowMs >= flow.DeadlineMs)
        {
            Forget(flow);
            return null;
        }
        return flow;
    }

    /// <summary>
    /// Whether a flow is remembered at a given moment: what the shared vector's <c>known</c>
    /// events ask.
    /// </summary>
    public bool Remembers(PeerEgressFlowTable.Key key, long nowMs) => Remembered(key, nowMs) is not null;

    /// <summary>Forgets every flow whose deadline has passed.</summary>
    private void ExpireFlows(long nowMs)
    {
        ExpireFrom(_udpByDeadline, nowMs);
        ExpireFrom(_tcpOpenByDeadline, nowMs);
        ExpireFrom(_tcpClosedByDeadline, nowMs);
    }

    private void ExpireFrom(LinkedList<Flow> byDeadline, long nowMs)
    {
        while (byDeadline.First is { } head && nowMs >= head.Value.DeadlineMs)
        {
            Forget(head.Value);
        }
    }

    /// <summary>
    /// Starts remembering a flow, evicting the least recently seen one when the table is full.
    /// Callers have just expired what was due, so a full table here is full of live flows.
    /// </summary>
    private Flow Register(PeerEgressFlowTable.Key key, long egress, long nowMs)
    {
        if (_flows.Count >= _flowCapacity)
        {
            Forget(LeastRecentlySeen());
        }
        var flow = new Flow(key, egress, ++_registrations, nowMs);
        _flows[key] = flow;
        _byRecency.AddLast(flow.RecencyNode);
        (flow.IsTcp ? _tcpOpenByDeadline : _udpByDeadline).AddLast(flow.DeadlineNode);
        return flow;
    }

    /// <summary>
    /// The flow a full table gives up: the oldest last packet, and among flows last seen at the
    /// same moment the one registered first.
    /// </summary>
    /// <remarks>
    /// Flows last seen at the same moment sit together at the front of the recency list, but in
    /// the order they were last touched rather than registered, so that run is scanned. It is as
    /// long as the number of flows that saw a packet in one millisecond.
    /// </remarks>
    private Flow LeastRecentlySeen()
    {
        var first = _byRecency.First!;
        var victim = first.Value;
        for (var node = first.Next; node is not null && node.Value.LastSeenMs == first.Value.LastSeenMs; node = node.Next)
        {
            if (node.Value.Registered < victim.Registered)
            {
                victim = node.Value;
            }
        }
        return victim;
    }

    /// <summary>Records a packet on a remembered flow, in either direction.</summary>
    private void Touch(Flow flow, byte[] packet, bool outbound, long nowMs)
    {
        flow.LastSeenMs = nowMs;
        MoveToBack(_byRecency, flow.RecencyNode);
        if (!flow.IsTcp)
        {
            MoveToBack(_udpByDeadline, flow.DeadlineNode);
            return;
        }
        if (flow.ClosedAtMs is not null)
        {
            // Its deadline was fixed when it closed; nothing on the flow moves it now.
            return;
        }
        flow.NoteTcpFlags(TcpFlags(packet), outbound, nowMs);
        if (flow.ClosedAtMs is null)
        {
            MoveToBack(_tcpOpenByDeadline, flow.DeadlineNode);
        }
        else
        {
            _tcpOpenByDeadline.Remove(flow.DeadlineNode);
            _tcpClosedByDeadline.AddLast(flow.DeadlineNode);
        }
    }

    private static void MoveToBack(LinkedList<Flow> list, LinkedListNode<Flow> node)
    {
        if (list.Last != node)
        {
            list.Remove(node);
            list.AddLast(node);
        }
    }

    private void Forget(Flow flow)
    {
        _flows.Remove(flow.Key);
        _byRecency.Remove(flow.RecencyNode);
        flow.DeadlineNode.List!.Remove(flow.DeadlineNode);
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
            HandleFlowReject(control, fromEgress, nowMs);
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
        if (!HasReturnFlow(parsed.Inner, parsed.Body, fromEgress, nowMs))
        {
            RecordBlocked("return-no-flow");
            return true;
        }
        toTun?.Invoke(parsed.Body);
        return true;
    }

    /// <summary>
    /// Reports whether a reply belongs to a flow this node opened through this egress. The tuple is
    /// mirrored, since the reply travels the other way. A reply that arrives after its flow was
    /// forgotten has nothing to belong to, and is refused like any other.
    /// </summary>
    private bool HasReturnFlow(PeerEgressFrame.Inner inner, byte[] packet, long fromEgress, long nowMs)
    {
        if (!Ipv4Cidr.TryParseAddress(inner.SourceIp, out var remote)
            || !Ipv4Cidr.TryParseAddress(inner.DestinationIp, out var local))
        {
            return false;
        }
        var key = new PeerEgressFlowTable.Key(
            inner.Protocol, local, (ushort)inner.DestinationPort, remote, (ushort)inner.SourcePort);
        if (Remembered(key, nowMs) is not { } flow || flow.Egress != fromEgress)
        {
            return false;
        }
        // Replies count as activity and carry the remote's FIN or RST, both of which decide when
        // the flow is forgotten.
        Touch(flow, packet, outbound: false, nowMs);
        // The egress has answered on this flow, which ends the per-datagram name-bind of a UDP flow.
        flow.Replied = true;
        return true;
    }

    /// <summary>
    /// A rejection can overtake (or survive loss of) the remote RST. Reset locally before forgetting
    /// the flow, and only accept its actual egress as the sender.
    /// </summary>
    private void HandleFlowReject(PeerEgressFrame.Control control, long fromEgress, long nowMs)
    {
        if (!Ipv4Cidr.TryParseAddress(control.DestinationIp, out var remote)
            || !Ipv4Cidr.TryParseAddress(control.SourceIp, out var local))
        {
            return;
        }
        var key = new PeerEgressFlowTable.Key(ProtocolNumberFor(control.Protocol),
            local, (ushort)control.SourcePort, remote, (ushort)control.DestinationPort);
        if (Remembered(key, nowMs) is not { } flow || flow.Egress != fromEgress)
        {
            return;
        }
        var reset = FlowResetPacket(key, flow);
        Forget(flow);
        RecordBlocked("rejected-" + control.Code.ToLowerInvariant());
        logger?.LogInformation("[peer-egress-consumer] egress={Egress} refused flow code={Code}",
            fromEgress, control.Code);
        if (reset is not null)
        {
            toTun?.Invoke(reset);
        }
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

    /// <summary>
    /// The flows held right now, including any that expired since the last packet or status read;
    /// <see cref="StatusSnapshot"/> forgets those before it counts.
    /// </summary>
    public int FlowCount => _flows.Count;
}
