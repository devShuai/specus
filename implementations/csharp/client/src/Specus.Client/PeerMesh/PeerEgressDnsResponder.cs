using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.PeerMesh;

/// <summary>What became of a packet handed to the responder.</summary>
internal enum PeerEgressDnsIntake
{
    /// <summary>Taken: answered, forwarded, or dropped as the wire rules say.</summary>
    Handled,

    /// <summary>Refused: the query did not come from this machine.</summary>
    NotLocal,
}

/// <summary>The responder's counters since it started (protocol/spec/peer-egress-dns.md, section seven).</summary>
/// <param name="Answered">Answers built here: records, NODATA, NXDOMAIN, FORMERR.</param>
/// <param name="Forwarded">Upstream answers relayed back.</param>
/// <param name="Failed">SERVFAIL because every upstream failed or the pool was full.</param>
internal readonly record struct PeerEgressDnsCounters(long Answered, long Forwarded, long Failed);

/// <summary>
/// The consumer's DNS responder: UDP and TCP port 53 of the fake-IP pool's listen address, answered
/// in the TUN read path (protocol/spec/peer-egress-dns.md, section three).
/// </summary>
/// <remarks>
/// No system socket is opened and no address is added to the TUN. The pool's route already carries
/// queries for the listen address into the TUN, so they are read here like any other packet and the
/// answers written back the same way; per-link resolvers, NRPT rules and service DNS settings all
/// reach it without anything on the machine listening on port 53.
///
/// <para>Only this machine is answered. A query from any source but the mesh address or one of this
/// machine's own addresses means the machine is routing for somebody else, and phase two does not
/// resolve names on somebody else's behalf.</para>
///
/// <para>TCP is here because a truncated answer sends the application to TCP, and it is the smallest
/// part of RFC 7766 that serves that: in-order data, two-byte length framing, answers in arrival
/// order, a one-second retransmission tried three times, and a close after ten idle seconds.</para>
///
/// <para>One lock covers everything. The consumer calls in holding its own lock, so this one is
/// always taken second, and nothing here calls back into the consumer: an upstream answer that
/// arrives later takes only this lock and writes to the TUN queue.</para>
/// </remarks>
internal sealed class PeerEgressDnsResponder
{
    internal const ushort DnsPort = 53;

    /// <summary>The largest MSS offered: fits a 1400-byte path with room for SPEG1 and a tunnel.</summary>
    internal const int MaxMss = 1360;

    internal const int MaxConnections = 64;
    internal const long RetransmitMs = 1000;
    internal const int MaxRetransmits = 3;
    internal const long IdleMs = 10_000;
    private const int Window = 65535;

    /// <summary>
    /// How many forwarded queries may wait on upstreams at once. Past it a query is answered
    /// SERVFAIL rather than given one more socket: the only thing that can reach this many is a
    /// local program asking faster than the upstreams answer.
    /// </summary>
    internal const int MaxForwarding = 256;

    /// <summary>How often the interface addresses are read again when a query's source is not among them.</summary>
    private const long LocalAddressRefreshMs = 1000;

    private readonly object _gate = new();
    private readonly Action<byte[]> _toTun;
    private readonly IPeerEgressDnsForwarder _forwarder;
    private readonly Func<long> _clock;
    private readonly Func<IReadOnlyList<string>> _localAddresses;
    private readonly ILogger? _logger;
    private readonly int _maxConnections;

    private IReadOnlyList<PeerEgressRule> _rules = [];
    private string _meshCidr = PeerEgressRules.DefaultMeshCidr;
    private PeerEgressFakeIpPool? _pool;
    private uint _virtualIp;
    private IReadOnlyList<PeerEgressDnsUpstream> _upstreams = [];

    private HashSet<uint> _local = [];
    private long _localReadAtMs = long.MinValue;

    private readonly Dictionary<(uint Client, ushort Port), Connection> _connections = [];
    private int _forwarding;
    private long _answered;
    private long _forwarded;
    private long _failed;

    /// <param name="toTun">Writes one packet to the TUN; must not block.</param>
    /// <param name="localAddresses">This machine's interface addresses, read again when a source is not among them.</param>
    public PeerEgressDnsResponder(Action<byte[]> toTun, IPeerEgressDnsForwarder? forwarder = null, Func<long>? clock = null,
        Func<IReadOnlyList<string>>? localAddresses = null, ILogger? logger = null, int maxConnections = MaxConnections)
    {
        _toTun = toTun;
        _forwarder = forwarder ?? new PeerEgressDnsForwarder();
        _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _localAddresses = localAddresses ?? PeerEgressEndpoints.LocalInterfaceAddresses;
        _logger = logger;
        _maxConnections = maxConnections;
    }

    /// <summary>
    /// What the responder answers with: the rules, the pool while phase two runs, this machine's
    /// mesh address, and the upstreams forwarded queries go to. An empty list answers every
    /// forwarded query with SERVFAIL.
    /// </summary>
    public void Configure(IReadOnlyList<PeerEgressRule> rules, string? meshCidr, PeerEgressFakeIpPool pool,
        string? virtualIp, IReadOnlyList<PeerEgressDnsUpstream> upstreams)
    {
        lock (_gate)
        {
            _rules = rules;
            _meshCidr = string.IsNullOrWhiteSpace(meshCidr) ? PeerEgressRules.DefaultMeshCidr : meshCidr.Trim();
            _pool = pool;
            _virtualIp = Ipv4Cidr.TryParseAddress(virtualIp?.Trim(), out var address) ? address : 0;
            _upstreams = upstreams;
        }
    }

    /// <summary>The listen address, or null before a pool is configured.</summary>
    public uint? Listen
    {
        get
        {
            lock (_gate)
            {
                return _pool?.Listen;
            }
        }
    }

    public IReadOnlyList<PeerEgressDnsUpstream> Upstreams
    {
        get
        {
            lock (_gate)
            {
                return _upstreams;
            }
        }
    }

    public PeerEgressDnsCounters Counters
    {
        get
        {
            lock (_gate)
            {
                return new PeerEgressDnsCounters(_answered, _forwarded, _failed);
            }
        }
    }

    /// <summary>The TCP connections held now.</summary>
    public int Connections
    {
        get
        {
            lock (_gate)
            {
                return _connections.Count;
            }
        }
    }

    /// <summary>
    /// Takes one packet the consumer found addressed to UDP or TCP port 53 of the listen address.
    /// </summary>
    public PeerEgressDnsIntake Handle(byte[] packet, long nowMs)
    {
        lock (_gate)
        {
            if (_pool is null || packet.Length < PeerEgressSegment.Ipv4MinHeaderBytes)
            {
                return PeerEgressDnsIntake.Handled;
            }
            var source = (uint)(packet[12] << 24 | packet[13] << 16 | packet[14] << 8 | packet[15]);
            if (!IsLocal(source, nowMs))
            {
                return PeerEgressDnsIntake.NotLocal;
            }
            if (packet[9] == PeerEgressDatagram.Ipv4ProtocolUdp)
            {
                // One that does not parse -- a bad checksum, a length that lies -- is not a query.
                if (PeerEgressDatagram.Parse(packet) is { } datagram)
                {
                    HandleDatagram(datagram, nowMs);
                }
            }
            else if (PeerEgressSegment.Parse(packet) is { } segment)
            {
                HandleSegment(segment, nowMs);
            }
            return PeerEgressDnsIntake.Handled;
        }
    }

    /// <summary>
    /// The mesh address, or an address of this machine's own. The interfaces are read again when a
    /// source is missing, at most once a second, so an address that appeared since is found without
    /// a flood of foreign queries costing an interface walk each.
    /// </summary>
    private bool IsLocal(uint source, long nowMs)
    {
        if (source == _virtualIp && source != 0)
        {
            return true;
        }
        if (_local.Contains(source))
        {
            return true;
        }
        if (_localReadAtMs != long.MinValue && nowMs - _localReadAtMs < LocalAddressRefreshMs)
        {
            return false;
        }
        _localReadAtMs = nowMs;
        var addresses = new HashSet<uint>();
        foreach (var text in _localAddresses())
        {
            if (Ipv4Cidr.TryParseAddress(text, out var address))
            {
                addresses.Add(address);
            }
        }
        _local = addresses;
        return addresses.Contains(source);
    }

    // ----------------------------------------------------------------------------------------------
    // UDP
    // ----------------------------------------------------------------------------------------------

    private void HandleDatagram(PeerEgressDatagram.Datagram query, long nowMs)
    {
        var decision = PeerEgressDnsWire.Respond(query.Payload, _rules, _meshCidr, _pool!, nowMs);
        switch (decision.Result)
        {
            case PeerEgressDnsResult.Answer:
                Count(decision);
                ReplyUdp(query, decision.Response!);
                break;
            case PeerEgressDnsResult.Forward:
                Forward(query.Payload, tcp: false, answer => ReplyUdp(query, answer));
                break;
        }
    }

    /// <summary>An answer back to where the query came from, from the listen address.</summary>
    private void ReplyUdp(PeerEgressDatagram.Datagram query, byte[] answer) =>
        _toTun(PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(
            query.DestinationIp, query.SourceIp, query.DestinationPort, query.SourcePort, answer)));

    private void Count(PeerEgressDnsDecision decision)
    {
        if (decision.Exhausted)
        {
            _failed++;
        }
        else
        {
            _answered++;
        }
    }

    /// <summary>
    /// Sends a query to the upstreams and hands <paramref name="deliver"/> what comes back, or a
    /// SERVFAIL when nothing does. Called with the lock held; the delivery takes it again.
    /// </summary>
    private void Forward(byte[] query, bool tcp, Action<byte[]> deliver)
    {
        var upstreams = _upstreams;
        if (upstreams.Count == 0 || _forwarding >= MaxForwarding)
        {
            _failed++;
            deliver(PeerEgressDnsWire.ServFail(query));
            return;
        }
        _forwarding++;
        _ = Task.Run(async () =>
        {
            byte[]? answer;
            try
            {
                answer = await _forwarder.ForwardAsync(query, tcp, upstreams).ConfigureAwait(false);
            }
            catch (Exception failure) when (failure is not (OutOfMemoryException or StackOverflowException))
            {
                answer = null;
            }
            lock (_gate)
            {
                _forwarding--;
                if (answer is null)
                {
                    _failed++;
                    // Without saying where to: the query's name is the user's browsing history.
                    _logger?.LogDebug("[peer-egress-dns] no upstream answered a forwarded query over {Transport}",
                        tcp ? "tcp" : "udp");
                    deliver(PeerEgressDnsWire.ServFail(query));
                }
                else
                {
                    _forwarded++;
                    deliver(answer);
                }
            }
        });
    }

    // ----------------------------------------------------------------------------------------------
    // TCP
    // ----------------------------------------------------------------------------------------------

    /// <summary>One answer owed on a connection, in the order its query arrived.</summary>
    private sealed class Slot
    {
        public byte[]? Answer { get; set; }
    }

    /// <summary>A segment sent and not yet acknowledged.</summary>
    private sealed class InFlight(uint seq, int flags, byte[] payload, long sentAtMs)
    {
        public uint Seq { get; } = seq;
        public int Flags { get; } = flags;
        public byte[] Payload { get; } = payload;
        public long SentAtMs { get; set; } = sentAtMs;
        public int Retransmits { get; set; }

        /// <summary>The sequence number after this segment: its payload, and one each for SYN and FIN.</summary>
        public uint End => Seq + (uint)Payload.Length
            + (uint)((Flags & PeerEgressSegment.FlagSyn) != 0 ? 1 : 0)
            + (uint)((Flags & PeerEgressSegment.FlagFin) != 0 ? 1 : 0);
    }

    private sealed class Connection(uint client, ushort port, uint iss, uint receiveNext, int mss, long nowMs)
    {
        public uint Client { get; } = client;
        public ushort Port { get; } = port;
        public uint Iss { get; } = iss;
        public uint SendUnacked { get; set; } = iss;
        public uint SendNext { get; set; } = iss;
        public uint ReceiveNext { get; set; } = receiveNext;
        public int Mss { get; } = mss;
        public bool Established { get; set; }
        public bool PeerFinished { get; set; }
        public bool FinQueued { get; set; }
        public bool FinSent { get; set; }
        public bool FinAcked { get; set; }
        public bool Closed { get; set; }
        public bool AckOwed { get; set; }

        /// <summary>When the last query arrived, or the connection opened: the idle clock.</summary>
        public long LastQueryMs { get; set; } = nowMs;
        public long LastSeenMs { get; set; } = nowMs;

        public List<byte> Received { get; } = [];
        public Queue<Slot> Owed { get; } = new();
        public List<byte> Unsent { get; } = [];
        public List<InFlight> InFlight { get; } = [];
    }

    private void HandleSegment(Segment segment, long nowMs)
    {
        var key = (segment.SourceIp, segment.SourcePort);
        _connections.TryGetValue(key, out var connection);
        if (segment.Has(PeerEgressSegment.FlagRst))
        {
            // Nothing answers a reset; a reset for a connection ends it.
            if (connection is not null)
            {
                Forget(connection);
            }
            return;
        }
        if (connection is null)
        {
            if (segment.Has(PeerEgressSegment.FlagSyn) && !segment.Has(PeerEgressSegment.FlagAck)
                && _connections.Count < _maxConnections)
            {
                Open(segment, nowMs);
                return;
            }
            // A segment for no connection, or a connection past the cap: refused outright, so the
            // application falls back or gives up now rather than retransmitting into silence.
            _toTun(PeerEgressSegment.BuildReset(segment));
            return;
        }
        connection.LastSeenMs = nowMs;
        if (segment.Has(PeerEgressSegment.FlagSyn))
        {
            if (!connection.Established && !segment.Has(PeerEgressSegment.FlagAck)
                && segment.Seq + 1 == connection.ReceiveNext)
            {
                // The SYN again: our SYN-ACK was lost. It goes again, and counts as its retransmission.
                if (connection.InFlight.Count > 0)
                {
                    Resend(connection, connection.InFlight[0], nowMs);
                }
                return;
            }
            // A SYN inside a live connection is answered with the current acknowledgement (RFC 5961)
            // rather than believed.
            SendAck(connection);
            return;
        }
        if (!segment.Has(PeerEgressSegment.FlagAck))
        {
            return;
        }
        Acknowledge(connection, segment, nowMs);
        if (connection.Closed || !connection.Established)
        {
            return;
        }
        Receive(connection, segment, nowMs);
        Pump(connection, nowMs);
        if (connection.AckOwed)
        {
            SendAck(connection);
        }
        CloseIfDone(connection);
    }

    /// <summary>A SYN for a new connection: SYN-ACK with an MSS no larger than ours or the peer's.</summary>
    private void Open(Segment syn, long nowMs)
    {
        var peerMss = syn.Mss > 0 ? syn.Mss : PeerEgressSegment.DefaultMss;
        var connection = new Connection(syn.SourceIp, syn.SourcePort, InitialSequence(), syn.Seq + 1,
            Math.Min(peerMss, MaxMss), nowMs);
        _connections[(syn.SourceIp, syn.SourcePort)] = connection;
        Send(connection, PeerEgressSegment.FlagSyn | PeerEgressSegment.FlagAck, [], nowMs, connection.Mss);
    }

    /// <summary>Takes what an ACK acknowledges.</summary>
    private static void Acknowledge(Connection connection, Segment segment, long nowMs)
    {
        var ack = segment.Ack;
        if (PeerEgressSegment.SeqLess(connection.SendUnacked, ack) && PeerEgressSegment.SeqLessEqual(ack, connection.SendNext))
        {
            connection.InFlight.RemoveAll(sent => PeerEgressSegment.SeqLessEqual(sent.End, ack));
            connection.SendUnacked = ack;
            if (!connection.Established && ack == connection.Iss + 1)
            {
                connection.Established = true;
                connection.LastQueryMs = nowMs;
            }
            if (connection.FinSent && ack == connection.SendNext)
            {
                connection.FinAcked = true;
            }
        }
    }

    /// <summary>
    /// In-order data only. A segment that starts ahead of what is expected is dropped and the
    /// current acknowledgement sent again, so the peer retransmits from the gap; one that repeats
    /// bytes already taken is trimmed to what is new.
    /// </summary>
    private void Receive(Connection connection, Segment segment, long nowMs)
    {
        var payload = segment.Payload;
        var fin = segment.Has(PeerEgressSegment.FlagFin);
        if (payload.Length == 0 && !fin)
        {
            return;
        }
        var seq = segment.Seq;
        if (PeerEgressSegment.SeqLess(seq, connection.ReceiveNext))
        {
            var repeated = connection.ReceiveNext - seq;
            if (repeated > (uint)payload.Length || (repeated == (uint)payload.Length && !fin))
            {
                connection.AckOwed = true;
                return;
            }
            payload = payload[(int)repeated..];
            seq = connection.ReceiveNext;
        }
        if (seq != connection.ReceiveNext || connection.PeerFinished)
        {
            connection.AckOwed = true;
            return;
        }
        connection.Received.AddRange(payload);
        connection.ReceiveNext += (uint)payload.Length;
        if (fin)
        {
            connection.ReceiveNext++;
            connection.PeerFinished = true;
        }
        connection.AckOwed = true;
        Frame(connection, nowMs);
    }

    /// <summary>Cuts the queries out of the byte stream by their length prefixes and takes each in turn.</summary>
    private void Frame(Connection connection, long nowMs)
    {
        while (connection.Received.Count >= 2)
        {
            var length = (connection.Received[0] << 8) | connection.Received[1];
            if (connection.Received.Count < 2 + length)
            {
                return;
            }
            var query = connection.Received.GetRange(2, length).ToArray();
            connection.Received.RemoveRange(0, 2 + length);
            connection.LastQueryMs = nowMs;
            Submit(connection, query, nowMs);
        }
    }

    /// <summary>
    /// One query from a connection. Its answer takes the next place in line whether it is built now
    /// or waits for an upstream, and every answer behind a waiting one waits with it.
    /// </summary>
    private void Submit(Connection connection, byte[] query, long nowMs)
    {
        var decision = PeerEgressDnsWire.Respond(query, _rules, _meshCidr, _pool!, nowMs);
        if (decision.Result == PeerEgressDnsResult.Drop)
        {
            return;
        }
        var slot = new Slot();
        connection.Owed.Enqueue(slot);
        if (decision.Result == PeerEgressDnsResult.Answer)
        {
            Count(decision);
            slot.Answer = decision.Response;
            return;
        }
        Forward(query, tcp: true, answer =>
        {
            slot.Answer = answer;
            if (connection.Closed)
            {
                return;
            }
            // Delivered on the forwarding task's own time, so the answers it unblocks go now.
            var now = _clock();
            Pump(connection, now);
            CloseIfDone(connection);
        });
    }

    /// <summary>
    /// Moves every answer at the head of the line into the stream, sends it in segments of at most
    /// the MSS, and after the last answer a FIN when one is due.
    /// </summary>
    private void Pump(Connection connection, long nowMs)
    {
        while (connection.Owed.Count > 0 && connection.Owed.Peek().Answer is { } answer)
        {
            connection.Owed.Dequeue();
            connection.Unsent.Add((byte)(answer.Length >> 8));
            connection.Unsent.Add((byte)answer.Length);
            connection.Unsent.AddRange(answer);
        }
        if (connection.PeerFinished && connection.Owed.Count == 0)
        {
            // The peer is done asking; the FIN follows the answers it is still owed.
            connection.FinQueued = true;
        }
        // The peer's window is not consulted: the peer is an application on this machine, whose
        // receive window is far larger than any one DNS answer.
        while (connection.Unsent.Count > 0)
        {
            var size = Math.Min(connection.Mss, connection.Unsent.Count);
            var payload = connection.Unsent.GetRange(0, size).ToArray();
            connection.Unsent.RemoveRange(0, size);
            Send(connection, PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, payload, nowMs);
        }
        if (connection.FinQueued && !connection.FinSent && connection.Unsent.Count == 0)
        {
            connection.FinSent = true;
            Send(connection, PeerEgressSegment.FlagFin | PeerEgressSegment.FlagAck, [], nowMs);
        }
    }

    /// <summary>Done once both sides have finished and ours has been acknowledged.</summary>
    private void CloseIfDone(Connection connection)
    {
        if (!connection.Closed && connection.FinAcked && connection.PeerFinished)
        {
            Forget(connection);
        }
    }

    /// <summary>
    /// Retransmission and idleness, on the mesh's clock. An unacknowledged segment goes again every
    /// second; one sent three times over without an acknowledgement ends the connection with a
    /// reset. A connection with nothing asked and nothing owed for ten seconds is closed with a FIN.
    /// </summary>
    public void OnTick(long nowMs)
    {
        lock (_gate)
        {
            foreach (var connection in _connections.Values.ToList())
            {
                foreach (var sent in connection.InFlight.ToList())
                {
                    if (nowMs - sent.SentAtMs < RetransmitMs)
                    {
                        continue;
                    }
                    if (sent.Retransmits >= MaxRetransmits)
                    {
                        // At the first byte the peer has not acknowledged: where it expects us, when
                        // what went missing was ours.
                        _toTun(Build(connection, PeerEgressSegment.FlagRst | PeerEgressSegment.FlagAck,
                            connection.SendUnacked, []));
                        Forget(connection);
                        break;
                    }
                    sent.Retransmits++;
                    Resend(connection, sent, nowMs);
                }
                if (connection.Closed)
                {
                    continue;
                }
                if (connection.Established && !connection.FinQueued && connection.Owed.Count == 0
                    && nowMs - connection.LastQueryMs >= IdleMs)
                {
                    connection.FinQueued = true;
                    Pump(connection, nowMs);
                }
                else if (connection.FinAcked && !connection.PeerFinished && nowMs - connection.LastSeenMs >= IdleMs)
                {
                    // Our FIN was taken and the peer never sent its own: there is nothing left to
                    // wait for.
                    Forget(connection);
                }
            }
        }
    }

    private void Forget(Connection connection)
    {
        connection.Closed = true;
        _connections.Remove((connection.Client, connection.Port));
    }

    /// <summary>Sends a segment at the next sequence number, keeping it for retransmission when it takes one.</summary>
    private void Send(Connection connection, int flags, byte[] payload, long nowMs, int mss = 0)
    {
        _toTun(Build(connection, flags, connection.SendNext, payload, mss));
        var sent = new InFlight(connection.SendNext, flags, payload, nowMs);
        if (sent.End != sent.Seq)
        {
            connection.InFlight.Add(sent);
            connection.SendNext = sent.End;
        }
        connection.AckOwed = false;
    }

    /// <summary>A segment again, as first sent, acknowledging what has arrived since.</summary>
    private void Resend(Connection connection, InFlight sent, long nowMs)
    {
        var mss = (sent.Flags & PeerEgressSegment.FlagSyn) != 0 ? connection.Mss : 0;
        _toTun(Build(connection, sent.Flags, sent.Seq, sent.Payload, mss));
        sent.SentAtMs = nowMs;
    }

    private void SendAck(Connection connection)
    {
        _toTun(Build(connection, PeerEgressSegment.FlagAck, connection.SendNext, []));
        connection.AckOwed = false;
    }

    private byte[] Build(Connection connection, int flags, uint seq, byte[] payload, int mss = 0) =>
        PeerEgressSegment.Build(new Segment(_pool!.Listen, connection.Client, DnsPort, connection.Port, seq,
            (flags & PeerEgressSegment.FlagAck) != 0 ? connection.ReceiveNext : 0, flags, Window, mss, payload));

    /// <summary>Random, so nobody who can guess the four-tuple can also guess where it starts.</summary>
    private static uint InitialSequence()
    {
        Span<byte> raw = stackalloc byte[4];
        RandomNumberGenerator.Fill(raw);
        return (uint)(raw[0] << 24 | raw[1] << 16 | raw[2] << 8 | raw[3]);
    }
}
