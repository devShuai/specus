using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.PeerMesh;

/// <summary>
/// User-space TCP termination for the egress side.
/// </summary>
/// <remarks>
/// A pure state machine: it performs no I/O and reads no clock. Segments and time come in as
/// arguments, and everything it wants to happen comes back in <see cref="Output"/> for the caller
/// to perform. Two reasons that shape matters. The conformance suite can drive loss, reordering and
/// timers deterministically without a network. And the same scenarios run against Go and Java,
/// where the I/O and scheduling primitives are different but the protocol decisions must not be.
///
/// <para>Held to <c>peer-egress-tcp-v1.json</c>, the shared fixture all three runtimes replay.</para>
/// </remarks>
internal sealed class PeerEgressTcpConnection
{
    internal enum State
    {
        SynReceived,
        Established,
        /// <summary>The application closed first, so we sent FIN and await its acknowledgement.</summary>
        FinWait1,
        FinWait2,
        /// <summary>The consumer closed first; we owe a FIN once the real socket drains.</summary>
        CloseWait,
        Closing,
        LastAck,
        TimeWait,
        Closed
    }

    /// <summary>
    /// The window we advertise. Phase one runs a conservative fixed window rather than a full
    /// congestion controller; the ceiling plus the existing RTT and path-MTU observations are what
    /// bound throughput.
    /// </summary>
    /// <remarks>
    /// 65535 and not 64 KiB: the header field is sixteen bits and there is no window scaling in this
    /// version, so a 65536 would go on the wire as a zero window and tell every consumer to stop
    /// sending.
    /// </remarks>
    public const uint ReceiveWindow = 65535;

    public const long InitialRtoMs = 1000;
    public const long MinRtoMs = 200;
    public const long MaxRtoMs = 60_000;

    /// <summary>How many times one segment is resent before the flow is abandoned.</summary>
    public const int MaxRetransmits = 6;

    /// <summary>
    /// Deliberately short of the classic 2*MSL. Nothing else on this host can bind the four-tuple,
    /// since it exists only inside this stack, so the window only has to outlive stragglers on the
    /// mesh path.
    /// </summary>
    public const long TimeWaitMs = 10_000;

    /// <summary>Bounds out-of-order segments per flow, so a peer that sends a hole cannot flood us.</summary>
    public const int MaxReassembly = 32;

    /// <summary>
    /// Keepalive finds out whether a silent consumer is still there sooner than the idle timeout
    /// would. It deliberately does not extend the idle budget: that budget is a resource limit
    /// rather than a liveness question.
    /// </summary>
    public const long KeepaliveIdleMs = 15_000;

    public const long KeepaliveIntervalMs = 5_000;
    public const int KeepaliveProbes = 3;

    /// <summary>Everything the state machine wants the caller to do. It never acts itself.</summary>
    internal sealed class Output
    {
        public List<byte[]> Segments { get; } = [];

        /// <summary>Payload to write to the real socket, in order.</summary>
        public byte[] Deliver { get; private set; } = [];

        /// <summary>The consumer finished sending, so the real socket should be half-closed for writing.</summary>
        public bool CloseApp { get; set; }

        /// <summary>The flow is finished and its resources can be released.</summary>
        public bool Done { get; set; }

        /// <summary>The flow ended abnormally; drop the socket rather than closing it gracefully.</summary>
        public bool Reset { get; set; }

        public void Send(byte[] packet) => Segments.Add(packet);

        public void AppendDeliver(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                return;
            }
            var merged = new byte[Deliver.Length + data.Length];
            Deliver.CopyTo(merged, 0);
            data.CopyTo(merged.AsSpan(Deliver.Length));
            Deliver = merged;
        }
    }

    private sealed class RetransmitEntry
    {
        public uint Seq;
        public int Flags;
        public byte[] Payload = [];
        public long SentAtMs;
        public int Attempts;

        /// <summary>
        /// Marks a segment that was resent, so its round-trip sample is discarded. That is Karn's
        /// algorithm: an ambiguous sample would poison the estimator whenever loss happens.
        /// </summary>
        public bool Retransmitted;
    }

    private sealed class OutOfOrder
    {
        public uint Seq;
        public byte[] Payload = [];
        public bool Fin;
    }

    private readonly uint _localIp;
    private readonly uint _remoteIp;
    private readonly ushort _localPort;
    private readonly ushort _remotePort;

    private State _state;

    private uint _sndUna;
    private uint _sndNxt;
    private int _sndWnd;

    private uint _rcvNxt;
    private readonly uint _rcvWnd;

    private int _sndMss;

    private readonly List<RetransmitEntry> _retransmit = [];
    private long _rtoMs = InitialRtoMs;
    private long _srttMs;
    private long _rttvarMs;

    private readonly List<OutOfOrder> _reassembly = [];

    private uint _finSeq;
    private bool _finSent;
    private bool _finReceived;
    private bool _appClosed;

    private long _lastActivityMs;
    private long _closedAtMs;
    private readonly long _idleTimeoutMs;

    private int _keepaliveProbes;
    private long _lastProbeMs;
    private bool _probed;

    private PeerEgressTcpConnection(Segment syn, uint iss, long idleTimeoutMs, long nowMs)
    {
        _localIp = syn.DestinationIp;
        _remoteIp = syn.SourceIp;
        _localPort = syn.DestinationPort;
        _remotePort = syn.SourcePort;
        _state = State.SynReceived;
        _sndUna = iss;
        _sndNxt = iss;
        _sndWnd = syn.Window;
        _rcvNxt = syn.Seq + 1;
        _rcvWnd = ReceiveWindow;
        _lastActivityMs = nowMs;
        _idleTimeoutMs = idleTimeoutMs;
    }

    /// <summary>
    /// Opens a flow from the consumer's SYN and produces the SYN-ACK.
    /// </summary>
    /// <remarks>
    /// The initial send sequence is supplied rather than generated here so tests are deterministic;
    /// production passes a random value, which is what keeps an off-path attacker from guessing the
    /// sequence space.
    /// </remarks>
    public static PeerEgressTcpConnection Accept(
        Segment syn, uint iss, int pathMtu, long idleTimeoutMs, long nowMs, Output output)
    {
        var connection = new PeerEgressTcpConnection(syn, iss, idleTimeoutMs, nowMs);
        var advertised = AdvertisedMss(pathMtu);
        connection._sndMss = syn.Mss > 0 ? Math.Min(syn.Mss, advertised) : advertised;
        connection.Emit(
            output, PeerEgressSegment.FlagSyn | PeerEgressSegment.FlagAck, [], nowMs, advertised);
        return connection;
    }

    public State CurrentState => _state;

    public bool IsDone => _state == State.Closed;

    public int SendMss => _sndMss;

    private static int AdvertisedMss(int pathMtu)
    {
        var mss = pathMtu - PeerEgressSegment.Ipv4MinHeaderBytes - PeerEgressSegment.TcpMinHeaderBytes;
        return Math.Max(mss, PeerEgressSegment.DefaultMss);
    }

    /// <summary>
    /// Renders one segment, queues it for retransmission when it occupies sequence space, and
    /// advances SND.NXT.
    /// </summary>
    private void Emit(Output output, int flags, byte[] payload, long nowMs, int mss)
    {
        var segment = new Segment(
            _localIp, _remoteIp, _localPort, _remotePort,
            _sndNxt, _rcvNxt, flags,
            PeerEgressSegment.AdvertisedWindow(_rcvWnd), mss, payload);
        output.Send(PeerEgressSegment.Build(segment));

        var length = segment.SegmentLength();
        if (length == 0)
        {
            return;
        }
        _retransmit.Add(new RetransmitEntry
        {
            Seq = _sndNxt,
            Flags = flags,
            Payload = payload,
            SentAtMs = nowMs
        });
        if (segment.Has(PeerEgressSegment.FlagFin))
        {
            _finSeq = _sndNxt + length - 1;
            _finSent = true;
        }
        _sndNxt += length;
    }

    private void Ack(Output output, long nowMs) =>
        Emit(output, PeerEgressSegment.FlagAck, [], nowMs, 0);

    /// <summary>
    /// Sends a reset and closes the flow.
    /// </summary>
    /// <remarks>
    /// The acknowledgement field is zero, not RCV.NXT. RFC 793 sends a reset that carries no ACK
    /// flag as &lt;SEQ=SND.NXT&gt;&lt;CTL=RST&gt;, and a field a receiver is told to ignore should
    /// not carry a value that looks meaningful.
    /// </remarks>
    private void ResetFlow(Output output)
    {
        output.Send(PeerEgressSegment.Build(new Segment(
            _localIp, _remoteIp, _localPort, _remotePort,
            _sndNxt, 0, PeerEgressSegment.FlagRst, 0, 0, [])));
        _state = State.Closed;
        _retransmit.Clear();
        _reassembly.Clear();
        output.Done = true;
        output.Reset = true;
    }

    /// <summary>Drives one segment arriving from the consumer.</summary>
    public Output OnSegment(Segment segment, long nowMs)
    {
        var output = new Output();
        if (_state == State.Closed)
        {
            return output;
        }

        // Any segment proves the consumer is still there, so the probe run restarts. The idle clock
        // is different: it measures data, not liveness. Letting a keepalive exchange refresh it
        // would mean two stacks could hold a socket and a quota slot open indefinitely by pinging
        // each other, which is exactly the resource the timeout exists to bound.
        _keepaliveProbes = 0;
        if (segment.SegmentLength() > 0)
        {
            _lastActivityMs = nowMs;
        }

        if (segment.Has(PeerEgressSegment.FlagRst))
        {
            // An in-window reset ends the flow. Out-of-window resets are ignored, which is what
            // stops a blind off-path attacker from tearing down flows by guessing.
            if (PeerEgressSegment.SeqInWindow(segment.Seq, _rcvNxt, _rcvWnd) || segment.Seq == _rcvNxt)
            {
                _state = State.Closed;
                _retransmit.Clear();
                _reassembly.Clear();
                output.Done = true;
                output.Reset = true;
            }
            return output;
        }

        if (segment.Has(PeerEgressSegment.FlagSyn) && _state != State.SynReceived)
        {
            // A SYN inside an established flow is either a stale duplicate or an attack; RFC 793
            // says answer with a reset rather than silently re-handshaking.
            ResetFlow(output);
            return output;
        }

        if (segment.Has(PeerEgressSegment.FlagAck))
        {
            ProcessAck(segment, nowMs, output);
            if (_state == State.Closed)
            {
                output.Done = true;
                return output;
            }
        }

        if (_state == State.SynReceived)
        {
            if (!segment.Has(PeerEgressSegment.FlagAck))
            {
                // A duplicate SYN: resend the SYN-ACK rather than opening a second flow.
                return output;
            }
            _state = State.Established;
            if (_appClosed)
            {
                // The real socket ended while the handshake was still in flight. The FIN could not
                // be sent then without running ahead of the sequence space, so it is owed now.
                // Without this the flow sits open until the idle timer collects it, and the
                // consumer waits on a connection that is already over.
                Emit(output, PeerEgressSegment.FlagAck | PeerEgressSegment.FlagFin, [], nowMs, 0);
                _state = State.FinWait1;
            }
        }

        // RFC 1122: a keepalive probe re-sends one byte of already acknowledged sequence space to
        // force an acknowledgement. Without answering it, a healthy flow looks dead to the consumer
        // and gets torn down from the far end. A normal bare ACK carries the sequence we already
        // expect, so only one below it is a probe.
        if (segment.Payload.Length == 0
            && !segment.Has(PeerEgressSegment.FlagFin)
            && !segment.Has(PeerEgressSegment.FlagSyn)
            && PeerEgressSegment.SeqLess(segment.Seq, _rcvNxt))
        {
            Ack(output, nowMs);
            return output;
        }

        AcceptData(segment, nowMs, output);
        UpdateStateAfterFin(output, nowMs);
        return output;
    }

    /// <summary>Advances the send window and retires acknowledged retransmission entries.</summary>
    private void ProcessAck(Segment segment, long nowMs, Output output)
    {
        var ack = segment.Ack;
        if (PeerEgressSegment.SeqLess(ack, _sndUna) || PeerEgressSegment.SeqLess(_sndNxt, ack))
        {
            // Acknowledges something we never sent. Ignored rather than answered with a reset: a
            // delayed duplicate must not be able to kill a healthy connection.
            return;
        }
        _sndUna = ack;
        _sndWnd = segment.Window;

        for (var index = _retransmit.Count - 1; index >= 0; index--)
        {
            var entry = _retransmit[index];
            var end = entry.Seq + EntryLength(entry);
            if (!PeerEgressSegment.SeqLessEqual(end, ack))
            {
                continue;
            }
            if (!entry.Retransmitted)
            {
                UpdateRto(nowMs - entry.SentAtMs);
            }
            _retransmit.RemoveAt(index);
        }

        if (_finSent && PeerEgressSegment.SeqLessEqual(_finSeq + 1, ack))
        {
            switch (_state)
            {
                case State.FinWait1:
                    _state = State.FinWait2;
                    break;
                case State.Closing:
                    EnterTimeWait(nowMs);
                    break;
                case State.LastAck:
                    _state = State.Closed;
                    output.Done = true;
                    break;
            }
        }
    }

    private static uint EntryLength(RetransmitEntry entry)
    {
        var length = (uint)entry.Payload.Length;
        if ((entry.Flags & PeerEgressSegment.FlagSyn) != 0)
        {
            length++;
        }
        if ((entry.Flags & PeerEgressSegment.FlagFin) != 0)
        {
            length++;
        }
        return length;
    }

    /// <summary>Jacobson/Karels, with the floor and ceiling the constants name.</summary>
    private void UpdateRto(long sampleMs)
    {
        if (sampleMs <= 0)
        {
            return;
        }
        if (_srttMs == 0)
        {
            _srttMs = sampleMs;
            _rttvarMs = sampleMs / 2;
        }
        else
        {
            var delta = Math.Abs(_srttMs - sampleMs);
            _rttvarMs = ((3 * _rttvarMs) + delta) / 4;
            _srttMs = ((7 * _srttMs) + sampleMs) / 8;
        }
        _rtoMs = Math.Min(Math.Max(_srttMs + (4 * _rttvarMs), MinRtoMs), MaxRtoMs);
    }

    /// <summary>Takes in-order payload, buffers out-of-order payload, and acknowledges.</summary>
    private void AcceptData(Segment segment, long nowMs, Output output)
    {
        var payload = segment.Payload;
        if (payload.Length == 0 && !segment.Has(PeerEgressSegment.FlagFin))
        {
            return;
        }
        if (_finReceived)
        {
            // Data after the peer's FIN is a protocol violation. Reset instead of quietly dropping,
            // so the far end learns its stack is out of step.
            if (payload.Length > 0)
            {
                ResetFlow(output);
            }
            return;
        }

        var seq = segment.Seq;
        if (PeerEgressSegment.SeqLess(seq, _rcvNxt))
        {
            // Wholly or partly retransmitted. Trim what we already have; if nothing new remains
            // this is a duplicate and only needs an ACK to re-synchronise the peer.
            var skip = _rcvNxt - seq;
            if (skip >= (uint)payload.Length)
            {
                if (segment.Has(PeerEgressSegment.FlagFin)
                    && seq + segment.SegmentLength() - 1 == _rcvNxt)
                {
                    _finReceived = true;
                    _rcvNxt++;
                    output.CloseApp = true;
                }
                Ack(output, nowMs);
                return;
            }
            payload = payload[(int)skip..];
            seq = _rcvNxt;
        }

        if (!PeerEgressSegment.SeqInWindow(seq, _rcvNxt, _rcvWnd))
        {
            // Outside the advertised window. Acknowledge so the peer re-syncs, but take nothing.
            Ack(output, nowMs);
            return;
        }

        if (seq != _rcvNxt)
        {
            BufferOutOfOrder(seq, payload, segment.Has(PeerEgressSegment.FlagFin));
            Ack(output, nowMs);
            return;
        }

        output.AppendDeliver(payload);
        _rcvNxt += (uint)payload.Length;
        if (segment.Has(PeerEgressSegment.FlagFin))
        {
            _finReceived = true;
            _rcvNxt++;
            output.CloseApp = true;
        }
        DrainReassembly(output);
        Ack(output, nowMs);
    }

    private void BufferOutOfOrder(uint seq, byte[] payload, bool fin)
    {
        if (_reassembly.Count >= MaxReassembly)
        {
            // Dropping is safe: the peer will retransmit. Growing without bound is not.
            return;
        }
        foreach (var held in _reassembly)
        {
            if (held.Seq == seq)
            {
                return;
            }
        }
        _reassembly.Add(new OutOfOrder { Seq = seq, Payload = payload, Fin = fin });
    }

    private void DrainReassembly(Output output)
    {
        var progressed = true;
        while (progressed)
        {
            progressed = false;
            for (var index = 0; index < _reassembly.Count; index++)
            {
                var held = _reassembly[index];
                if (held.Seq != _rcvNxt)
                {
                    continue;
                }
                output.AppendDeliver(held.Payload);
                _rcvNxt += (uint)held.Payload.Length;
                if (held.Fin)
                {
                    _finReceived = true;
                    _rcvNxt++;
                    output.CloseApp = true;
                }
                _reassembly.RemoveAt(index);
                progressed = true;
                break;
            }
        }
    }

    private void UpdateStateAfterFin(Output output, long nowMs)
    {
        if (!_finReceived)
        {
            return;
        }
        switch (_state)
        {
            case State.Established:
                _state = State.CloseWait;
                break;
            case State.FinWait1:
                _state = State.Closing;
                break;
            case State.FinWait2:
                EnterTimeWait(nowMs);
                break;
        }
    }

    private void EnterTimeWait(long nowMs)
    {
        _state = State.TimeWait;
        _closedAtMs = nowMs;
        _retransmit.Clear();
        _reassembly.Clear();
    }

    /// <summary>Data read from the real socket, on its way to the consumer.</summary>
    public Output OnAppData(byte[] data, long nowMs)
    {
        var output = new Output();
        if (_state != State.Established && _state != State.CloseWait)
        {
            return output;
        }
        _lastActivityMs = nowMs;
        var offset = 0;
        while (offset < data.Length)
        {
            var size = Math.Min(_sndMss, data.Length - offset);
            Emit(
                output,
                PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh,
                data[offset..(offset + size)],
                nowMs,
                0);
            offset += size;
        }
        return output;
    }

    /// <summary>The real socket reached EOF.</summary>
    public Output OnAppClose(long nowMs)
    {
        var output = new Output();
        if (_appClosed || _state == State.Closed)
        {
            return output;
        }
        _appClosed = true;
        _lastActivityMs = nowMs;
        switch (_state)
        {
            case State.Established:
                Emit(output, PeerEgressSegment.FlagAck | PeerEgressSegment.FlagFin, [], nowMs, 0);
                _state = State.FinWait1;
                break;
            case State.CloseWait:
                Emit(output, PeerEgressSegment.FlagAck | PeerEgressSegment.FlagFin, [], nowMs, 0);
                _state = State.LastAck;
                break;
            case State.SynReceived:
                // Nothing to send yet: a FIN here would sit beyond a sequence space the consumer
                // has not acknowledged. _appClosed is already set, and OnSegment sends the FIN the
                // moment the handshake completes.
                break;
        }
        return output;
    }

    /// <summary>Tears the flow down deliberately, which is what a revocation or a quota breach uses.</summary>
    public Output Abort()
    {
        var output = new Output();
        if (_state == State.Closed)
        {
            return output;
        }
        ResetFlow(output);
        return output;
    }

    /// <summary>Drives retransmission, the TIME_WAIT expiry, the idle timeout and keepalive.</summary>
    public Output OnTick(long nowMs)
    {
        var output = new Output();
        if (_state == State.Closed)
        {
            return output;
        }
        if (_state == State.TimeWait)
        {
            if (nowMs - _closedAtMs >= TimeWaitMs)
            {
                _state = State.Closed;
                output.Done = true;
            }
            return output;
        }
        if (_idleTimeoutMs > 0 && nowMs - _lastActivityMs >= _idleTimeoutMs)
        {
            // An idle flow holds a socket and a quota slot on the egress; reclaim it rather than
            // letting a forgotten consumer pin resources. Checked before the keepalive so a probe
            // cannot hold a flow past the limit the policy set.
            ResetFlow(output);
            return output;
        }
        if (Keepalive(nowMs, output))
        {
            return output;
        }

        foreach (var entry in _retransmit)
        {
            if (nowMs - entry.SentAtMs < _rtoMs)
            {
                continue;
            }
            if (entry.Attempts >= MaxRetransmits)
            {
                ResetFlow(output);
                return output;
            }
            entry.Attempts++;
            entry.Retransmitted = true;
            entry.SentAtMs = nowMs;
            output.Send(PeerEgressSegment.Build(new Segment(
                _localIp, _remoteIp, _localPort, _remotePort,
                entry.Seq, _rcvNxt, entry.Flags,
                PeerEgressSegment.AdvertisedWindow(_rcvWnd), 0, entry.Payload)));
            // Exponential backoff, capped. Doing this per entry keeps one lost segment from
            // resetting the estimator for the whole flow.
            _rtoMs = Math.Min(_rtoMs * 2, MaxRtoMs);
        }
        return output;
    }

    /// <summary>
    /// Probes a silent flow and reports whether the flow ended because the consumer never answered.
    /// </summary>
    /// <remarks>
    /// Established flows only: in any closing state the peer already told us where it stands, and
    /// the retransmission timer covers whatever is still outstanding.
    ///
    /// <para>The probe carries the last byte of already acknowledged sequence space and no payload,
    /// which is what RFC 1122 says forces an acknowledgement. It is built directly rather than
    /// through Emit because it occupies no new sequence space and must not enter the retransmission
    /// queue.</para>
    /// </remarks>
    private bool Keepalive(long nowMs, Output output)
    {
        if (_state != State.Established || nowMs - _lastActivityMs < KeepaliveIdleMs)
        {
            return false;
        }
        if (_keepaliveProbes >= KeepaliveProbes)
        {
            ResetFlow(output);
            return true;
        }
        if (_probed && nowMs - _lastProbeMs < KeepaliveIntervalMs)
        {
            return false;
        }
        _keepaliveProbes++;
        _probed = true;
        _lastProbeMs = nowMs;
        output.Send(PeerEgressSegment.Build(new Segment(
            _localIp, _remoteIp, _localPort, _remotePort,
            _sndNxt - 1, _rcvNxt, PeerEgressSegment.FlagAck,
            PeerEgressSegment.AdvertisedWindow(_rcvWnd), 0, [])));
        return false;
    }
}
