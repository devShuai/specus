using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The subset of a socket the egress plane uses. Injected so the fault-injection cases can produce
/// refusals, timeouts and mid-connection failures without a network.
/// </summary>
internal interface IPeerEgressSocket : IDisposable
{
    /// <summary>Returns the byte count, or -1 at end of stream.</summary>
    int Read(byte[] buffer);

    void Write(byte[] data);

    /// <summary>
    /// Half-closes the write side. The consumer finished sending but still expects replies, so
    /// closing both would discard a response the application is still producing.
    /// </summary>
    void CloseWrite()
    {
    }
}

/// <summary>Opens the real outbound socket.</summary>
internal interface IPeerEgressDialer
{
    IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs);
}

/// <summary>What the periodic egress-report carries, alongside the per-code refusal counts.</summary>
internal readonly record struct PeerEgressStats(long TotalFlows, long BytesIn, long BytesOut);

/// <summary>
/// The egress data plane: the only place authorization turns into a connect.
/// </summary>
/// <remarks>
/// Everything under it is pure. The TCP state machine, the datagram codec, the judgment layer and
/// the flow table hold no sockets and read no clock. This class is where they meet real ones, so it
/// is also where every resource is acquired and released, and the reason the layers below could stay
/// testable without a network.
///
/// <para>One lock serialises the whole plane. The flow table documents that it expects a single
/// caller, and a finer lock would let a reader task hold a flow past the moment the table stopped
/// vouching for it, which is exactly the window a revocation must not have.</para>
/// </remarks>
internal sealed class PeerEgressRuntime
{
    /// <summary>
    /// Bounds a flow's opening connect. A consumer waiting on a black-holed destination should get
    /// a reset it can act on rather than a socket held until the operating system gives up.
    /// </summary>
    public const long ConnectTimeoutMs = 10_000L;

    /// <summary>
    /// Used until the mesh reports a measured one. It is the conservative value the path-MTU prober
    /// starts from.
    /// </summary>
    public const int DefaultPathMtu = 1280;

    private const int TcpReadBuffer = 32 * 1024;
    private const int UdpReadBuffer = 65535;

    private sealed record TcpFlow(PeerEgressTcpConnection Connection, IPeerEgressSocket Socket);

    private sealed record UdpFlow(IPeerEgressSocket Socket);

    // A plain object rather than System.Threading.Lock: the connect path has to release the lock
    // before dialling and take it again afterwards, which needs Monitor.Enter and Monitor.Exit.
    private readonly object _lock = new();
    private readonly Action<long, byte[]>? _send;
    private readonly IPeerEgressDialer _dialer;
    private readonly Action<Action> _executor;
    private readonly Func<long> _clock;
    private readonly ILogger? _logger;

    private bool _enabled;
    private PeerEgressPolicy _policy = new();
    private PeerEgressContext _context = PeerEgressContext.Default;
    private int _pathMtu = DefaultPathMtu;

    /// <summary>
    /// Reports whether the mesh still authorises this consumer. It lives outside the policy because
    /// the mesh ACL and the egress policy are revoked independently.
    /// </summary>
    /// <remarks>
    /// Usually null, and that is correct rather than lax: a frame only reaches this plane over a
    /// session the mesh already authenticated, and withdrawal arrives as a RevokeConsumer call
    /// rather than as something to poll. Polling would mean reaching for the mesh's lock from under
    /// this one.
    /// </remarks>
    private Func<long, bool>? _peerAclAllows;

    /// <summary>The last accepted egress-config snapshot.</summary>
    private long _revision;

    /// <summary>
    /// The networks this host owns. Forwarding into one would loop back into this node's own
    /// capture path.
    /// </summary>
    private IReadOnlyList<string> _localInterfaces = [];

    private readonly PeerEgressFlowTable _flows = new(0);
    private long _totalFlows;
    private long _bytesIn;
    private long _bytesOut;
    private bool _closed;

    public PeerEgressRuntime(
        Action<long, byte[]>? send,
        IPeerEgressDialer dialer,
        Action<Action>? executor = null,
        Func<long>? clock = null,
        ILogger? logger = null)
    {
        _send = send;
        _dialer = dialer;
        _executor = executor ?? (reader => Task.Run(reader));
        _clock = clock ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _logger = logger;
    }

    public PeerEgressRejectionLog Rejections { get; } = new();

    public PeerEgressStats Stats
    {
        get
        {
            lock (_lock)
            {
                return new PeerEgressStats(_totalFlows, _bytesIn, _bytesOut);
            }
        }
    }

    public int FlowCount
    {
        get
        {
            lock (_lock)
            {
                return _flows.Count;
            }
        }
    }

    public void SetPeerAclAllows(Func<long, bool>? predicate)
    {
        lock (_lock)
        {
            _peerAclAllows = predicate;
        }
    }

    /// <summary>
    /// Installs a pushed policy and closes whatever it no longer allows.
    /// </summary>
    /// <remarks>
    /// Both gates are off by default, so a runtime that has received nothing forwards nothing.
    /// Turning the switch off drains every flow rather than waiting for idle expiry: an operator who
    /// disables the egress means now.
    /// </remarks>
    public void ApplyPolicy(PeerEgressPolicy policy, PeerEgressContext context, long nowMs)
    {
        lock (_lock)
        {
            if (_closed)
            {
                return;
            }
            _policy = policy;
            _context = context;
            _enabled = policy.Enabled;
            _flows.IdleTimeoutMs = policy.Limits.IdleTimeoutSeconds * 1000L;

            if (!_enabled)
            {
                ReleaseAll(
                    PeerEgressFlowTable.RevocationsFor(_flows.Drain(), PeerEgressCodes.Disabled), nowMs);
                return;
            }
            ReleaseAll(_flows.Reauthorize(policy, _peerAclAllows, context, _localInterfaces), nowMs);
        }
    }

    /// <summary>Closes a consumer's flows the moment the mesh withdraws its authorization.</summary>
    public void RevokeConsumer(long consumer, long nowMs)
    {
        lock (_lock)
        {
            ReleaseAll(PeerEgressFlowTable.RevocationsFor(
                _flows.RevokeConsumer(consumer), PeerEgressCodes.PeerAclDenied), nowMs);
        }
    }

    /// <summary>
    /// Releases everything. After it returns the runtime forwards nothing, so a caller can rely on
    /// it to have stopped traffic rather than merely to have asked it to stop.
    /// </summary>
    public void Shutdown(long nowMs)
    {
        lock (_lock)
        {
            _closed = true;
            _enabled = false;
            ReleaseAll(PeerEgressFlowTable.RevocationsFor(_flows.Drain(), PeerEgressCodes.Disabled), nowMs);
        }
    }

    /// <summary>
    /// The SPEG1 entry point: one decrypted payload from one consumer.
    /// </summary>
    /// <remarks>
    /// Returns false when the payload is not an egress frame at all, so the mesh dispatch can go on
    /// to its other cases. A payload that carries the magic but nothing valid returns true, because
    /// it was addressed here and has already been refused with its own code.
    /// </remarks>
    public bool HandleFrame(long consumer, byte[] payload, long nowMs)
    {
        if (!PeerEgressFrame.LooksLikeFrame(payload))
        {
            return false;
        }
        var frame = PeerEgressFrame.Parse(payload);
        if (!frame.Accepted)
        {
            Refuse(consumer, null, frame.Code!, nowMs);
            return true;
        }
        if (frame.Type == PeerEgressFrame.TypeIpPacket)
        {
            HandleInnerPacket(consumer, frame, nowMs);
        }
        else if (frame.Type == PeerEgressFrame.TypeControl)
        {
            HandleControl(consumer, frame, nowMs);
        }
        return true;
    }

    private void HandleInnerPacket(long consumer, PeerEgressFrame.Decoded frame, long nowMs)
    {
        var protocol = frame.Inner.Protocol;
        if (protocol == PeerEgressSegment.Ipv4ProtocolTcp)
        {
            if (PeerEgressSegment.Parse(frame.Body) is { } segment)
            {
                HandleSegment(consumer, segment, nowMs);
                return;
            }
        }
        else if (protocol == PeerEgressDatagram.Ipv4ProtocolUdp)
        {
            if (PeerEgressDatagram.Parse(frame.Body) is { } datagram)
            {
                HandleDatagram(consumer, datagram, nowMs);
                return;
            }
        }
        else
        {
            // ICMP and anything else this version does not carry. Refusing rather than passing it
            // through is the spec's rule: silently forwarding a protocol we do not account for
            // would leak traffic past the policy.
            Refuse(
                consumer,
                new PeerEgressFlowTable.Key(protocol, 0, 0, 0, (ushort)frame.Inner.DestinationPort),
                PeerEgressCodes.ProtocolDenied,
                nowMs);
            return;
        }
        Refuse(consumer, new PeerEgressFlowTable.Key(protocol, 0, 0, 0, 0),
            PeerEgressCodes.FrameTruncated, nowMs);
    }

    private void HandleControl(long consumer, PeerEgressFrame.Decoded frame, long nowMs)
    {
        var control = PeerEgressFrame.DecodeControl(frame.Body);
        // flow-reject travels egress to consumer. Receiving one means the peer is confused about
        // which end it is, and acting on it would let a consumer close flows by assertion.
        if (control is null || control.Type != PeerEgressFrame.ControlFlowPurge)
        {
            return;
        }
        lock (_lock)
        {
            // Scoped to the sender: a purge speaks for its own flows, not every other consumer's.
            ReleaseAll(PeerEgressFlowTable.RevocationsFor(
                _flows.PurgeDestinations(consumer, control.Destinations), null), nowMs);
        }
    }

    /// <summary>Drives one TCP segment from a consumer.</summary>
    private void HandleSegment(long consumer, PeerEgressSegment.Segment segment, long nowMs)
    {
        var key = new PeerEgressFlowTable.Key(
            PeerEgressSegment.Ipv4ProtocolTcp,
            segment.SourceIp, segment.SourcePort, segment.DestinationIp, segment.DestinationPort);

        Monitor.Enter(_lock);
        var flow = _flows.Lookup(key);
        if (flow is null)
        {
            Monitor.Exit(_lock);
            // Only a SYN opens a flow. A stray segment for something we never opened gets a reset,
            // which is what tells a consumer holding stale state to give up rather than retry.
            if (!segment.Has(PeerEgressSegment.FlagSyn) || segment.Has(PeerEgressSegment.FlagAck))
            {
                if (!segment.Has(PeerEgressSegment.FlagRst))
                {
                    EmitSegment(consumer, PeerEgressSegment.BuildReset(segment));
                }
                return;
            }
            OpenTcpFlow(consumer, key, segment, nowMs);
            return;
        }

        try
        {
            if (flow.Handle is not TcpFlow handle)
            {
                // The reservation exists but its connect has not returned, so there is no state
                // machine to drive yet. Dropping is correct rather than merely tolerable: the
                // consumer's own retransmission covers it, and answering now would mean answering
                // for a socket that may still fail to open.
                return;
            }
            flow.LastSeenMs = nowMs;
            ApplyTcpOutput(consumer, flow, handle, handle.Connection.OnSegment(segment, nowMs));
        }
        finally
        {
            Monitor.Exit(_lock);
        }
    }

    /// <summary>
    /// Authorises, connects and completes the handshake.
    /// </summary>
    /// <remarks>
    /// The connect happens outside the lock: it can take as long as <see cref="ConnectTimeoutMs"/>,
    /// and holding the plane for that would stall every other flow. The reservation is taken first
    /// so the quota is charged for the whole attempt, not only after it succeeds; a consumer opening
    /// a thousand flows to a black hole would otherwise pass every limit check.
    /// </remarks>
    // Internal rather than private so a test can drive two calls into it at once. The race it
    // guards -- two frames for one four-tuple both finding no flow -- cannot be produced through the
    // public entry point, because the lock serialises them there.
    internal void OpenTcpFlow(
        long consumer, PeerEgressFlowTable.Key key, PeerEgressSegment.Segment syn, long nowMs)
    {
        Monitor.Enter(_lock);
        var (reserved, code, opened) = Reserve(consumer, key, nowMs);
        if (code is not null)
        {
            Monitor.Exit(_lock);
            Refuse(consumer, key, code, nowMs);
            EmitSegment(consumer, PeerEgressSegment.BuildReset(syn));
            return;
        }
        if (!opened)
        {
            // A retransmitted SYN, or a second frame that raced this one. The reservation already
            // exists, so dialling again would leave two sockets and two state machines on one entry
            // with the loser leaked. Dropping is right: the consumer retransmits until the flow this
            // call is opening answers.
            Monitor.Exit(_lock);
            return;
        }
        var flow = reserved!;
        var mtu = _pathMtu;
        Monitor.Exit(_lock);

        IPeerEgressSocket? socket = null;
        Exception? failure = null;
        try
        {
            socket = _dialer.Dial("tcp", Ipv4Cidr.FormatAddress(key.RemoteIp), key.RemotePort, ConnectTimeoutMs);
        }
        catch (Exception error)
        {
            failure = error;
        }

        Monitor.Enter(_lock);
        // The flow can have been revoked, purged or drained while the connect was in flight.
        // Closing the socket we just opened is the only correct outcome: the authorization it was
        // opened under no longer exists.
        if (!ReferenceEquals(_flows.Lookup(key), flow) || _closed)
        {
            Monitor.Exit(_lock);
            socket?.Dispose();
            return;
        }
        if (failure is not null || socket is null)
        {
            _flows.Close(key);
            Monitor.Exit(_lock);
            Unreachable(consumer, key, failure);
            EmitSegment(consumer, PeerEgressSegment.BuildReset(syn));
            return;
        }

        try
        {
            var output = new PeerEgressTcpConnection.Output();
            var connection = PeerEgressTcpConnection.Accept(
                syn, NewInitialSendSequence(), mtu, _flows.IdleTimeoutMs, nowMs, output);
            var handle = new TcpFlow(connection, socket);
            flow.Handle = handle;
            _totalFlows++;
            ApplyTcpOutput(consumer, flow, handle, output);
            StartTcpReader(consumer, flow, handle);
        }
        finally
        {
            Monitor.Exit(_lock);
        }
    }

    /// <summary>Pumps the real socket into the state machine. Called with the lock held.</summary>
    private void StartTcpReader(long consumer, PeerEgressFlowTable.Flow flow, TcpFlow handle)
    {
        _executor(() =>
        {
            var buffer = new byte[TcpReadBuffer];
            while (true)
            {
                int read;
                try
                {
                    read = handle.Socket.Read(buffer);
                }
                catch (Exception)
                {
                    FinishTcpReader(consumer, flow, handle, endOfStream: false);
                    return;
                }
                if (read < 0)
                {
                    // A clean end of stream is a half-close the consumer should see as a FIN.
                    FinishTcpReader(consumer, flow, handle, endOfStream: true);
                    return;
                }
                if (read == 0)
                {
                    continue;
                }
                var data = buffer[..read];
                var nowMs = _clock();
                lock (_lock)
                {
                    if (!ReferenceEquals(_flows.Lookup(flow.Key), flow))
                    {
                        return;
                    }
                    flow.LastSeenMs = nowMs;
                    flow.BytesFromRemote += read;
                    _bytesIn += read;
                    ApplyTcpOutput(consumer, flow, handle, handle.Connection.OnAppData(data, nowMs));
                }
            }
        });
    }

    /// <summary>
    /// Ends a reader loop. A clean end of stream is a half-close the consumer should see as a FIN;
    /// any other error ended the connection abnormally, which is a reset.
    /// </summary>
    private void FinishTcpReader(
        long consumer, PeerEgressFlowTable.Flow flow, TcpFlow handle, bool endOfStream)
    {
        var nowMs = _clock();
        lock (_lock)
        {
            if (!ReferenceEquals(_flows.Lookup(flow.Key), flow))
            {
                return;
            }
            var output = endOfStream ? handle.Connection.OnAppClose(nowMs) : handle.Connection.Abort();
            ApplyTcpOutput(consumer, flow, handle, output);
        }
    }

    /// <summary>Performs everything the state machine asked for. Called with the lock held.</summary>
    private void ApplyTcpOutput(
        long consumer, PeerEgressFlowTable.Flow flow, TcpFlow handle, PeerEgressTcpConnection.Output output)
    {
        foreach (var packet in output.Segments)
        {
            EmitSegment(consumer, packet);
        }
        if (output.Deliver.Length > 0)
        {
            try
            {
                handle.Socket.Write(output.Deliver);
            }
            catch (Exception)
            {
                // The socket died under us. Reset rather than leaving the consumer waiting for data
                // that will never arrive.
                foreach (var packet in handle.Connection.Abort().Segments)
                {
                    EmitSegment(consumer, packet);
                }
                Release(flow);
                return;
            }
            flow.BytesToRemote += output.Deliver.Length;
            _bytesOut += output.Deliver.Length;
        }
        if (output.CloseApp)
        {
            // The consumer finished sending but still expects replies, so only the write side
            // closes. Closing both would discard a response the application is still producing.
            handle.Socket.CloseWrite();
        }
        if (output.Done || output.Reset)
        {
            Release(flow);
        }
    }

    /// <summary>
    /// Drives one UDP datagram from a consumer. UDP has no handshake, so the first datagram of a
    /// four-tuple is the authorization point and every later one rides that decision.
    /// </summary>
    private void HandleDatagram(long consumer, PeerEgressDatagram.Datagram datagram, long nowMs)
    {
        var key = new PeerEgressFlowTable.Key(
            PeerEgressDatagram.Ipv4ProtocolUdp,
            datagram.SourceIp, datagram.SourcePort, datagram.DestinationIp, datagram.DestinationPort);

        Monitor.Enter(_lock);
        var flow = _flows.Lookup(key);
        if (flow is null)
        {
            var (reserved, code, opened) = Reserve(consumer, key, nowMs);
            if (code is not null)
            {
                Monitor.Exit(_lock);
                Refuse(consumer, key, code, nowMs);
                return;
            }
            if (!opened)
            {
                // Another datagram for the same four-tuple is already opening this session. Two
                // sockets on one entry would leak the loser and split the session's replies.
                Monitor.Exit(_lock);
                return;
            }
            var pending = reserved!;
            Monitor.Exit(_lock);

            IPeerEgressSocket? socket = null;
            Exception? failure = null;
            try
            {
                socket = _dialer.Dial("udp", Ipv4Cidr.FormatAddress(key.RemoteIp), key.RemotePort, ConnectTimeoutMs);
            }
            catch (Exception error)
            {
                failure = error;
            }

            Monitor.Enter(_lock);
            if (!ReferenceEquals(_flows.Lookup(key), pending) || _closed)
            {
                Monitor.Exit(_lock);
                socket?.Dispose();
                return;
            }
            if (failure is not null || socket is null)
            {
                _flows.Close(key);
                Monitor.Exit(_lock);
                Unreachable(consumer, key, failure);
                return;
            }
            var udp = new UdpFlow(socket);
            pending.Handle = udp;
            _totalFlows++;
            StartUdpReader(consumer, pending, udp);
            flow = pending;
        }

        IPeerEgressSocket target;
        byte[] payload;
        try
        {
            if (flow.Handle is not UdpFlow handle)
            {
                // The session is still connecting. Dropping one datagram is what UDP already
                // promises, and holding it would mean buffering for a socket that may never open.
                return;
            }
            flow.LastSeenMs = nowMs;
            target = handle.Socket;
            payload = datagram.Payload;
            flow.BytesToRemote += payload.Length;
            _bytesOut += payload.Length;
        }
        finally
        {
            Monitor.Exit(_lock);
        }

        try
        {
            target.Write(payload);
        }
        catch (Exception)
        {
            lock (_lock)
            {
                ReleaseKey(key);
            }
        }
    }

    /// <summary>Returns the socket's replies to the consumer. Called with the lock held.</summary>
    private void StartUdpReader(long consumer, PeerEgressFlowTable.Flow flow, UdpFlow handle)
    {
        _executor(() =>
        {
            var buffer = new byte[UdpReadBuffer];
            while (true)
            {
                int read;
                try
                {
                    read = handle.Socket.Read(buffer);
                }
                catch (Exception)
                {
                    return;
                }
                if (read < 0)
                {
                    return;
                }
                var payload = buffer[..read];

                lock (_lock)
                {
                    if (!ReferenceEquals(_flows.Lookup(flow.Key), flow))
                    {
                        return;
                    }
                    flow.LastSeenMs = _clock();
                    flow.BytesFromRemote += read;
                    _bytesIn += read;
                }

                // Addresses are mirrored from the flow key rather than read off the socket, so a
                // reply can only ever claim the address the consumer asked us to contact.
                EmitSegment(consumer, PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(
                    flow.Key.RemoteIp, flow.Key.ConsumerIp,
                    flow.Key.RemotePort, flow.Key.ConsumerPort, payload)));
            }
        });
    }

    /// <summary>
    /// Advances timers: TCP retransmission and the idle expiry that is the only thing ending a UDP
    /// session. Called with no lock held.
    /// </summary>
    public void OnTick(long nowMs)
    {
        lock (_lock)
        {
            if (_closed)
            {
                return;
            }
            foreach (var flow in FlowSnapshot())
            {
                if (flow.Handle is TcpFlow handle)
                {
                    ApplyTcpOutput(flow.Consumer, flow, handle, handle.Connection.OnTick(nowMs));
                }
            }
            // An expired session ended the way UDP sessions end. Recording it as a refusal would put
            // normal life cycle events into the counts an operator reads as blocked traffic.
            ReleaseAll(PeerEgressFlowTable.RevocationsFor(_flows.Expire(nowMs), null), nowMs);
        }
    }

    /// <summary>Copies the live flows so a tick can release entries while iterating.</summary>
    private List<PeerEgressFlowTable.Flow> FlowSnapshot()
    {
        var snapshot = _flows.Live();
        PeerEgressFlowTable.Sort(snapshot);
        return snapshot;
    }

    /// <summary>
    /// Runs the judgment layer and, on approval, takes the quota slot. Called with the lock held.
    /// The reservation exists before the socket does so that a slow or failing connect still counts
    /// against the limits for its whole duration.
    /// </summary>
    /// <remarks>
    /// The third result says whether this call is the one that created the entry. A second frame for
    /// the same four-tuple arriving while the first is still connecting finds the reservation
    /// already there, and must not dial again.
    /// </remarks>
    private (PeerEgressFlowTable.Flow? Flow, string? Code, bool Opened) Reserve(
        long consumer, PeerEgressFlowTable.Key key, long nowMs)
    {
        if (_closed || !_enabled)
        {
            return (null, PeerEgressCodes.Disabled, false);
        }
        var peerAllowed = _peerAclAllows is null || _peerAclAllows(consumer);

        var decision = PeerEgressAuthorization.Authorize(
            new PeerEgressRequest
            {
                ConsumerClientId = consumer,
                DestinationIp = Ipv4Cidr.FormatAddress(key.RemoteIp),
                DestinationPort = key.RemotePort,
                Protocol = key.ProtocolName(),
                ActiveFlowsForConsumer = _flows.CountFor(consumer),
                ActiveFlowsTotal = _flows.Count,
                LocalInterfaceCidrs = _localInterfaces,
            },
            _policy, peerAllowed, _context);
        if (!decision.Allowed)
        {
            return (null, decision.Code, false);
        }
        var opened = _flows.Open(key, consumer, nowMs);
        return opened is not null ? (opened, null, true) : (_flows.Lookup(key), null, false);
    }

    /// <summary>
    /// Records a refusal and tells the consumer why. Called with no lock held.
    /// </summary>
    /// <remarks>
    /// The control message is diagnostic only. A refused TCP flow is ended by the reset the caller
    /// also sends, because an application waits on its own stack, not on a message it never sees.
    /// </remarks>
    private void Refuse(long consumer, PeerEgressFlowTable.Key? key, string code, long nowMs)
    {
        var subject = key ?? new PeerEgressFlowTable.Key(0, 0, 0, 0, 0);
        PeerEgressRejectionLog.Decision decision;
        lock (_lock)
        {
            decision = Rejections.Record(consumer, code, nowMs);
        }
        if (decision.ShouldLog)
        {
            _logger?.LogInformation(
                "[peer-egress] refused consumer={Consumer} protocol={Protocol} destination={Destination}:{Port} code={Code} suppressed={Suppressed}",
                consumer, subject.ProtocolName(), Ipv4Cidr.FormatAddress(subject.RemoteIp),
                subject.RemotePort, code, decision.Suppressed);
        }
        EmitFrame(consumer, PeerEgressFrame.TypeControl,
            PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.FlowReject(
                subject.ProtocolName(), Ipv4Cidr.FormatAddress(subject.ConsumerIp),
                subject.ConsumerPort, Ipv4Cidr.FormatAddress(subject.RemoteIp),
                subject.RemotePort, code)));
    }

    /// <summary>
    /// Reports a flow the policy allowed but the network did not deliver. Called with no lock held.
    /// </summary>
    /// <remarks>
    /// Deliberately not a refusal. The spec's codes all describe an authorization or validation
    /// outcome, and reporting a refused connection as <c>EGRESS_DEST_DENIED</c> would send an
    /// operator hunting for a policy rule that never fired, while inflating the refusal counts the
    /// server aggregates. The consumer learns what happened from the reset its own stack receives,
    /// which is what the application waits on anyway.
    /// </remarks>
    private void Unreachable(long consumer, PeerEgressFlowTable.Key key, Exception? cause)
    {
        _logger?.LogInformation(
            "[peer-egress] connect failed consumer={Consumer} protocol={Protocol} destination={Destination}:{Port} err={Error}",
            consumer, key.ProtocolName(), Ipv4Cidr.FormatAddress(key.RemoteIp), key.RemotePort,
            cause?.Message ?? "no socket");
    }

    /// <summary>Closes one flow's socket and drops its table entry. Called with the lock held.</summary>
    private void Release(PeerEgressFlowTable.Flow flow)
    {
        if (_flows.Lookup(flow.Key) is null)
        {
            return;
        }
        _flows.Close(flow.Key);
        CloseHandle(flow.Handle);
    }

    private void ReleaseKey(PeerEgressFlowTable.Key key)
    {
        if (_flows.Close(key) is { } flow)
        {
            CloseHandle(flow.Handle);
        }
    }

    /// <summary>
    /// Closes flows the table already removed. Called with the lock held.
    /// </summary>
    /// <remarks>
    /// The reason travels to the consumer so an operator sees a blocked connection explained rather
    /// than merely dropped, and so a client can distinguish a revoked flow from a network failure.
    /// </remarks>
    private void ReleaseAll(IReadOnlyList<PeerEgressFlowTable.Revocation> revoked, long nowMs)
    {
        foreach (var entry in revoked)
        {
            var flow = entry.Flow;
            if (flow.Handle is TcpFlow handle)
            {
                // The reset is what the application actually reacts to. Without it a consumer sits
                // waiting on a connection this node has already stopped serving.
                foreach (var packet in handle.Connection.Abort().Segments)
                {
                    EmitSegment(flow.Consumer, packet);
                }
            }
            CloseHandle(flow.Handle);
            if (entry.Code is null)
            {
                continue;
            }
            Rejections.Record(flow.Consumer, entry.Code, nowMs);
            EmitFrame(flow.Consumer, PeerEgressFrame.TypeControl,
                PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.FlowReject(
                    flow.Key.ProtocolName(), Ipv4Cidr.FormatAddress(flow.Key.ConsumerIp),
                    flow.Key.ConsumerPort, Ipv4Cidr.FormatAddress(flow.Key.RemoteIp),
                    flow.Key.RemotePort, entry.Code)));
        }
    }

    private static void CloseHandle(object? handle)
    {
        switch (handle)
        {
            case TcpFlow tcp:
                tcp.Socket.Dispose();
                break;
            case UdpFlow udp:
                udp.Socket.Dispose();
                break;
        }
    }

    private void EmitSegment(long consumer, byte[] packet) =>
        EmitFrame(consumer, PeerEgressFrame.TypeIpPacket, packet);

    /// <summary>
    /// Wraps a body and hands it to the sender. hop stays clear: this node is acting as an egress,
    /// not forwarding as a consumer of another one.
    /// </summary>
    private void EmitFrame(long consumer, int type, byte[] body) =>
        _send?.Invoke(consumer, PeerEgressFrame.Encode(type, false, body));

    /// <summary>
    /// Records the budget a returning segment has to fit. A value below the IPv4 minimum is ignored
    /// rather than applied, since a bad measurement should not be able to shrink every flow's
    /// segments to nothing.
    /// </summary>
    public void SetPathMtu(int mtu)
    {
        if (mtu < PeerEgressSegment.Ipv4MinHeaderBytes
            + PeerEgressSegment.TcpMinHeaderBytes + PeerEgressSegment.DefaultMss)
        {
            return;
        }
        lock (_lock)
        {
            _pathMtu = mtu;
        }
    }

    public void SetLocalInterfaceCidrs(IReadOnlyList<string>? networks)
    {
        lock (_lock)
        {
            _localInterfaces = networks ?? [];
        }
    }

    /// <summary>
    /// Applies the spec's monotonic guard: a snapshot at or below the last accepted one is ignored,
    /// so a reordered or replayed push cannot walk the policy backwards. A revision of zero is
    /// accepted, since a server that numbers nothing must still be able to configure the node.
    /// </summary>
    public bool AcceptRevision(long candidate)
    {
        lock (_lock)
        {
            if (candidate != 0 && candidate <= _revision)
            {
                return false;
            }
            _revision = candidate;
            return true;
        }
    }

    /// <summary>
    /// Picks an initial send sequence number.
    /// </summary>
    /// <remarks>
    /// Random rather than counted: a predictable value lets anyone who can guess the four-tuple
    /// inject segments a flow will accept.
    /// </remarks>
    private static uint NewInitialSendSequence()
    {
        Span<byte> raw = stackalloc byte[4];
        RandomNumberGenerator.Fill(raw);
        return (uint)((raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]);
    }
}
