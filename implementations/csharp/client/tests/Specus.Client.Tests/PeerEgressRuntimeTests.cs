using System.Collections.Concurrent;
using System.Text;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// Fault injection for the egress data plane.
/// </summary>
/// <remarks>
/// The layers below this one are pure and already have conformance suites. What is left to prove is
/// the part that owns real resources: that a refused flow never reaches a socket, that a socket is
/// released on every path including the ones nobody plans for, and that a revocation takes effect
/// while traffic is in flight rather than at the next idle sweep.
///
/// <para>The dialer is injected, so an unreachable target, a hung connect and a connection that
/// breaks mid-stream are all produced without a network.</para>
/// </remarks>
public class PeerEgressRuntimeTests
{
    private const long Epoch = 1_800_000_000_000L;

    private static readonly object EndOfStream = new();

    /// <summary>
    /// One end of a socket the runtime believes in. A read blocks until a test supplies data, an end
    /// of stream, or an error, which is what lets each failure path be driven on purpose.
    /// </summary>
    private sealed class FakeSocket : IPeerEgressSocket
    {
        private readonly BlockingCollection<object> _events = [];
        private readonly List<byte[]> _writes = [];

        public bool IsClosed { get; private set; }

        public bool IsHalfClosed { get; private set; }

        public int Read(byte[] buffer)
        {
            var item = _events.Take();
            if (ReferenceEquals(item, EndOfStream))
            {
                return -1;
            }
            if (item is Exception error)
            {
                throw error;
            }
            var chunk = (byte[])item;
            var length = Math.Min(chunk.Length, buffer.Length);
            chunk.AsSpan(0, length).CopyTo(buffer);
            return length;
        }

        public void Write(byte[] data)
        {
            lock (_writes)
            {
                _writes.Add((byte[])data.Clone());
            }
        }

        public void CloseWrite() => IsHalfClosed = true;

        public void Dispose()
        {
            if (IsClosed)
            {
                return;
            }
            IsClosed = true;
            // Unblocks a reader the way a real close does. The runtime drops what the reader reports
            // because the flow has already left the table, which is the check that makes a close
            // race harmless.
            _events.Add(new IOException("socket closed"));
        }

        public void Deliver(byte[] data) => _events.Add(data);

        public void EndOfStreamNow() => _events.Add(EndOfStream);

        public void Fail(string reason) => _events.Add(new IOException(reason));

        public bool Drained => _events.Count == 0;

        public IReadOnlyList<byte[]> Written
        {
            get
            {
                lock (_writes)
                {
                    return [.. _writes];
                }
            }
        }
    }

    /// <summary>Everything a test needs to observe: what was sent, what was dialled, and which sockets.</summary>
    private sealed class Harness : IPeerEgressDialer
    {
        private readonly List<byte[]> _frames = [];
        private readonly List<string> _dialed = [];
        private readonly List<FakeSocket> _sockets = [];

        public Exception? DialError { get; set; }

        /// <summary>Blocks the dialer so a test can act while a connect is still in flight.</summary>
        public ManualResetEventSlim? Gate { get; set; }

        public PeerEgressRuntime Runtime { get; }

        public Harness(params string[] destinations)
        {
            Runtime = new PeerEgressRuntime(
                (_, frame) =>
                {
                    lock (_frames)
                    {
                        _frames.Add((byte[])frame.Clone());
                    }
                },
                this,
                reader => new Thread(() => reader()) { IsBackground = true }.Start(),
                () => Epoch);
            Runtime.ApplyPolicy(Policy(destinations), PeerEgressContext.Default, Epoch);
        }

        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs)
        {
            ManualResetEventSlim? waiting;
            lock (_dialed)
            {
                _dialed.Add($"{host}:{port}");
                waiting = Gate;
            }
            waiting?.Wait();
            if (DialError is not null)
            {
                throw DialError;
            }
            var socket = new FakeSocket();
            lock (_sockets)
            {
                _sockets.Add(socket);
            }
            return socket;
        }

        public int DialCount
        {
            get
            {
                lock (_dialed)
                {
                    return _dialed.Count;
                }
            }
        }

        public FakeSocket Socket(int index)
        {
            lock (_sockets)
            {
                Assert.True(index < _sockets.Count,
                    $"no socket at index {index}, only {_sockets.Count} opened");
                return _sockets[index];
            }
        }

        public void ClearFrames()
        {
            lock (_frames)
            {
                _frames.Clear();
            }
        }

        private List<byte[]> Snapshot()
        {
            lock (_frames)
            {
                return [.. _frames];
            }
        }

        /// <summary>Every TCP segment the runtime sent back to a consumer.</summary>
        public List<Segment> Segments()
        {
            var output = new List<Segment>();
            foreach (var raw in Snapshot())
            {
                var frame = PeerEgressFrame.Parse(raw);
                if (!frame.Accepted || frame.Type != PeerEgressFrame.TypeIpPacket)
                {
                    continue;
                }
                if (PeerEgressSegment.Parse(frame.Body) is { } segment)
                {
                    output.Add(segment);
                }
            }
            return output;
        }

        public List<PeerEgressDatagram.Datagram> Datagrams()
        {
            var output = new List<PeerEgressDatagram.Datagram>();
            foreach (var raw in Snapshot())
            {
                var frame = PeerEgressFrame.Parse(raw);
                if (!frame.Accepted || frame.Type != PeerEgressFrame.TypeIpPacket)
                {
                    continue;
                }
                if (PeerEgressDatagram.Parse(frame.Body) is { } datagram)
                {
                    output.Add(datagram);
                }
            }
            return output;
        }

        public List<string> RejectCodes()
        {
            var codes = new List<string>();
            foreach (var raw in Snapshot())
            {
                var frame = PeerEgressFrame.Parse(raw);
                if (!frame.Accepted || frame.Type != PeerEgressFrame.TypeControl)
                {
                    continue;
                }
                var control = PeerEgressFrame.DecodeControl(frame.Body);
                if (control is not null && control.Type == PeerEgressFrame.ControlFlowReject)
                {
                    codes.Add(control.Code);
                }
            }
            return codes;
        }

        public bool SawFlag(int flag) => Segments().Exists(segment => segment.Has(flag));

        public bool SawReset() => SawFlag(PeerEgressSegment.FlagRst);

        public bool SawFin() => SawFlag(PeerEgressSegment.FlagFin);

        /// <summary>Acknowledges the SYN-ACK so the flow reaches ESTABLISHED.</summary>
        public void CompleteHandshake(long consumer, Segment syn)
        {
            var sent = Segments();
            Assert.True(sent.Count > 0, "no SYN-ACK to acknowledge");
            Runtime.HandleFrame(consumer, FrameFor(PeerEgressSegment.Build(new Segment(
                syn.SourceIp, syn.DestinationIp, syn.SourcePort, syn.DestinationPort,
                syn.Seq + 1, sent[0].Seq + 1, PeerEgressSegment.FlagAck, 65535, 0, []))), Epoch);
        }
    }

    /// <summary>Runs something that blocks, off the thread pool. Returns the thread so a test can join it.</summary>
    private static Thread StartBlocking(Action work)
    {
        var thread = new Thread(() => work()) { IsBackground = true };
        thread.Start();
        return thread;
    }

    /// <summary>Polls a condition the reader threads satisfy asynchronously.</summary>
    private static void WaitFor(string what, Func<bool> condition)
    {
        // Generous on purpose. The condition is satisfied by another thread, and a deadline tight
        // enough to fail on a loaded CI runner would report a scheduling delay as a defect.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }
            Thread.Sleep(1);
        }
        Assert.Fail($"timed out waiting for {what}");
    }

    private static PeerEgressPolicy Policy(params string[] destinations)
    {
        var cidrs = destinations.Length == 0 ? ["203.0.113.0/24"] : destinations;
        var rules = new List<PeerEgressDestinationRule>();
        foreach (var cidr in cidrs)
        {
            rules.Add(new PeerEgressDestinationRule
            {
                Cidr = cidr,
                Protocols = ["tcp", "udp"],
                // An empty portRanges denies every port, so a rule meant to allow traffic says so.
                PortRanges = [[1, 65535]],
            });
        }
        return new PeerEgressPolicy
        {
            Enabled = true,
            Scope = PeerEgressAuthorization.ScopePublic,
            AllowedConsumerClientIds = [7L, 9L],
            DestinationRules = rules,
        };
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static Segment Syn(string source, ushort sourcePort, string destination, ushort destinationPort) =>
        new(Address(source), Address(destination), sourcePort, destinationPort,
            1000, 0, PeerEgressSegment.FlagSyn, 65535, 1360, []);

    private static byte[] FrameFor(byte[] packet) =>
        PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet);

    /// <summary>The happy path, present so the failure cases below are read against something known to work.</summary>
    [Fact]
    public void OpensAndForwardsATcpFlow()
    {
        var harness = new Harness();
        var opening = Syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(opening)), Epoch);

        Assert.Equal(1, harness.DialCount);
        Assert.True(
            harness.Segments().Exists(s => s.Has(PeerEgressSegment.FlagSyn) && s.Has(PeerEgressSegment.FlagAck)),
            "the consumer never received a SYN-ACK");

        harness.CompleteHandshake(7, opening);
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n");
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(new Segment(
            opening.SourceIp, opening.DestinationIp, opening.SourcePort, opening.DestinationPort,
            opening.Seq + 1, harness.Segments()[0].Seq + 1,
            PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, 65535, 0, payload))), Epoch);

        WaitFor("payload to reach the socket", () => harness.Socket(0).Written.Count > 0);
        Assert.Equal("GET / HTTP/1.0\r\n\r\n", Encoding.ASCII.GetString(harness.Socket(0).Written[0]));
    }

    /// <summary>
    /// A refused flow must never reach a socket. Dialing first and checking after would leak a
    /// connection to a destination the policy forbids, which is the whole failure this layer exists
    /// to prevent.
    /// </summary>
    [Fact]
    public void RefusesBeforeDialing()
    {
        var harness = new Harness("203.0.113.0/24");
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "198.51.100.10", 443))), Epoch);

        Assert.True(harness.DialCount == 0, "a refused flow opened a socket");
        Assert.True(harness.SawReset(),
            "the consumer was not reset, so its application waits on a flow that will never open");
        Assert.Equal([PeerEgressCodes.DestinationDenied], harness.RejectCodes());
    }

    /// <summary>
    /// The forced-deny list has to hold against a policy broad enough to cover the address, which is
    /// the case it exists for.
    /// </summary>
    [Fact]
    public void RefusesForcedDenyUnderABroadPolicy()
    {
        var harness = new Harness("0.0.0.0/0");
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "169.254.169.254", 80))), Epoch);

        Assert.True(harness.DialCount == 0, "cloud metadata was dialled");
        Assert.Equal([PeerEgressCodes.ForbiddenDestination], harness.RejectCodes());
    }

    /// <summary>
    /// The quota is charged at reservation, before the connect. A consumer aiming a burst at a black
    /// hole would otherwise pass every limit check, because no flow would ever be counted as open.
    /// </summary>
    [Fact]
    public void ChargesQuotaWhileConnectIsInFlight()
    {
        var harness = new Harness();
        harness.Runtime.ApplyPolicy(
            Policy("203.0.113.0/24") with { Limits = new PeerEgressLimits { MaxFlowsPerConsumer = 1 } },
            PeerEgressContext.Default, Epoch);

        harness.Gate = new ManualResetEventSlim(false);
        // A thread rather than a pool task: the call blocks on the gate for the whole test, and a
        // pool thread parked like that is one the readers cannot have.
        StartBlocking(() => harness.Runtime.HandleFrame(7,
            FrameFor(PeerEgressSegment.Build(Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch));
        WaitFor("the first connect to start", () => harness.DialCount == 1);

        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40001, "203.0.113.10", 443))), Epoch);

        Assert.True(harness.DialCount == 1,
            "the second flow dialled despite the quota being held by a pending connect");
        Assert.Equal([PeerEgressCodes.LimitExceeded], harness.RejectCodes());
        harness.Gate.Set();
    }

    /// <summary>
    /// A connect that fails is not a refusal. Reporting it as one would send an operator hunting for
    /// a policy rule that never fired, and would inflate the refusal counts the server aggregates.
    /// </summary>
    [Fact]
    public void SeparatesAnUnreachableTargetFromARefusal()
    {
        var harness = new Harness { DialError = new IOException("connection refused") };

        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);

        Assert.True(harness.SawReset(), "an unreachable target left the consumer without a reset");
        Assert.Empty(harness.RejectCodes());
        Assert.Empty(harness.Runtime.Rejections.DrainCounts());
        // The reservation must come back, or a flapping destination would exhaust the quota.
        Assert.True(harness.Runtime.FlowCount == 0, "flows left after a failed connect");
    }

    /// <summary>
    /// A connection that dies mid-stream has to reach the consumer as a reset. Silence would leave
    /// the application waiting for data that is never coming.
    /// </summary>
    [Fact]
    public void ResetsWhenTheConnectionBreaks()
    {
        var harness = new Harness();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        WaitFor("the flow to open", () => harness.Runtime.FlowCount == 1);
        harness.ClearFrames();

        harness.Socket(0).Fail("connection reset by peer");

        WaitFor("the flow to be released", () => harness.Runtime.FlowCount == 0);
        Assert.True(harness.SawReset(), "a broken connection produced no reset for the consumer");
        Assert.True(harness.Socket(0).IsClosed, "the socket was not closed");
    }

    /// <summary>
    /// A clean end of stream is a half-close, not a failure. Turning it into a reset would discard a
    /// response the consumer is still entitled to read.
    /// </summary>
    [Fact]
    public void TurnsSocketEndOfStreamIntoAFin()
    {
        var harness = new Harness();
        var opening = Syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(opening)), Epoch);
        WaitFor("the flow to open", () => harness.Runtime.FlowCount == 1);
        harness.CompleteHandshake(7, opening);
        harness.ClearFrames();

        harness.Socket(0).EndOfStreamNow();

        WaitFor("a FIN for the consumer", harness.SawFin);
        Assert.False(harness.SawReset(), "a clean end of stream was reported as a reset");
    }

    /// <summary>
    /// A socket that ends while the handshake is still in flight owes the consumer a FIN as soon as
    /// the handshake completes. Sending it earlier would run ahead of a sequence space the consumer
    /// has not acknowledged; never sending it leaves the flow open until the idle timer collects it,
    /// with the consumer waiting on a connection that is already over.
    /// </summary>
    [Fact]
    public void DefersAFinUntilTheHandshakeCompletes()
    {
        var harness = new Harness();
        var opening = Syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(opening)), Epoch);
        WaitFor("the flow to open", () => harness.Runtime.FlowCount == 1);

        harness.Socket(0).EndOfStreamNow();
        // Wait for the reader to have taken the event, so the check below is about what the state
        // machine decided rather than about whether it has looked yet.
        WaitFor("the reader to observe the end of stream", () => harness.Socket(0).Drained);
        Assert.False(harness.SawFin(), "a FIN was sent before the consumer acknowledged the SYN-ACK");

        harness.CompleteHandshake(7, opening);
        WaitFor("the deferred FIN", harness.SawFin);
        Assert.False(harness.SawReset(), "the deferred close was turned into a reset");
    }

    /// <summary>Revocation must take effect while traffic is in flight, not at the next idle sweep.</summary>
    [Fact]
    public void RevokesLiveFlowsImmediately()
    {
        var harness = new Harness();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        harness.Runtime.HandleFrame(9, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.2", 40000, "203.0.113.11", 443))), Epoch);
        WaitFor("both flows to open", () => harness.Runtime.FlowCount == 2);
        harness.ClearFrames();

        harness.Runtime.RevokeConsumer(7, Epoch);

        Assert.True(harness.Runtime.FlowCount == 1, "the other consumer was touched");
        Assert.True(harness.Socket(0).IsClosed, "the revoked flow's socket stayed open");
        Assert.False(harness.Socket(1).IsClosed, "revoking one consumer closed another's socket");
        Assert.Equal([PeerEgressCodes.PeerAclDenied], harness.RejectCodes());
        Assert.True(harness.SawReset(), "the revoked consumer got no reset");
    }

    /// <summary>Turning the switch off means now, not at the next idle sweep.</summary>
    [Fact]
    public void DrainsWhenTheSwitchGoesOff()
    {
        var harness = new Harness();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        WaitFor("the flow to open", () => harness.Runtime.FlowCount == 1);

        harness.Runtime.ApplyPolicy(
            Policy("203.0.113.0/24") with { Enabled = false }, PeerEgressContext.Default, Epoch);

        Assert.True(harness.Runtime.FlowCount == 0, "a flow survived the switch going off");
        Assert.True(harness.Socket(0).IsClosed, "a socket survived the switch going off");

        // A further attempt must be refused rather than opening on a disabled egress.
        harness.ClearFrames();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40002, "203.0.113.10", 443))), Epoch);
        Assert.Equal([PeerEgressCodes.Disabled], harness.RejectCodes());
    }

    /// <summary>A narrowed policy closes the flows it no longer covers, and tells each one why.</summary>
    [Fact]
    public void ClosesFlowsANarrowedPolicyDrops()
    {
        var harness = new Harness("203.0.113.0/24", "198.51.100.0/24");
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40001, "198.51.100.10", 443))), Epoch);
        WaitFor("both flows to open", () => harness.Runtime.FlowCount == 2);
        harness.ClearFrames();

        harness.Runtime.ApplyPolicy(Policy("203.0.113.0/24"), PeerEgressContext.Default, Epoch);

        Assert.True(harness.Runtime.FlowCount == 1, "the flow the policy still covers was closed");
        Assert.Equal([PeerEgressCodes.DestinationDenied], harness.RejectCodes());
    }

    /// <summary>
    /// A purge speaks for its sender's flows. Acting on it for everyone would let any consumer tear
    /// down every other consumer's traffic with one message.
    /// </summary>
    [Fact]
    public void PurgeOnlyTouchesItsSender()
    {
        var harness = new Harness();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        harness.Runtime.HandleFrame(9, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.2", 40000, "203.0.113.10", 443))), Epoch);
        WaitFor("both flows to open", () => harness.Runtime.FlowCount == 2);

        var body = PeerEgressFrame.EncodeControl(
            PeerEgressFrame.Control.FlowPurge(["203.0.113.0/24"], string.Empty));
        harness.Runtime.HandleFrame(7,
            PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body), Epoch);

        Assert.True(harness.Runtime.FlowCount == 1, "a purge closed more than its sender's flows");
        Assert.False(harness.Socket(1).IsClosed, "one consumer's purge closed another's socket");
    }

    /// <summary>
    /// UDP has no handshake, so the first datagram is the authorization point and the reply path has
    /// to be built from the flow key rather than from whatever the socket reports.
    /// </summary>
    [Fact]
    public void CarriesAUdpSession()
    {
        var harness = new Harness();
        var query = new PeerEgressDatagram.Datagram(
            Address("100.96.0.1"), Address("203.0.113.53"), 51000, 53, Encoding.ASCII.GetBytes("query"));
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressDatagram.Build(query)), Epoch);

        WaitFor("the query to reach the socket",
            () => harness.DialCount == 1 && harness.Socket(0).Written.Count == 1);
        harness.Socket(0).Deliver(Encoding.ASCII.GetBytes("answer"));

        WaitFor("the reply to reach the consumer", () => harness.Datagrams().Count > 0);
        var reply = harness.Datagrams()[0];
        Assert.Equal(query.DestinationIp, reply.SourceIp);
        Assert.Equal(query.SourceIp, reply.DestinationIp);
        Assert.Equal(query.DestinationPort, reply.SourcePort);
        Assert.Equal(query.SourcePort, reply.DestinationPort);
        Assert.Equal("answer", Encoding.ASCII.GetString(reply.Payload));
    }

    /// <summary>Nothing in UDP says a session ended, so without this the socket would be held forever.</summary>
    [Fact]
    public void ExpiresAnIdleUdpSession()
    {
        var harness = new Harness();
        harness.Runtime.ApplyPolicy(
            Policy("203.0.113.0/24") with { Limits = new PeerEgressLimits { IdleTimeoutSeconds = 30 } },
            PeerEgressContext.Default, Epoch);

        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(
            Address("100.96.0.1"), Address("203.0.113.53"), 51000, 53,
            Encoding.ASCII.GetBytes("query")))), Epoch);
        WaitFor("the session to open", () => harness.Runtime.FlowCount == 1);

        harness.Runtime.OnTick(Epoch + 10_000);
        Assert.True(harness.Runtime.FlowCount == 1, "the session expired before its timeout");
        harness.Runtime.OnTick(Epoch + 31_000);
        Assert.True(harness.Runtime.FlowCount == 0, "the session outlived its idle timeout");
        Assert.True(harness.Socket(0).IsClosed, "an expired session left its socket open");
        // An expiring session is the normal end of life, not something to report as blocked traffic.
        Assert.Empty(harness.Runtime.Rejections.DrainCounts());
    }

    /// <summary>
    /// A stray segment for a flow that was never opened gets a reset, which is what tells a consumer
    /// holding stale state to give up rather than retry into silence.
    /// </summary>
    [Fact]
    public void ResetsSegmentsForUnknownFlows()
    {
        var harness = new Harness();
        var stray = PeerEgressSegment.Build(new Segment(
            Address("100.96.0.1"), Address("203.0.113.10"), 40000, 443,
            5000, 9000, PeerEgressSegment.FlagAck, 65535, 0, Encoding.ASCII.GetBytes("stale")));
        harness.Runtime.HandleFrame(7, FrameFor(stray), Epoch);

        Assert.True(harness.DialCount == 0, "a stray segment opened a socket");
        Assert.True(harness.SawReset(), "a stray segment got no reset");
    }

    /// <summary>Shutdown has to have stopped traffic by the time it returns, not merely have asked it to.</summary>
    [Fact]
    public void ShutdownReleasesEverything()
    {
        var harness = new Harness();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40000, "203.0.113.10", 443))), Epoch);
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(
            Address("100.96.0.1"), Address("203.0.113.53"), 51000, 53,
            Encoding.ASCII.GetBytes("query")))), Epoch);
        WaitFor("both flows to open", () => harness.Runtime.FlowCount == 2);

        harness.Runtime.Shutdown(Epoch);

        Assert.True(harness.Runtime.FlowCount == 0, "flows survived shutdown");
        Assert.True(harness.Socket(0).IsClosed, "socket 0 survived shutdown");
        Assert.True(harness.Socket(1).IsClosed, "socket 1 survived shutdown");

        harness.ClearFrames();
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(
            Syn("100.96.0.1", 40003, "203.0.113.10", 443))), Epoch);
        Assert.True(harness.DialCount == 2, "a shut-down runtime opened a new socket");
    }

    /// <summary>
    /// Forwarding a protocol the egress does not account for would leak traffic past the policy, so
    /// it is refused rather than passed through.
    /// </summary>
    [Fact]
    public void RefusesProtocolsItDoesNotCarry()
    {
        var harness = new Harness("0.0.0.0/0");
        // A minimal ICMP echo request; only the IPv4 header matters to the dispatch.
        var packet = new byte[28];
        packet[0] = 0x45;
        packet[3] = 28;
        packet[9] = 1;
        new byte[] { 100, 96, 0, 1 }.CopyTo(packet, 12);
        new byte[] { 203, 0, 113, 10 }.CopyTo(packet, 16);
        packet[20] = 8;

        harness.Runtime.HandleFrame(7, FrameFor(packet), Epoch);

        Assert.True(harness.DialCount == 0, "an unsupported protocol opened a socket");
        Assert.Equal([PeerEgressCodes.ProtocolDenied], harness.RejectCodes());
    }

    /// <summary>A half-close reaches the real socket as one, so a response still in flight is not discarded.</summary>
    [Fact]
    public void HalfClosesTheSocketWhenTheConsumerFinishesSending()
    {
        var harness = new Harness();
        var opening = Syn("100.96.0.1", 40000, "203.0.113.10", 443);
        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(opening)), Epoch);
        WaitFor("the flow to open", () => harness.Runtime.FlowCount == 1);
        harness.CompleteHandshake(7, opening);

        harness.Runtime.HandleFrame(7, FrameFor(PeerEgressSegment.Build(new Segment(
            opening.SourceIp, opening.DestinationIp, opening.SourcePort, opening.DestinationPort,
            opening.Seq + 1, harness.Segments()[0].Seq + 1,
            PeerEgressSegment.FlagAck | PeerEgressSegment.FlagFin, 65535, 0, []))), Epoch);

        Assert.True(harness.Socket(0).IsHalfClosed, "the write side was not half-closed");
        Assert.False(harness.Socket(0).IsClosed, "the whole socket was closed on a half-close");
    }

    /// <summary>
    /// Two frames for the same four-tuple can both find no flow before either has reserved one. Only
    /// the call that created the reservation may dial: two sockets on one entry would leak the loser
    /// and leave two state machines answering for the same connection.
    /// </summary>
    [Fact]
    public void DialsOnceForOneFlow()
    {
        var harness = new Harness { Gate = new ManualResetEventSlim(false) };

        var opening = Syn("100.96.0.1", 40000, "203.0.113.10", 443);
        var key = new PeerEgressFlowTable.Key(
            PeerEgressSegment.Ipv4ProtocolTcp, opening.SourceIp, opening.SourcePort,
            opening.DestinationIp, opening.DestinationPort);

        var first = StartBlocking(() => harness.Runtime.OpenTcpFlow(7, key, opening, Epoch));
        WaitFor("the first connect to start", () => harness.DialCount == 1);

        // The racing second attempt, which the reservation must already have claimed. Run on its own
        // task: an implementation that dials again would block on the gate, and a hung test says far
        // less than a counted one.
        var second = StartBlocking(() => harness.Runtime.OpenTcpFlow(7, key, opening, Epoch));
        second.Join(TimeSpan.FromSeconds(1));

        Assert.True(harness.DialCount == 1, "dialled more than once for one flow");
        Assert.True(harness.Runtime.FlowCount == 1, "more than one flow for one four-tuple");

        harness.Gate.Set();
        first.Join(TimeSpan.FromSeconds(2));
    }
}
