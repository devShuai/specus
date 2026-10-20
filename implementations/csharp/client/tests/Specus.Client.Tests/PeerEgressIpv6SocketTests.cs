using System.Net;
using System.Net.Sockets;
using System.Text;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Xunit.Abstractions;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// The egress carrying IPv6 over real sockets: a handshake and a byte each way through the user-space
/// stack to a TCP listener on ::1, and a datagram and its answer through a UDP one.
/// </summary>
/// <remarks>
/// The consumer and the policy speak a routable destination while the dialer reaches ::1, as the IPv4
/// suite does with 127.0.0.1: ::1 is on the forced-deny list, so naming it would only ever prove the
/// refusal. A host without IPv6 loopback cannot run these; each test says so and returns.
/// </remarks>
public sealed class PeerEgressIpv6SocketTests(ITestOutputHelper output)
{
    private const string ConsumerMesh = "100.96.0.1";

    private static UInt128 Consumer6()
    {
        Assert.True(PeerEgressMeshAddress.TryDerive(ConsumerMesh, out var address));
        return address;
    }

    private static UInt128 Address6(string text)
    {
        Assert.True(Ipv6Cidr.TryParseAddress(text, out var value), $"{text} did not parse");
        return value;
    }

    /// <summary>Dials ::1 at the listener's port whatever the flow names, through the production dialer.</summary>
    private sealed class LoopbackDialer(int port) : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int ignored, long timeoutMs) =>
            new PeerEgressSocketDialer(PeerEgressSocketBinder.None()).Dial(protocol, "::1", port, timeoutMs);
    }

    /// <summary>The IPv6 counterpart of a consumer: its own sequence space, and only what it reads off the wire.</summary>
    private sealed class Consumer
    {
        private readonly object _gate = new();
        private uint _seq = 1000;
        private uint _ack;

        public Consumer(int port, string destination)
        {
            Remote = Address6(destination);
            Runtime = new PeerEgressRuntime((_, frame) => OnFrame(frame), new LoopbackDialer(port));
            Runtime.ApplyPolicy(new PeerEgressPolicy
            {
                Enabled = true,
                Scope = PeerEgressAuthorization.ScopePublic,
                AllowedConsumerClientIds = [7L],
                DestinationRules =
                [
                    new PeerEgressDestinationRule { Cidr = destination + "/128", Protocols = ["tcp", "udp"], PortRanges = [[1, 65535]] },
                ],
            }, PeerEgressContext.Default, Now());
        }

        public PeerEgressRuntime Runtime { get; }

        public UInt128 Local { get; } = Consumer6();

        public UInt128 Remote { get; }

        public List<byte[]> Packets { get; } = [];

        public List<Segment> Inbound { get; } = [];

        public List<PeerEgressDatagram.Datagram> Datagrams { get; } = [];

        public List<byte> Received { get; } = [];

        public List<string> Problems { get; } = [];

        private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        private void OnFrame(byte[] raw)
        {
            var frame = PeerEgressFrame.Parse(raw, ipv6: true);
            lock (_gate)
            {
                if (!frame.Accepted)
                {
                    Problems.Add($"a frame that does not parse: {frame.Code}");
                    return;
                }
                if (frame.Type != PeerEgressFrame.TypeIpPacket)
                {
                    Problems.Add("a control frame: " + Encoding.UTF8.GetString(frame.Body));
                    return;
                }
                Packets.Add(frame.Body);
                if (PeerEgressDatagram.Parse6(frame.Body) is { } datagram)
                {
                    Datagrams.Add(datagram);
                    return;
                }
                if (PeerEgressSegment.Parse6(frame.Body) is not { } segment)
                {
                    Problems.Add("an IPv6 packet that is neither TCP nor UDP");
                    return;
                }
                Inbound.Add(segment);
                if (segment.Payload.Length > 0)
                {
                    Received.AddRange(segment.Payload);
                    _ack = segment.Seq + (uint)segment.Payload.Length;
                }
            }
        }

        public void Send(int flags, byte[] payload)
        {
            Segment segment;
            lock (_gate)
            {
                segment = new Segment(0, 0, 40000, 443, _seq, _ack, flags, 65535,
                    (flags & PeerEgressSegment.FlagSyn) != 0 ? 1360 : 0, payload,
                    Ipv6: true, SourceIp6: Local, DestinationIp6: Remote);
                _seq += segment.SegmentLength();
            }
            Runtime.HandleFrameFrom(7, ConsumerMesh,
                PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, PeerEgressSegment.Build(segment)), Now());
        }

        public void SendDatagram(PeerEgressDatagram.Datagram datagram) =>
            Runtime.HandleFrameFrom(7, ConsumerMesh,
                PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, PeerEgressDatagram.Build(datagram)), Now());

        public T WaitFor<T>(string what, Func<T?> found) where T : class
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                lock (_gate)
                {
                    if (found() is { } value)
                    {
                        return value;
                    }
                }
                Thread.Sleep(1);
            }
            throw new TimeoutException($"timed out waiting for {what}");
        }

        public void Acknowledge(uint ack)
        {
            lock (_gate)
            {
                _ack = ack;
            }
        }
    }

    /// <summary>Runs the listener's side on a thread of its own, off the pool.</summary>
    private static Thread Serve(Action work)
    {
        var thread = new Thread(() => work()) { IsBackground = true };
        thread.Start();
        return thread;
    }

    private bool NoIpv6Loopback(SocketException failure)
    {
        output.WriteLine($"no IPv6 loopback on this host ({failure.SocketErrorCode}); the IPv6 real-socket tests need ::1 and did not run");
        return true;
    }

    [Fact]
    public void CarriesTcpEndToEnd()
    {
        TcpListener listener;
        try
        {
            listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();
        }
        catch (SocketException failure) when (NoIpv6Loopback(failure))
        {
            return;
        }
        try
        {
            var served = Serve(() =>
            {
                using var socket = listener.AcceptSocket();
                var buffer = new byte[64];
                var read = socket.Receive(buffer);
                socket.Send([.. "echo:"u8.ToArray(), .. buffer[..read]]);
            });

            var consumer = new Consumer(((IPEndPoint)listener.LocalEndpoint).Port, "2001:db8:1::c8");
            try
            {
                consumer.Send(PeerEgressSegment.FlagSyn, []);
                var synAck = consumer.WaitFor("the SYN-ACK", () => consumer.Inbound.Find(segment =>
                    segment.Has(PeerEgressSegment.FlagSyn) && segment.Has(PeerEgressSegment.FlagAck)));
                // The path MTU the stack starts from is 1280; an IPv6 header and a TCP header come out of it.
                Assert.Equal(PeerEgressRuntime.DefaultPathMtu - PeerEgressIpv6.HeaderBytes - PeerEgressSegment.TcpMinHeaderBytes,
                    synAck.Mss);
                consumer.Acknowledge(synAck.Seq + 1);
                consumer.Send(PeerEgressSegment.FlagAck, []);
                consumer.Send(PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, "hello"u8.ToArray());

                consumer.WaitFor("the echoed reply", () =>
                    Encoding.ASCII.GetString([.. consumer.Received]) == "echo:hello" ? "done" : null);
                Assert.True(served.Join(TimeSpan.FromSeconds(10)), "the listener never finished");

                var packets = consumer.WaitFor("the returned packets", () => consumer.Packets.ToList());
                Assert.NotEmpty(packets);
                foreach (var packet in packets)
                {
                    PeerEgressRuntimeTests.AssertReturnHeader(packet, consumer.Remote, consumer.Local);
                }
                Assert.Empty(consumer.Problems);
            }
            finally
            {
                consumer.Runtime.Shutdown(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void CarriesUdpEndToEnd()
    {
        Socket listener;
        try
        {
            listener = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            listener.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        }
        catch (SocketException failure) when (NoIpv6Loopback(failure))
        {
            return;
        }
        using (listener)
        {
            var answered = Serve(() =>
            {
                var buffer = new byte[64];
                EndPoint from = new IPEndPoint(IPAddress.IPv6Any, 0);
                var read = listener.ReceiveFrom(buffer, ref from);
                listener.SendTo([.. "answer:"u8.ToArray(), .. buffer[..read]], from);
            });

            var consumer = new Consumer(((IPEndPoint)listener.LocalEndPoint!).Port, "2001:db8:1::35");
            try
            {
                var query = new PeerEgressDatagram.Datagram(0, 0, 51000, 53, "query"u8.ToArray(),
                    Ipv6: true, SourceIp6: consumer.Local, DestinationIp6: consumer.Remote);
                consumer.SendDatagram(query);

                var reply = consumer.WaitFor("the answer", () => consumer.Datagrams.FirstOrDefault());
                Assert.True(answered.Join(TimeSpan.FromSeconds(10)), "the listener never answered");
                Assert.Equal("answer:query", Encoding.ASCII.GetString(reply.Payload));
                Assert.Equal(query.DestinationIp6, reply.SourceIp6);
                Assert.Equal(query.SourceIp6, reply.DestinationIp6);
                Assert.Equal(query.DestinationPort, reply.SourcePort);
                Assert.Equal(query.SourcePort, reply.DestinationPort);
                var packet = consumer.WaitFor("the returned packet", () => consumer.Packets.FirstOrDefault());
                PeerEgressRuntimeTests.AssertReturnHeader(packet, consumer.Remote, consumer.Local);
                Assert.Empty(consumer.Problems);
            }
            finally
            {
                consumer.Runtime.Shutdown(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            }
        }
    }
}
