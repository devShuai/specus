using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// Step four: the consumer's DNS responder, bound to the <c>wire</c> and <c>answers</c> sections of
/// <c>peer-egress-dns-v1.json</c> and to protocol/spec/peer-egress-dns.md section three.
/// </summary>
/// <remarks>
/// The wire cases run twice: against the decision alone, and as UDP packets through the responder
/// that the TUN path hands them to, where an answer has to come back as a packet and a forward has
/// to reach the upstream byte for byte. Forwarding runs against resolvers stood up on local sockets.
/// The TCP endpoint is driven with real segments on a clock the test owns.
/// </remarks>
public class PeerEgressDnsResponderTests
{
    private const long Epoch = 1_800_000_000_000L;
    private const string VirtualIp = "100.96.0.7";
    private const string Listen = "198.18.0.1";
    private const string Pool = "198.18.0.0/15";

    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-dns-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-dns-v1.json");
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), dotted);
        return value;
    }

    private static Ipv4Cidr Cidr(string text)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var value), text);
        return value;
    }

    private static List<PeerEgressRule> VectorRules(JsonDocument vector) =>
        [.. vector.RootElement.GetProperty("rules").EnumerateArray()
            .Select(node => JsonSerializer.Deserialize<PeerEgressRule>(node.GetRawText())!)];

    private static void Until(Func<bool> condition, string what)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(watch.ElapsedMilliseconds < 5000, $"timed out waiting for {what}");
            Thread.Sleep(2);
        }
    }

    /// <summary>A standard query, recursion desired, with an OPT record when asked.</summary>
    private static byte[] Query(ushort id, string name, ushort type, bool edns = false)
    {
        var bytes = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, (byte)(edns ? 1 : 0) };
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.AddRange([0, (byte)(type >> 8), (byte)type, 0, 1]);
        if (edns)
        {
            bytes.AddRange([0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
        }
        return [.. bytes];
    }

    /// <summary>What a stand-in upstream says: the query back with QR and RA set, and whatever else is asked.</summary>
    private static byte[] UpstreamAnswer(byte[] query, int extraFlags = 0, int padding = 0)
    {
        var answer = new byte[query.Length + padding];
        query.CopyTo(answer, 0);
        answer[2] |= 0x80;
        answer[3] |= 0x80;
        var flags = BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(2)) | extraFlags;
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(2), (ushort)flags);
        return answer;
    }

    private static byte[] UdpQuery(string source, ushort port, byte[] payload, string destination = Listen, ushort destinationPort = 53) =>
        PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(Address(source), Address(destination), port, destinationPort, payload));

    /// <summary>A forwarder that answers as the test says and remembers what it was asked.</summary>
    private sealed class ScriptedForwarder : IPeerEgressDnsForwarder
    {
        private readonly List<(byte[] Query, bool Tcp)> _calls = [];

        public Func<byte[], bool, Task<byte[]?>> Answer { get; set; } =
            (query, _) => Task.FromResult<byte[]?>(UpstreamAnswer(query));

        public List<(byte[] Query, bool Tcp)> Calls
        {
            get
            {
                lock (_calls)
                {
                    return [.. _calls];
                }
            }
        }

        public Task<byte[]?> ForwardAsync(byte[] query, bool tcp, IReadOnlyList<PeerEgressDnsUpstream> upstreams)
        {
            lock (_calls)
            {
                _calls.Add(((byte[])query.Clone(), tcp));
            }
            return Answer(query, tcp);
        }
    }

    /// <summary>A responder over a pool, with what it writes to the TUN kept in order.</summary>
    private sealed class Responder
    {
        private readonly List<byte[]> _tun = [];

        public Responder(IReadOnlyList<PeerEgressRule> rules, string pool = Pool, IPeerEgressDnsForwarder? forwarder = null,
            Func<IReadOnlyList<string>>? localAddresses = null, int maxConnections = PeerEgressDnsResponder.MaxConnections,
            IReadOnlyList<PeerEgressDnsUpstream>? upstreams = null)
        {
            Now = Epoch;
            FakeIp = new PeerEgressFakeIpPool(Cidr(pool), () => Now);
            var chosen = forwarder ?? new ScriptedForwarder();
            Forwarder = chosen as ScriptedForwarder;
            Server = new PeerEgressDnsResponder(packet =>
            {
                lock (_tun)
                {
                    _tun.Add(packet);
                }
            }, chosen, () => Now, localAddresses ?? (() => []), maxConnections: maxConnections);
            PeerEgressDnsUpstream.TryParse("127.0.0.1:53", out var placeholder);
            Server.Configure(rules, PeerEgressRules.DefaultMeshCidr, FakeIp, VirtualIp, upstreams ?? [placeholder]);
        }

        public long Now { get; set; }

        public PeerEgressFakeIpPool FakeIp { get; }

        public PeerEgressDnsResponder Server { get; }

        public ScriptedForwarder? Forwarder { get; }

        public List<byte[]> Tun
        {
            get
            {
                lock (_tun)
                {
                    return [.. _tun];
                }
            }
        }

        public void ClearTun()
        {
            lock (_tun)
            {
                _tun.Clear();
            }
        }

        public PeerEgressDnsIntake Handle(byte[] packet) => Server.Handle(packet, Now);
    }

    // ----------------------------------------------------------------------------------------------
    // The wire format
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public void WireMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        Assert.Equal(PeerEgressDnsWire.AnswerTtlSeconds, root.GetProperty("responderAnswerTtlSeconds").GetInt32());
        Assert.Equal(PeerEgressDnsWire.EdnsPayload, root.GetProperty("responderEdnsPayload").GetInt32());
        var rules = VectorRules(vector);
        foreach (var testCase in root.GetProperty("wire").EnumerateArray())
        {
            var pool = new PeerEgressFakeIpPool(Cidr(testCase.GetProperty("cidr").GetString()!), () => Epoch);
            var results = testCase.GetProperty("results").EnumerateArray().ToList();
            var step = 0;
            foreach (var wireEvent in testCase.GetProperty("events").EnumerateArray())
            {
                var expected = results[step++];
                var name = wireEvent.GetProperty("name").GetString();
                var decision = PeerEgressDnsWire.Respond(Convert.FromHexString(wireEvent.GetProperty("query").GetString()!),
                    rules, PeerEgressRules.DefaultMeshCidr, pool, Epoch + wireEvent.GetProperty("at").GetInt64() * 1000);
                Assert.True(expected.GetProperty("result").GetString() == decision.Result.ToString().ToLowerInvariant(),
                    $"{name}: {decision.Result}");
                var response = expected.TryGetProperty("response", out var hex) ? hex.GetString() : null;
                Assert.True(response == (decision.Response is null ? null : Convert.ToHexStringLower(decision.Response)),
                    $"{name}: {(decision.Response is null ? "none" : Convert.ToHexStringLower(decision.Response))}");
                Assert.True(expected.TryGetProperty("exhausted", out _) == decision.Exhausted, $"{name}: exhausted {decision.Exhausted}");
            }
        }
    }

    /// <summary>
    /// The same cases as UDP packets through the responder: an answer comes back as a datagram from
    /// the listen address carrying exactly the vector's bytes, a forward reaches the upstream
    /// untouched and its answer comes back unchanged, and a drop writes nothing.
    /// </summary>
    [Fact]
    public void WireThroughTheResponderMatchesTheSharedVector()
    {
        using var vector = Vector();
        var rules = VectorRules(vector);
        foreach (var testCase in vector.RootElement.GetProperty("wire").EnumerateArray())
        {
            var cidr = testCase.GetProperty("cidr").GetString()!;
            var responder = new Responder(rules, cidr, new ScriptedForwarder());
            var listen = Ipv4Cidr.FormatAddress(responder.FakeIp.Listen);
            var results = testCase.GetProperty("results").EnumerateArray().ToList();
            var answered = 0L;
            var failed = 0L;
            var forwarded = 0L;
            var step = 0;
            foreach (var wireEvent in testCase.GetProperty("events").EnumerateArray())
            {
                var expected = results[step];
                var name = wireEvent.GetProperty("name").GetString();
                var query = Convert.FromHexString(wireEvent.GetProperty("query").GetString()!);
                var port = (ushort)(50000 + step);
                step++;
                responder.Now = Epoch + wireEvent.GetProperty("at").GetInt64() * 1000;
                responder.ClearTun();
                var callsBefore = responder.Forwarder!.Calls.Count;
                Assert.Equal(PeerEgressDnsIntake.Handled, responder.Handle(UdpQuery(VirtualIp, port, query, listen)));
                switch (expected.GetProperty("result").GetString())
                {
                    case "drop":
                        Assert.True(responder.Tun.Count == 0 && responder.Forwarder.Calls.Count == callsBefore, $"{name}: not dropped");
                        break;
                    case "answer":
                    {
                        var written = PeerEgressDatagram.Parse(Assert.Single(responder.Tun));
                        Assert.NotNull(written);
                        Assert.Equal(Address(listen), written.SourceIp);
                        Assert.Equal(Address(VirtualIp), written.DestinationIp);
                        Assert.Equal((ushort)53, written.SourcePort);
                        Assert.Equal(port, written.DestinationPort);
                        Assert.True(expected.GetProperty("response").GetString() == Convert.ToHexStringLower(written.Payload), name);
                        if (expected.TryGetProperty("exhausted", out _))
                        {
                            failed++;
                        }
                        else
                        {
                            answered++;
                        }
                        break;
                    }
                    default:
                    {
                        Until(() => responder.Tun.Count == 1, $"{name}: the forwarded answer");
                        var call = responder.Forwarder.Calls[callsBefore];
                        Assert.Equal(query, call.Query);
                        Assert.False(call.Tcp);
                        var written = PeerEgressDatagram.Parse(responder.Tun[0]);
                        Assert.NotNull(written);
                        Assert.Equal(UpstreamAnswer(query), written.Payload);
                        Assert.Equal(port, written.DestinationPort);
                        forwarded++;
                        break;
                    }
                }
            }
            Assert.Equal(new PeerEgressDnsCounters(answered, forwarded, failed), responder.Server.Counters);
        }
    }

    [Fact]
    public void AnswersMatchTheSharedVector()
    {
        using var vector = Vector();
        var rules = VectorRules(vector);
        var types = new Dictionary<string, ushort>
        {
            ["A"] = 1, ["AAAA"] = 28, ["HTTPS"] = 65, ["SVCB"] = 64, ["ANY"] = 255, ["MX"] = 15,
        };
        var pool = new PeerEgressFakeIpPool(Cidr(Pool), () => Epoch);
        ushort id = 0x4000;
        foreach (var testCase in vector.RootElement.GetProperty("answers").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var decision = PeerEgressDnsWire.Respond(
                Query(id++, testCase.GetProperty("query").GetString()!, types[testCase.GetProperty("type").GetString()!]),
                rules, PeerEgressRules.DefaultMeshCidr, pool, Epoch);
            switch (testCase.GetProperty("answer").GetString())
            {
                case "forward":
                    Assert.True(decision.Result == PeerEgressDnsResult.Forward, $"{name}: {decision.Result}");
                    break;
                case "nodata":
                    Assert.True(decision.Result == PeerEgressDnsResult.Answer, $"{name}: {decision.Result}");
                    Assert.Equal(0x8180, BinaryPrimitives.ReadUInt16BigEndian(decision.Response.AsSpan(2)));
                    Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(decision.Response.AsSpan(6)));
                    break;
                default:
                    Assert.True(decision.Result == PeerEgressDnsResult.Answer, $"{name}: {decision.Result}");
                    Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(decision.Response.AsSpan(6)));
                    Assert.True(pool.Contains(BinaryPrimitives.ReadUInt32BigEndian(decision.Response.AsSpan(decision.Response!.Length - 4))),
                        $"{name}: the answer is not a pool address");
                    break;
            }
        }
    }

    // ----------------------------------------------------------------------------------------------
    // The TUN path
    // ----------------------------------------------------------------------------------------------

    private sealed class ConsumerPath
    {
        public ConsumerPath(Func<IReadOnlyList<string>>? localAddresses = null)
        {
            using var vector = Vector();
            Rules = VectorRules(vector);
            FakeIp = new PeerEgressFakeIpPool(Cidr(Pool), () => Now);
            Server = new PeerEgressDnsResponder(Tun.Add, new ScriptedForwarder(), () => Now, localAddresses ?? (() => []));
            PeerEgressDnsUpstream.TryParse("127.0.0.1", out var upstream);
            Server.Configure(Rules, PeerEgressRules.DefaultMeshCidr, FakeIp, VirtualIp, [upstream]);
            Consumer = new PeerEgressConsumer((_, _) => true, Tun.Add);
            Consumer.Configure(Rules, PeerEgressRules.DefaultMeshCidr, VirtualIp, Now, FakeIp);
            Consumer.DnsResponder = Server;
        }

        public long Now { get; set; } = Epoch;

        public List<PeerEgressRule> Rules { get; }

        public PeerEgressFakeIpPool FakeIp { get; }

        public PeerEgressDnsResponder Server { get; }

        public PeerEgressConsumer Consumer { get; }

        public List<byte[]> Tun { get; } = [];

        public PeerEgressConsumerOutcome Send(byte[] packet) => Consumer.HandleOutbound(packet, Now);
    }

    /// <summary>
    /// A query read from the TUN is answered with a packet the application's stack accepts: IPv4 and
    /// UDP headers right, both checksums right, from the listen address to the query's source.
    /// </summary>
    [Fact]
    public void AUdpQueryReadFromTheTunIsAnsweredWithAWellFormedPacket()
    {
        var path = new ConsumerPath();
        var query = Query(0x5151, "www.example.com", 1);
        Assert.Equal(PeerEgressConsumerOutcome.DnsQuery, path.Send(UdpQuery(VirtualIp, 53001, query)));

        var reply = Assert.Single(path.Tun);
        Assert.Equal(0x45, reply[0]);
        Assert.Equal(reply.Length, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(2)));
        Assert.True(reply[8] > 0, "TTL zero");
        Assert.Equal(17, reply[9]);
        Assert.Equal(Address(Listen), BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(12)));
        Assert.Equal(Address(VirtualIp), BinaryPrimitives.ReadUInt32BigEndian(reply.AsSpan(16)));
        Assert.Equal(0, PeerIpPacket.Checksum(reply.AsSpan(0, 20)));
        Assert.Equal(53, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(20)));
        Assert.Equal(53001, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(22)));
        Assert.Equal(reply.Length - 20, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(24)));
        Assert.NotEqual(0, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(26)));
        Assert.Equal(0, UdpChecksum(reply));
        var answer = reply[28..];
        Assert.Equal(0x5151, BinaryPrimitives.ReadUInt16BigEndian(answer));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(6)));
        Assert.Equal(path.FakeIp.Query("www.example.com", path.Now).Address,
            BinaryPrimitives.ReadUInt32BigEndian(answer.AsSpan(answer.Length - 4)));
        Assert.Equal(new PeerEgressDnsCounters(1, 0, 0), path.Server.Counters);
    }

    /// <summary>The UDP checksum over the pseudo-header, summing to zero when it is right.</summary>
    private static int UdpChecksum(byte[] packet)
    {
        ulong sum = 0;
        for (var index = 12; index < 20; index += 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(index));
        }
        sum += 17;
        sum += (ulong)(packet.Length - 20);
        for (var index = 20; index < packet.Length; index += 2)
        {
            sum += index + 1 < packet.Length
                ? BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(index))
                : (ulong)packet[index] << 8;
        }
        while (sum >> 16 != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int)(~sum & 0xFFFF);
    }

    /// <summary>
    /// Only this machine is answered: the mesh address and its own interface addresses. Anything else
    /// is dropped unanswered and counted, and an address that appears later is found once the list
    /// is read again. The listen address's other ports stay unmapped, as in step three.
    /// </summary>
    [Fact]
    public void OnlyThisMachineIsAnswered()
    {
        var local = new List<string> { "192.168.1.20" };
        var path = new ConsumerPath(() => [.. local]);
        var query = Query(0x6161, "www.example.com", 1);

        Assert.Equal(PeerEgressConsumerOutcome.BlockedDnsNotLocal, path.Send(UdpQuery("10.9.9.9", 53002, query)));
        Assert.Empty(path.Tun);
        Assert.Equal(1, path.Consumer.BlockedCounts()["dns-not-local"]);

        Assert.Equal(PeerEgressConsumerOutcome.DnsQuery, path.Send(UdpQuery("192.168.1.20", 53003, query)));
        Assert.Single(path.Tun);

        // Read again at most once a second: the new address is refused until then, then answered.
        local.Add("10.9.9.9");
        path.Now += 500;
        Assert.Equal(PeerEgressConsumerOutcome.BlockedDnsNotLocal, path.Send(UdpQuery("10.9.9.9", 53004, query)));
        path.Now += 1000;
        Assert.Equal(PeerEgressConsumerOutcome.DnsQuery, path.Send(UdpQuery("10.9.9.9", 53005, query)));
        Assert.Equal(2, path.Tun.Count);
        Assert.Equal(2, path.Consumer.BlockedCounts()["dns-not-local"]);

        // TCP to port 53 is the responder's too; another port of the listen address is not.
        var syn = PeerEgressSegment.Build(new Segment(Address(VirtualIp), Address(Listen), 40000, 53, 7, 0,
            PeerEgressSegment.FlagSyn, 65535, 1460, []));
        Assert.Equal(PeerEgressConsumerOutcome.DnsQuery, path.Send(syn));
        var other = PeerEgressSegment.Build(new Segment(Address(VirtualIp), Address(Listen), 40001, 80, 7, 0,
            PeerEgressSegment.FlagSyn, 65535, 1460, []));
        Assert.Equal(PeerEgressConsumerOutcome.BlockedFakeIp, path.Send(other));
        Assert.Equal(1, path.Consumer.BlockedCounts()["fake-ip-unmapped"]);
    }

    // ----------------------------------------------------------------------------------------------
    // Forwarding over real sockets
    // ----------------------------------------------------------------------------------------------

    private static PeerEgressDnsUpstream Upstream(IPEndPoint endpoint)
    {
        Assert.True(PeerEgressDnsUpstream.TryParse(endpoint.ToString(), out var upstream));
        return upstream;
    }

    /// <summary>A UDP resolver on a local port: silent, or answering each query the way it is told.</summary>
    private sealed class UdpUpstream : IDisposable
    {
        private readonly UdpClient _socket = new(new IPEndPoint(IPAddress.Loopback, 0));
        private readonly List<byte[]> _received = [];

        public UdpUpstream(Func<byte[], IEnumerable<byte[]>>? answer = null)
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    UdpReceiveResult datagram;
                    try
                    {
                        datagram = await _socket.ReceiveAsync();
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    lock (_received)
                    {
                        _received.Add(datagram.Buffer);
                    }
                    foreach (var reply in answer?.Invoke(datagram.Buffer) ?? [])
                    {
                        await _socket.SendAsync(reply, reply.Length, datagram.RemoteEndPoint);
                    }
                }
            });
        }

        public IPEndPoint EndPoint => (IPEndPoint)_socket.Client.LocalEndPoint!;

        public List<byte[]> Received
        {
            get
            {
                lock (_received)
                {
                    return [.. _received];
                }
            }
        }

        public void Dispose() => _socket.Dispose();
    }

    /// <summary>A TCP resolver on a local port: silent, or answering each framed query as told.</summary>
    private sealed class TcpUpstream : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly List<byte[]> _received = [];

        public TcpUpstream(Func<byte[], byte[]?> answer)
        {
            _listener.Start();
            Task.Run(async () =>
            {
                while (true)
                {
                    TcpClient client;
                    try
                    {
                        client = await _listener.AcceptTcpClientAsync();
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            var stream = client.GetStream();
                            var prefix = new byte[2];
                            await stream.ReadExactlyAsync(prefix);
                            var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
                            await stream.ReadExactlyAsync(query);
                            lock (_received)
                            {
                                _received.Add(query);
                            }
                            if (answer(query) is not { } reply)
                            {
                                // Silent: holds the connection open well past any forwarding deadline.
                                await Task.Delay(10_000);
                                return;
                            }
                            var framed = new byte[2 + reply.Length];
                            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)reply.Length);
                            reply.CopyTo(framed, 2);
                            await stream.WriteAsync(framed);
                        }
                    });
                }
            });
        }

        public IPEndPoint EndPoint => (IPEndPoint)_listener.LocalEndpoint;

        public List<byte[]> Received
        {
            get
            {
                lock (_received)
                {
                    return [.. _received];
                }
            }
        }

        public void Dispose() => _listener.Stop();
    }

    /// <summary>A local port nothing listens on, for an upstream that refuses.</summary>
    private static IPEndPoint ClosedPort(ProtocolType protocol)
    {
        using var socket = new Socket(AddressFamily.InterNetwork,
            protocol == ProtocolType.Udp ? SocketType.Dgram : SocketType.Stream, protocol);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (IPEndPoint)socket.LocalEndPoint!;
    }

    [Fact]
    public void UpstreamsAreAnAddressWithAnOptionalPort()
    {
        Assert.Equal(2000, PeerEgressDnsForwarder.UpstreamTimeoutMs);
        Assert.True(PeerEgressDnsUpstream.TryParse(" 192.0.2.53 ", out var plain));
        Assert.Equal(53, plain.Port);
        Assert.Equal("192.0.2.53", plain.ToString());
        Assert.True(PeerEgressDnsUpstream.TryParse("127.0.0.1:5353", out var ported));
        Assert.Equal(5353, ported.Port);
        Assert.Equal("127.0.0.1:5353", ported.ToString());
        Assert.True(PeerEgressDnsUpstream.TryParse("2001:db8::53", out var six));
        Assert.Equal(53, six.Port);
        Assert.True(PeerEgressDnsUpstream.TryParse("[2001:db8::53]:5353", out var sixPorted));
        Assert.Equal("[2001:db8::53]:5353", sixPorted.ToString());
        Assert.False(PeerEgressDnsUpstream.TryParse("resolver.example", out _));
        Assert.False(PeerEgressDnsUpstream.TryParse("", out _));
    }

    /// <summary>
    /// Over UDP the upstreams are asked in order, each for its own time: a silent one is waited out,
    /// a refusing one passed over, and an answer with another ID is not taken for the one asked.
    /// The query arrives and the answer returns byte for byte.
    /// </summary>
    [Fact]
    public async Task UdpForwardingFallsBackInOrder()
    {
        var query = Query(0x7171, "example.org", 1);
        var answer = UpstreamAnswer(query, extraFlags: 0x0200, padding: 5);
        using var silent = new UdpUpstream();
        using var answering = new UdpUpstream(received =>
        {
            var stranger = (byte[])answer.Clone();
            stranger[0] ^= 0xFF;
            return [stranger, answer];
        });
        var forwarder = new PeerEgressDnsForwarder(perUpstreamMs: 300);

        var watch = Stopwatch.StartNew();
        var relayed = await forwarder.ForwardAsync(query,
            tcp: false, [Upstream(ClosedPort(ProtocolType.Udp)), Upstream(silent.EndPoint), Upstream(answering.EndPoint)]);
        Assert.Equal(answer, relayed);
        Assert.True(watch.ElapsedMilliseconds >= 250, $"the silent upstream was not waited for: {watch.ElapsedMilliseconds} ms");
        Assert.Equal(query, Assert.Single(silent.Received));
        Assert.Equal(query, Assert.Single(answering.Received));

        Assert.Null(await forwarder.ForwardAsync(query, tcp: false, [Upstream(silent.EndPoint)]));
        Assert.Null(await forwarder.ForwardAsync(query, tcp: false, []));
    }

    /// <summary>Over TCP likewise, with the two-byte framing both ways and the time covering the connect.</summary>
    [Fact]
    public async Task TcpForwardingFallsBackInOrder()
    {
        var query = Query(0x7272, "example.org", 1);
        var answer = UpstreamAnswer(query, padding: 3000);
        using var silent = new TcpUpstream(_ => null);
        using var answering = new TcpUpstream(_ => answer);
        var forwarder = new PeerEgressDnsForwarder(perUpstreamMs: 300);

        var relayed = await forwarder.ForwardAsync(query,
            tcp: true, [Upstream(ClosedPort(ProtocolType.Tcp)), Upstream(silent.EndPoint), Upstream(answering.EndPoint)]);
        Assert.Equal(answer, relayed);
        Until(() => silent.Received.Count == 1, "the silent upstream's query");
        Assert.Equal(query, silent.Received[0]);
        Assert.Equal(query, Assert.Single(answering.Received));

        Assert.Null(await forwarder.ForwardAsync(query, tcp: true, [Upstream(silent.EndPoint)]));
    }

    /// <summary>
    /// Through the responder with real sockets: an upstream's answer, truncation bit and all, goes
    /// back unchanged; when every upstream fails the responder builds the SERVFAIL itself, and with no
    /// upstreams at all it does so at once.
    /// </summary>
    [Fact]
    public void TheResponderRelaysOrFailsForwardedQueries()
    {
        using var vector = Vector();
        var rules = VectorRules(vector);
        var query = Query(0x7373, "example.org", 1, edns: true);
        var truncated = UpstreamAnswer(query, extraFlags: 0x0200);
        using var answering = new UdpUpstream(_ => [truncated]);
        using var silent = new UdpUpstream();

        var relaying = new Responder(rules, forwarder: new PeerEgressDnsForwarder(perUpstreamMs: 300),
            upstreams: [Upstream(answering.EndPoint)]);
        relaying.Handle(UdpQuery(VirtualIp, 53010, query));
        Until(() => relaying.Tun.Count == 1, "the relayed answer");
        Assert.Equal(truncated, PeerEgressDatagram.Parse(relaying.Tun[0])!.Payload);
        Assert.Equal(new PeerEgressDnsCounters(0, 1, 0), relaying.Server.Counters);

        var failing = new Responder(rules, forwarder: new PeerEgressDnsForwarder(perUpstreamMs: 200),
            upstreams: [Upstream(silent.EndPoint), Upstream(ClosedPort(ProtocolType.Udp))]);
        failing.Handle(UdpQuery(VirtualIp, 53011, query));
        Until(() => failing.Tun.Count == 1, "the SERVFAIL");
        var servfail = PeerEgressDatagram.Parse(failing.Tun[0])!.Payload;
        Assert.Equal(PeerEgressDnsWire.ServFail(query), servfail);
        // ID kept, QR RD RA set, SERVFAIL; the question copied and EDNS echoed.
        Assert.Equal("737381820001000000000001", Convert.ToHexStringLower(servfail[..12]));
        Assert.Equal(query[12..^11], servfail[12..^11]);
        Assert.Equal("0000290" + "4d0000000000000", Convert.ToHexStringLower(servfail[^11..]));
        Assert.Equal(new PeerEgressDnsCounters(0, 0, 1), failing.Server.Counters);

        var none = new Responder(rules, upstreams: []);
        none.Handle(UdpQuery(VirtualIp, 53012, query));
        Assert.Equal(PeerEgressDnsWire.ServFail(query), PeerEgressDatagram.Parse(Assert.Single(none.Tun))!.Payload);
        Assert.Empty(none.Forwarder!.Calls);
    }

    /// <summary>
    /// A forwarded query whose question cannot be read fails with the header alone; one with a
    /// single readable question gets it back, with OPT when it carried one.
    /// </summary>
    [Fact]
    public void ASoleUnreadableQuestionFailsWithTheHeaderAlone()
    {
        var single = Query(0x7474, "example.org", 1);
        var twoQuestions = single.ToArray();
        twoQuestions[5] = 2;
        var pointer = Convert.FromHexString("747501000001000000000000c00c00010001");
        var opcode = single.ToArray();
        opcode[2] = 0x11;

        Assert.Equal("747481820000000000000000", Convert.ToHexStringLower(PeerEgressDnsWire.ServFail(twoQuestions)));
        Assert.Equal("747581820000000000000000", Convert.ToHexStringLower(PeerEgressDnsWire.ServFail(pointer)));
        // The opcode is copied, as in every answer built here; its one readable question with it.
        var notQuery = PeerEgressDnsWire.ServFail(opcode);
        Assert.Equal("7474918200010000", Convert.ToHexStringLower(notQuery[..8]));
        Assert.Equal(single[12..], notQuery[12..]);
        Assert.Equal("7474818200010000", Convert.ToHexStringLower(PeerEgressDnsWire.ServFail(single)[..8]));
    }

    /// <summary>
    /// At most 256 forwards wait on upstreams at once; the next query is not forwarded but answered
    /// SERVFAIL at once and counted as failed.
    /// </summary>
    [Fact]
    public void ForwardsInFlightAreCapped()
    {
        var never = new TaskCompletionSource<byte[]?>();
        var responder = new Responder(Rules(), forwarder: new ScriptedForwarder { Answer = (_, _) => never.Task });
        for (var index = 0; index < PeerEgressDnsResponder.MaxForwarding; index++)
        {
            responder.Handle(UdpQuery(VirtualIp, (ushort)(20000 + index), Query((ushort)index, "example.org", 1)));
        }
        Until(() => responder.Forwarder!.Calls.Count == 256, "the forwards");
        Assert.Empty(responder.Tun);

        var over = Query(0x7575, "example.org", 1);
        responder.Handle(UdpQuery(VirtualIp, 30000, over));
        Assert.Equal(PeerEgressDnsWire.ServFail(over), PeerEgressDatagram.Parse(Assert.Single(responder.Tun))!.Payload);
        Assert.Equal(256, responder.Forwarder!.Calls.Count);
        Assert.Equal(new PeerEgressDnsCounters(0, 0, 1), responder.Server.Counters);
    }

    // ----------------------------------------------------------------------------------------------
    // TCP in the TUN
    // ----------------------------------------------------------------------------------------------

    /// <summary>One TCP client of the responder, sending real segments and reading what comes back.</summary>
    private sealed class TcpClientSide(Responder responder, ushort port = 40000, int mss = 1460)
    {
        private const uint Isn = 1000;

        public uint Next { get; private set; } = Isn + 1;

        /// <summary>The responder's next sequence number, as last acknowledged by us.</summary>
        public uint ServerNext { get; private set; }

        public Segment Connect()
        {
            responder.ClearTun();
            Send(PeerEgressSegment.FlagSyn, Isn, 0, [], mss);
            var synAck = Assert.Single(Segments());
            Assert.Equal(PeerEgressSegment.FlagSyn | PeerEgressSegment.FlagAck, synAck.Flags);
            Assert.Equal(Isn + 1, synAck.Ack);
            ServerNext = synAck.Seq + 1;
            responder.ClearTun();
            Send(PeerEgressSegment.FlagAck, Next, ServerNext, []);
            Assert.Empty(responder.Tun);
            return synAck;
        }

        public void Send(int flags, uint seq, uint ack, byte[] payload, int segmentMss = 0) =>
            Assert.Equal(PeerEgressDnsIntake.Handled, responder.Handle(PeerEgressSegment.Build(new Segment(
                Address(VirtualIp), Address(Listen), port, 53, seq, ack, flags, 65535, segmentMss, payload))));

        /// <summary>Queries, framed, in one segment.</summary>
        public void Ask(params byte[][] queries)
        {
            var stream = new List<byte>();
            foreach (var query in queries)
            {
                stream.Add((byte)(query.Length >> 8));
                stream.Add((byte)query.Length);
                stream.AddRange(query);
            }
            Send(PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, Next, ServerNext, [.. stream]);
            Next += (uint)stream.Count;
        }

        public void AckAll(uint through)
        {
            ServerNext = through;
            Send(PeerEgressSegment.FlagAck, Next, ServerNext, []);
        }

        public List<Segment> Segments() =>
            [.. responder.Tun.Select(packet => PeerEgressSegment.Parse(packet)!).Where(segment => segment.DestinationPort == port)];

        /// <summary>The answers in the data segments sent, reassembled and unframed.</summary>
        public static List<byte[]> Answers(IEnumerable<Segment> segments)
        {
            var stream = segments.Where(segment => segment.Payload.Length > 0).OrderBy(segment => segment.Seq)
                .SelectMany(segment => segment.Payload).ToList();
            var answers = new List<byte[]>();
            while (stream.Count >= 2)
            {
                var length = (stream[0] << 8) | stream[1];
                answers.Add([.. stream.GetRange(2, length)]);
                stream.RemoveRange(0, 2 + length);
            }
            return answers;
        }
    }

    private static List<PeerEgressRule> Rules()
    {
        using var vector = Vector();
        return VectorRules(vector);
    }

    [Fact]
    public void TheHandshakeOffersAnMssNoLargerThan1360()
    {
        var responder = new Responder(Rules());
        Assert.Equal(1360, new TcpClientSide(responder, 40000, 1460).Connect().Mss);
        Assert.Equal(536, new TcpClientSide(responder, 40001, 536).Connect().Mss);
        // No option: the IPv4 default.
        Assert.Equal(536, new TcpClientSide(responder, 40002, 0).Connect().Mss);
        Assert.Equal(3, responder.Server.Connections);
    }

    /// <summary>One query, then two in one segment: answered in the order asked, each framed.</summary>
    [Fact]
    public void QueriesAreAnsweredInTheOrderTheyArrived()
    {
        var responder = new Responder(Rules());
        var client = new TcpClientSide(responder);
        client.Connect();

        client.Ask(Query(0x0101, "www.example.com", 1));
        var first = client.Segments();
        var data = Assert.Single(first);
        Assert.Equal(PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, data.Flags);
        Assert.Equal(client.Next, data.Ack);
        var answer = Assert.Single(TcpClientSide.Answers(first));
        Assert.Equal(0x0101, PeerEgressDnsWire.Id(answer));
        client.AckAll(data.Seq + (uint)data.Payload.Length);

        responder.ClearTun();
        client.Ask(Query(0x0202, "api.example.com", 1), Query(0x0303, "www.example.com", 28));
        var answers = TcpClientSide.Answers(client.Segments());
        Assert.Equal([0x0202, 0x0303], answers.Select(item => (int)PeerEgressDnsWire.Id(item)));
        Assert.Equal(new PeerEgressDnsCounters(3, 0, 0), responder.Server.Counters);
    }

    /// <summary>
    /// A forwarded query holds back every answer behind it until its own arrives, and a large one is
    /// sent in segments of the MSS.
    /// </summary>
    [Fact]
    public void AForwardedAnswerKeepsItsPlaceAndIsSplitByTheMss()
    {
        var upstream = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var forwarder = new ScriptedForwarder { Answer = (_, _) => upstream.Task };
        var responder = new Responder(Rules(), forwarder: forwarder);
        var client = new TcpClientSide(responder);
        client.Connect();

        var forwardedQuery = Query(0x0A0A, "example.org", 1);
        client.Ask(forwardedQuery, Query(0x0B0B, "www.example.com", 1));
        var acked = Assert.Single(client.Segments());
        Assert.Empty(acked.Payload);
        Assert.Equal(client.Next, acked.Ack);
        // The forward starts on a task of its own.
        Until(() => forwarder.Calls.Count == 1, "the forward");
        Assert.Equal(forwardedQuery, Assert.Single(forwarder.Calls).Query);
        Assert.True(forwarder.Calls[0].Tcp);

        responder.ClearTun();
        var large = UpstreamAnswer(forwardedQuery, padding: 3000);
        upstream.SetResult(large);
        Until(() => client.Segments().Count == 3, "the answers");
        var segments = client.Segments();
        var answers = TcpClientSide.Answers(segments);
        Assert.Equal(large, answers[0]);
        Assert.Equal(0x0B0B, PeerEgressDnsWire.Id(answers[1]));
        // Both answers, framed, in segments of the MSS the handshake settled on.
        var stream = answers.Sum(item => 2 + item.Length);
        Assert.Equal([1360, 1360, stream - 2720], segments.Select(segment => segment.Payload.Length));
        Assert.Equal(new PeerEgressDnsCounters(1, 1, 0), responder.Server.Counters);
    }

    /// <summary>
    /// A segment starting past the next expected byte is dropped and the expected byte acknowledged
    /// again; nothing in it is answered.
    /// </summary>
    [Fact]
    public void AnOutOfOrderSegmentIsDroppedWithADuplicateAck()
    {
        var responder = new Responder(Rules());
        var client = new TcpClientSide(responder);
        client.Connect();
        var query = Query(0x0C0C, "www.example.com", 1);
        var framed = new byte[2 + query.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
        query.CopyTo(framed, 2);
        client.Send(PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, client.Next + 10, client.ServerNext, framed);
        var ack = Assert.Single(client.Segments());
        Assert.Empty(ack.Payload);
        Assert.Equal(client.Next, ack.Ack);
        Assert.Equal(new PeerEgressDnsCounters(0, 0, 0), responder.Server.Counters);
    }

    /// <summary>
    /// An unacknowledged answer goes again each second, three times; still unacknowledged, the
    /// connection ends with a reset.
    /// </summary>
    [Fact]
    public void AnUnacknowledgedAnswerIsRetransmittedThreeTimesThenReset()
    {
        var responder = new Responder(Rules());
        var client = new TcpClientSide(responder);
        client.Connect();
        client.Ask(Query(0x0D0D, "www.example.com", 1));
        var original = Assert.Single(client.Segments());
        var start = responder.Now;
        for (var round = 1; round <= 3; round++)
        {
            responder.ClearTun();
            responder.Server.OnTick(start + round * 1000 - 1);
            Assert.Empty(responder.Tun);
            responder.Server.OnTick(start + round * 1000);
            var again = Assert.Single(client.Segments());
            Assert.Equal(original.Seq, again.Seq);
            Assert.Equal(original.Payload, again.Payload);
        }
        responder.ClearTun();
        responder.Server.OnTick(start + 4000);
        var reset = Assert.Single(client.Segments());
        Assert.True(reset.Has(PeerEgressSegment.FlagRst));
        Assert.Equal(0, responder.Server.Connections);
    }

    /// <summary>
    /// The peer's FIN is answered with ours only after the answers it is still owed, and the
    /// connection is gone once our FIN is acknowledged.
    /// </summary>
    [Fact]
    public void APeerFinIsAnsweredAfterWhatIsOwed()
    {
        var upstream = new TaskCompletionSource<byte[]?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var responder = new Responder(Rules(), forwarder: new ScriptedForwarder { Answer = (_, _) => upstream.Task });
        var client = new TcpClientSide(responder);
        client.Connect();
        var query = Query(0x0E0E, "example.org", 1);
        client.Ask(query);
        responder.ClearTun();
        client.Send(PeerEgressSegment.FlagAck | PeerEgressSegment.FlagFin, client.Next, client.ServerNext, []);
        var ack = Assert.Single(client.Segments());
        Assert.False(ack.Has(PeerEgressSegment.FlagFin), "FIN before the owed answer");
        Assert.Equal(client.Next + 1, ack.Ack);

        responder.ClearTun();
        upstream.SetResult(UpstreamAnswer(query));
        Until(() => client.Segments().Any(segment => segment.Has(PeerEgressSegment.FlagFin)), "our FIN");
        var segments = client.Segments();
        Assert.Equal(UpstreamAnswer(query), Assert.Single(TcpClientSide.Answers(segments)));
        var fin = segments.Last();
        Assert.True(fin.Has(PeerEgressSegment.FlagFin));
        Assert.Equal(1, responder.Server.Connections);
        client.Send(PeerEgressSegment.FlagAck, client.Next + 1, fin.Seq + 1, []);
        Assert.Equal(0, responder.Server.Connections);
    }

    /// <summary>Ten seconds with nothing asked and nothing owed, and the responder closes with a FIN.</summary>
    [Fact]
    public void AnIdleConnectionIsClosed()
    {
        var responder = new Responder(Rules());
        var client = new TcpClientSide(responder);
        client.Connect();
        responder.Now += 2000;
        client.Ask(Query(0x0F0F, "www.example.com", 1));
        var data = Assert.Single(client.Segments());
        client.AckAll(data.Seq + (uint)data.Payload.Length);
        responder.ClearTun();

        responder.Server.OnTick(responder.Now + PeerEgressDnsResponder.IdleMs - 1);
        Assert.Empty(responder.Tun);
        responder.Server.OnTick(responder.Now + PeerEgressDnsResponder.IdleMs);
        var fin = Assert.Single(client.Segments());
        Assert.True(fin.Has(PeerEgressSegment.FlagFin));

        // The peer acknowledges and closes its side; nothing is left.
        client.Send(PeerEgressSegment.FlagAck | PeerEgressSegment.FlagFin, client.Next, fin.Seq + 1, []);
        Assert.Equal(0, responder.Server.Connections);
    }

    /// <summary>
    /// At most 64 connections, the next SYN reset; a segment for no connection reset; a reset for a
    /// connection ends it, and a reset for none is not answered.
    /// </summary>
    [Fact]
    public void ConnectionsAreCappedAndStrangersReset()
    {
        var responder = new Responder(Rules());
        for (ushort port = 1; port <= PeerEgressDnsResponder.MaxConnections; port++)
        {
            new TcpClientSide(responder, port).Connect();
        }
        Assert.Equal(64, responder.Server.Connections);
        responder.ClearTun();
        var extra = new TcpClientSide(responder, 30000);
        extra.Send(PeerEgressSegment.FlagSyn, 5000, 0, [], 1460);
        var refused = Assert.Single(extra.Segments());
        Assert.True(refused.Has(PeerEgressSegment.FlagRst));
        Assert.Equal(5001u, refused.Ack);
        Assert.Equal(64, responder.Server.Connections);

        responder.ClearTun();
        var stranger = new TcpClientSide(responder, 30001);
        stranger.Send(PeerEgressSegment.FlagAck, 9000, 4242, []);
        var reset = Assert.Single(stranger.Segments());
        Assert.True(reset.Has(PeerEgressSegment.FlagRst));
        Assert.Equal(4242u, reset.Seq);

        responder.ClearTun();
        stranger.Send(PeerEgressSegment.FlagRst, 9000, 0, []);
        Assert.Empty(responder.Tun);

        var first = new TcpClientSide(responder, 1);
        first.Send(PeerEgressSegment.FlagRst, 1001, 0, []);
        Assert.Equal(63, responder.Server.Connections);
    }

    // ----------------------------------------------------------------------------------------------
    // The mesh
    // ----------------------------------------------------------------------------------------------

    private sealed class Host(string directory) : IPeerEgressMeshHost
    {
        public List<byte[]> Device { get; } = [];

        public IReadOnlyList<PeerEgressRule> ConsumerRules { get; set; } = [];

        public bool DnsTakeover => true;

        public IReadOnlyList<string> DnsUpstreams => ["127.0.0.1:5353", "resolver.example"];

        public IReadOnlyList<string> LocalInterfaceNetworks() => [];

        public IReadOnlyList<string> LocalInterfaceAddresses() => [];

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task WriteToDeviceAsync(byte[] packet)
        {
            lock (Device)
            {
                Device.Add(packet);
            }
            return Task.CompletedTask;
        }

        public string TunName => "specus0";

        public string MeshCidr => PeerEgressRules.DefaultMeshCidr;

        public string VirtualIp => PeerEgressDnsResponderTests.VirtualIp;

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => [];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");
    }

    private sealed class AcceptingCommander : IPeerEgressRouteCommander
    {
        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) => PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
        }

        public void Remove(PeerEgressRoute route)
        {
        }
    }

    /// <summary>
    /// With phase two running, a query read from the TUN reaches the responder through the mesh, the
    /// answer goes out on the device queue, a foreign query is counted, and the status says where the
    /// responder listens, where it forwards and what it has done.
    /// </summary>
    [Fact]
    public void TheMeshAnswersAndReportsTheResponder()
    {
        var directory = Path.Combine(Path.GetTempPath(), "specus-egress-dns-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var host = new Host(directory) { ConsumerRules = Rules() };
        using (var mesh = new PeerEgressMesh(host, commander: new AcceptingCommander(), dnsForwarder: new ScriptedForwarder()))
        {
            mesh.ReconcileRoutes();
            Assert.NotNull(mesh.DnsResponder);
            Assert.True(mesh.HandleOutbound(UdpQuery(VirtualIp, 53100, Query(0x1111, "www.example.com", 1))));
            Until(() =>
            {
                lock (host.Device)
                {
                    return host.Device.Count == 1;
                }
            }, "the answer on the device");
            Assert.True(mesh.HandleOutbound(UdpQuery("10.0.0.9", 53101, Query(0x1112, "www.example.com", 1))));

            var consumer = JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer");
            var dns = consumer.GetProperty("dns");
            Assert.Equal(["takeover", "listen", "pool", "mappings", "quarantined", "upstreams", "queries"],
                dns.EnumerateObject().Select(field => field.Name));
            Assert.Equal(Listen, dns.GetProperty("listen").GetString());
            Assert.Equal(["127.0.0.1:5353"], dns.GetProperty("upstreams").EnumerateArray().Select(item => item.GetString()));
            Assert.Equal(1, dns.GetProperty("mappings").GetInt32());
            var queries = dns.GetProperty("queries");
            Assert.Equal(1, queries.GetProperty("answered").GetInt64());
            Assert.Equal(0, queries.GetProperty("forwarded").GetInt64());
            Assert.Equal(0, queries.GetProperty("failed").GetInt64());
            Assert.Equal(1, consumer.GetProperty("blocked").GetProperty("dns-not-local").GetInt64());
        }
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }
}
