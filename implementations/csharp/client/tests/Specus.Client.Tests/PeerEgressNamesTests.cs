using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Phase two on the egress side, bound to <c>peer-egress-dns-v1.json</c>: the name-bind a consumer
/// sends, the address an egress picks for a name, and the flows a name-bind closes.
/// </summary>
public class PeerEgressNamesTests
{
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
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    /// <summary>name-bind is encoded byte for byte as the other runtimes encode it, with the name normalised.</summary>
    [Fact]
    public void NameBindMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("nameBind").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var body = PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.NameBind(
                testCase.GetProperty("address").GetString()!, testCase.GetProperty("domain").GetString()!));
            Assert.True(testCase.GetProperty("json").GetString() == Encoding.UTF8.GetString(body), name);
            var frame = PeerEgressFrame.Parse(PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body));
            Assert.True(frame.Accepted, $"{name}: the encoded binding does not validate: {frame.Code}");
        }
    }

    /// <summary>
    /// The egress dials the first resolved address the policy allows. This build resolves IPv4 only
    /// and does not announce IPv6 targets, so a case that expects an AAAA address is one it answers as
    /// unresolved; every other case must match the vector exactly.
    /// </summary>
    [Fact]
    public void AddressChoiceMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("egressChoice").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var a = testCase.GetProperty("a").EnumerateArray().Select(item => Address(item.GetString()!)).ToList();
            var aaaa = testCase.GetProperty("aaaa").GetArrayLength();
            var decisions = testCase.GetProperty("decisions");
            var choice = PeerEgressRuntime.ChooseAddress(a, address =>
            {
                var code = decisions.GetProperty(Ipv4Cidr.FormatAddress(address)).GetString();
                return code == PeerEgressCodes.Allowed ? null : code;
            });
            if (a.Count == 0 && aaaa > 0 && testCase.GetProperty("ipv6TargetCapable").GetBoolean())
            {
                Assert.True(choice.Code == PeerEgressCodes.NameUnresolved,
                    $"{name}: an IPv4-only egress should find nothing to dial, got {choice.Code}");
                continue;
            }
            Assert.True(testCase.GetProperty("code").GetString() == (choice.Code ?? PeerEgressCodes.Allowed),
                $"{name}: code {choice.Code}");
            var expected = testCase.GetProperty("address");
            if (expected.ValueKind == JsonValueKind.String)
            {
                Assert.True(expected.GetString() == Ipv4Cidr.FormatAddress(choice.Address),
                    $"{name}: chose {Ipv4Cidr.FormatAddress(choice.Address)}");
            }
        }
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("WWW.Example.COM.", true)]
    [InlineData("example.com..", true)]
    [InlineData("xn--fiqs8s.example", true)]
    [InlineData("localhost", false)]
    [InlineData("*.example.com", false)]
    [InlineData("a_b.example.com", false)]
    [InlineData("-a.example", false)]
    [InlineData("1.2.3.4", false)]
    [InlineData("", false)]
    [InlineData("中国.example", false)]
    public void ValidatesNames(string name, bool valid) => Assert.Equal(valid, PeerEgressNames.Valid(name));

    [Theory]
    [InlineData("{\"type\":\"name-bind\"}")]
    [InlineData("{\"type\":\"name-bind\",\"address\":\"198.18.0.5\"}")]
    [InlineData("{\"type\":\"name-bind\",\"address\":\"not-an-address\",\"name\":\"example.com\"}")]
    [InlineData("{\"type\":\"name-bind\",\"address\":\"198.18.0.5\",\"name\":\"*.example.com\"}")]
    public void RefusesAMalformedNameBind(string body)
    {
        var frame = PeerEgressFrame.Parse(PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, Encoding.UTF8.GetBytes(body)));
        Assert.Equal(PeerEgressCodes.FrameMalformedControl, frame.Code);
    }

    [Fact]
    public void KeepsBindingsByRecentUseWithinTheCaps()
    {
        var table = new PeerEgressNameTable();
        for (uint address = 1; address <= PeerEgressNameTable.CapacityPerConsumer; address++)
        {
            table.Bind(7, address, "example.com");
        }
        table.Lookup(7, 1);
        table.Bind(7, PeerEgressNameTable.CapacityPerConsumer + 1, "late.example");
        Assert.True(table.Lookup(7, 1) is not null, "the binding just used was evicted");
        Assert.True(table.Lookup(7, 2) is null, "the least recently used binding survived a full table");

        table.Bind(9, 1, "other.example");
        table.DropConsumer(7);
        Assert.Equal(1, table.Count);
        Assert.Equal("other.example", table.Lookup(9, 1));
    }

    /// <summary>
    /// Which flows each name-bind closes at a real egress runtime, and which of them the application
    /// hears about (vector <c>nameBindClosesFlows</c>).
    /// </summary>
    /// <remarks>
    /// A flow's name is observed from what it did: one opened for a name resolved that name and
    /// dialled what it resolved to, one opened by address dialled the address. A closed flow's socket
    /// is closed. One opened before any name is closed silently -- no reset reaches the consumer,
    /// because its retransmitted SYN follows and a reset would refuse that connection -- and one
    /// opened for another name is reset. Neither is followed by a flow-reject, which would make the
    /// consumer forget the flow the next packet reopens.
    /// </remarks>
    [Fact]
    public void NameBindClosesTheFlowsTheSharedVectorSays()
    {
        using var vector = Vector();
        var section = vector.RootElement.GetProperty("nameBindClosesFlows");
        var events = section.GetProperty("events").EnumerateArray().ToList();
        var results = section.GetProperty("results").EnumerateArray().ToList();
        using var egress = new EgressHarness();
        var flows = new Dictionary<string, (int Socket, ushort Port)>();
        for (var step = 0; step < events.Count; step++)
        {
            var egressEvent = events[step];
            var expected = results[step];
            var consumer = egressEvent.GetProperty("consumer").GetInt64();
            var address = egressEvent.GetProperty("address").GetString()!;
            if (egressEvent.TryGetProperty("open", out var open))
            {
                var id = open.GetString()!;
                var resolvedBefore = egress.Resolved.Count;
                var socketsBefore = egress.SocketCount;
                var port = (ushort)(40000 + step);
                egress.Syn(consumer, port, address);
                Assert.True(egress.SocketCount == socketsBefore + 1, $"{id}: no flow was opened");
                var name = expected.GetProperty("name");
                if (name.ValueKind == JsonValueKind.Null)
                {
                    Assert.True(egress.Resolved.Count == resolvedBefore, $"{id}: resolved a name it had no binding for");
                    Assert.Equal($"{address}:443", egress.Dialed[^1]);
                }
                else
                {
                    Assert.True(egress.Resolved.Count == resolvedBefore + 1 && egress.Resolved[^1] == name.GetString(),
                        $"{id}: resolved [{string.Join(",", egress.Resolved)}]");
                    Assert.Equal($"{EgressHarness.Resolution}:443", egress.Dialed[^1]);
                }
                flows[id] = (socketsBefore, port);
                continue;
            }
            var openBefore = flows.Where(flow => !egress.Closed(flow.Value.Socket)).Select(flow => flow.Key).ToList();
            var flowCount = egress.Runtime.FlowCount;
            egress.ClearFrames();
            egress.NameBind(consumer, address, egressEvent.GetProperty("nameBind").GetString()!);
            var closed = openBefore.Where(id => egress.Closed(flows[id].Socket)).Order(StringComparer.Ordinal).ToList();
            var wantClosed = expected.GetProperty("closed").EnumerateArray().Select(item => item.GetString()!).ToList();
            Assert.True(wantClosed.SequenceEqual(closed), $"step {step}: closed [{string.Join(",", closed)}]");
            Assert.Equal(flowCount - wantClosed.Count, egress.Runtime.FlowCount);
            var resetPorts = egress.ResetPorts();
            var reset = flows.Where(flow => resetPorts.Contains(flow.Value.Port)).Select(flow => flow.Key)
                .Order(StringComparer.Ordinal).ToList();
            var wantReset = expected.GetProperty("reset").EnumerateArray().Select(item => item.GetString()!).ToList();
            Assert.True(wantReset.SequenceEqual(reset), $"step {step}: reset [{string.Join(",", reset)}]");
            Assert.True(egress.RejectCodes().Count == 0, "a name-bind told the consumer to forget a flow");
        }
    }

    /// <summary>A real egress runtime whose sockets, dialer and resolver this test controls.</summary>
    private sealed class EgressHarness : IPeerEgressDialer, IDisposable
    {
        /// <summary>What every name resolves to here.</summary>
        public const string Resolution = "203.0.113.10";

        private const long Epoch = 1_800_000_000_000L;

        private readonly List<(long Consumer, byte[] Frame)> _frames = [];
        private readonly List<string> _dialed = [];
        private readonly List<string> _resolved = [];
        private readonly List<BlockingSocket> _sockets = [];

        public EgressHarness()
        {
            Runtime = new PeerEgressRuntime((consumer, frame) =>
            {
                lock (_frames)
                {
                    _frames.Add((consumer, (byte[])frame.Clone()));
                }
            }, this, reader => new Thread(() => reader()) { IsBackground = true }.Start(), () => Epoch);
            Runtime.Resolve = name =>
            {
                lock (_resolved)
                {
                    _resolved.Add(name);
                }
                return [Address(Resolution)];
            };
            Runtime.ApplyPolicy(new PeerEgressPolicy
            {
                Enabled = true,
                Scope = PeerEgressAuthorization.ScopePublic,
                AllowedConsumerClientIds = [1L, 7L],
                DestinationRules =
                [
                    new PeerEgressDestinationRule { Cidr = "198.18.0.0/15", Protocols = ["tcp", "udp"], PortRanges = [[1, 65535]] },
                    new PeerEgressDestinationRule { Cidr = "203.0.113.0/24", Protocols = ["tcp", "udp"], PortRanges = [[1, 65535]] },
                ],
            }, PeerEgressContext.Default, Epoch);
        }

        public PeerEgressRuntime Runtime { get; }

        public List<string> Resolved
        {
            get
            {
                lock (_resolved)
                {
                    return [.. _resolved];
                }
            }
        }

        public List<string> Dialed
        {
            get
            {
                lock (_dialed)
                {
                    return [.. _dialed];
                }
            }
        }

        public int SocketCount
        {
            get
            {
                lock (_sockets)
                {
                    return _sockets.Count;
                }
            }
        }

        public bool Closed(int socket)
        {
            lock (_sockets)
            {
                return _sockets[socket].IsClosed;
            }
        }

        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs)
        {
            lock (_dialed)
            {
                _dialed.Add($"{host}:{port}");
            }
            var socket = new BlockingSocket();
            lock (_sockets)
            {
                _sockets.Add(socket);
            }
            return socket;
        }

        /// <summary>A SYN from the consumer's own mesh address.</summary>
        public void Syn(long consumer, ushort sourcePort, string address)
        {
            var packet = PeerEgressSegment.Build(new PeerEgressSegment.Segment(Address($"100.96.0.{consumer}"),
                Address(address), sourcePort, 443, 1000, 0, PeerEgressSegment.FlagSyn, 65535, 0, []));
            Assert.True(Runtime.HandleFrame(consumer, PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet), Epoch));
        }

        /// <summary>
        /// A name-bind with the name as the vector writes it, not normalised on the way: the egress
        /// normalises what it receives.
        /// </summary>
        public void NameBind(long consumer, string address, string name)
        {
            var body = Encoding.UTF8.GetBytes(
                $"{{\"type\":\"name-bind\",\"address\":{JsonSerializer.Serialize(address)},\"name\":{JsonSerializer.Serialize(name)}}}");
            Assert.True(Runtime.HandleFrame(consumer, PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body), Epoch));
        }

        public void ClearFrames()
        {
            lock (_frames)
            {
                _frames.Clear();
            }
        }

        private List<PeerEgressFrame.Decoded> Frames()
        {
            lock (_frames)
            {
                return [.. _frames.Select(entry => PeerEgressFrame.Parse(entry.Frame)).Where(frame => frame.Accepted)];
            }
        }

        /// <summary>The consumer ports a reset was sent to since the frames were last cleared.</summary>
        public HashSet<ushort> ResetPorts() =>
        [
            .. Frames()
                .Where(frame => frame.Type == PeerEgressFrame.TypeIpPacket)
                .Select(frame => PeerEgressSegment.Parse(frame.Body))
                .Where(segment => segment is not null && segment.Has(PeerEgressSegment.FlagRst))
                .Select(segment => segment!.DestinationPort),
        ];

        public List<string> RejectCodes() =>
        [
            .. Frames()
                .Where(frame => frame.Type == PeerEgressFrame.TypeControl)
                .Select(frame => PeerEgressFrame.DecodeControl(frame.Body))
                .Where(control => control is not null && control.Type == PeerEgressFrame.ControlFlowReject)
                .Select(control => control!.Code),
        ];

        public void Dispose() => Runtime.Shutdown(Epoch);

        /// <summary>A socket whose reads wait until it is closed, as an idle connection's do.</summary>
        private sealed class BlockingSocket : IPeerEgressSocket
        {
            private readonly BlockingCollection<Exception> _closing = [];

            public bool IsClosed { get; private set; }

            public int Read(byte[] buffer) => throw _closing.Take();

            public void Write(byte[] data)
            {
            }

            public void Dispose()
            {
                if (IsClosed)
                {
                    return;
                }
                IsClosed = true;
                _closing.Add(new IOException("socket closed"));
            }
        }
    }
}
