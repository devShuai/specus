using System.Buffers.Binary;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Phase two on the consumer's side, bound to <c>peer-egress-dns-v1.json</c>: when phase two runs,
/// which rules are in force, which rule a name selects, how the fake-IP pool hands out and takes
/// back addresses, what the consumer keeps from <c>egress-catalog</c>, and what happens to each
/// packet sent into the pool. The egress's side of a name-bind is in <see cref="PeerEgressNamesTests"/>.
/// </summary>
/// <remarks>
/// Every case goes through the code the client runs, not a model of it. The steering case is
/// replayed twice: once against the consumer itself with the vector's clock, and once through the
/// mesh wiring, where the catalogue arrives as JSON, the rules through a reconcile and every frame
/// through the real send queue.
/// </remarks>
public class PeerEgressPhaseTwoVectorTests
{
    private const long Epoch = 1_800_000_000_000L;
    private const string ConsumerIp = "100.96.0.7";

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

    private static Ipv4Cidr Cidr(string text)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var value), $"{text} did not parse");
        return value;
    }

    private static PeerEgressRule Rule(JsonElement node) => JsonSerializer.Deserialize<PeerEgressRule>(node.GetRawText())!;

    private static List<PeerEgressRule> Rules(JsonElement array) => [.. array.EnumerateArray().Select(Rule)];

    private static string? Text(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    [Fact]
    public void PhaseTwoRunsWhenTheSharedVectorSays()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        var mesh = root.GetProperty("meshCidr").GetString();
        foreach (var testCase in root.GetProperty("phaseTwo").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var phase = PeerEgressRules.PhaseTwo(testCase.GetProperty("consumerEnabled").GetBoolean(),
                testCase.GetProperty("takeover").GetBoolean(), testCase.GetProperty("cidr").GetString(), mesh);
            Assert.True(testCase.GetProperty("active").GetBoolean() == phase.Active, $"{name}: active {phase.Active}");
            Assert.True(Text(testCase, "code") == phase.Code, $"{name}: code {phase.Code}");
            Assert.True(phase.Active == phase.RunningPool.HasValue, $"{name}: a pool without phase two, or none with it");
        }
    }

    /// <summary>
    /// Rule validation with phase two running over the vector's pool, or not running; the pool's own
    /// configuration; and the capability check the other runtimes apply to a rule.
    /// </summary>
    [Fact]
    public void ValidationMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        var mesh = root.GetProperty("meshCidr").GetString();
        var pool = Cidr(root.GetProperty("fakeIpCidr").GetString()!);
        Assert.Equal(PeerEgressRules.DefaultFakeIpCidr, pool.ToString());
        foreach (var testCase in root.GetProperty("validation").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var code = PeerEgressRules.Validate(Rule(testCase.GetProperty("rule")), mesh,
                testCase.GetProperty("takeover").GetBoolean() ? pool : null);
            Assert.True(Text(testCase, "code") == code, $"{name}: {code}");
        }
        foreach (var testCase in root.GetProperty("poolConfig").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var code = PeerEgressRules.FakeIpPoolProblem(testCase.GetProperty("cidr").GetString(), mesh);
            Assert.True(Text(testCase, "code") == code, $"{name}: {code}");
        }
        foreach (var testCase in root.GetProperty("egressCapability").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var capable = testCase.GetProperty("egressDomainTargetCapable").GetBoolean();
            var code = PeerEgressRules.RuleStatus(Rule(testCase.GetProperty("rule")), mesh, pool, _ => true, _ => capable);
            Assert.True(Text(testCase, "code") == code, $"{name}: {code}");
        }
    }

    [Fact]
    public void RuleStatusMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        var mesh = root.GetProperty("meshCidr").GetString();
        var pool = Cidr(root.GetProperty("fakeIpCidr").GetString()!);
        foreach (var testCase in root.GetProperty("ruleStatus").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var online = testCase.GetProperty("egressOnline").GetBoolean();
            var capable = testCase.GetProperty("egressDomainTargetCapable").GetBoolean();
            var code = PeerEgressRules.RuleStatus(Rule(testCase.GetProperty("rule")), mesh,
                testCase.GetProperty("takeover").GetBoolean() ? pool : null,
                egress => egress == 2 && online, egress => egress == 2 && capable);
            Assert.True(Text(testCase, "code") == code, $"{name}: {code}");
        }
    }

    [Fact]
    public void SelectionMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        var mesh = root.GetProperty("meshCidr").GetString();
        var pool = Cidr(root.GetProperty("fakeIpCidr").GetString()!);
        var rules = Rules(root.GetProperty("rules"));
        foreach (var testCase in root.GetProperty("selection").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var index = PeerEgressRules.SelectDomainRule(rules, testCase.GetProperty("query").GetString(), mesh, pool);
            var expected = testCase.GetProperty("ruleIndex");
            Assert.True((expected.ValueKind == JsonValueKind.Null ? -1 : expected.GetInt32()) == index, $"{name}: {index}");
        }
        // The responder's cases name the rule the same selection picks.
        foreach (var testCase in root.GetProperty("answers").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var index = PeerEgressRules.SelectDomainRule(rules, testCase.GetProperty("query").GetString(), mesh, pool);
            var expected = testCase.GetProperty("ruleIndex");
            Assert.True((expected.ValueKind == JsonValueKind.Null ? -1 : expected.GetInt32()) == index, $"{name}: {index}");
        }
    }

    /// <summary>
    /// Each step of each pool case: the address a query gets, what it evicts, and what traffic to an
    /// address finds. Queries run on the pool's own clock, the one the responder will use.
    /// </summary>
    [Fact]
    public void PoolMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        Assert.Equal(PeerEgressFakeIpPool.MinLifetimeMs, root.GetProperty("minLifetimeSeconds").GetInt64() * 1000);
        Assert.Equal(PeerEgressFakeIpPool.QuarantineMs, root.GetProperty("quarantineSeconds").GetInt64() * 1000);
        foreach (var testCase in root.GetProperty("pool").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var now = Epoch;
            var pool = new PeerEgressFakeIpPool(Cidr(testCase.GetProperty("cidr").GetString()!), () => now);
            var results = testCase.GetProperty("results").EnumerateArray().ToList();
            var step = 0;
            foreach (var poolEvent in testCase.GetProperty("events").EnumerateArray())
            {
                var expected = results[step];
                var label = $"{name} step {step}";
                now = Epoch + poolEvent.GetProperty("at").GetInt64() * 1000;
                if (poolEvent.TryGetProperty("query", out var query))
                {
                    var answer = pool.Query(query.GetString()!);
                    Assert.True(expected.TryGetProperty("exhausted", out _) == answer.Exhausted, $"{label}: exhausted {answer.Exhausted}");
                    if (!answer.Exhausted)
                    {
                        Assert.True(expected.GetProperty("address").GetString() == Ipv4Cidr.FormatAddress(answer.Address),
                            $"{label}: got {Ipv4Cidr.FormatAddress(answer.Address)}");
                    }
                    Assert.True(expected.GetProperty("evicted").EnumerateArray().Select(item => item.GetString()!)
                        .SequenceEqual(answer.Evicted), $"{label}: evicted {string.Join(",", answer.Evicted)}");
                }
                else
                {
                    var found = pool.Use(Address(poolEvent.GetProperty("traffic").GetString()!), now);
                    if (expected.TryGetProperty("blocked", out var blocked))
                    {
                        Assert.Equal("fake-ip-unmapped", blocked.GetString());
                        Assert.True(found is null, $"{label}: found {found}");
                    }
                    else
                    {
                        Assert.True(expected.GetProperty("name").GetString() == found, $"{label}: found {found}");
                    }
                }
                step++;
            }
        }
    }

    [Fact]
    public void CatalogMatchesTheSharedVector()
    {
        using var vector = Vector();
        var catalog = new PeerEgressCatalog();
        foreach (var testCase in vector.RootElement.GetProperty("catalog").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            if (testCase.TryGetProperty("newSession", out _))
            {
                catalog.NewSession();
            }
            else
            {
                var accepted = catalog.Read(testCase.GetProperty("json").GetString());
                Assert.True(testCase.GetProperty("accepted").GetBoolean() == accepted, $"{name}: accepted {accepted}");
            }
            var expected = testCase.GetProperty("domainTargetCapable").EnumerateArray().Select(item => item.GetInt64());
            Assert.True(expected.SequenceEqual(catalog.CapableIds()), $"{name}: {string.Join(",", catalog.CapableIds())}");
        }
    }

    /// <summary>The consumer itself, on the vector's clock.</summary>
    [Fact]
    public void SteeringMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("steering").EnumerateArray())
        {
            var target = new ConsumerTarget(Rules(testCase.GetProperty("rules")), Cidr(testCase.GetProperty("cidr").GetString()!));
            ReplaySteering(testCase, target);
        }
    }

    /// <summary>
    /// The same case through the mesh: the pool is built by phase two starting, rules reach the
    /// consumer through a reconcile, the catalogue arrives as the JSON the server pushes, egress
    /// availability comes from the host, and every frame leaves through the send queue in order.
    /// </summary>
    /// <remarks>
    /// The pool is a /24, the narrowest a configuration may name, rather than the case's /29. The
    /// case allocates three addresses and exhausts nothing, so both hand out the same ones.
    /// </remarks>
    [Fact]
    public void SteeringThroughTheMeshMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("steering").EnumerateArray())
        {
            Assert.Equal("198.18.0.0/29", testCase.GetProperty("cidr").GetString());
            using var target = new MeshTarget(Rules(testCase.GetProperty("rules")), "198.18.0.0/24");
            ReplaySteering(testCase, target);
        }
    }

    // ----------------------------------------------------------------------------------------------
    // Steering replay
    // ----------------------------------------------------------------------------------------------

    /// <summary>What one steering replay drives and observes.</summary>
    private abstract class SteeringTarget
    {
        public abstract PeerEgressFakeIpPool.Answer Map(string name, long nowMs);

        /// <summary>Whether the consumer claimed the packet.</summary>
        public abstract bool Outbound(byte[] packet, long nowMs);

        public abstract void Reply(long egress, byte[] packet, long nowMs);

        public abstract void Change(List<PeerEgressRule>? rules, Dictionary<long, bool>? online,
            Dictionary<long, bool>? catalog, long nowMs);

        /// <summary>Every frame sent to an egress, in order.</summary>
        public abstract List<(long Egress, byte[] Frame)> Sent();

        /// <summary>Every packet written to the TUN, in order.</summary>
        public abstract List<byte[]> ToTun();

        public abstract IReadOnlyDictionary<string, long> Blocked();

        /// <summary>Waits until at least this much has been delivered; immediate where delivery is.</summary>
        public virtual void Settle(int sent, int tun)
        {
        }
    }

    /// <summary>The consumer on its own. Purges become the flow-purge frames the mesh would send.</summary>
    private sealed class ConsumerTarget : SteeringTarget
    {
        private readonly List<(long, byte[])> _sent = [];
        private readonly List<byte[]> _tun = [];
        private readonly PeerEgressConsumer _consumer;
        private readonly PeerEgressFakeIpPool _pool;

        public ConsumerTarget(List<PeerEgressRule> rules, Ipv4Cidr cidr)
        {
            _pool = new PeerEgressFakeIpPool(cidr, () => Epoch);
            _consumer = new PeerEgressConsumer((egress, frame) =>
            {
                _sent.Add((egress, frame));
                return true;
            }, _tun.Add);
            Assert.Empty(_consumer.Configure(rules, PeerEgressRules.DefaultMeshCidr, ConsumerIp, Epoch, _pool));
        }

        public override PeerEgressFakeIpPool.Answer Map(string name, long nowMs) => _pool.Query(name, nowMs);

        public override bool Outbound(byte[] packet, long nowMs) =>
            _consumer.HandleOutbound(packet, nowMs) != PeerEgressConsumerOutcome.NotMine;

        public override void Reply(long egress, byte[] packet, long nowMs) =>
            Assert.True(_consumer.HandleInbound(PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet), egress, nowMs));

        public override void Change(List<PeerEgressRule>? rules, Dictionary<long, bool>? online,
            Dictionary<long, bool>? catalog, long nowMs)
        {
            var purge = new SortedDictionary<long, SortedSet<string>>();
            void Add(IReadOnlyDictionary<long, IReadOnlyList<string>> more)
            {
                foreach (var (egress, destinations) in more)
                {
                    if (!purge.TryGetValue(egress, out var set))
                    {
                        purge[egress] = set = new SortedSet<string>(StringComparer.Ordinal);
                    }
                    set.UnionWith(destinations);
                }
            }
            if (rules is not null)
            {
                Add(_consumer.Configure(rules, PeerEgressRules.DefaultMeshCidr, ConsumerIp, nowMs, _pool));
            }
            foreach (var (egress, up) in online ?? [])
            {
                Add(_consumer.SetEgressOnline(egress, up, nowMs));
            }
            if (catalog is not null)
            {
                Add(_consumer.SetEgressCapabilities(catalog, nowMs));
            }
            foreach (var (egress, destinations) in purge)
            {
                _sent.Add((egress, PeerEgressMesh.PurgeFrame([.. destinations])));
            }
        }

        public override List<(long Egress, byte[] Frame)> Sent() => [.. _sent];

        public override List<byte[]> ToTun() => [.. _tun];

        public override IReadOnlyDictionary<string, long> Blocked() => _consumer.BlockedCounts();
    }

    /// <summary>The mesh with phase two switched on, driven the way the client drives it.</summary>
    private sealed class MeshTarget : SteeringTarget, IDisposable
    {
        private readonly string _directory =
            Path.Combine(Path.GetTempPath(), "specus-egress-phase-two-" + Guid.NewGuid().ToString("N"));
        private readonly Host _host;
        private readonly PeerEgressMesh _mesh;
        private long _catalogRevision;

        public MeshTarget(List<PeerEgressRule> rules, string pool)
        {
            Directory.CreateDirectory(_directory);
            _host = new Host(_directory, pool) { Rules = rules };
            _mesh = new PeerEgressMesh(_host, dialer: new RefusingDialer(), commander: new AcceptingCommander());
            _mesh.ReconcileRoutes();
            Assert.NotNull(_mesh.FakeIpPool);
        }

        public void Dispose()
        {
            _mesh.Dispose();
            try
            {
                Directory.Delete(_directory, recursive: true);
            }
            catch (IOException)
            {
                // A leftover temp directory is not worth failing a test over.
            }
        }

        public override PeerEgressFakeIpPool.Answer Map(string name, long nowMs) => _mesh.FakeIpPool!.Query(name);

        public override bool Outbound(byte[] packet, long nowMs) => _mesh.HandleOutbound(packet);

        public override void Reply(long egress, byte[] packet, long nowMs) =>
            Assert.True(_mesh.HandleInboundFrame(egress, PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet)));

        public override void Change(List<PeerEgressRule>? rules, Dictionary<long, bool>? online,
            Dictionary<long, bool>? catalog, long nowMs)
        {
            if (rules is not null)
            {
                _host.Rules = rules;
                _mesh.ReconcileRoutes();
            }
            if (online is not null)
            {
                var availability = new Dictionary<long, bool>(_host.EgressAvailability);
                foreach (var (egress, up) in online)
                {
                    availability[egress] = up;
                }
                _host.EgressAvailability = availability;
                _mesh.SyncEgressAvailability(availability);
            }
            if (catalog is not null)
            {
                var egresses = string.Join(",", catalog.Select(entry =>
                    $"{{\"clientId\":{entry.Key},\"online\":true,\"domainTargetCapable\":{(entry.Value ? "true" : "false")}}}"));
                _mesh.ApplyEgressCatalog($"{{\"type\":\"egress-catalog\",\"revision\":{++_catalogRevision},\"egresses\":[{egresses}]}}");
            }
        }

        public override List<(long Egress, byte[] Frame)> Sent() => _host.SentSnapshot();

        public override List<byte[]> ToTun() => _host.DeviceSnapshot();

        public override IReadOnlyDictionary<string, long> Blocked()
        {
            var consumer = (Dictionary<string, object?>)_mesh.Status()["consumer"]!;
            return (IReadOnlyDictionary<string, long>)consumer["blocked"]!;
        }

        public override void Settle(int sent, int tun)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while ((Sent().Count < sent || ToTun().Count < tun) && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(5);
            }
        }

        private sealed class Host(string directory, string pool) : IPeerEgressMeshHost
        {
            private readonly List<(long, byte[])> _sent = [];
            private readonly List<byte[]> _device = [];

            public List<PeerEgressRule> Rules { get; set; } = [];

            public IReadOnlyDictionary<long, bool> EgressAvailability { get; set; } = new Dictionary<long, bool>();

            public IReadOnlyList<PeerEgressRule> ConsumerRules => Rules;

            public bool DnsTakeover => true;

            public string FakeIpCidr => pool;

            public IReadOnlyList<string> LocalInterfaceNetworks() => ["192.168.1.0/24"];

            public bool CanReach(long peerId) => true;

            public Task<bool> SendToPeerAsync(long peerId, byte[] frame)
            {
                lock (_sent)
                {
                    _sent.Add((peerId, (byte[])frame.Clone()));
                }
                return Task.FromResult(true);
            }

            public Task WriteToDeviceAsync(byte[] packet)
            {
                lock (_device)
                {
                    _device.Add((byte[])packet.Clone());
                }
                return Task.CompletedTask;
            }

            public List<(long Egress, byte[] Frame)> SentSnapshot()
            {
                lock (_sent)
                {
                    return [.. _sent];
                }
            }

            public List<byte[]> DeviceSnapshot()
            {
                lock (_device)
                {
                    return [.. _device];
                }
            }

            public string TunName => "specus0";

            public string MeshCidr => PeerEgressRules.DefaultMeshCidr;

            public string VirtualIp => ConsumerIp;

            public IReadOnlyList<string> DeploymentDenyCidrs() => [];

            public IReadOnlyList<string> PeerEndpointAddresses() => [];

            public int? PathMtuForPeer(long peerId) => null;

            public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");
        }
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

    private sealed class RefusingDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            throw new IOException("nothing is dialled in this test");
    }

    private static int Flags(string letters)
    {
        var flags = 0;
        foreach (var letter in letters)
        {
            flags |= letter switch
            {
                'S' => PeerEgressSegment.FlagSyn,
                'A' => PeerEgressSegment.FlagAck,
                'F' => PeerEgressSegment.FlagFin,
                'R' => PeerEgressSegment.FlagRst,
                _ => throw new InvalidOperationException($"unknown TCP flag {letter}"),
            };
        }
        return flags;
    }

    private static byte[] Tcp(uint source, uint destination, ushort sourcePort, ushort destinationPort, string flags) =>
        PeerEgressSegment.Build(new PeerEgressSegment.Segment(source, destination, sourcePort, destinationPort,
            1000, flags.Contains('A') ? 2000u : 0u, Flags(flags), 65535, 0, []));

    private static byte[] Udp(uint source, uint destination, ushort sourcePort, ushort destinationPort) =>
        PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(source, destination, sourcePort, destinationPort,
            "datagram"u8.ToArray()));

    /// <summary>An ICMP echo request, which the consumer does not carry.</summary>
    private static byte[] Icmp(uint source, uint destination)
    {
        var packet = new byte[28];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 28);
        packet[8] = 64;
        packet[9] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12), source);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16), destination);
        packet[20] = 8;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), PeerIpPacket.Checksum(packet.AsSpan(20)));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10), PeerIpPacket.Checksum(packet.AsSpan(0, 20)));
        return packet;
    }

    private static Dictionary<long, bool> Flags(JsonElement map) =>
        map.EnumerateObject().ToDictionary(entry => long.Parse(entry.Name), entry => entry.Value.GetBoolean());

    /// <summary>
    /// Replays one steering case and checks everything the consumer did at each step: the frames it
    /// sent and their order, what it wrote to the TUN, and which counter moved.
    /// </summary>
    /// <remarks>
    /// A purge event names the destinations to purge. It also resets the application's side of a
    /// purged TCP flow the application had acknowledged on, which the vector does not list, so the
    /// replay keeps the flows it forwarded to know how many resets to expect.
    /// </remarks>
    private static void ReplaySteering(JsonElement testCase, SteeringTarget target)
    {
        var consumerIp = Address(ConsumerIp);
        var flows = new Dictionary<(string Protocol, int SourcePort, string Destination, int DestinationPort), (long Egress, bool Acked)>();
        var sent = 0;
        var tun = 0;
        var events = testCase.GetProperty("events").EnumerateArray().ToList();
        var results = testCase.GetProperty("results").EnumerateArray().ToList();
        Assert.Equal(events.Count, results.Count);
        for (var step = 0; step < events.Count; step++)
        {
            var steeringEvent = events[step];
            var expected = results[step];
            var label = $"step {step} ({steeringEvent.GetRawText()})";
            var nowMs = Epoch + steeringEvent.GetProperty("at").GetInt64() * 1000;
            var blockedBefore = new Dictionary<string, long>(target.Blocked());
            var newFrames = new List<(long Egress, byte[] Frame)>();
            var newWrites = new List<byte[]>();

            if (steeringEvent.TryGetProperty("map", out var map))
            {
                var answer = target.Map(map.GetString()!, nowMs);
                Assert.False(answer.Exhausted, label);
                Assert.True(expected.GetProperty("address").GetString() == Ipv4Cidr.FormatAddress(answer.Address),
                    $"{label}: mapped to {Ipv4Cidr.FormatAddress(answer.Address)}");
                Assert.Equal(expected.GetProperty("evicted").GetArrayLength(), answer.Evicted.Count);
            }
            else if (steeringEvent.TryGetProperty("packet", out var packetEvent))
            {
                var protocol = packetEvent.GetProperty("protocol").GetString()!;
                var destination = packetEvent.GetProperty("destination").GetString()!;
                var sourcePort = packetEvent.TryGetProperty("sourcePort", out var sp) ? sp.GetInt32() : 0;
                var destinationPort = packetEvent.TryGetProperty("destinationPort", out var dp) ? dp.GetInt32() : 0;
                var flags = Text(packetEvent, "flags") ?? string.Empty;
                var packet = protocol switch
                {
                    "tcp" => Tcp(consumerIp, Address(destination), (ushort)sourcePort, (ushort)destinationPort, flags),
                    "udp" => Udp(consumerIp, Address(destination), (ushort)sourcePort, (ushort)destinationPort),
                    _ => Icmp(consumerIp, Address(destination)),
                };
                var claimed = target.Outbound(packet, nowMs);
                var outcome = expected.GetProperty("outcome").GetString();
                if (outcome == "not-mine")
                {
                    Assert.False(claimed, $"{label}: claimed a destination no rule covers");
                }
                else if (outcome == "forwarded")
                {
                    Assert.True(claimed, label);
                    var egress = expected.GetProperty("egressClientId").GetInt64();
                    var nameBind = expected.GetProperty("nameBind");
                    sent += nameBind.ValueKind == JsonValueKind.Null ? 1 : 2;
                    target.Settle(sent, tun);
                    newFrames = target.Sent()[(sent - (nameBind.ValueKind == JsonValueKind.Null ? 1 : 2))..];
                    var index = 0;
                    if (nameBind.ValueKind != JsonValueKind.Null)
                    {
                        // The binding goes first, to the same egress, so the name is there before the
                        // packet opens anything.
                        Assert.True(newFrames[0].Egress == egress, $"{label}: name-bind to {newFrames[0].Egress}");
                        var frame = PeerEgressFrame.Parse(newFrames[0].Frame);
                        Assert.True(frame.Accepted && frame.Type == PeerEgressFrame.TypeControl, $"{label}: first frame is not a control frame");
                        var control = PeerEgressFrame.DecodeControl(frame.Body)!;
                        Assert.Equal(PeerEgressFrame.ControlNameBind, control.Type);
                        Assert.Equal(nameBind.GetProperty("address").GetString(), control.Address);
                        Assert.Equal(nameBind.GetProperty("name").GetString(), control.Name);
                        index = 1;
                    }
                    Assert.True(newFrames[index].Egress == egress, $"{label}: packet to {newFrames[index].Egress}");
                    var carried = PeerEgressFrame.Parse(newFrames[index].Frame);
                    Assert.True(carried.Accepted && carried.Type == PeerEgressFrame.TypeIpPacket, $"{label}: packet frame");
                    Assert.Equal(packet, carried.Body);
                    var key = (protocol, sourcePort, destination, destinationPort);
                    flows[key] = (egress, (flows.TryGetValue(key, out var known) && known.Acked) || flags.Contains('A'));
                }
                else
                {
                    Assert.True(claimed, $"{label}: a blocked packet was not claimed");
                    var reason = expected.GetProperty("reason").GetString()!;
                    var answered = expected.GetProperty("answered").GetBoolean();
                    // An answer is what egress-unavailable has always written: a reset for TCP, an
                    // unreachable for UDP, and nothing for a protocol that cannot be answered.
                    var writes = answered && protocol is "tcp" or "udp" ? 1 : 0;
                    tun += writes;
                    target.Settle(sent, tun);
                    newWrites = target.ToTun()[(tun - writes)..];
                    var blockedAfter = target.Blocked();
                    Assert.True(blockedAfter.GetValueOrDefault(reason) == blockedBefore.GetValueOrDefault(reason) + 1,
                        $"{label}: {reason} did not move");
                    Assert.True(blockedAfter.Where(entry => entry.Key != reason)
                        .All(entry => blockedBefore.GetValueOrDefault(entry.Key) == entry.Value),
                        $"{label}: another counter moved: {JsonSerializer.Serialize(blockedAfter)}");
                    if (writes == 1 && protocol == "tcp")
                    {
                        var reset = PeerEgressSegment.Parse(newWrites[0]);
                        Assert.True(reset is not null && reset.Has(PeerEgressSegment.FlagRst), $"{label}: the answer is not a reset");
                        Assert.Equal(Address(destination), reset!.SourceIp);
                        Assert.Equal(consumerIp, reset.DestinationIp);
                    }
                    if (writes == 1 && protocol == "udp")
                    {
                        Assert.True(newWrites[0][9] == 1, $"{label}: the answer is not ICMP");
                    }
                }
            }
            else if (steeringEvent.TryGetProperty("reply", out var reply))
            {
                var protocol = reply.GetProperty("protocol").GetString()!;
                var destination = reply.GetProperty("destination").GetString()!;
                var sourcePort = reply.GetProperty("sourcePort").GetInt32();
                var destinationPort = reply.GetProperty("destinationPort").GetInt32();
                var egress = flows[(protocol, sourcePort, destination, destinationPort)].Egress;
                var packet = protocol == "udp"
                    ? Udp(Address(destination), consumerIp, (ushort)destinationPort, (ushort)sourcePort)
                    : Tcp(Address(destination), consumerIp, (ushort)destinationPort, (ushort)sourcePort, "A");
                target.Reply(egress, packet, nowMs);
                var accepted = expected.GetProperty("accepted").GetBoolean();
                if (accepted)
                {
                    tun++;
                    target.Settle(sent, tun);
                    Assert.Equal(packet, target.ToTun()[^1]);
                }
                else
                {
                    Assert.True(target.Blocked().GetValueOrDefault("return-no-flow") == blockedBefore.GetValueOrDefault("return-no-flow") + 1,
                        $"{label}: the reply was not refused");
                }
            }
            else
            {
                var rules = steeringEvent.TryGetProperty("rules", out var ruleList) ? Rules(ruleList) : null;
                var online = steeringEvent.TryGetProperty("online", out var onlineMap) ? Flags(onlineMap) : null;
                var catalog = steeringEvent.TryGetProperty("catalog", out var catalogMap) ? Flags(catalogMap) : null;
                target.Change(rules, online, catalog, nowMs);
                var purge = expected.GetProperty("purge").EnumerateObject()
                    .ToDictionary(entry => long.Parse(entry.Name),
                        entry => entry.Value.EnumerateArray().Select(item => item.GetString()!).ToList());
                var resets = 0;
                foreach (var (key, flow) in flows.ToList())
                {
                    if (purge.TryGetValue(flow.Egress, out var destinations) && destinations.Contains(key.Destination + "/32"))
                    {
                        flows.Remove(key);
                        resets += key.Protocol == "tcp" && flow.Acked ? 1 : 0;
                    }
                }
                sent += purge.Count;
                tun += resets;
                target.Settle(sent, tun);
                newFrames = target.Sent()[(sent - purge.Count)..];
                var purged = new Dictionary<long, List<string>>();
                foreach (var (egress, raw) in newFrames)
                {
                    var frame = PeerEgressFrame.Parse(raw);
                    Assert.True(frame.Accepted && frame.Type == PeerEgressFrame.TypeControl, $"{label}: purge frame");
                    var control = PeerEgressFrame.DecodeControl(frame.Body)!;
                    Assert.Equal(PeerEgressFrame.ControlFlowPurge, control.Type);
                    purged[egress] = [.. control.Destinations];
                }
                Assert.True(purge.Count == purged.Count
                    && purge.All(entry => purged.TryGetValue(entry.Key, out var got) && got.SequenceEqual(entry.Value)),
                    $"{label}: purged {JsonSerializer.Serialize(purged)}");
                foreach (var write in target.ToTun()[(tun - resets)..])
                {
                    Assert.True(PeerEgressSegment.Parse(write) is { } reset && reset.Has(PeerEgressSegment.FlagRst),
                        $"{label}: a purge wrote something other than a reset");
                }
            }

            target.Settle(sent, tun);
            Assert.True(target.Sent().Count == sent, $"{label}: {target.Sent().Count} frames sent, expected {sent}");
            Assert.True(target.ToTun().Count == tun, $"{label}: {target.ToTun().Count} packets to the TUN, expected {tun}");
            if (!(expected.TryGetProperty("outcome", out var kind) && kind.GetString() == "blocked")
                && !(expected.TryGetProperty("accepted", out var took) && !took.GetBoolean()))
            {
                // Only a blocked packet or a refused reply moves a counter.
                Assert.True(blockedBefore.OrderBy(entry => entry.Key).SequenceEqual(target.Blocked().OrderBy(entry => entry.Key)),
                    $"{label}: a counter moved: {JsonSerializer.Serialize(target.Blocked())}");
            }
        }
    }
}
