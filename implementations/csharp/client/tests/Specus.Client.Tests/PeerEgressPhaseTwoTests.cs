using System.Text.Json;
using Microsoft.Extensions.Logging;
using Specus.Client.Cli;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Phase two's joins that the shared vector does not reach: the pool's route, the status, the
/// control message carrying the catalogue, and the configuration keys.
/// </summary>
public sealed class PeerEgressPhaseTwoTests : IDisposable
{
    private const string Mesh = PeerEgressRules.DefaultMeshCidr;
    private const string VirtualIp = "100.96.0.7";

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-phase-two-" + Guid.NewGuid().ToString("N"));

    private PeerEgressMesh? _mesh;

    public PeerEgressPhaseTwoTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        _mesh?.Dispose();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }

    private static PeerEgressRule Rule(string match, string action, long? egress = null) =>
        new() { Match = match, Action = action, EgressClientId = egress };

    private static Ipv4Cidr Cidr(string text)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var value), text);
        return value;
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), dotted);
        return value;
    }

    // ----------------------------------------------------------------------------------------------
    // Routes
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public void PhaseTwoSendsThePoolIntoTheTun()
    {
        List<PeerEgressRule> rules =
        [
            Rule("example.com", "egress", 2),
            Rule("203.0.113.0/24", "egress", 2),
            Rule("198.18.0.0/16", "block"),
        ];
        var plan = PeerEgressRoutePlanner.Plan(rules, ["198.18.3.4", "192.0.2.9"], Mesh, Cidr("198.18.0.0/15"));

        // The pool is a TUN route of its own origin, it pins a bypass address inside it the way a
        // rule's prefix does, and a domain rule installs nothing: its traffic arrives through the pool.
        Assert.Equal(
        [
            new PeerEgressRoute("198.18.3.4/32", PeerEgressRouteKind.Bypass, "bypass"),
            new PeerEgressRoute("198.18.0.0/15", PeerEgressRouteKind.Tun, PeerEgressRoutePlanner.FakeIpPoolOrigin),
            new PeerEgressRoute("203.0.113.0/24", PeerEgressRouteKind.Tun, "rule:203.0.113.0/24"),
        ], plan.Routes);
        // An address rule reaching into the pool is refused, not installed under it.
        Assert.Equal([new PeerEgressRuleRefusal(2, "198.18.0.0/16", PeerEgressCodes.RuleFakeIpOverlap)], plan.Refused);

        var phaseOne = PeerEgressRoutePlanner.Plan(rules, ["198.18.3.4"], Mesh);
        Assert.DoesNotContain(phaseOne.Routes, route => route.Origin == PeerEgressRoutePlanner.FakeIpPoolOrigin);
        Assert.Equal([new PeerEgressRuleRefusal(0, "example.com", PeerEgressCodes.RuleDomainUnsupported)], phaseOne.Refused);
        Assert.Contains(new PeerEgressRoute("198.18.0.0/16", PeerEgressRouteKind.Tun, "rule:198.18.0.0/16"), phaseOne.Routes);
    }

    /// <summary>A routing table that records what it was asked to do and can refuse one prefix.</summary>
    private sealed class RecordingCommander(string? failing = null) : IPeerEgressRouteCommander
    {
        public List<string> Installed { get; } = [];

        public List<string> Removed { get; } = [];

        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) => PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
            if (route.Cidr == failing)
            {
                throw new InvalidOperationException("route add refused");
            }
            Installed.Add(route.Cidr);
        }

        public void Remove(PeerEgressRoute route) => Removed.Add(route.Cidr);
    }

    /// <summary>The pool's route is journalled, withdrawn and rolled back like a rule's.</summary>
    [Fact]
    public void ThePoolRouteIsJournalledAndRolledBackLikeARuleRoute()
    {
        var journal = Path.Combine(_directory, "egress-routes.json");
        var plan = PeerEgressRoutePlanner.Plan([Rule("203.0.113.0/24", "egress", 2)], [], Mesh, Cidr("198.18.0.0/15"));

        var commander = new RecordingCommander();
        var installer = new PeerEgressRouteInstaller(commander, journal);
        var applied = installer.Apply(plan.Routes);
        Assert.Null(applied.Error);
        Assert.Contains("198.18.0.0/15", commander.Installed);
        Assert.Contains("\"fake-ip-pool\"", File.ReadAllText(journal));
        var adopted = new PeerEgressRouteInstaller(new RecordingCommander(), journal);
        adopted.Load();
        Assert.Contains(new PeerEgressRoute("198.18.0.0/15", PeerEgressRouteKind.Tun, PeerEgressRoutePlanner.FakeIpPoolOrigin),
            adopted.Installed);
        installer.WithdrawAll();
        Assert.Contains("198.18.0.0/15", commander.Removed);

        // The rule's prefix sorts after the pool's; its failure takes the pool route back out.
        var failing = new RecordingCommander(failing: "203.0.113.0/24");
        var rolled = new PeerEgressRouteInstaller(failing, Path.Combine(_directory, "rolled.json"));
        var result = rolled.Apply(plan.Routes);
        Assert.True(result.RolledBack);
        Assert.Contains("198.18.0.0/15", failing.Removed);
        Assert.Empty(rolled.Installed);
    }

    // ----------------------------------------------------------------------------------------------
    // The mesh: status and wiring
    // ----------------------------------------------------------------------------------------------

    private sealed class Host(string directory) : IPeerEgressMeshHost
    {
        public List<PeerEgressRule> Rules { get; set; } = [];

        public bool Takeover { get; set; } = true;

        public string Pool { get; set; } = PeerEgressRules.DefaultFakeIpCidr;

        public List<string> Interfaces { get; set; } = ["192.168.1.0/24"];

        public List<byte[]> Device { get; } = [];

        public IReadOnlyDictionary<long, bool> EgressAvailability { get; set; } = new Dictionary<long, bool>();

        public IReadOnlyList<PeerEgressRule> ConsumerRules => Rules;

        public bool DnsTakeover => Takeover;

        public string FakeIpCidr => Pool;

        public IReadOnlyList<string> LocalInterfaceNetworks() => Interfaces;

        public List<(long Peer, byte[] Frame)> Sent { get; } = [];

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame)
        {
            lock (Sent)
            {
                Sent.Add((peerId, frame));
            }
            return Task.FromResult(true);
        }

        public Task WriteToDeviceAsync(byte[] packet)
        {
            lock (Device)
            {
                Device.Add(packet);
            }
            return Task.CompletedTask;
        }

        public string TunName => "specus0";

        public string MeshCidr => Mesh;

        public string VirtualIp => PeerEgressPhaseTwoTests.VirtualIp;

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

    private sealed class RefusingDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            throw new IOException("nothing is dialled in this test");
    }

    private PeerEgressMesh MeshFor(Host host)
    {
        _mesh = new PeerEgressMesh(host, dialer: new RefusingDialer(), commander: new AcceptingCommander());
        _mesh.ReconcileRoutes();
        return _mesh;
    }

    private static JsonElement Consumer(PeerEgressMesh mesh) =>
        JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer");

    private static string Catalog(long revision, params (long Id, bool Capable)[] egresses) =>
        JsonSerializer.Serialize(new
        {
            type = "egress-catalog",
            revision,
            egresses = egresses.Select(entry => new { clientId = entry.Id, online = true, domainTargetCapable = entry.Capable }),
        });

    /// <summary>
    /// With the switch on and a usable pool, the status says phase two runs, counts the mappings,
    /// and lists the pool's route with its own origin.
    /// </summary>
    [Fact]
    public void TheStatusDescribesPhaseTwo()
    {
        var host = new Host(_directory) { Rules = [Rule("example.com", "egress", 2)] };
        var mesh = MeshFor(host);
        var pool = mesh.FakeIpPool;
        Assert.NotNull(pool);
        Assert.False(pool.Query("www.example.com").Exhausted);

        var consumer = Consumer(mesh);
        var dns = consumer.GetProperty("dns");
        Assert.True(dns.GetProperty("takeover").GetBoolean());
        Assert.Equal("198.18.0.0/15", dns.GetProperty("pool").GetString());
        Assert.Equal(1, dns.GetProperty("mappings").GetInt32());
        Assert.Equal(0, dns.GetProperty("quarantined").GetInt32());
        Assert.False(dns.TryGetProperty("code", out _));
        Assert.Equal(["takeover", "pool", "mappings", "quarantined"], dns.EnumerateObject().Select(field => field.Name));
        var route = consumer.GetProperty("routes").EnumerateArray().Single();
        Assert.Equal("198.18.0.0/15", route.GetProperty("cidr").GetString());
        Assert.Equal("tun", route.GetProperty("kind").GetString());
        Assert.Equal("fake-ip-pool", route.GetProperty("origin").GetString());
        Assert.True(route.GetProperty("installed").GetBoolean());
        var rule = consumer.GetProperty("rules").EnumerateArray().Single();
        Assert.Equal("domain", rule.GetProperty("kind").GetString());
        Assert.True(rule.GetProperty("inForce").GetBoolean());
    }

    /// <summary>The section is absent without the switch, so a phase-one node's status reads as before.</summary>
    [Fact]
    public void TheDnsSectionNeedsTheSwitch()
    {
        var host = new Host(_directory) { Takeover = false, Rules = [Rule("example.com", "egress", 2), Rule("203.0.113.0/24", "egress", 2)] };
        var mesh = MeshFor(host);
        Assert.Null(mesh.FakeIpPool);
        var consumer = Consumer(mesh);
        Assert.False(consumer.TryGetProperty("dns", out _));
        var rules = consumer.GetProperty("rules").EnumerateArray().ToList();
        Assert.Equal(["domain", "cidr"], rules.Select(rule => rule.GetProperty("kind").GetString()));
        Assert.Equal(PeerEgressCodes.RuleDomainUnsupported, rules[0].GetProperty("code").GetString());
        Assert.DoesNotContain(consumer.GetProperty("routes").EnumerateArray(),
            route => route.GetProperty("origin").GetString() == "fake-ip-pool");
    }

    /// <summary>
    /// An unusable pool stops phase two alone: the status says why, domain rules read as with the
    /// switch off, no pool route goes in, and the address rules carry on.
    /// </summary>
    [Theory]
    [InlineData("198.18.0.0/25", null)]
    [InlineData("198.18.0.0/15", "198.18.4.0/24")]
    public void AnUnusablePoolStopsPhaseTwoAlone(string pool, string? localNetwork)
    {
        var host = new Host(_directory)
        {
            Pool = pool,
            Rules = [Rule("example.com", "egress", 2), Rule("203.0.113.0/24", "egress", 2)],
        };
        if (localNetwork is not null)
        {
            host.Interfaces = [localNetwork];
        }
        var mesh = MeshFor(host);
        Assert.Null(mesh.FakeIpPool);
        var consumer = Consumer(mesh);
        var dns = consumer.GetProperty("dns");
        Assert.False(dns.GetProperty("takeover").GetBoolean());
        Assert.Equal(PeerEgressCodes.FakeIpPoolInvalid, dns.GetProperty("code").GetString());
        Assert.Equal(pool, dns.GetProperty("pool").GetString());
        var rules = consumer.GetProperty("rules").EnumerateArray().ToList();
        Assert.Equal(PeerEgressCodes.RuleDomainUnsupported, rules[0].GetProperty("code").GetString());
        Assert.True(rules[1].GetProperty("inForce").GetBoolean());
        Assert.Equal(["203.0.113.0/24"], consumer.GetProperty("routes").EnumerateArray().Select(route => route.GetProperty("cidr").GetString()));
    }

    /// <summary>
    /// A domain rule is out of force for its egress's capability only while that egress is online,
    /// and contributes no peer while it is; the catalogue saying yes puts it back.
    /// </summary>
    [Fact]
    public void ADomainRuleWaitsForItsEgressToResolveNames()
    {
        var host = new Host(_directory)
        {
            Rules = [Rule("example.com", "egress", 2), Rule("*.example.org", "egress", 3)],
            EgressAvailability = new Dictionary<long, bool> { [2] = true },
        };
        var mesh = MeshFor(host);

        var rules = Consumer(mesh).GetProperty("rules").EnumerateArray().ToList();
        Assert.False(rules[0].GetProperty("inForce").GetBoolean());
        Assert.Equal(PeerEgressCodes.RuleEgressNoDomain, rules[0].GetProperty("code").GetString());
        // Egress 3 is offline, so the catalogue's false is not held against its rule.
        Assert.True(rules[1].GetProperty("inForce").GetBoolean());
        var peers = Consumer(mesh).GetProperty("peers").EnumerateArray().ToList();
        Assert.Equal([3L], peers.Select(peer => peer.GetProperty("clientId").GetInt64()));

        mesh.ApplyEgressCatalog(Catalog(1, (2, true)));
        rules = Consumer(mesh).GetProperty("rules").EnumerateArray().ToList();
        Assert.True(rules[0].GetProperty("inForce").GetBoolean());
        Assert.Contains(Consumer(mesh).GetProperty("peers").EnumerateArray(), peer => peer.GetProperty("clientId").GetInt64() == 2);
    }

    /// <summary>
    /// A packet to a pool address nothing was handed out as is refused, answered, and counted where
    /// every other refusal is counted.
    /// </summary>
    [Fact]
    public void AnUnmappedPoolAddressIsCountedAndAnswered()
    {
        var host = new Host(_directory) { Rules = [Rule("example.com", "egress", 2)] };
        var mesh = MeshFor(host);
        var syn = PeerEgressSegment.Build(new PeerEgressSegment.Segment(Address(VirtualIp), Address("198.18.0.9"),
            40000, 443, 1000, 0, PeerEgressSegment.FlagSyn, 65535, 0, []));
        Assert.True(mesh.HandleOutbound(syn));

        var blocked = Consumer(mesh).GetProperty("blocked");
        Assert.Equal(1, blocked.GetProperty("fake-ip-unmapped").GetInt64());
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            lock (host.Device)
            {
                if (host.Device.Count > 0)
                {
                    break;
                }
            }
            Thread.Sleep(5);
        }
        lock (host.Device)
        {
            var reset = PeerEgressSegment.Parse(Assert.Single(host.Device));
            Assert.True(reset is not null && reset.Has(PeerEgressSegment.FlagRst));
        }

        // The responder's port is left to the responder, which is step four's.
        var query = PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(Address(VirtualIp), Address("198.18.0.1"),
            53000, 53, "query"u8.ToArray()));
        Assert.False(mesh.HandleOutbound(query));
    }

    /// <summary>
    /// A node whose own configuration runs phase two refuses, as an egress, to dial into its own
    /// pool: that traffic would be routed into its own tunnel and steered by its own names.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnEgressRunningPhaseTwoRefusesItsOwnPool(bool takeover)
    {
        var host = new Host(_directory) { Takeover = takeover };
        _mesh = new PeerEgressMesh(host, dialer: new RefusingDialer(), commander: new AcceptingCommander());
        _mesh.ApplyEgressConfig("""
            {"type":"egress-config","enabled":true,"revision":1,"scope":"PUBLIC","allowedConsumerClientIds":[5],
             "destinationRules":[{"cidr":"198.18.0.0/15","protocols":["tcp"],"portRanges":[[443,443]]}]}
            """);
        var syn = PeerEgressSegment.Build(new PeerEgressSegment.Segment(Address("100.96.0.5"), Address("198.18.0.9"),
            40000, 443, 1000, 0, PeerEgressSegment.FlagSyn, 65535, 0, []));
        Assert.True(_mesh.HandleInboundFrame(5, PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, syn)));

        // Either way a reset answers the SYN: refused, or dialled by a dialer that fails.
        var deadline = DateTime.UtcNow.AddSeconds(5);
        List<PeerEgressFrame.Decoded> frames = [];
        while (DateTime.UtcNow < deadline)
        {
            lock (host.Sent)
            {
                frames = [.. host.Sent.Select(entry => PeerEgressFrame.Parse(entry.Frame))];
            }
            if (frames.Any(frame => frame.Type == PeerEgressFrame.TypeIpPacket))
            {
                break;
            }
            Thread.Sleep(5);
        }
        Assert.Contains(frames, frame => frame.Type == PeerEgressFrame.TypeIpPacket);
        var codes = frames.Where(frame => frame.Type == PeerEgressFrame.TypeControl)
            .Select(frame => PeerEgressFrame.DecodeControl(frame.Body)?.Code).ToList();
        if (takeover)
        {
            Assert.Equal([PeerEgressCodes.ForbiddenDestination], codes);
        }
        else
        {
            Assert.Empty(codes);
        }
    }

    // ----------------------------------------------------------------------------------------------
    // The control message
    // ----------------------------------------------------------------------------------------------

    private sealed class CapturingLogger : ILogger<PeerMeshClient>
    {
        private readonly List<string> _lines = [];

        public List<string> Lines
        {
            get
            {
                lock (_lines)
                {
                    return [.. _lines];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (_lines)
            {
                _lines.Add(formatter(state, exception));
            }
        }
    }

    /// <summary>
    /// The catalogue arrives as a peer-control message and reaches the consumer; its revision counts
    /// within one control session, and the next session starts the count again.
    /// </summary>
    [Fact]
    public async Task TheCatalogueArrivesOnThePeerControlChannel()
    {
        var logger = new CapturingLogger();
        await using var client = new PeerMeshClient(new SpecusClientConfig(), logger);
        var runtime = new SpecusRuntimeState();
        await using var writer = new FrameWriter(new MemoryStream());

        await client.HandleControlAsync(Catalog(4, (2, true)), runtime, writer, CancellationToken.None);
        Assert.Contains(logger.Lines, line => line.Contains("egress catalog applied revision=4 domainTargetCapable=[2]", StringComparison.Ordinal));

        await client.HandleControlAsync(Catalog(3, (3, true)), runtime, writer, CancellationToken.None);
        Assert.DoesNotContain(logger.Lines, line => line.Contains("revision=3", StringComparison.Ordinal));

        client.Suspend();
        await client.HandleControlAsync(Catalog(1, (3, true)), runtime, writer, CancellationToken.None);
        Assert.Contains(logger.Lines, line => line.Contains("egress catalog applied revision=1 domainTargetCapable=[3]", StringComparison.Ordinal));
    }

    // ----------------------------------------------------------------------------------------------
    // Configuration
    // ----------------------------------------------------------------------------------------------

    private const string Credentials = "\"serverBaseUrl\":\"https://example.test\",\"apiKey\":\"key\",\"secret\":\"secret\"";

    [Fact]
    public void TheSwitchAndThePoolAreConfigured()
    {
        var defaults = SpecusClientConfigLoader.Parse("{" + Credentials + "}", "client.jsonc");
        Assert.False(defaults.PeerEgressDnsTakeover);
        Assert.Equal("198.18.0.0/15", defaults.PeerEgressFakeIpCidr);

        var set = SpecusClientConfigLoader.Parse(
            "{" + Credentials + ",\"peerEgressDnsTakeover\":true,\"peerEgressFakeIpCidr\":\" 10.64.0.0/16 \"}", "client.jsonc");
        Assert.True(set.PeerEgressDnsTakeover);
        Assert.Equal("10.64.0.0/16", set.PeerEgressFakeIpCidr);

        var blank = SpecusClientConfigLoader.Parse("{" + Credentials + ",\"peerEgressFakeIpCidr\":\"\"}", "client.jsonc");
        Assert.Equal("198.18.0.0/15", blank.PeerEgressFakeIpCidr);
    }

    /// <summary>
    /// The validate path knows both keys, lets a domain rule through only with a usable pool, and
    /// says when the pool is what keeps domain rules out of force.
    /// </summary>
    [Fact]
    public void ConfigurationWarningsFollowPhaseTwo()
    {
        List<string> Warnings(string extra)
        {
            var json = "{" + Credentials + ",\"peerEgressEnabled\":true" + extra
                + ",\"peerEgressRules\":[{\"match\":\"example.com\",\"action\":\"egress\",\"egressClientId\":2}]}";
            var warnings = new List<string>();
            SpecusClientConfigLoader.Parse(json, "client.jsonc", warnings.Add);
            return warnings;
        }

        Assert.Empty(Warnings(",\"peerEgressDnsTakeover\":true,\"peerEgressFakeIpCidr\":\"198.18.0.0/15\""));
        Assert.Equal(["peerEgressRules[0] is not in force: EGRESS_RULE_DOMAIN_UNSUPPORTED"], Warnings(""));
        Assert.Equal(
        [
            "peerEgressFakeIpCidr is not usable: EGRESS_FAKE_IP_POOL_INVALID; domain rules are not in force",
            "peerEgressRules[0] is not in force: EGRESS_RULE_DOMAIN_UNSUPPORTED",
        ], Warnings(",\"peerEgressDnsTakeover\":true,\"peerEgressFakeIpCidr\":\"100.96.0.0/16\""));
    }

    /// <summary>The editing commands accept a domain rule under the same condition the runtime does.</summary>
    [Fact]
    public void TheEditingCommandsFollowPhaseTwo()
    {
        var change = new EgressEdit.Change("add", Match: "example.com", Action: "egress", EgressClientId: 2);
        var phaseOne = new SpecusClientConfig();
        var failure = Assert.Throws<EgressEdit.PlanFailure>(() => EgressEdit.Plan(phaseOne, change));
        Assert.Contains(PeerEgressCodes.RuleDomainUnsupported, failure.Message);

        var phaseTwo = new SpecusClientConfig { PeerEgressDnsTakeover = true };
        var planned = EgressEdit.Plan(phaseTwo, change);
        Assert.Equal("peerEgressRules", planned.Key);
        Assert.Contains("example.com", planned.Value);
        Assert.Null(EgressEdit.RuleCode(phaseTwo, Rule("example.com", "egress", 2)));
        Assert.Equal(PeerEgressCodes.RuleFakeIpOverlap, EgressEdit.RuleCode(phaseTwo, Rule("198.18.0.0/16", "direct")));
    }
}
