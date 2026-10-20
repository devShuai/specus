using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// Route takeover for IPv6 (protocol/spec/peer-egress.md, IPv6 数据面, 消费端): the plan, the journal,
/// the repair against the IPv6 table, the mesh's activation rule, and each platform's commands and
/// readings, against synthetic tables and against output sampled from the real tools. No route on
/// this machine is touched.
/// </summary>
public sealed class PeerEgressRoutesIpv6Tests : IDisposable
{
    private const long Start = 1_758_196_800_000L;

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-ipv6-routes-" + Guid.NewGuid().ToString("N"));

    private PeerEgressMesh? _mesh;

    public PeerEgressRoutesIpv6Tests() => Directory.CreateDirectory(_directory);

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

    private string JournalPath => Path.Combine(_directory, "egress-routes.json");

    private static PeerEgressRule Rule(string match, string action, long? egress = null) =>
        new() { Match = match, Action = action, EgressClientId = egress };

    private static List<PeerEgressRule> PlanRules() =>
    [
        Rule("203.0.113.0/24", PeerEgressRules.ActionEgress, 2),
        Rule("2001:DB8:1:0::/48", PeerEgressRules.ActionEgress, 2),
        Rule("2001:db8:2::/48", PeerEgressRules.ActionBlock),
        Rule("2001:db8:3::/48", PeerEgressRules.ActionDirect),
        Rule("2001:db8:1::/48", PeerEgressRules.ActionBlock),
        Rule("fd53:7065:6375:7300::/96", PeerEgressRules.ActionEgress, 2),
        Rule("::/0", PeerEgressRules.ActionEgress, 2),
        Rule("::/1", PeerEgressRules.ActionBlock),
    ];

    private static PeerEgressRoute Tun(string cidr, string origin) => new(cidr, PeerEgressRouteKind.Tun, origin);

    private static PeerEgressRoute Bypass(string cidr) => new(cidr, PeerEgressRouteKind.Bypass, "bypass");

    /// <summary>
    /// A routing table of both families that can be read back. Each family has its own physical
    /// routes, which a test changes to move the machine to another network.
    /// </summary>
    private sealed class TableCommander : IPeerEgressRouteCommander
    {
        public SortedDictionary<string, PeerEgressRoute> Table { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> Foreign { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, Exception> InstallErr { get; } = new(StringComparer.Ordinal);
        public List<string> InstallLog { get; } = [];
        public List<string> RemoveLog { get; } = [];
        public Dictionary<string, PeerEgressBindRoute> Hops { get; } = new(StringComparer.Ordinal);
        public List<PeerEgressBindRoute> Physical { get; set; } = [new("0.0.0.0/0", "eth0", "192.0.2.1", 100, true)];
        public List<PeerEgressBindRoute> Physical6 { get; set; } = [new("::/0", "eth0", "fe80::1", 100, true)];
        public Exception? Table6Error { get; set; }
        public int Table6Reads { get; private set; }

        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) =>
            Foreign.TryGetValue(route.Cidr, out var existing)
                ? new PeerEgressRouteConflictCheck(true, existing)
                : PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
            InstallLog.Add(route.Cidr);
            if (InstallErr.TryGetValue(route.Cidr, out var failure))
            {
                throw failure;
            }
            if (route.Kind == PeerEgressRouteKind.Bypass)
            {
                // Resolved the way the real commanders resolve it: from the physical routes, now.
                var physical = PeerEgressRoutePlanner.IsIpv6(route) ? Physical6 : Physical;
                Hops[route.Cidr] = PeerEgressSocketBinding.SelectBypassHop(physical, "specus0", [],
                        PeerEgressRoutePlanner.BypassAddress(route.Cidr))
                    ?? throw new PeerEgressNoPhysicalRouteException(route.Cidr);
            }
            Table[route.Cidr] = route;
        }

        public void Remove(PeerEgressRoute route)
        {
            RemoveLog.Add(route.Cidr);
            Table.Remove(route.Cidr);
            Hops.Remove(route.Cidr);
        }

        PeerEgressRouteTable IPeerEgressRouteCommander.Table() => new(Rows(Physical, ipv6: false), "specus0");

        PeerEgressRouteTable IPeerEgressRouteCommander.Table6()
        {
            Table6Reads++;
            if (Table6Error is not null)
            {
                throw Table6Error;
            }
            return new PeerEgressRouteTable(Rows(Physical6, ipv6: true), "specus0");
        }

        /// <summary>One family's table: its physical routes, then the installed routes of that family.</summary>
        private List<PeerEgressBindRoute> Rows(List<PeerEgressBindRoute> physical, bool ipv6)
        {
            var rows = new List<PeerEgressBindRoute>(physical);
            foreach (var (cidr, route) in Table)
            {
                if (PeerEgressRoutePlanner.IsIpv6(route) != ipv6)
                {
                    continue;
                }
                rows.Add(route.Kind == PeerEgressRouteKind.Bypass
                    ? new PeerEgressBindRoute(cidr, Hops[cidr].Interface, Hops[cidr].Gateway, 0, true)
                    : new PeerEgressBindRoute(cidr, "specus0", string.Empty, 0, true));
            }
            return rows;
        }

        /// <summary>Drops a route from the table behind the journal's back, the way an interface going down does.</summary>
        public void Lose(string cidr)
        {
            Table.Remove(cidr);
            Hops.Remove(cidr);
        }
    }

    // ---- the plan ---------------------------------------------------------------------------------

    /// <summary>
    /// Exact IPv6 prefixes, written canonically; nothing for a direct rule; a route for a block rule;
    /// one route for two rules over one prefix; the refusals returned; and a /128 bypass for an IPv6
    /// endpoint an IPv6 rule covers, first.
    /// </summary>
    [Fact]
    public void TheIpv6PlanFollowsTheIpv4Rules()
    {
        // fd00::1 is covered by no rule; everything in 2001::/16 is, by ::/1 at least.
        string[] bypass = ["198.51.100.7", "2001:db8:1::9", "2001:db8:1:0::9", "2001:db8:9::1", "2001:db8:2::5", "203.0.113.4", "fd00::1"];
        var plan = PeerEgressRoutePlanner.Plan(PlanRules(), bypass, PeerEgressRules.DefaultMeshCidr, null, carriesIpv6: true);
        Assert.Equal(
        [
            Bypass("203.0.113.4/32"),
            Bypass("2001:db8:1::9/128"),
            Bypass("2001:db8:2::5/128"),
            Bypass("2001:db8:9::1/128"),
            Tun("203.0.113.0/24", "rule:203.0.113.0/24"),
            // ::/1 is not invented; written by hand it is a rule like any other.
            Tun("::/1", "rule:::/1"),
            Tun("2001:db8:1::/48", "rule:2001:DB8:1:0::/48"),
            Tun("2001:db8:2::/48", "rule:2001:db8:2::/48"),
        ], plan.Routes);
        Assert.Equal([(5, PeerEgressCodes.RuleMeshOverlap), (6, PeerEgressCodes.RuleDefaultRoute)],
            plan.Refused.Select(refusal => (refusal.Index, refusal.Code)));

        // Without the data plane the IPv6 rules are refused and the plan is the IPv4 one alone,
        // exactly what it was before IPv6.
        var without = PeerEgressRoutePlanner.Plan(PlanRules(), bypass, PeerEgressRules.DefaultMeshCidr, null, carriesIpv6: false);
        var before = PeerEgressRoutePlanner.Plan([PlanRules()[0]], bypass, PeerEgressRules.DefaultMeshCidr);
        Assert.Equal(before.Routes, without.Routes);
        Assert.All(without.Refused, refusal =>
            Assert.Contains(refusal.Code, new[] { PeerEgressCodes.RuleIpv6Unsupported, PeerEgressCodes.RuleDefaultRoute }));
        Assert.Equal(7, without.Refused.Count);
    }

    /// <summary>
    /// One order across both families: bypass first, IPv4 before IPv6, by value within a family.
    /// Sorted as text across families and by value within one, these three would each sort before
    /// the next.
    /// </summary>
    [Fact]
    public void TheSortIsOneOrderAcrossFamilies()
    {
        List<PeerEgressRoute> routes =
        [
            Tun("2001:db8::/32", ""), Tun("10.0.0.0/8", ""), Tun("9.0.0.0/8", ""), Bypass("2001:db8::1/128"),
            Tun("fd00::/8", ""), Tun("::/1", ""), Bypass("9.0.0.9/32"),
        ];
        PeerEgressRoutePlanner.Sort(routes);
        Assert.Equal(["9.0.0.9/32", "2001:db8::1/128", "9.0.0.0/8", "10.0.0.0/8", "::/1", "2001:db8::/32", "fd00::/8"],
            routes.Select(route => route.Cidr));
    }

    /// <summary>
    /// The journal carries IPv6 prefixes in the shared format, written first and read back, and a
    /// restart takes them back like any other.
    /// </summary>
    [Fact]
    public void TheJournalCarriesIpv6RoutesAndARestartTakesThemBack()
    {
        var commander = new TableCommander();
        var installer = new PeerEgressRouteInstaller(commander, JournalPath);
        var plan = PeerEgressRoutePlanner.Plan(PlanRules(), ["2001:db8:1::9"], PeerEgressRules.DefaultMeshCidr, null, true).Routes;
        var result = installer.Apply(plan);
        Assert.Null(result.Error);
        Assert.Equal(plan.Count, result.Added.Count);

        using (var journal = JsonDocument.Parse(File.ReadAllText(JournalPath)))
        {
            Assert.Equal(1, journal.RootElement.GetProperty("version").GetInt32());
            var found = journal.RootElement.GetProperty("routes").EnumerateArray().ToDictionary(
                entry => entry.GetProperty("cidr").GetString()!,
                entry => entry.GetProperty("kind").GetString() + "|" + entry.GetProperty("origin").GetString());
            Assert.Equal("bypass|bypass", found["2001:db8:1::9/128"]);
            Assert.Equal("tun|rule:2001:DB8:1:0::/48", found["2001:db8:1::/48"]);
        }
        // The bypass went where the IPv6 table says, through the link-local gateway.
        Assert.Equal(("eth0", "fe80::1"), (commander.Hops["2001:db8:1::9/128"].Interface, commander.Hops["2001:db8:1::9/128"].Gateway));

        var restarted = new PeerEgressRouteInstaller(commander, JournalPath);
        restarted.Load();
        Assert.Equal(plan.Count, restarted.WithdrawAll().Count);
        Assert.Empty(commander.Table);
        Assert.False(File.Exists(JournalPath), "the journal is still there");
    }

    /// <summary>
    /// The IPv6 routes are checked against the IPv6 table: one gone is put back, a bypass whose
    /// gateway moved is re-pointed, and one on somebody else's interface is given up. A machine that
    /// owns no IPv6 route never reads the IPv6 table.
    /// </summary>
    [Fact]
    public void TheIpv6RoutesAreRepairedAgainstTheIpv6Table()
    {
        var commander = new TableCommander();
        var installer = new PeerEgressRouteInstaller(commander, JournalPath);
        installer.Apply(PeerEgressRoutePlanner.Plan([PlanRules()[0]], ["203.0.113.4"], PeerEgressRules.DefaultMeshCidr).Routes);
        var ipv4Only = installer.Repair();
        Assert.True(ipv4Only.TableError is null && ipv4Only.Repaired.Count == 0 && commander.Table6Reads == 0,
            "a machine that owns no IPv6 route read the IPv6 table");

        installer.Apply(PeerEgressRoutePlanner.Plan(PlanRules(), ["2001:db8:1::9", "203.0.113.4"],
            PeerEgressRules.DefaultMeshCidr, null, true).Routes);
        var healthy = installer.Repair();
        Assert.True(healthy.TableError is null && healthy.Repaired.Count == 0 && healthy.Lost.Count == 0);

        commander.Lose("2001:db8:2::/48");
        commander.Physical6 = [new PeerEgressBindRoute("::/0", "wlan0", "fe80::9", 50, true)];
        var result = installer.Repair();
        Assert.Null(result.TableError);
        Assert.Null(result.Error);
        Assert.Equal(2, result.Repaired.Count);
        Assert.Equal(("wlan0", "fe80::9"), (commander.Hops["2001:db8:1::9/128"].Interface, commander.Hops["2001:db8:1::9/128"].Gateway));
        Assert.True(commander.Table.ContainsKey("2001:db8:2::/48"), "the lost route was not put back");
        // The IPv4 bypass did not move: its family's table did not change.
        Assert.Equal("eth0", commander.Hops["203.0.113.4/32"].Interface);

        // Somebody else's route on one of ours is reported and given up.
        commander.Lose("2001:db8:1::/48");
        commander.Physical6.Add(new PeerEgressBindRoute("2001:db8:1::/48", "eth1", "", 0, true));
        result = installer.Repair();
        Assert.Equal("2001:db8:1::/48", Assert.Single(result.Lost).Route.Cidr);
        Assert.False(installer.Owns("2001:db8:1::/48"));

        // The IPv6 table unreadable is said like the IPv4 one.
        commander.Table6Error = new IOException("no ip -6");
        Assert.NotNull(installer.Repair().TableError);
    }

    // ---- the mesh -------------------------------------------------------------------------------

    private sealed class Host(string directory) : IPeerEgressMeshHost
    {
        public IReadOnlyList<PeerEgressRule> Rules { get; set; } = [];
        public bool Platform { get; set; } = true;
        public bool DeviceUp { get; set; } = true;
        public string Status { get; set; } = "UP";
        public (bool Ready, string Reason) Ipv6 { get; set; } = (true, "");
        public IReadOnlyList<string?> Bypass { get; set; } = [];
        public Dictionary<long, bool> Online { get; } = [];
        public List<byte[]> ToDevice { get; } = [];

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task WriteToDeviceAsync(byte[] packet)
        {
            lock (ToDevice)
            {
                ToDevice.Add(packet);
            }
            return Task.CompletedTask;
        }

        public string TunName => "specus0";

        public string MeshCidr => "100.96.0.0/11";

        public string VirtualIp => "100.96.0.1";

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => [];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");

        public IReadOnlyList<PeerEgressRule> ConsumerRules => Rules;

        public bool DeviceReady => DeviceUp;

        public string DeviceStatus => Status;

        public bool PlatformCarriesIpv6 => Platform;

        public (bool Ready, string Reason) DeviceIpv6 => Ipv6;

        public IReadOnlyDictionary<long, bool> EgressAvailability => new Dictionary<long, bool>(Online);

        public IReadOnlyList<string?> BypassHosts() => Bypass;
    }

    private sealed class RefusingDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            throw new IOException("nothing is dialled in this test");
    }

    private sealed class Lines : ILogger
    {
        private readonly List<string> _lines = [];

        public string Text
        {
            get
            {
                lock (_lines)
                {
                    return string.Join("\n", _lines);
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

    private (Host Host, TableCommander Commander, Lines Log) NewMesh(params PeerEgressRule[] rules)
    {
        var host = new Host(_directory) { Rules = rules };
        var commander = new TableCommander();
        var log = new Lines();
        _mesh = new PeerEgressMesh(host, log, dialer: new RefusingDialer(), commander: commander,
            lookup: _ => throw new SocketException((int)SocketError.HostNotFound));
        return (host, commander, log);
    }

    private JsonElement Consumer() => JsonSerializer.SerializeToElement(_mesh!.Status()).GetProperty("consumer");

    private static byte[] SynFrom(string source, string destination)
    {
        Assert.True(source.Contains(':') ? Ipv6Cidr.TryParseAddress(source, out var from) : PeerEgressMeshAddress.TryDerive(source, out from));
        Assert.True(Ipv6Cidr.TryParseAddress(destination, out var to));
        return PeerEgressSegment.Build(new Segment(0, 0, 40000, 443, 1, 0, PeerEgressSegment.FlagSyn, 65535, 0, [],
            Ipv6: true, SourceIp6: from, DestinationIp6: to));
    }

    /// <summary>
    /// The plan the mesh applies with the data plane: IPv6 rules routed, an IPv6 endpoint a rule
    /// covers bypassed, and the status listing the IPv6 route installed. Without the data plane the
    /// same configuration routes no IPv6 at all.
    /// </summary>
    [Fact]
    public void TheMeshRoutesIpv6WithTheDataPlane()
    {
        var (host, commander, _) = NewMesh(Rule("2001:db8:1::/48", "egress", 2), Rule("203.0.113.0/24", "egress", 2));
        host.Bypass = ["https://[2001:db8:1::443]:8443"];
        _mesh!.Reconcile(host.Rules, Start);
        Assert.Contains("2001:db8:1::/48", commander.InstallLog);
        Assert.Contains("2001:db8:1::443/128", commander.InstallLog);
        Assert.Contains(Consumer().GetProperty("routes").EnumerateArray(), route =>
            route.GetProperty("cidr").GetString() == "2001:db8:1::/48" && route.GetProperty("installed").GetBoolean());

        _mesh.Dispose();
        var (off, offCommander, _) = NewMesh(Rule("2001:db8:1::/48", "egress", 2));
        off.Platform = false;
        off.Bypass = ["https://[2001:db8:1::443]:8443"];
        _mesh!.Reconcile(off.Rules, Start);
        Assert.Empty(offCommander.InstallLog);
        var rule = Assert.Single(Consumer().GetProperty("rules").EnumerateArray());
        Assert.Equal(PeerEgressCodes.RuleIpv6Unsupported, rule.GetProperty("code").GetString());
    }

    /// <summary>
    /// The status says which rule waits on an egress that does not take IPv6, and counts the new
    /// reasons under their own names.
    /// </summary>
    [Fact]
    public void TheStatusNamesTheIpv6Refusals()
    {
        var (host, _, _) = NewMesh(Rule("2001:db8:1::/48", "egress", 2));
        host.Online[2] = true;
        _mesh!.NewControlSession();
        _mesh.ApplyEgressCatalog("""{"type":"egress-catalog","revision":1,"egresses":[{"clientId":2,"egressVersion":1}]}""");
        _mesh.Reconcile(host.Rules, Start);

        Assert.True(_mesh.HandleOutbound(SynFrom("100.96.0.1", "2001:db8:1::5")), "the packet was not claimed");
        Assert.True(_mesh.HandleOutbound(SynFrom("2001:db8:ff::5", "2001:db8:1::5")), "the packet was not claimed");

        var section = Consumer();
        var rule = Assert.Single(section.GetProperty("rules").EnumerateArray());
        Assert.False(rule.GetProperty("inForce").GetBoolean());
        Assert.Equal(PeerEgressCodes.RuleEgressNoIpv6, rule.GetProperty("code").GetString());
        Assert.Empty(section.GetProperty("peers").EnumerateArray());
        var blocked = section.GetProperty("blocked");
        Assert.Equal(1, blocked.GetProperty("egress-no-ipv6").GetInt64());
        Assert.Equal(1, blocked.GetProperty("ipv6-source-not-mesh").GetInt64());

        // A catalogue that says it takes IPv6 packets puts the rule in force.
        _mesh.ApplyEgressCatalog("""{"type":"egress-catalog","revision":2,"egresses":[{"clientId":2,"egressVersion":1,"ipv6PacketCapable":true}]}""");
        Assert.True(Consumer().GetProperty("rules")[0].GetProperty("inForce").GetBoolean());
    }

    /// <summary>
    /// A device whose derived IPv6 address could not be assigned has no IPv6 data plane: its IPv6
    /// rules report EGRESS_RULE_IPV6_UNSUPPORTED, nothing IPv6 is planned, and the IPv4 routes are
    /// installed and stay installed -- an IPv6 install that would fail cannot roll them back. Said once
    /// in the log. When the device carries IPv6 again the next reconcile puts the IPv6 rules in force,
    /// and when it stops the IPv6 routes go and the IPv4 ones stay.
    /// </summary>
    [Fact]
    public void WithoutTheTunsIpv6AddressIpv4StaysAndIpv6IsRefused()
    {
        var (host, commander, log) = NewMesh(Rule("203.0.113.0/24", "egress", 2), Rule("2001:db8:1::/48", "egress", 2));
        host.Ipv6 = (false, "the TUN's IPv6 address could not be assigned: RTNETLINK answers: Permission denied");
        host.Bypass = ["https://[2001:db8:1::443]:8443"];
        // Were an IPv6 route attempted it would fail, and the failure would take the IPv4 route with it.
        commander.InstallErr["2001:db8:1::/48"] = new InvalidOperationException("ip -6 route add failed: IPv6 is disabled");

        _mesh!.Reconcile(host.Rules, Start);
        _mesh.Reconcile(host.Rules, Start + PeerEgressRoutePlanner.RetryAfterMillis);
        Assert.Contains("203.0.113.0/24", commander.InstallLog);
        Assert.DoesNotContain(commander.InstallLog, cidr => cidr.Contains(':'));
        Assert.True(commander.Table.ContainsKey("203.0.113.0/24"), "the IPv4 route did not stay installed");
        var section = Consumer();
        var rules = section.GetProperty("rules");
        Assert.True(rules[0].GetProperty("inForce").GetBoolean());
        Assert.False(rules[1].GetProperty("inForce").GetBoolean());
        Assert.Equal(PeerEgressCodes.RuleIpv6Unsupported, rules[1].GetProperty("code").GetString());
        Assert.False(section.TryGetProperty("routeError", out _), "a route error was reported");
        Assert.False(section.GetProperty("rolledBack").GetBoolean());
        Assert.DoesNotContain(section.GetProperty("routes").EnumerateArray(), route => route.GetProperty("cidr").GetString()!.Contains(':'));
        Assert.Equal(1, CountOf(log.Text, "IPv6 rules not in force"));
        Assert.Contains("Permission denied", log.Text);
        Assert.False(_mesh.HandleOutbound(SynFrom("100.96.0.1", "2001:db8:1::5")), "an IPv6 packet was claimed without the data plane");

        // The device recreated with its address: the next reconcile puts the IPv6 rule in force.
        commander.InstallErr.Clear();
        host.Ipv6 = (true, "");
        _mesh.Reconcile(host.Rules, Start + PeerEgressRoutePlanner.RetryAfterMillis + 1_000);
        Assert.True(commander.Table.ContainsKey("2001:db8:1::/48"), "the IPv6 route was not installed once the device carried IPv6");
        Assert.Contains("2001:db8:1::443/128", commander.InstallLog);
        Assert.NotEqual(PeerEgressCodes.RuleIpv6Unsupported,
            Consumer().GetProperty("rules")[1].TryGetProperty("code", out var code) ? code.GetString() : null);
        Assert.True(_mesh.HandleOutbound(SynFrom("100.96.0.1", "2001:db8:1::5")), "the IPv6 packet was not claimed with the data plane");

        // And losing it again takes the IPv6 routes out, the IPv4 one staying.
        host.Ipv6 = (false, "the TUN is closed");
        _mesh.Reconcile(host.Rules, Start + PeerEgressRoutePlanner.RetryAfterMillis + 2_000);
        Assert.False(commander.Table.ContainsKey("2001:db8:1::/48"), "the IPv6 route stayed after the device stopped carrying IPv6");
        Assert.True(commander.Table.ContainsKey("203.0.113.0/24"), "the IPv4 route went with the IPv6 one");
        Assert.Equal(2, CountOf(log.Text, "IPv6 rules not in force"));
    }

    private static int CountOf(string text, string part)
    {
        var count = 0;
        for (var index = text.IndexOf(part, StringComparison.Ordinal); index >= 0; index = text.IndexOf(part, index + 1, StringComparison.Ordinal))
        {
            count++;
        }
        return count;
    }

    /// <summary>A device that is not up, or that does not carry IPv6, has no data plane whatever the platform says.</summary>
    [Fact]
    public void OnlyAnUpDeviceWithItsAddressCarriesIpv6()
    {
        var (host, _, _) = NewMesh();
        Assert.True(_mesh!.Ipv6State().Carries);
        host.Ipv6 = (false, PeerEgressIpv6Plane.NotAsked);
        Assert.Equal((false, PeerEgressIpv6Plane.NotAsked), _mesh.Ipv6State());
        host.Ipv6 = (true, "");
        host.DeviceUp = false;
        host.Status = "NOOP";
        Assert.Equal((false, "the virtual device is NOOP"), _mesh.Ipv6State());
        host.DeviceUp = true;
        host.Platform = false;
        Assert.False(_mesh.Ipv6State().Carries);

        // The noop device itself says nothing about IPv6, and the host reads that as no.
        Assert.False(typeof(IPeerVirtualDeviceIpv6).IsAssignableFrom(typeof(NoopPeerVirtualDevice)));
    }

    // ---- the bypass resolver and the catalogue --------------------------------------------------------

    /// <summary>The bypass resolver gives IPv6 answers and literals only through Resolve6, in RFC 5952 form.</summary>
    [Fact]
    public void TheResolverResolvesIpv6Apart()
    {
        var calls = 0;
        var resolver = new PeerEgressBypassResolver(name =>
        {
            calls++;
            return name == "stun.example.test"
                ? [IPAddress.Parse("2001:DB8:0::1"), IPAddress.Parse("203.0.113.60"), IPAddress.Parse("::ffff:198.51.100.2")]
                : throw new SocketException((int)SocketError.HostNotFound);
        });
        string?[] entries = ["https://[2001:db8::443]:8443/login", "stun.example.test:3478", "[2001:db8::2]:3478",
            "2001:db8::3", "198.51.100.1", "[fe80::1%eth0]:3478", "::ffff:192.0.2.1"];
        Assert.Equal(["203.0.113.60", "198.51.100.1"], resolver.Resolve(entries, Start).Addresses);
        Assert.Equal(["2001:db8::443", "2001:db8::1", "2001:db8::2", "2001:db8::3"], resolver.Resolve6(entries, Start));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void TheCatalogueListsTheEgressesThatTakeIpv6Packets()
    {
        var catalog = new PeerEgressCatalog();
        Assert.True(catalog.Read("""
            {"type":"egress-catalog","revision":1,"egresses":[{"clientId":3,"ipv6PacketCapable":true},
            {"clientId":2,"ipv6PacketCapable":true},{"clientId":4,"ipv6PacketCapable":"true"},{"clientId":5}]}
            """));
        Assert.Equal([2L, 3L], catalog.Ipv6CapableIds());
        Assert.True(catalog.Snapshot().Listed[2].Ipv6PacketCapable);
    }

    // ---- Linux -------------------------------------------------------------------------------------

    /// <summary>What <c>ip -6 route</c> says, sampled in a WSL 2 network namespace (iproute2 6.1.0) with a real TUN.</summary>
    private const string LinuxIpv6MainTable =
        "2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium\n"
        + "2001:db8:64::/64 dev eth0 proto kernel metric 256 pref medium\n"
        + "2001:db8:65::/64 dev eth1 proto kernel metric 256 pref medium\n"
        + "2001:db8:77::/48 metric 1024 pref medium\n"
        + "\tnexthop via fe80::1 dev eth0 weight 1 \n"
        + "\tnexthop via fe80::2 dev eth1 weight 1 \n"
        + "blackhole 2001:db8:dead::/48 dev lo metric 1024 pref medium\n"
        + "fd53:7065:6375:7300::6460:5 dev specus0 proto kernel metric 256 linkdown pref medium\n"
        + "fe80::/64 dev eth0 proto kernel metric 256 pref medium\n"
        + "fe80::/64 dev eth1 proto kernel metric 256 pref medium\n"
        + "default via fe80::1 dev eth0 metric 1024 pref medium\n";

    [Fact]
    public void TheLinuxIpv6TableAndCommandsReadAsTheyShould()
    {
        var routes = PeerEgressRouteCommands.ParseRouteTable6(LinuxIpv6MainTable);
        Assert.Equal(
        [
            new PeerEgressBindRoute("2001:db8:1::/48", "specus0", "", 1024, true),
            new PeerEgressBindRoute("2001:db8:64::/64", "eth0", "", 256, true),
            new PeerEgressBindRoute("2001:db8:65::/64", "eth1", "", 256, true),
            new PeerEgressBindRoute("2001:db8:77::/48", "eth0", "fe80::1", 1024, true),
            new PeerEgressBindRoute("2001:db8:dead::/48", "", "", 1024, true),
            new PeerEgressBindRoute("fd53:7065:6375:7300::6460:5/128", "specus0", "", 256, true),
            new PeerEgressBindRoute("fe80::/64", "eth0", "", 256, true),
            new PeerEgressBindRoute("fe80::/64", "eth1", "", 256, true),
            new PeerEgressBindRoute("::/0", "eth0", "fe80::1", 1024, true),
        ], routes);
        // Each reader is only ever given its own family's table; an IPv4 prefix still reads as nothing
        // to the IPv6 one, and an IPv4 gateway is no gateway.
        var mixed = Assert.Single(PeerEgressRouteCommands.ParseRouteTable6("10.0.0.0/8 dev eth0 \n2001:db8::/32 via 192.168.64.1 dev eth0 \n"));
        Assert.Equal(("2001:db8::/32", ""), (mixed.Prefix, mixed.Gateway));

        // The fallback hop for an address the tunnel's own route covers: past the tunnel, the default
        // through the link-local gateway; behind the blackhole, nothing.
        var hop = PeerEgressSocketBinding.SelectBypassHop(routes, "specus0", [], "2001:db8:1::9");
        Assert.Equal(("eth0", "fe80::1"), (hop?.Interface, hop?.Gateway));
        Assert.Null(PeerEgressSocketBinding.SelectBypassHop(routes, "specus0", [], "2001:db8:dead::9"));
        Assert.Throws<PeerEgressNoPhysicalRouteException>(() =>
            PeerEgressSocketBinding.BypassHopFromTable("2001:db8:dead::9", "specus0", () => routes));
        // A bypass being put back leaves its own /128 out.
        var putBack = PeerEgressSocketBinding.BypassHopFromTable("2001:db8:1::9", "specus0",
            () => [.. routes, new PeerEgressBindRoute("2001:db8:1::9/128", "eth1", "fe80::2", 0, true)]);
        Assert.Equal("eth0", putBack.Interface);

        Assert.Equal(new PeerEgressRouteHop("", "specus0"), PeerEgressRouteCommands.ParseRouteGet(
            "2001:db8:1::9 from :: dev specus0 src fd53:7065:6375:7300::6460:5 metric 1024 pref medium\n"));
        Assert.Equal(new PeerEgressRouteHop("fe80::1", "eth0"), PeerEgressRouteCommands.ParseRouteGet(
            "2001:db8:5::9 from :: via fe80::1 dev eth0 src 2001:db8:64::7 metric 1024 pref medium\n"));
        Assert.Equal(new PeerEgressRouteHop("", "eth0"), PeerEgressRouteCommands.ParseRouteGet(
            "2001:db8:64::9 from :: dev eth0 proto kernel src 2001:db8:64::7 metric 256 pref medium\n"));
        Assert.Equal(new PeerEgressExistingRoute(true, "2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium"),
            PeerEgressRouteCommands.ParseShowExact("2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium\n"));

        // The commands: IPv4 exactly as before, IPv6 with -6.
        Assert.Equal("route add 203.0.113.0/24 dev specus0",
            string.Join(' ', PeerEgressRouteCommands.RouteArgs("203.0.113.0/24", "add", "203.0.113.0/24", "dev", "specus0")));
        Assert.Equal("-6 route add 2001:db8:1::/48 dev specus0",
            string.Join(' ', PeerEgressRouteCommands.RouteArgs("2001:db8:1::/48", "add", "2001:db8:1::/48", "dev", "specus0")));
        Assert.Equal("-6 route add 2001:db8:1::9/128 via fe80::1 dev eth0", string.Join(' ',
            PeerEgressRouteCommands.RouteArgs("2001:db8:1::9/128", "add", "2001:db8:1::9/128", "via", "fe80::1", "dev", "eth0")));
        Assert.Equal("-6 route get 2001:db8:1::9",
            string.Join(' ', PeerEgressRouteCommands.RouteArgs("2001:db8:1::9/128", "get", "2001:db8:1::9")));
        Assert.Equal("-6 route show exact 2001:db8:1::/48",
            string.Join(' ', PeerEgressRouteCommands.RouteArgs("2001:db8:1::/48", "show", "exact", "2001:db8:1::/48")));
        Assert.Equal("-6 route del 2001:db8:1::/48",
            string.Join(' ', PeerEgressRouteCommands.RouteArgs("2001:db8:1::/48", "del", "2001:db8:1::/48")));
        Assert.Equal("-6 route show table main", string.Join(' ', PeerEgressRouteCommands.ShowMainTableArgs6()));
    }

    // ---- Windows -----------------------------------------------------------------------------------

    [Fact]
    public void TheWindowsIpv6ScriptsAreBuiltFromCheckedValuesOnly()
    {
        Assert.Equal("try{New-NetRoute -AddressFamily IPv6 -DestinationPrefix '2001:db8:1::/48' -NextHop '::' "
            + "-InterfaceIndex 9 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress "
            + "-InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}",
            PeerEgressWindowsRouteCommands.InstallRouteScript6("2001:db8:1::/48", 9, ""));
        Assert.Contains("-DestinationPrefix '2001:db8:1::9/128' -NextHop 'fe80::1' -InterfaceIndex 3 ",
            PeerEgressWindowsRouteCommands.InstallRouteScript6("2001:db8:1::9/128", 3, "fe80::1"));
        Assert.Equal("try{Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '2001:db8:1::/48' -Confirm:$false "
            + "-PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress -InputObject "
            + "@{errorId=$_.FullyQualifiedErrorId};exit 1}",
            PeerEgressWindowsRouteCommands.RemoveRouteScript6("2001:db8:1::/48"));
        Assert.Equal("foreach($a in @('2001:db8:1::9')){ConvertTo-Json -Compress -InputObject "
            + "@(Find-NetRoute -RemoteIPAddress $a -ErrorAction SilentlyContinue|Select-Object "
            + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0",
            PeerEgressWindowsRouteCommands.FindRoutesScript6(["2001:db8:1::9"]));
        Assert.Equal(PeerEgressWindowsRouteCommands.ShowAllRoutesScript().Replace("IPv4", "IPv6"),
            PeerEgressWindowsRouteCommands.ShowAllRoutesScript6());
        var assign = PeerEgressWindowsRouteCommands.AssignAddress6Script(17, "fd53:7065:6375:7300::6460:1", 1280);
        Assert.Contains("New-NetIPAddress -AddressFamily IPv6 -IPAddress 'fd53:7065:6375:7300::6460:1' "
            + "-PrefixLength 128 -InterfaceIndex 17 -PolicyStore ActiveStore", assign);
        Assert.Contains("Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex 17 -NlMtuBytes 1280 -PolicyStore ActiveStore", assign);

        // Nothing but an IPv6 prefix in the canonical form reaches an IPv6 script, and nothing IPv6
        // reaches an IPv4 one.
        foreach (var bad in new[] { "2001:db8:1::/48';Remove-NetRoute -DestinationPrefix '::/0", "2001:DB8:1::/48",
                     "2001:db8:1:0::/48", "2001:db8:1::", "203.0.113.0/24", "$(Get-NetRoute)", "fe80::1%3/128", "" })
        {
            Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.InstallRouteScript6(bad, 9, ""));
            Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.RemoveRouteScript6(bad));
        }
        foreach (var bad in new[] { "fe80::1%3", "[2001:db8::1]", "::ffff:192.0.2.1", "2001:db8::1'", "203.0.113.9" })
        {
            Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.FindRoutesScript6([bad]));
            Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.InstallRouteScript6("2001:db8:1::9/128", 3, bad));
        }
        Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.InstallRouteScript("2001:db8:1::/48", 9, null));
        Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.AssignAddress6Script(0, "fd53:7065:6375:7300::6460:1", 1280));
        Assert.Throws<ArgumentException>(() => PeerEgressWindowsRouteCommands.AssignAddress6Script(17, "fd53::1';x", 1280));
    }

    /// <summary>
    /// Get-NetRoute -AddressFamily IPv6 as it comes back (shape sampled on Windows 11, Windows
    /// PowerShell 5.1: on-link is "::"): the conflict check compares by value, and the find reads the
    /// route, not the source-address object.
    /// </summary>
    [Fact]
    public void TheWindowsIpv6TableReadsByValue()
    {
        const string table = """
            [{"InterfaceIndex":44,"DestinationPrefix":"ff00::/8","NextHop":"::","RouteMetric":256},
            {"InterfaceIndex":3,"DestinationPrefix":"2001:db8:1::/48","NextHop":"fe80::1","RouteMetric":0},
            {"InterfaceIndex":3,"DestinationPrefix":"2001:DB8:2:0::/48","NextHop":"::","RouteMetric":5}]
            """;
        Assert.Equal(new PeerEgressExistingRoute(true, "2001:db8:1::/48 nexthop fe80::1 ifIndex 3 metric 0"),
            PeerEgressWindowsRouteCommands.ConflictFromTable6(table, "2001:db8:1::/48"));
        Assert.Equal(new PeerEgressExistingRoute(true, "2001:DB8:2:0::/48 on-link ifIndex 3 metric 5"),
            PeerEgressWindowsRouteCommands.ConflictFromTable6(table, "2001:db8:2::/48"));
        Assert.False(PeerEgressWindowsRouteCommands.ConflictFromTable6(table, "2001:db8:3::/48").Present);
        Assert.False(PeerEgressWindowsRouteCommands.ConflictFromTable6("[]", "2001:db8:1::/48").Present);
        // The IPv4 reading of the same table finds nothing: it compares text, and IPv4 text.
        Assert.False(PeerEgressWindowsRouteCommands.ConflictFromTable(table, "2001:db8:2::/48").Present);

        var hop = PeerEgressWindowsRouteCommands.ParseRouteFind("""
            [{"InterfaceIndex":3,"DestinationPrefix":null,"NextHop":null,"RouteMetric":null},
            {"InterfaceIndex":3,"DestinationPrefix":"::/0","NextHop":"fe80::1","RouteMetric":0}]
            """);
        Assert.Equal(new PeerEgressWindowsRouteHop("fe80::1", 3), hop);
        Assert.Equal(new PeerEgressWindowsRouteHop("", 3), PeerEgressWindowsRouteCommands.ParseRouteFind(
            """[{"InterfaceIndex":3,"DestinationPrefix":"2001:db8:64::/64","NextHop":"::","RouteMetric":256}]"""));
    }

    [Fact]
    public void TheWindowsCommanderRefusesAnInjectedIpv6PrefixBeforeRunningAnything()
    {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        foreach (var cidr in new[] { "2001:db8::/32';Remove-NetRoute -DestinationPrefix '::/0", "2001:DB8::/32",
                     "2001:db8::/129", "2001:db8::1/32", "fe80::1%3/128" })
        {
            var route = Tun(cidr, "rule:" + cidr);
            Assert.Throws<ArgumentException>(() => commander.Install(route));
            Assert.Throws<ArgumentException>(() => commander.Remove(route));
        }
        Assert.False(commander.TableRead || commander.Table6Read, "a refused route ran a query");
    }

    // ---- macOS -------------------------------------------------------------------------------------

    [Fact]
    public void TheMacosIpv6CommandsAndReadings()
    {
        Assert.Equal("route -n add -inet6 -net 2001:db8:1::/48 -interface utun4",
            string.Join(' ', PeerEgressMacosRouteCommands.InstallInterfaceArgs6("2001:db8:1::/48", "utun4")));
        Assert.Equal("route -n add -inet6 -net 2001:db8:1::9/128 fe80::1%en0",
            string.Join(' ', PeerEgressMacosRouteCommands.InstallGatewayArgs6("2001:db8:1::9/128", "fe80::1%en0")));
        Assert.Equal("route -n delete -inet6 -net 2001:db8:1::/48",
            string.Join(' ', PeerEgressMacosRouteCommands.RemoveArgs6("2001:db8:1::/48")));
        Assert.Equal("route -n get -inet6 2001:db8:1::9", string.Join(' ', PeerEgressMacosRouteCommands.FindRouteArgs6("2001:db8:1::9")));
        Assert.Equal("ifconfig utun4 inet6 fd53:7065:6375:7300::6460:1 prefixlen 128",
            string.Join(' ', PeerEgressMacosRouteCommands.AssignAddress6Args("utun4", "fd53:7065:6375:7300::6460:1")));
        Assert.Equal("netstat -rn -f inet6", string.Join(' ', PeerEgressMacosRouteCommands.ShowTableArgs6()));
        foreach (var bad in new[] { "2001:DB8:1::/48", "2001:db8:1::/129", "2001:db8:1::", "-net", "203.0.113.0/24" })
        {
            Assert.Throws<ArgumentException>(() => PeerEgressMacosRouteCommands.InstallInterfaceArgs6(bad, "utun4"));
            Assert.Throws<ArgumentException>(() => PeerEgressMacosRouteCommands.RemoveArgs6(bad));
        }
        foreach (var bad in new[] { "fe80::1%-x", "fe80::1%en0 extra", "[fe80::1]", "-inet6" })
        {
            Assert.Throws<ArgumentException>(() => PeerEgressMacosRouteCommands.InstallGatewayArgs6("2001:db8:1::9/128", bad));
        }
        Assert.Throws<ArgumentException>(() => PeerEgressMacosRouteCommands.FindRouteArgs6("fe80::1%en0"));
        Assert.Throws<ArgumentException>(() => PeerEgressMacosRouteCommands.AssignAddress6Args("-utun4", "fd53:7065:6375:7300::6460:1"));
        Assert.Throws<ArgumentException>(() => PeerEgressMacosRouteCommands.InstallInterfaceArgs("2001:db8:1::/48", "utun4"));

        const string get = "   route to: 2001:db8:1::9\ndestination: default\n       mask: default\n    gateway: fe80::1%en0\n"
            + "  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        Assert.Equal(new PeerEgressRouteHop("fe80::1%en0", "en0"), PeerEgressMacosRouteCommands.ParseRouteGet6(get, ""));
        Assert.Equal(new PeerEgressRouteHop("", "en0"),
            PeerEgressMacosRouteCommands.ParseRouteGet6("   route to: 2001:db8:64::9\n    gateway: link#6\n  interface: en0\n", ""));
        Assert.Null(PeerEgressMacosRouteCommands.ParseRouteGet6("", "route: writing to routing socket: not in table\n"));

        const string table = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n"
            + "default            192.168.1.1        UGScg                 en0\n\nInternet6:\n"
            + "Destination                             Gateway                                 Flags               Netif Expire\n"
            + "default                                 fe80::1%en0                             UGcg                  en0\n"
            + "2001:db8:1::/48                         utun4                                   USc                 utun4\n"
            + "2001:db8:5::9                           fe80::1%en0                             UGHS                  en0\n"
            + "2001:db8:64::9                          a4:83:e7:0:0:1                          UHLWIi                en0\n";
        Assert.Equal(new PeerEgressExistingRoute(true, "2001:db8:1::/48 gateway utun4 netif utun4 flags USc"),
            PeerEgressMacosRouteCommands.ConflictFromTable6(table, "2001:db8:1::/48"));
        Assert.False(PeerEgressMacosRouteCommands.ConflictFromTable6(table, "2001:db8:64::9/128").Present,
            "a kernel-generated neighbour entry conflicted");
        Assert.True(PeerEgressMacosRouteCommands.ConflictFromTable6(table, "::/0").Present);
        Assert.True(PeerEgressMacosRouteCommands.ConflictFromTable(table, "0.0.0.0/0").Present);
        var routes = PeerEgressSocketBinding.MacosBypassRoutes6(table);
        var hop = PeerEgressSocketBinding.SelectBypassHop(routes, "utun4", [], "2001:db8:1::9");
        Assert.Equal(("en0", "fe80::1%en0"), (hop?.Interface, hop?.Gateway));
        Assert.Equal("fe80::1%en0", routes.Single(route => route.Prefix == "2001:db8:5::9/128").Gateway);
        // The socket binder's reading keeps no gateway: choosing an interface needs none.
        Assert.All(PeerEgressSocketBinding.MacosRoutes6(table), route => Assert.Equal("", route.Gateway));
    }

    [Fact]
    public void TheMacosCommanderRefusesAMalformedIpv6PrefixBeforeRunningAnything()
    {
        var commander = new MacosPeerEgressRouteCommander("lo0");
        foreach (var cidr in new[] { "2001:DB8::/32", "2001:db8::/129", "2001:db8::1/32", "2001:db8::", "-inet6" })
        {
            Assert.Throws<ArgumentException>(() => commander.Install(Tun(cidr, "rule:" + cidr)));
        }
    }
}
