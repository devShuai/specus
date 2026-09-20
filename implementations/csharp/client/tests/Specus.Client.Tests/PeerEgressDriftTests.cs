using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Putting back what the routing table lost.
/// </summary>
/// <remarks>
/// The comparison is pinned by the shared vector; what is argued here is what the installer does
/// with it -- which routes are taken out and put back, which are given up as somebody else's, and
/// what happens to the journal in each case -- and that the mesh's tick runs it and backs off.
/// </remarks>
public sealed class PeerEgressDriftTests : IDisposable
{
    private const long Start = 1_758_196_800_000L;

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-drift-" + Guid.NewGuid().ToString("N"));

    private TableCommander _commander = new();
    private PeerEgressRouteInstaller? _installer;
    private PeerEgressMesh? _mesh;

    public PeerEgressDriftTests() => Directory.CreateDirectory(_directory);

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

    /// <summary>
    /// A routing table that can be read back. The physical routes are what a test changes to move
    /// the machine to another network; where each bypass was pointed when it was installed stays
    /// put, the way a real row does.
    /// </summary>
    private sealed class TableCommander : IPeerEgressRouteCommander
    {
        public SortedDictionary<string, PeerEgressRoute> Table { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string> Foreign { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, Exception> InstallErr { get; } = new(StringComparer.Ordinal);
        public List<string> InstallLog { get; } = [];
        public List<string> RemoveLog { get; } = [];
        public List<string> ConflictLog { get; } = [];
        public string Tunnel { get; set; } = "specus0";
        public List<PeerEgressBindRoute> Physical { get; set; } =
            [new PeerEgressBindRoute("0.0.0.0/0", "eth0", "192.0.2.1", 100, true)];
        public Dictionary<string, PeerEgressBindRoute> Hops { get; } = new(StringComparer.Ordinal);
        public Exception? TableError { get; set; }

        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route)
        {
            ConflictLog.Add(route.Cidr);
            return Foreign.TryGetValue(route.Cidr, out var existing)
                ? new PeerEgressRouteConflictCheck(true, existing)
                : PeerEgressRouteConflictCheck.None;
        }

        public void Install(PeerEgressRoute route)
        {
            if (InstallErr.TryGetValue(route.Cidr, out var failure))
            {
                throw failure;
            }
            if (route.Kind == PeerEgressRouteKind.Bypass)
            {
                // Resolved the way the real commanders resolve it: from the physical routes, now.
                Hops[route.Cidr] = PeerEgressSocketBinding.SelectBypassHop(Physical, Tunnel, [], route.Cidr[..^3])
                    ?? throw new PeerEgressNoPhysicalRouteException(route.Cidr);
            }
            Table[route.Cidr] = route;
            InstallLog.Add(route.Cidr);
        }

        public void Remove(PeerEgressRoute route)
        {
            Table.Remove(route.Cidr);
            Hops.Remove(route.Cidr);
            RemoveLog.Add(route.Cidr);
        }

        public PeerEgressRouteTable TableRead()
        {
            if (TableError is not null)
            {
                throw TableError;
            }
            var rows = new List<PeerEgressBindRoute>(Physical);
            foreach (var (cidr, route) in Table)
            {
                rows.Add(route.Kind == PeerEgressRouteKind.Bypass
                    ? new PeerEgressBindRoute(cidr, Hops[cidr].Interface, Hops[cidr].Gateway, 0, true)
                    : new PeerEgressBindRoute(cidr, Tunnel, string.Empty, 0, true));
            }
            return new PeerEgressRouteTable(rows, Tunnel);
        }

        PeerEgressRouteTable IPeerEgressRouteCommander.Table() => TableRead();

        /// <summary>Drops a route from the table behind the journal's back, the way an interface going down does.</summary>
        public void Lose(string cidr)
        {
            Table.Remove(cidr);
            Hops.Remove(cidr);
        }
    }

    private static PeerEgressRoute Tun(string cidr) => new(cidr, PeerEgressRouteKind.Tun, "rule:" + cidr);

    private static PeerEgressRoute Bypass(string cidr) => new(cidr, PeerEgressRouteKind.Bypass, "bypass");

    private PeerEgressRouteInstaller Fixture()
    {
        _commander = new TableCommander();
        _installer = new PeerEgressRouteInstaller(_commander, Path.Combine(_directory, "egress-routes.json"));
        var result = _installer.Apply([Bypass("203.0.113.7/32"), Tun("203.0.113.0/24")]);
        Assert.Null(result.Error);
        Assert.Equal(2, result.Added.Count);
        return _installer;
    }

    /// <summary>A bypass being put back has its stale row still in the table; it must not choose itself.</summary>
    [Fact]
    public void TheHopFromTheTableLeavesItsOwnRouteOut()
    {
        var hop = PeerEgressSocketBinding.BypassHopFromTable("198.51.100.7", "specus0", () =>
        [
            new PeerEgressBindRoute("0.0.0.0/0", "wlan0", "10.0.0.1", 600, true),
            new PeerEgressBindRoute("198.51.100.7/32", "eth0", "192.168.64.1", 0, true),
        ]);
        Assert.Equal("wlan0", hop.Interface);
        Assert.Equal("10.0.0.1", hop.Gateway);
    }

    /// <summary>A healthy table costs nothing: no removals, no installs, no conflict queries.</summary>
    [Fact]
    public void RepairLeavesAHealthyTableAlone()
    {
        var installer = Fixture();
        var installs = _commander.InstallLog.Count;
        var queries = _commander.ConflictLog.Count;

        var result = installer.Repair();
        Assert.Null(result.TableError);
        Assert.Null(result.Error);
        Assert.Empty(result.Repaired);
        Assert.Empty(result.Lost);
        Assert.Equal(installs, _commander.InstallLog.Count);
        Assert.Equal(queries, _commander.ConflictLog.Count);
        Assert.Empty(_commander.RemoveLog);
    }

    /// <summary>A route the kernel dropped is put back, and stays in the journal throughout.</summary>
    [Fact]
    public void RepairPutsBackARouteTheTableLost()
    {
        var installer = Fixture();
        _commander.Lose("203.0.113.0/24");

        var result = installer.Repair();
        Assert.Null(result.Error);
        Assert.Single(result.Repaired);
        Assert.Equal(PeerEgressSocketBinding.DriftMissing, result.Repaired[0].Reason);
        Assert.Equal(2, _commander.InstallLog.Count(cidr => cidr == "203.0.113.0/24"));
        Assert.True(installer.Owns("203.0.113.0/24"), "the route left the journal while it was being put back");
        Assert.Empty(installer.Repair().Repaired);
    }

    /// <summary>
    /// Back from sleep on another network: the bypass still names the old gateway, so it is moved
    /// to the new one. The tunnel route, which did not move, is not touched.
    /// </summary>
    [Fact]
    public void RepairMovesABypassToTheNewGateway()
    {
        var installer = Fixture();
        _commander.Physical = [new PeerEgressBindRoute("0.0.0.0/0", "wlan0", "10.0.0.1", 600, true)];

        var result = installer.Repair();
        Assert.Null(result.Error);
        Assert.Single(result.Repaired);
        Assert.Equal(PeerEgressSocketBinding.DriftMoved, result.Repaired[0].Reason);
        Assert.Equal("203.0.113.7/32", result.Repaired[0].Route.Cidr);
        Assert.Equal(["203.0.113.7/32"], _commander.RemoveLog);
        Assert.Equal("wlan0", _commander.Hops["203.0.113.7/32"].Interface);
        Assert.Equal("10.0.0.1", _commander.Hops["203.0.113.7/32"].Gateway);
        Assert.Empty(installer.Repair().Repaired);
    }

    /// <summary>
    /// A prefix somebody else took while ours was gone is theirs: reported, dropped from the
    /// journal, and not installed over.
    /// </summary>
    [Fact]
    public void RepairGivesUpAPrefixSomebodyElseTook()
    {
        var installer = Fixture();
        const string existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        _commander.Lose("203.0.113.0/24");
        _commander.Physical.Add(new PeerEgressBindRoute("203.0.113.0/24", "eth0", "192.0.2.1", 0, true));
        _commander.Foreign["203.0.113.0/24"] = existing;
        var installs = _commander.InstallLog.Count;

        var result = installer.Repair();
        Assert.Null(result.Error);
        Assert.Empty(result.Repaired);
        Assert.Single(result.Lost);
        Assert.Equal("203.0.113.0/24", result.Lost[0].Route.Cidr);
        Assert.Equal(existing, result.Lost[0].Existing);
        Assert.Equal(installs, _commander.InstallLog.Count);
        Assert.DoesNotContain("203.0.113.0/24", _commander.RemoveLog);
        Assert.False(installer.Owns("203.0.113.0/24"), "a prefix somebody else holds is still in the journal");
        Assert.DoesNotContain("203.0.113.0/24", File.ReadAllText(Path.Combine(_directory, "egress-routes.json")));
    }

    /// <summary>A reinstall that fails keeps the route owned, so the next repair tries again.</summary>
    [Fact]
    public void RepairKeepsARouteItCouldNotPutBack()
    {
        var installer = Fixture();
        _commander.Lose("203.0.113.0/24");
        _commander.InstallErr["203.0.113.0/24"] = new IOException("permission denied");

        var result = installer.Repair();
        Assert.NotNull(result.Error);
        Assert.Empty(result.Repaired);
        Assert.True(installer.Owns("203.0.113.0/24"), "a route that could not be put back was dropped");

        _commander.InstallErr.Clear();
        var again = installer.Repair();
        Assert.Null(again.Error);
        Assert.Single(again.Repaired);
    }

    [Fact]
    public void RepairReportsAnUnreadableTable()
    {
        var installer = Fixture();
        _commander.TableError = new IOException("ip: not found");

        var result = installer.Repair();
        Assert.NotNull(result.TableError);
        Assert.Empty(result.Repaired);
        Assert.Empty(result.Lost);
    }

    // ---- the tick --------------------------------------------------------------------------------

    private sealed class Host(string directory) : IPeerEgressMeshHost
    {
        public IReadOnlyList<PeerEgressRule> Rules { get; set; } = [];

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task WriteToDeviceAsync(byte[] packet) => Task.CompletedTask;

        public string TunName => "specus0";

        public string MeshCidr => "100.96.0.0/11";

        public string VirtualIp => "100.96.0.1";

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => [];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");

        public IReadOnlyList<PeerEgressRule> ConsumerRules => Rules;
    }

    private sealed class RefusingDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            throw new IOException("nothing is dialled in this test");
    }

    private Host MeshWithRule()
    {
        var host = new Host(_directory)
        {
            Rules = [new PeerEgressRule { Match = "203.0.113.0/24", Action = "egress", EgressClientId = 2L }],
        };
        _commander = new TableCommander();
        _mesh = new PeerEgressMesh(host, dialer: new RefusingDialer(), commander: _commander);
        return host;
    }

    private JsonElement Consumer() =>
        JsonSerializer.SerializeToElement(_mesh!.Status()).GetProperty("consumer");

    /// <summary>The tick puts routes back, and backs off when it cannot.</summary>
    [Fact]
    public void TheTickPutsBackRoutesTheTableLost()
    {
        var host = MeshWithRule();
        var now = Start;
        _mesh!.Reconcile(host.Rules, now);
        var applied = Consumer().GetProperty("appliedAtUnixMs").GetInt64();

        _commander.Lose("203.0.113.0/24");
        now += 5_000;
        _mesh.Reconcile(host.Rules, now);
        Assert.Equal(2, _commander.InstallLog.Count(cidr => cidr == "203.0.113.0/24"));
        Assert.Equal(applied, Consumer().GetProperty("appliedAtUnixMs").GetInt64());

        _commander.Lose("203.0.113.0/24");
        _commander.InstallErr["203.0.113.0/24"] = new IOException("permission denied");
        now += 5_000;
        _mesh.Reconcile(host.Rules, now);
        var attempts = _commander.InstallLog.Count;
        now += 5_000;
        _mesh.Reconcile(host.Rules, now);
        Assert.True(attempts == _commander.InstallLog.Count,
            "a failed reinstall was retried on the next tick rather than after the interval");
        _commander.InstallErr.Clear();
        now += PeerEgressRoutePlanner.RetryAfterMillis;
        _mesh.Reconcile(host.Rules, now);
        Assert.True(_commander.Table.ContainsKey("203.0.113.0/24"), "the route was not put back once the interval had passed");
    }

    /// <summary>
    /// A prefix another route took shows in the status as not installed, and the plan asks for it
    /// again after the interval.
    /// </summary>
    [Fact]
    public void APrefixLostToAnotherRouteIsReported()
    {
        var host = MeshWithRule();
        var now = Start;
        _mesh!.Reconcile(host.Rules, now);

        const string existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        _commander.Lose("203.0.113.0/24");
        _commander.Physical.Add(new PeerEgressBindRoute("203.0.113.0/24", "eth0", "192.0.2.1", 0, true));
        _commander.Foreign["203.0.113.0/24"] = existing;
        now += 5_000;
        _mesh.Reconcile(host.Rules, now);

        var reported = Consumer().GetProperty("routes").EnumerateArray()
            .Single(route => route.GetProperty("cidr").GetString() == "203.0.113.0/24");
        Assert.False(reported.GetProperty("installed").GetBoolean());
        Assert.Equal(existing, reported.GetProperty("conflict").GetString());

        // The other route goes away; the plan, marked troubled, asks again after the interval.
        _commander.Physical.RemoveAt(1);
        _commander.Foreign.Clear();
        now += 5_000;
        _mesh.Reconcile(host.Rules, now);
        Assert.False(_commander.Table.ContainsKey("203.0.113.0/24"), "the prefix was reinstalled before the interval");
        now += PeerEgressRoutePlanner.RetryAfterMillis;
        _mesh.Reconcile(host.Rules, now);
        Assert.True(_commander.Table.ContainsKey("203.0.113.0/24"), "the prefix was not asked for again");
    }
}
