using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Keeping the consumer's routes true while the process runs.
/// </summary>
/// <remarks>
/// The plan is recomputed on the mesh's tick and applied only when it changed or when a retry is
/// due. What these cases pin is the wiring around that: what the plan is fed, when the installer is
/// asked to act, and what happens to the routes when the device is not there.
/// </remarks>
public sealed class PeerEgressReconcileTests : IDisposable
{
    private const long Start = 1_758_196_800_000L;

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-reconcile-" + Guid.NewGuid().ToString("N"));

    private readonly MutableHost _host;
    private readonly LoggingCommander _commander = new();
    private readonly Dictionary<string, IPAddress[]> _lookups = new(StringComparer.Ordinal);
    private PeerEgressMesh? _mesh;
    private long _now = Start;

    public PeerEgressReconcileTests()
    {
        Directory.CreateDirectory(_directory);
        _host = new MutableHost(_directory);
    }

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

    /// <summary>A host whose answers the test changes between ticks.</summary>
    private sealed class MutableHost(string directory) : IPeerEgressMeshHost
    {
        public IReadOnlyList<PeerEgressRule> Rules { get; set; } = [];
        public bool DeviceUp { get; set; } = true;
        public IReadOnlyList<string?> Bypass { get; set; } = [];
        public IReadOnlyList<string> Peers { get; set; } = [];

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task WriteToDeviceAsync(byte[] packet) => Task.CompletedTask;

        public string TunName => "specus0";

        public string MeshCidr => "100.96.0.0/11";

        public string VirtualIp => "100.96.0.1";

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => Peers;

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");

        public IReadOnlyList<PeerEgressRule> ConsumerRules => Rules;

        public bool DeviceReady => DeviceUp;

        public IReadOnlyList<string?> BypassHosts() => Bypass;
    }

    /// <summary>A routing table that records what it was asked, and whose conflicts the test chooses.</summary>
    private sealed class LoggingCommander : IPeerEgressRouteCommander
    {
        public Dictionary<string, string> Foreign { get; } = new(StringComparer.Ordinal);
        public List<string> ConflictLog { get; } = [];
        public List<string> InstallLog { get; } = [];
        public List<string> RemoveLog { get; } = [];

        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route)
        {
            ConflictLog.Add(route.Cidr);
            return Foreign.TryGetValue(route.Cidr, out var existing)
                ? new PeerEgressRouteConflictCheck(true, existing)
                : PeerEgressRouteConflictCheck.None;
        }

        public void Install(PeerEgressRoute route) => InstallLog.Add(route.Cidr);

        public void Remove(PeerEgressRoute route) => RemoveLog.Add(route.Cidr);
    }

    private sealed class RefusingDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            throw new IOException("nothing is dialled in this test");
    }

    private PeerEgressMesh NewMesh(params PeerEgressRule[] rules)
    {
        _host.Rules = rules;
        _mesh = new PeerEgressMesh(_host, dialer: new RefusingDialer(), commander: _commander,
            lookup: name => _lookups.TryGetValue(name, out var answer)
                ? answer
                : throw new SocketException((int)SocketError.HostNotFound));
        return _mesh;
    }

    private static PeerEgressRule EgressTo(string match, long target) =>
        new() { Match = match, Action = "egress", EgressClientId = target };

    private JsonElement Consumer() =>
        JsonSerializer.SerializeToElement(_mesh!.Status()).GetProperty("consumer");

    /// <summary>
    /// With no rules there is nothing for a consumer to do, so none is built and the status says
    /// so. The journal is still read, which the next case proves.
    /// </summary>
    [Fact]
    public void BuildsNoConsumerWithoutRules()
    {
        var mesh = NewMesh();
        mesh.Reconcile([], _now);

        Assert.False(Consumer().GetProperty("active").GetBoolean(),
            "the status reports a consumer with no rules as active");
    }

    /// <summary>
    /// A journal from a process that was killed describes routes whose interface is gone. They are
    /// taken back on the first reconcile -- with no rules at all, which is the case that used to
    /// leave them.
    /// </summary>
    [Fact]
    public void TakesBackRoutesLeftByAPreviousRun()
    {
        File.WriteAllText(Path.Combine(_directory, "egress-routes.json"), """
            {"version":1,"routes":[
              {"cidr":"198.51.100.7/32","kind":"bypass","origin":"bypass"},
              {"cidr":"203.0.113.0/24","kind":"tun","origin":"rule:203.0.113.0/24"}]}
            """);
        var mesh = NewMesh();

        mesh.Reconcile([], _now);

        Assert.Contains("203.0.113.0/24", _commander.RemoveLog);
        Assert.Contains("198.51.100.7/32", _commander.RemoveLog);
        Assert.False(File.Exists(Path.Combine(_directory, "egress-routes.json")),
            "the journal still exists after its routes were taken back");
    }

    /// <summary>
    /// An unchanged plan is not reapplied, and the table is not asked about it again. When a peer's
    /// endpoint falls under a rule, its bypass goes in on the next tick; when the peer goes, so
    /// does the bypass.
    /// </summary>
    [Fact]
    public void AppliesOnlyWhenThePlanChanges()
    {
        var mesh = NewMesh(EgressTo("203.0.113.0/24", 2L));

        mesh.Reconcile(_host.Rules, _now);
        Assert.Contains("203.0.113.0/24", _commander.InstallLog);
        var first = Consumer().GetProperty("appliedAtUnixMs").GetInt64();
        var queries = _commander.ConflictLog.Count;

        _now += 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.True(first == Consumer().GetProperty("appliedAtUnixMs").GetInt64(),
            "an unchanged plan was applied again");
        Assert.True(queries == _commander.ConflictLog.Count, "an unchanged plan queried the table again");

        _host.Peers = ["203.0.113.7"];
        _now += 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.Contains("203.0.113.7/32", _commander.InstallLog);
        Assert.True(_now == Consumer().GetProperty("appliedAtUnixMs").GetInt64(),
            "a changed plan was not applied on the tick it changed");

        _host.Peers = [];
        _now += 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.Contains("203.0.113.7/32", _commander.RemoveLog);
        Assert.DoesNotContain("203.0.113.0/24", _commander.RemoveLog);
    }

    /// <summary>
    /// A prefix somebody else owns is asked about again after the interval, not on every tick, and
    /// is installed once the other route is gone.
    /// </summary>
    [Fact]
    public void RetriesAConflictAfterTheInterval()
    {
        var mesh = NewMesh(EgressTo("203.0.113.0/24", 2L));
        _commander.Foreign["203.0.113.0/24"] = "203.0.113.0/24 via 192.0.2.1 dev eth0";

        mesh.Reconcile(_host.Rules, _now);
        Assert.Single(_commander.ConflictLog);
        Assert.Empty(_commander.InstallLog);

        _now += 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.True(_commander.ConflictLog.Count == 1, "the conflict was retried inside the interval");

        _now += PeerEgressRoutePlanner.RetryAfterMillis - 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.True(_commander.ConflictLog.Count == 2, "the conflict was not retried after the interval");

        _commander.Foreign.Clear();
        _now += PeerEgressRoutePlanner.RetryAfterMillis;
        mesh.Reconcile(_host.Rules, _now);
        Assert.Contains("203.0.113.0/24", _commander.InstallLog);
        foreach (var route in Consumer().GetProperty("routes").EnumerateArray())
        {
            Assert.False(route.TryGetProperty("conflict", out _), "the status still reports the conflict");
        }
    }

    /// <summary>Routes point into the device, so there are none until it is up, and none once it is gone.</summary>
    [Fact]
    public void FollowsTheDevice()
    {
        var mesh = NewMesh(EgressTo("203.0.113.0/24", 2L));
        _host.DeviceUp = false;

        mesh.Reconcile(_host.Rules, _now);
        Assert.Empty(_commander.InstallLog);
        Assert.True(Consumer().GetProperty("active").GetBoolean(),
            "the consumer was not built while the device was down; the rules should still be reported");

        _host.DeviceUp = true;
        _now += 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.Contains("203.0.113.0/24", _commander.InstallLog);

        _host.DeviceUp = false;
        _now += 5_000;
        mesh.Reconcile(_host.Rules, _now);
        Assert.Contains("203.0.113.0/24", _commander.RemoveLog);
    }

    /// <summary>
    /// Everything the tunnel's transport talks to is pinned when a rule covers it, whether it
    /// arrived as a URL, a name with a port, or a literal; and an IPv6 answer is not a route.
    /// </summary>
    [Fact]
    public void PinsTheTransportEndpoints()
    {
        var mesh = NewMesh(EgressTo("203.0.113.0/24", 2L));
        _lookups["api.example.test"] = [IPAddress.Parse("203.0.113.61")];
        _lookups["stun.example.test"] = [IPAddress.Parse("2001:db8::1"), IPAddress.Parse("203.0.113.60")];
        _host.Bypass = ["https://api.example.test:8443/", "stun.example.test:3478",
            "203.0.113.50", "gone.example.test", "198.51.100.9"];

        mesh.Reconcile(_host.Rules, _now);

        Assert.Contains("203.0.113.61/32", _commander.InstallLog);
        Assert.Contains("203.0.113.60/32", _commander.InstallLog);
        Assert.Contains("203.0.113.50/32", _commander.InstallLog);
        Assert.DoesNotContain("198.51.100.9/32", _commander.InstallLog);
        Assert.Equal(4, _commander.InstallLog.Count);
    }

    /// <summary>The reconcile entry point the mesh calls reads the rules from the host.</summary>
    [Fact]
    public void TheTickReadsTheRulesFromTheHost()
    {
        var mesh = NewMesh(EgressTo("203.0.113.0/24", 2L));
        mesh.ReconcileRoutes();
        Assert.Contains("203.0.113.0/24", _commander.InstallLog);
    }

    /// <summary>
    /// The resolver reads a URL, a host with a port, and a bare host or literal, and answers from
    /// its cache for the TTL -- for a failure as well as for a success.
    /// </summary>
    [Fact]
    public void TheResolverReadsEveryFormAndCaches()
    {
        var calls = new Dictionary<string, int>(StringComparer.Ordinal);
        var resolver = new PeerEgressBypassResolver(name =>
        {
            calls[name] = calls.GetValueOrDefault(name) + 1;
            return name switch
            {
                "api.example.test" => [IPAddress.Parse("203.0.113.61")],
                "stun.example.test" => [IPAddress.Parse("2001:db8::1"), IPAddress.Parse("203.0.113.60")],
                _ => throw new SocketException((int)SocketError.HostNotFound),
            };
        });
        string?[] entries = [
            "https://api.example.test:8443/login", "stun.example.test:3478", "203.0.113.9:443",
            "198.51.100.1", "", "[2001:db8::2]:3478", "gone.example.test", "stun.example.test",
        ];

        var first = resolver.Resolve(entries, Start);
        Assert.Equal(["203.0.113.61", "203.0.113.60", "203.0.113.9", "198.51.100.1"], first.Addresses);
        Assert.Equal(["gone.example.test"], first.Failed);

        // Inside the TTL nothing is asked again, and the failure is still reported from the cache.
        var again = resolver.Resolve(entries, Start + PeerEgressBypassResolver.ResolveTtlMillis - 1);
        Assert.Equal(1, calls["api.example.test"]);
        Assert.Equal(1, calls["stun.example.test"]);
        Assert.Equal(1, calls["gone.example.test"]);
        Assert.Equal(["gone.example.test"], again.Failed);

        // At the TTL everything is asked again.
        resolver.Resolve(entries, Start + PeerEgressBypassResolver.ResolveTtlMillis);
        Assert.Equal(2, calls["api.example.test"]);
        Assert.Equal(2, calls["gone.example.test"]);
    }
}
