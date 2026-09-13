using System.Text.Json;
using Specus.Client.Cli;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// What the status surface has to be able to say, and what a person is shown.
/// </summary>
/// <remarks>
/// The three things it exists for are a rule that is configured and not in force, a route this
/// feature wanted and did not get, and an egress peer a rule names that is offline. Each of those
/// is a way for the feature to be doing nothing while every other surface looks healthy, so each
/// one gets a case here.
///
/// <para>The shape is the one the Go client writes, because any of the three CLIs reads whichever
/// wrote the state file. <c>protocol/spec/peer-egress.md</c> is where the shape is pinned.</para>
/// </remarks>
public sealed class PeerEgressStatusTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-status-" + Guid.NewGuid().ToString("N"));

    private PeerEgressMesh? _mesh;

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
        catch (UnauthorizedAccessException)
        {
        }
        GC.SuppressFinalize(this);
    }

    private sealed class Host(string directory) : IPeerEgressMeshHost
    {
        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task WriteToDeviceAsync(byte[] packet) => Task.CompletedTask;

        public string TunName => "specus0";

        public string MeshCidr => "100.96.0.0/11";

        public string VirtualIp => "100.96.0.7";

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => ["198.51.100.240"];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");
    }

    /// <summary>A routing table whose answers this test chooses.</summary>
    private sealed class ChosenCommander(Dictionary<string, string> owned)
        : IPeerEgressRouteCommander
    {
        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) =>
            owned.TryGetValue(route.Cidr, out var existing)
                ? new PeerEgressRouteConflictCheck(true, existing)
                : PeerEgressRouteConflictCheck.None;

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

    private PeerEgressMesh MeshOwning(Dictionary<string, string> owned)
    {
        Directory.CreateDirectory(_directory);
        _mesh = new PeerEgressMesh(new Host(_directory), dialer: new RefusingDialer(),
            commander: new ChosenCommander(owned));
        return _mesh;
    }

    private static PeerEgressRule Rule(string match, long? target) =>
        new() { Match = match, Action = "egress", EgressClientId = target };

    private static JsonElement Section(PeerEgressMesh mesh) =>
        JsonSerializer.SerializeToElement(mesh.Status());

    /// <summary>
    /// A refused rule is reported as refused, with its code, rather than being left out.
    /// </summary>
    /// <remarks>
    /// Left out is the failure that matters: an operator who wrote a rule and reads a status
    /// listing only the rules that worked has no way to see that the one they care about is text in
    /// a file.
    /// </remarks>
    [Fact]
    public void ARuleThatIsNotInForceIsReportedAsSuch()
    {
        var mesh = MeshOwning([]);
        // The second rule is refused: phase one does not take over the default route.
        mesh.ApplyRules([Rule("203.0.113.0/24", 42L), Rule("0.0.0.0/0", 42L)]);

        var consumer = Section(mesh).GetProperty("consumer");
        Assert.True(consumer.GetProperty("active").GetBoolean());
        var rules = consumer.GetProperty("rules").EnumerateArray().ToList();
        Assert.Equal(2, rules.Count);
        Assert.True(rules[0].GetProperty("inForce").GetBoolean(),
            "the usable rule is not in force");
        Assert.False(rules[0].TryGetProperty("code", out _),
            "the usable rule carries a refusal code");
        Assert.False(rules[1].GetProperty("inForce").GetBoolean(),
            "the default-route rule is reported as in force");
        Assert.Equal(PeerEgressCodes.RuleDefaultRoute, rules[1].GetProperty("code").GetString());
    }

    /// <summary>
    /// A refused rule contributes no egress peer. Reporting one would advertise a peer this node
    /// will never send to, which reads as a healthy destination for a rule that steers nothing.
    /// </summary>
    [Fact]
    public void ARefusedRuleContributesNoEgressPeer()
    {
        var mesh = MeshOwning([]);
        mesh.ApplyRules([Rule("0.0.0.0/0", 77L)]);

        Assert.Empty(Section(mesh).GetProperty("consumer").GetProperty("peers")
            .EnumerateArray());
    }

    /// <summary>A route refused because something already owned the prefix is listed, not dropped.</summary>
    [Fact]
    public void ARouteThatWasNotInstalledIsReported()
    {
        const string existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        var mesh = MeshOwning(new Dictionary<string, string> { ["203.0.113.0/24"] = existing });
        mesh.ApplyRules([Rule("203.0.113.0/24", 42L)]);

        var consumer = Section(mesh).GetProperty("consumer");
        var contested = consumer.GetProperty("routes").EnumerateArray()
            .Where(route => route.GetProperty("cidr").GetString() == "203.0.113.0/24")
            .ToList();
        Assert.Single(contested);
        Assert.False(contested[0].GetProperty("installed").GetBoolean(),
            "the contested route is reported as installed");
        Assert.Equal(existing, contested[0].GetProperty("conflict").GetString());
        Assert.True(consumer.TryGetProperty("appliedAtUnixMs", out _),
            "the section does not say when it was applied");
    }

    /// <summary>
    /// Before anything has been applied the section says so, rather than reporting an empty rule
    /// set, which would read as "configured and nothing matched".
    /// </summary>
    [Fact]
    public void NeverAppliedReadsDifferentlyFromNothingConfigured()
    {
        var consumer = Section(MeshOwning([])).GetProperty("consumer");
        Assert.False(consumer.GetProperty("active").GetBoolean(),
            "the consumer reports itself active before any rules were applied");
        Assert.False(consumer.TryGetProperty("appliedAtUnixMs", out _),
            "an apply time is reported before any apply happened");
    }

    /// <summary>The egress role's own half: not serving until a policy enables it.</summary>
    [Fact]
    public void WhetherThisNodeIsServingIsReported()
    {
        var mesh = MeshOwning([]);
        Assert.False(Section(mesh).GetProperty("egress").GetProperty("active").GetBoolean(),
            "the egress reports itself serving before any policy arrived");

        mesh.ApplyEgressConfig("""
            {"type":"egress-config","enabled":true,"revision":3,"scope":"PUBLIC",
             "allowedConsumerClientIds":[5],
             "destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],
                                  "portRanges":[[443,443]]}],
             "limits":{"maxConcurrentFlows":256,"maxFlowsPerConsumer":64,
                       "idleTimeoutSeconds":60}}
            """);

        var egress = Section(mesh).GetProperty("egress");
        Assert.True(egress.GetProperty("active").GetBoolean(),
            "the egress does not report itself serving");
        Assert.Equal(3L, egress.GetProperty("revision").GetInt64());
    }

    /// <summary>
    /// What a person is shown: the problems, and a count of the rest.
    /// </summary>
    /// <remarks>
    /// Rendered from the same section the JSON form carries, so this is also the check that the two
    /// do not disagree about which rule is broken.
    /// </remarks>
    [Fact]
    public void TheViewNamesTheProblemsAndCountsTheRest()
    {
        const string existing = "203.0.113.0/24 via 192.0.2.1 dev eth0";
        var mesh = MeshOwning(new Dictionary<string, string> { ["203.0.113.0/24"] = existing });
        mesh.ApplyRules([Rule("203.0.113.0/24", 42L), Rule("0.0.0.0/0", 42L)]);

        var output = string.Join("\n", EgressView.Lines(Section(mesh)));
        Assert.Contains("2 rules (1 not in force)", output);
        Assert.Contains($"rule 1 \"0.0.0.0/0\": NOT IN FORCE ({PeerEgressCodes.RuleDefaultRoute})",
            output);
        Assert.Contains($"NOT INSTALLED, already present: {existing}", output);
        // The peer named by the rule that is in force has never been reported online.
        Assert.Contains("egress peer 42: offline", output);
        Assert.Contains("egress: not serving", output);
    }

    /// <summary>
    /// The state file may have been written by the Go or Java client, so a missing or wrongly typed
    /// field has to produce a line rather than an exception. A status command that threw on a field
    /// somebody spelled differently would be worse than one that prints a zero.
    /// </summary>
    [Fact]
    public void TheViewToleratesStateItDidNotWrite()
    {
        foreach (var document in new[]
        {
            "{}",
            """{"consumer":null,"egress":null}""",
            """{"consumer":{"active":true,"rules":"not a list","routes":7,"peers":{},"flows":"three","blocked":[1,2]},"egress":{"active":"yes"}}""",
            """{"consumer":{"active":true,"rules":[null,5,{"inForce":"maybe"}],"routes":[{"installed":null}]},"egress":{"active":true,"flows":null}}""",
        })
        {
            using var parsed = JsonDocument.Parse(document);
            Assert.NotEmpty(EgressView.Lines(parsed.RootElement));
        }
        var missing = EgressView.Lines(null);
        Assert.Single(missing);
        Assert.Contains("No egress state", missing[0]);
    }
}
