using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Replays <c>peer-egress-routes-v1.json</c> against the .NET route planner.
/// </summary>
/// <remarks>
/// Unlike the TCP fixture, this one's expectations come from an independent reference planner in
/// <c>tools/protocol/generate_peer_egress_route_vectors.py</c> rather than from any implementation,
/// so agreeing with it is independent agreement rather than a shared mistake.
///
/// <para>The operator-visible <c>origin</c> string is asserted too. Three runtimes that installed
/// the same prefixes but described them differently would still leave an operator unable to compare
/// one machine's log with another's.</para>
/// </remarks>
public class PeerEgressRouteVectorTests
{
    private static JsonDocument ReadVector(string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException($"cannot locate {name}");
    }

    private static List<PeerEgressRoute> RoutesOf(JsonElement array)
    {
        var routes = new List<PeerEgressRoute>();
        foreach (var node in array.EnumerateArray())
        {
            routes.Add(new PeerEgressRoute(
                node.GetProperty("cidr").GetString()!,
                PeerEgressRoutePlanner.KindFromWireName(node.GetProperty("kind").GetString()),
                node.GetProperty("origin").GetString()!));
        }
        return routes;
    }

    private static void AssertRoutes(string label, IReadOnlyList<PeerEgressRoute> got, JsonElement want)
    {
        var expected = RoutesOf(want);
        Assert.True(expected.Count == got.Count,
            $"{label}: planned {got.Count} routes, want {expected.Count}: {string.Join(", ", got)}");
        for (var index = 0; index < expected.Count; index++)
        {
            Assert.Equal(expected[index], got[index]);
        }
    }

    private static PeerEgressRule RuleOf(JsonElement node) => new()
    {
        Match = node.TryGetProperty("match", out var match) ? match.GetString() ?? string.Empty : string.Empty,
        Action = node.TryGetProperty("action", out var action) ? action.GetString() ?? string.Empty : string.Empty,
        EgressClientId = node.TryGetProperty("egressClientId", out var target) ? target.GetInt64() : null,
        Port = node.TryGetProperty("port", out var port) ? port.GetInt32() : null,
    };

    [Fact]
    public void RoutePlansMatchTheSharedVector()
    {
        using var vector = ReadVector("peer-egress-routes-v1.json");
        var meshCidr = vector.RootElement.GetProperty("meshCidr").GetString();
        var planCases = vector.RootElement.GetProperty("planCases");
        Assert.True(planCases.GetArrayLength() > 0, "routes vector carried no plan cases");

        foreach (var testCase in planCases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            var rules = testCase.GetProperty("rules").EnumerateArray().Select(RuleOf).ToList();
            var bypass = testCase.GetProperty("bypass").EnumerateArray()
                .Select(node => node.GetString() ?? string.Empty).ToList();

            var plan = PeerEgressRoutePlanner.Plan(rules, bypass, meshCidr);
            AssertRoutes(name, plan.Routes, testCase.GetProperty("expect").GetProperty("routes"));

            // Asserted alongside the routes because a planner that silently dropped a bad rule
            // would produce exactly the same route list.
            var wantRefused = testCase.GetProperty("expect").GetProperty("refused");
            Assert.True(wantRefused.GetArrayLength() == plan.Refused.Count,
                $"{name}: refused {plan.Refused.Count} rules, want {wantRefused.GetArrayLength()}");
            var index = 0;
            foreach (var want in wantRefused.EnumerateArray())
            {
                var got = plan.Refused[index];
                Assert.Equal(want.GetProperty("index").GetInt32(), got.Index);
                Assert.Equal(want.GetProperty("match").GetString(), got.Match);
                Assert.Equal(want.GetProperty("code").GetString(), got.Code);
                index++;
            }
        }
    }

    [Fact]
    public void RouteDiffsMatchTheSharedVector()
    {
        using var vector = ReadVector("peer-egress-routes-v1.json");
        var diffCases = vector.RootElement.GetProperty("diffCases");
        Assert.True(diffCases.GetArrayLength() > 0, "routes vector carried no diff cases");

        foreach (var testCase in diffCases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            var difference = PeerEgressRoutePlanner.Diff(
                RoutesOf(testCase.GetProperty("current")), RoutesOf(testCase.GetProperty("desired")));
            AssertRoutes($"{name}/remove", difference.Remove, testCase.GetProperty("expect").GetProperty("remove"));
            AssertRoutes($"{name}/add", difference.Add, testCase.GetProperty("expect").GetProperty("add"));
        }
    }

    /// <summary>
    /// The parsers read output formats nobody controls, which makes them the part most likely to be
    /// wrong. Each runtime writing its own fixtures from its own reading of the man page is how
    /// three readings of one format come about, so all three read these.
    /// </summary>
    [Fact]
    public void RouteCommandParsingMatchesTheSharedVector()
    {
        using var vector = ReadVector("peer-egress-routes-v1.json");
        var commands = vector.RootElement.GetProperty("routeCommands");

        var routeGet = commands.GetProperty("routeGet");
        Assert.True(routeGet.GetArrayLength() > 0, "routes vector carried no routeGet cases");
        foreach (var testCase in routeGet.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            var hop = PeerEgressRouteCommands.ParseRouteGet(testCase.GetProperty("output").GetString());
            var expect = testCase.GetProperty("expect");
            if (!expect.GetProperty("parsed").GetBoolean())
            {
                Assert.True(hop is null, name);
                continue;
            }
            Assert.True(hop is not null, name);
            Assert.Equal(expect.GetProperty("gateway").GetString(), hop!.Value.Gateway);
            Assert.Equal(expect.GetProperty("device").GetString(), hop.Value.Device);
        }

        var showExact = commands.GetProperty("showExact");
        Assert.True(showExact.GetArrayLength() > 0, "routes vector carried no showExact cases");
        foreach (var testCase in showExact.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            var existing = PeerEgressRouteCommands.ParseShowExact(testCase.GetProperty("output").GetString());
            Assert.True(testCase.GetProperty("expect").GetProperty("present").GetBoolean() == existing.Present, name);
            Assert.Equal(testCase.GetProperty("expect").GetProperty("description").GetString(), existing.Description);
        }

        var tunnelDevice = commands.GetProperty("tunnelDevice").GetProperty("cases");
        Assert.True(tunnelDevice.GetArrayLength() > 0, "routes vector carried no tunnelDevice cases");
        foreach (var testCase in tunnelDevice.EnumerateArray())
        {
            var got = PeerEgressRouteCommands.HopIsDevice(
                new PeerEgressRouteHop(string.Empty, testCase.GetProperty("device").GetString()!),
                testCase.GetProperty("tun").GetString());
            Assert.True(testCase.GetProperty("expect").GetBoolean() == got,
                $"{testCase.GetProperty("device").GetString()} against {testCase.GetProperty("tun").GetString()}");
        }
    }
}
