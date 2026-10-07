using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Client.Runtime;

namespace Specus.Client.Tests;

/// <summary>
/// Replays <c>client.cases</c> of protocol/test-vectors/http-route-lifecycle-v1.json: the route
/// table starts from the HTTP login snapshot, then every NAT_CONTROL body goes through the real
/// control-message path (deserialization, the handler's route table and the route display). Each
/// push replaces the whole table; a missing or null <c>httpSpecusConfigList</c> is the empty table.
/// </summary>
public sealed class HttpRouteLifecycleVectorTests
{
    private const string VectorPath = "protocol/test-vectors/http-route-lifecycle-v1.json";

    public static TheoryData<string> CaseIds()
    {
        var ids = new TheoryData<string>();
        foreach (var testCase in LoadVector().Client.Cases)
        {
            ids.Add(testCase.Id);
        }
        return ids;
    }

    [Fact]
    public void EveryClientCaseOfTheVectorIsReplayed()
    {
        var cases = LoadVector().Client.Cases;
        Assert.Equal(5, cases.Count);
        Assert.Equal(cases.Count, cases.Select(testCase => testCase.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(8, cases.Sum(testCase => testCase.Steps.Count));
    }

    [Theory]
    [MemberData(nameof(CaseIds))]
    public async Task NatControlReplacesTheWholeRouteTable(string id)
    {
        var testCase = LoadVector().Client.Cases.Single(item => item.Id == id);
        await using var stream = new MemoryStream();
        await using var writer = new FrameWriter(stream);
        using var http = new HttpClient();
        using var forwarder = new DirectHttpForwarder(http);
        var directHttp = new DirectHttpHandler(testCase.LoginSnapshot, writer, forwarder,
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(Array.Empty<SpecusConfigEntry>(), "route-lifecycle", writer,
            directHttp, NullLogger<NatClientHandler>.Instance);
        nat.Bind(CancellationToken.None);
        var observer = new RouteObserver();
        var config = new SpecusClientConfig
        {
            ServerBaseUrl = "http://127.0.0.1:9",
            ApiKey = "ak_route_lifecycle",
            Secret = "sk_route_lifecycle",
        };
        var auth = new ClientAuthService(config, http, NullLogger<ClientAuthService>.Instance);
        await using var client = new SpecusControlClient(config, auth, forwarder, NullLoggerFactory.Instance,
            observer);

        foreach (var (step, index) in testCase.Steps.Select((step, index) => (step, index)))
        {
            await client.ApplyNatControlAsync(step.NatControl, nat, directHttp);

            var expected = step.ExpectRoutes.OrderBy(pair => pair.Key, StringComparer.Ordinal).ToList();
            var forwarded = directHttp.SnapshotRoutes().OrderBy(pair => pair.Key, StringComparer.Ordinal).ToList();
            Assert.True(expected.SequenceEqual(forwarded),
                $"{id} step {index}: route table\nexpected: {Describe(expected)}\nactual:   {Describe(forwarded)}");
            var shown = Assert.IsType<SpecusClientRoutesSnapshot>(observer.Last);
            var displayed = shown.HttpRoutes
                .Select(route => KeyValuePair.Create(route.Route, route.TargetBaseUrl))
                .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .ToList();
            Assert.True(expected.SequenceEqual(displayed),
                $"{id} step {index}: displayed routes\nexpected: {Describe(expected)}\nactual:   {Describe(displayed)}");
        }
    }

    private static string Describe(IEnumerable<KeyValuePair<string, string>> routes) =>
        "{" + string.Join(", ", routes.Select(pair => pair.Key + "=" + pair.Value)) + "}";

    private static LifecycleVector LoadVector() => ProtocolVectorTestHelper.Read<LifecycleVector>(VectorPath);

    private sealed class RouteObserver : ISpecusClientObserver
    {
        public SpecusClientRoutesSnapshot? Last { get; private set; }

        public void OnRoutesChanged(SpecusClientRoutesSnapshot snapshot) => Last = snapshot;
    }

    private sealed record LifecycleVector(ClientSection Client);

    private sealed record ClientSection(List<ClientCase> Cases);

    private sealed record ClientCase(string Id, List<HttpSpecusConfigEntry> LoginSnapshot, List<ClientStep> Steps);

    private sealed record ClientStep(string NatControl, Dictionary<string, string> ExpectRoutes);
}
