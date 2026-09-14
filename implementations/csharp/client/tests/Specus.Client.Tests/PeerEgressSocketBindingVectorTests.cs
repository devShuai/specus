using System.Text.Json;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// Replays <c>peer-egress-socket-binding-v1.json</c> against the .NET choice of interface for an
/// egress socket and the two platforms' table readings.
/// </summary>
/// <remarks>
/// The expectations come from an independent reference in
/// <c>tools/protocol/generate_peer_egress_socket_binding_vectors.py</c>, whose Windows tables are
/// built from the SDK's structure layouts with ctypes and whose macOS tables are sampled captures.
/// </remarks>
public class PeerEgressSocketBindingVectorTests
{
    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "peer-egress-socket-binding-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-socket-binding-v1.json");
    }

    private static List<PeerEgressBindRoute> Routes(JsonElement array) =>
        array.EnumerateArray().Select(route => new PeerEgressBindRoute(
            route.GetProperty("prefix").GetString()!,
            route.GetProperty("interface").GetString()!,
            route.GetProperty("metric").GetInt64(),
            route.GetProperty("usable").GetBoolean())).ToList();

    private static void AssertChoice(string name, IReadOnlyList<PeerEgressBindRoute> routes, JsonElement testCase)
    {
        var expected = testCase.GetProperty("expect").GetProperty("interface");
        var chosen = PeerEgressSocketBinding.Select(routes, testCase.GetProperty("tunnel").GetString(),
            testCase.GetProperty("destination").GetString()!);
        if (expected.ValueKind == JsonValueKind.Null)
        {
            Assert.True(chosen is null, $"{name}: chose {chosen}, want the dial refused");
        }
        else
        {
            Assert.True(expected.GetString() == chosen, $"{name}: chose {chosen}, want {expected.GetString()}");
        }
    }

    [Fact]
    public void SelectionMatchesTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("select").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no selection cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            AssertChoice(testCase.GetProperty("name").GetString()!, Routes(testCase.GetProperty("routes")), testCase);
        }
    }

    [Fact]
    public void WindowsTablesMatchTheSharedVector()
    {
        using var vector = Vector();
        var windows = vector.RootElement.GetProperty("windows");
        var forwardByName = new Dictionary<string, List<PeerEgressWindowsForwardRow>>();
        foreach (var table in windows.GetProperty("forwardTables").EnumerateArray())
        {
            var name = table.GetProperty("name").GetString()!;
            var rows = PeerEgressSocketBinding.ParseWindowsForwardTable(
                Convert.FromHexString(table.GetProperty("hex").GetString()!));
            Assert.True(table.GetProperty("expect").GetProperty("parsed").GetBoolean() == rows is not null,
                $"forward {name}: parsed flag");
            if (rows is null)
            {
                continue;
            }
            var expected = table.GetProperty("expect").GetProperty("rows").EnumerateArray()
                .Select(row => new PeerEgressWindowsForwardRow(row.GetProperty("interfaceIndex").GetInt64(),
                    row.GetProperty("prefix").GetString()!, row.GetProperty("metric").GetInt64()))
                .ToList();
            Assert.Equal(expected, rows);
            forwardByName[name] = rows;
        }
        var interfacesByName = new Dictionary<string, List<PeerEgressWindowsInterfaceRow>>();
        foreach (var table in windows.GetProperty("interfaceTables").EnumerateArray())
        {
            var name = table.GetProperty("name").GetString()!;
            var rows = PeerEgressSocketBinding.ParseWindowsInterfaceTable(
                Convert.FromHexString(table.GetProperty("hex").GetString()!));
            Assert.True(table.GetProperty("expect").GetProperty("parsed").GetBoolean() == rows is not null,
                $"interfaces {name}: parsed flag");
            if (rows is null)
            {
                continue;
            }
            var expected = table.GetProperty("expect").GetProperty("rows").EnumerateArray()
                .Select(row => new PeerEgressWindowsInterfaceRow(row.GetProperty("interfaceIndex").GetInt64(),
                    row.GetProperty("metric").GetInt64(), row.GetProperty("connected").GetBoolean(),
                    row.GetProperty("disableDefaultRoutes").GetBoolean()))
                .ToList();
            Assert.Equal(expected, rows);
            interfacesByName[name] = rows;
        }

        var joined = windows.GetProperty("routes");
        var routes = PeerEgressSocketBinding.WindowsRoutes(
            forwardByName[joined.GetProperty("forward").GetString()!],
            interfacesByName[joined.GetProperty("interfaces").GetString()!]);
        Assert.Equal(Routes(joined.GetProperty("expect")), routes);
        foreach (var testCase in windows.GetProperty("cases").EnumerateArray())
        {
            AssertChoice("windows " + testCase.GetProperty("name").GetString(), routes, testCase);
        }
    }

    [Fact]
    public void MacosTablesMatchTheSharedVector()
    {
        using var vector = Vector();
        var macos = vector.RootElement.GetProperty("macos");
        var byTable = new Dictionary<string, List<PeerEgressBindRoute>>();
        foreach (var entry in macos.GetProperty("routes").EnumerateArray())
        {
            var table = entry.GetProperty("table").GetString()!;
            var routes = PeerEgressSocketBinding.MacosRoutes(macos.GetProperty("tables").GetProperty(table).GetString());
            Assert.Equal(Routes(entry.GetProperty("expect")), routes);
            byTable[table] = routes;
        }
        foreach (var testCase in macos.GetProperty("cases").EnumerateArray())
        {
            AssertChoice("macos " + testCase.GetProperty("name").GetString(),
                byTable[testCase.GetProperty("table").GetString()!], testCase);
        }
    }

    [Fact]
    public void SocketOptionsMatchTheSharedVector()
    {
        using var vector = Vector();
        var options = vector.RootElement.GetProperty("socketOptions");
        Assert.Equal(PeerEgressSocketBinding.WindowsIpUnicastIf, options.GetProperty("windows").GetProperty("name").GetInt32());
        Assert.Equal(PeerEgressSocketBinding.MacosIpBoundIf, options.GetProperty("macos").GetProperty("name").GetInt32());
        Assert.Equal(PeerEgressSocketBinding.IpProtoIp, options.GetProperty("windows").GetProperty("level").GetInt32());
        Assert.Equal(PeerEgressSocketBinding.IpProtoIp, options.GetProperty("macos").GetProperty("level").GetInt32());
        foreach (var testCase in options.GetProperty("windows").GetProperty("cases").EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("hex").GetString(), Convert.ToHexStringLower(
                PeerEgressSocketBinding.WindowsUnicastInterfaceOption(testCase.GetProperty("index").GetInt64())));
        }
        foreach (var testCase in options.GetProperty("macos").GetProperty("cases").EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("hex").GetString(), Convert.ToHexStringLower(
                PeerEgressSocketBinding.MacosBoundInterfaceOption(testCase.GetProperty("index").GetInt64())));
        }
    }
}
