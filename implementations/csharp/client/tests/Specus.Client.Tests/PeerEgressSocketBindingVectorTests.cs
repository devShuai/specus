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
            route.TryGetProperty("gateway", out var gateway) ? gateway.GetString()! : "",
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
                    row.GetProperty("prefix").GetString()!, row.GetProperty("nextHop").GetString()!,
                    row.GetProperty("metric").GetInt64()))
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
    public void LinuxTablesMatchTheSharedVector()
    {
        using var vector = Vector();
        var linux = vector.RootElement.GetProperty("linux");
        Assert.True(linux.GetProperty("routes").GetArrayLength() > 0, "no Linux tables");
        foreach (var entry in linux.GetProperty("routes").EnumerateArray())
        {
            var table = entry.GetProperty("table").GetString()!;
            Assert.Equal(Routes(entry.GetProperty("expect")),
                PeerEgressRouteCommands.ParseRouteTable(linux.GetProperty("tables").GetProperty(table).GetString()));
        }
        // The captures that justify reading the table at all: `ip route get` answering with the tunnel.
        foreach (var capture in linux.GetProperty("captures").EnumerateObject())
        {
            if (!capture.Name.StartsWith("get-covered", StringComparison.Ordinal))
            {
                continue;
            }
            var hop = PeerEgressRouteCommands.ParseRouteGet(capture.Value.GetProperty("stdout").GetString());
            Assert.True(hop is { } parsed && PeerEgressRouteCommands.HopIsDevice(parsed, "specus0"),
                $"{capture.Name} parsed as {hop}");
        }
    }

    [Fact]
    public void BypassHopsMatchTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        var tables = new Dictionary<string, Dictionary<string, List<PeerEgressBindRoute>>>
        {
            ["linux"] = root.GetProperty("linux").GetProperty("tables").EnumerateObject()
                .ToDictionary(table => table.Name, table => PeerEgressRouteCommands.ParseRouteTable(table.Value.GetString())),
            ["macos"] = root.GetProperty("macos").GetProperty("tables").EnumerateObject()
                .ToDictionary(table => table.Name, table => PeerEgressSocketBinding.MacosRoutes(table.Value.GetString())),
        };
        var windows = root.GetProperty("windows");
        var forward = windows.GetProperty("forwardTables").EnumerateArray()
            .Where(table => table.GetProperty("name").GetString() == windows.GetProperty("routes").GetProperty("forward").GetString())
            .Select(table => PeerEgressSocketBinding.ParseWindowsForwardTable(Convert.FromHexString(table.GetProperty("hex").GetString()!)))
            .Single();
        var interfaces = windows.GetProperty("interfaceTables").EnumerateArray()
            .Where(table => table.GetProperty("name").GetString() == windows.GetProperty("routes").GetProperty("interfaces").GetString())
            .Select(table => PeerEgressSocketBinding.ParseWindowsInterfaceTable(Convert.FromHexString(table.GetProperty("hex").GetString()!)))
            .Single();
        tables["windows"] = new() { ["typical"] = PeerEgressSocketBinding.WindowsRoutes(forward!, interfaces!) };

        var cases = root.GetProperty("hops").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no hop cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var platform = testCase.GetProperty("platform").GetString()!;
            var routes = platform == "inline"
                ? Routes(testCase.GetProperty("routes"))
                : tables[platform][testCase.GetProperty("table").GetString()!];
            var owned = testCase.GetProperty("owned").EnumerateArray().Select(prefix => prefix.GetString()!).ToList();
            var hop = PeerEgressSocketBinding.SelectBypassHop(routes, testCase.GetProperty("tunnel").GetString(),
                owned, testCase.GetProperty("destination").GetString()!);
            var expected = testCase.GetProperty("expect").GetProperty("hop");
            if (expected.ValueKind == JsonValueKind.Null)
            {
                Assert.True(hop is null, $"{name}: chose {hop}, want no hop");
            }
            else
            {
                Assert.True(hop is { } chosen
                        && chosen.Interface == expected.GetProperty("interface").GetString()
                        && chosen.Gateway == expected.GetProperty("gateway").GetString(),
                    $"{name}: chose {hop}, want {expected}");
            }
        }
    }

    /// <summary>
    /// The fallback a commander takes when its query answers with the tunnel: the table with the
    /// tunnel left out, and a refusal that says why when nothing else leads there.
    /// </summary>
    /// <summary>Every sampled table in the vector, as this runtime parses it.</summary>
    private static Dictionary<string, Dictionary<string, List<PeerEgressBindRoute>>> Tables(JsonElement root)
    {
        var tables = new Dictionary<string, Dictionary<string, List<PeerEgressBindRoute>>>
        {
            ["linux"] = root.GetProperty("linux").GetProperty("tables").EnumerateObject()
                .ToDictionary(table => table.Name, table => PeerEgressRouteCommands.ParseRouteTable(table.Value.GetString())),
            ["macos"] = root.GetProperty("macos").GetProperty("tables").EnumerateObject()
                .ToDictionary(table => table.Name, table => PeerEgressSocketBinding.MacosRoutes(table.Value.GetString())),
        };
        var windows = root.GetProperty("windows");
        var forward = windows.GetProperty("forwardTables").EnumerateArray()
            .Where(table => table.GetProperty("name").GetString() == windows.GetProperty("routes").GetProperty("forward").GetString())
            .Select(table => PeerEgressSocketBinding.ParseWindowsForwardTable(Convert.FromHexString(table.GetProperty("hex").GetString()!)))
            .Single();
        var interfaces = windows.GetProperty("interfaceTables").EnumerateArray()
            .Where(table => table.GetProperty("name").GetString() == windows.GetProperty("routes").GetProperty("interfaces").GetString())
            .Select(table => PeerEgressSocketBinding.ParseWindowsInterfaceTable(Convert.FromHexString(table.GetProperty("hex").GetString()!)))
            .Single();
        tables["windows"] = new() { ["typical"] = PeerEgressSocketBinding.WindowsRoutes(forward!, interfaces!) };
        return tables;
    }

    /// <summary>
    /// What the consumer's own routes look like after a network change, and the repair each needs.
    /// The policy -- a tunnel route on another interface is a conflict, a bypass follows the hop the
    /// table would choose with the owned prefixes left out -- has to be the same in three runtimes.
    /// </summary>
    [Fact]
    public void DriftMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        var tables = Tables(root);
        var cases = root.GetProperty("drift").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "no drift cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var platform = testCase.GetProperty("platform").GetString()!;
            var routes = platform == "inline"
                ? Routes(testCase.GetProperty("routes"))
                : tables[platform][testCase.GetProperty("table").GetString()!];
            var owned = testCase.GetProperty("owned").EnumerateArray()
                .Select(entry => new PeerEgressRoute(entry.GetProperty("cidr").GetString()!,
                    PeerEgressRoutePlanner.KindFromWireName(entry.GetProperty("kind").GetString()), string.Empty))
                .ToList();
            var found = PeerEgressSocketBinding.Drifts(owned, routes, testCase.GetProperty("tunnel").GetString()!);
            var expect = testCase.GetProperty("expect").EnumerateArray().ToList();
            Assert.True(expect.Count == found.Count, $"{name}: found {string.Join(", ", found)}");
            for (var index = 0; index < expect.Count; index++)
            {
                Assert.True(expect[index].GetProperty("cidr").GetString() == found[index].Route.Cidr
                    && expect[index].GetProperty("reason").GetString() == found[index].Reason
                    && expect[index].GetProperty("action").GetString() == found[index].Action,
                    $"{name}: drift {index} = {found[index]}, want {expect[index]}");
            }
        }
    }

    [Fact]
    public void TheHopFromTheTableLeavesTheTunnelOut()
    {
        using var vector = Vector();
        var routes = PeerEgressRouteCommands.ParseRouteTable(
            vector.RootElement.GetProperty("linux").GetProperty("tables").GetProperty("show-rich").GetString());

        var hop = PeerEgressSocketBinding.BypassHopFromTable("203.0.113.9", "specus0", () => routes);
        Assert.Equal("eth0", hop.Interface);
        Assert.Equal("192.168.64.1", hop.Gateway);
        Assert.Throws<PeerEgressNoPhysicalRouteException>(
            () => PeerEgressSocketBinding.BypassHopFromTable("192.0.2.9", "specus0", () => routes));
        var unreadable = Assert.Throws<IOException>(() => PeerEgressSocketBinding.BypassHopFromTable(
            "203.0.113.9", "specus0", () => throw new InvalidOperationException("ip: not found")));
        Assert.Contains("ip: not found", unreadable.Message);
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
