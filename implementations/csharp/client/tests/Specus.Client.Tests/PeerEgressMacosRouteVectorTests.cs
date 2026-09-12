using System.Text.Json;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// Replays <c>peer-egress-macos-routes-v1.json</c> against the .NET macOS route readings.
/// </summary>
/// <remarks>
/// Everything marked sampled in that file is literal output captured from a real macOS machine, and
/// three of those captures changed the design rather than confirming it: <c>route</c> exits 0 when
/// it fails, it accepts a /33 and installs half the IPv4 address space, and the readings are cheap
/// enough that caching them would buy nothing.
///
/// <para>The expectations come from an independent reference implementation in
/// <c>tools/protocol/generate_peer_egress_macos_route_vectors.py</c>, so agreement here is
/// independent agreement rather than three copies of one mistake.</para>
/// </remarks>
public class PeerEgressMacosRouteVectorTests
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

    private static JsonDocument Vector() => ReadVector("peer-egress-macos-routes-v1.json");

    /// <summary>
    /// <c>route -n get</c> is how a bypass next hop is found, and the reading that matters is that
    /// an on-link destination has no gateway line at all -- not even the gateway's own address,
    /// which has a cloned entry carrying a MAC address.
    /// </summary>
    [Fact]
    public void RouteGetMatchesTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("routeGet");
        Assert.True(cases.GetArrayLength() > 0, "vector carried no route-get cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var hop = PeerEgressMacosRouteCommands.ParseRouteGet(
                testCase.GetProperty("stdout").GetString(),
                testCase.GetProperty("stderr").GetString());
            var expect = testCase.GetProperty("expect");
            if (!expect.GetProperty("parsed").GetBoolean())
            {
                Assert.Null(hop);
                continue;
            }
            Assert.NotNull(hop);
            Assert.Equal(expect.GetProperty("gateway").GetString(), hop!.Value.Gateway);
            Assert.Equal(expect.GetProperty("interface").GetString(), hop.Value.Device);
            Assert.NotNull(name);
        }
    }

    /// <summary>
    /// netstat abbreviates the destination column and the abbreviations are not guessable: "127" is
    /// a /8, "203.0.113" is a /24, "100.64/10" fills in the missing octet. Reading one wrong means
    /// the conflict check compares against a prefix nobody asked about.
    /// </summary>
    [Fact]
    public void PrefixNormalisationMatchesTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("normalisePrefix").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "vector carried no normalisation cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var input = testCase.GetProperty("input").GetString();
            Assert.Equal(testCase.GetProperty("expect").GetString(),
                PeerEgressMacosRouteCommands.NormalisePrefix(input));
        }
    }

    /// <summary>
    /// Which rows of <c>netstat -rn</c> are routes, and which section they have to come from.
    /// </summary>
    [Fact]
    public void TableParsingMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        foreach (var section in new[] { "table", "bothFamilies", "duplicates", "tunRoute" })
        {
            var testCase = root.GetProperty(section);
            var stdout = testCase.GetProperty("stdout").GetString();
            Assert.False(string.IsNullOrEmpty(stdout), section);
            var routes = PeerEgressMacosRouteCommands.ParseTable(stdout);
            var expect = testCase.GetProperty("expect");
            Assert.Equal(expect.GetProperty("rows").GetInt32(), routes.Count);
            var wanted = expect.GetProperty("prefixes").EnumerateArray()
                .Select(entry => entry.GetString()).ToList();
            Assert.Equal(wanted, routes.Select(route => (string?)route.Prefix).ToList());
        }
        // The two-family table has to yield the same routes as the IPv4-only one: "default" is the
        // one destination whose IPv6 spelling is indistinguishable from its IPv4 spelling, and the
        // sampling machine had four of them, one per utun.
        Assert.Equal(
            root.GetProperty("table").GetProperty("expect").GetProperty("prefixes").ToString(),
            root.GetProperty("bothFamilies").GetProperty("expect").GetProperty("prefixes")
                .ToString());
    }

    /// <summary>The conflict check, which decides whether a rule is applied or refused.</summary>
    [Fact]
    public void ConflictFromTableMatchesTheSharedVector()
    {
        using var vector = Vector();
        var section = vector.RootElement.GetProperty("conflictFromTable");
        var cases = section.GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "vector carried no conflict cases");
        foreach (var testCase in cases.EnumerateArray())
        {
            var prefix = testCase.GetProperty("prefix").GetString();
            var tableName = testCase.GetProperty("table").GetString()!;
            Assert.True(section.GetProperty("tables").TryGetProperty(tableName, out var table),
                $"vector names a table it does not carry: {tableName}");
            var existing = PeerEgressMacosRouteCommands.ConflictFromTable(table.GetString(),
                prefix);
            var expect = testCase.GetProperty("expect");
            Assert.Equal(expect.GetProperty("present").GetBoolean(), existing.Present);
            Assert.Equal(expect.GetProperty("existing").GetString(), existing.Description);
        }
    }

    /// <summary>Whether a mutation worked, which cannot be read from the exit status.</summary>
    [Fact]
    public void CommandResultsMatchTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        Assert.Equal(PeerEgressMacosRouteCommands.KernelGeneratedFlag,
            root.GetProperty("kernelGeneratedFlag").GetString());
        Assert.Equal(PeerEgressMacosRouteCommands.FailurePermissionDenied,
            root.GetProperty("failureKinds").GetProperty("denied").GetString());
        Assert.Equal(PeerEgressMacosRouteCommands.FailureOther,
            root.GetProperty("failureKinds").GetProperty("other").GetString());

        var cases = root.GetProperty("commandResults");
        Assert.True(cases.GetArrayLength() > 0, "vector carried no command results");
        var zeroExitFailures = 0;
        foreach (var testCase in cases.EnumerateArray())
        {
            var expected = testCase.GetProperty("expect").GetProperty("failure").GetString();
            Assert.Equal(expected, PeerEgressMacosRouteCommands.ClassifyFailure(
                testCase.GetProperty("stdout").GetString(),
                testCase.GetProperty("stderr").GetString()));
            if (testCase.GetProperty("exit").GetInt32() == 0 && !string.IsNullOrEmpty(expected))
            {
                zeroExitFailures++;
            }
        }
        // The reason none of this reads the exit status. Without a case like this an implementation
        // could check it and pass the whole file.
        Assert.True(zeroExitFailures > 0, "the vector no longer carries a failure that exited 0");
    }

    /// <summary>
    /// The argv arrays are pinned as well as their output. Three runtimes each assembling their own
    /// arguments is exactly how two of them end up using -net while the third uses -host, with
    /// nothing in the parsed output to show it.
    /// </summary>
    [Fact]
    public void CommandsMatchTheSharedVector()
    {
        using var vector = Vector();
        var commands = vector.RootElement.GetProperty("commands");
        Assert.Equal(Argv(commands.GetProperty("showTable")),
            PeerEgressMacosRouteCommands.ShowTableArgs());
        foreach (var testCase in commands.GetProperty("findRoute").EnumerateArray())
        {
            Assert.Equal(Argv(testCase.GetProperty("argv")),
                PeerEgressMacosRouteCommands.FindRouteArgs(
                    testCase.GetProperty("address").GetString()));
        }
        foreach (var testCase in commands.GetProperty("installInterface").EnumerateArray())
        {
            Assert.Equal(Argv(testCase.GetProperty("argv")),
                PeerEgressMacosRouteCommands.InstallInterfaceArgs(
                    testCase.GetProperty("prefix").GetString(),
                    testCase.GetProperty("interface").GetString()));
        }
        foreach (var testCase in commands.GetProperty("installGateway").EnumerateArray())
        {
            Assert.Equal(Argv(testCase.GetProperty("argv")),
                PeerEgressMacosRouteCommands.InstallGatewayArgs(
                    testCase.GetProperty("prefix").GetString(),
                    testCase.GetProperty("gateway").GetString()));
        }
        foreach (var testCase in commands.GetProperty("remove").EnumerateArray())
        {
            Assert.Equal(Argv(testCase.GetProperty("argv")),
                PeerEgressMacosRouteCommands.RemoveArgs(
                    testCase.GetProperty("prefix").GetString()));
        }
    }

    /// <summary>
    /// What has to be refused. The one that matters is 203.0.113.0/33: <c>route</c> accepts it,
    /// prints a success line naming 203.0.113.0, exits 0, and installs 128.0/1.
    /// </summary>
    [Fact]
    public void RefusedArgumentsMatchTheSharedVector()
    {
        using var vector = Vector();
        var cases = vector.RootElement.GetProperty("commands")
            .GetProperty("rejectedArguments");
        Assert.True(cases.GetArrayLength() > 0, "vector carried no refused arguments");
        foreach (var testCase in cases.EnumerateArray())
        {
            var kind = testCase.GetProperty("kind").GetString();
            var value = testCase.GetProperty("value").GetString();
            var refused = Assert.Throws<ArgumentException>(() =>
            {
                switch (kind)
                {
                    case "prefix":
                        PeerEgressMacosRouteCommands.InstallInterfaceArgs(value, "utun3");
                        break;
                    case "address":
                        PeerEgressMacosRouteCommands.FindRouteArgs(value);
                        break;
                    case "interface":
                        PeerEgressMacosRouteCommands.InstallInterfaceArgs("203.0.113.0/24", value);
                        break;
                    default:
                        throw new InvalidOperationException(
                            $"vector asks about an argument kind nothing builds: {kind}");
                }
            });
            Assert.Contains(PeerEgressMacosRouteCommands.Refusal, refused.Message);
        }
        // Withdrawal validates too. A removal built from a prefix nobody checked is a removal of
        // whatever `route` decides that text means.
        Assert.Throws<ArgumentException>(
            () => PeerEgressMacosRouteCommands.RemoveArgs("203.0.113.0/33"));
    }

    /// <summary>
    /// The capture that says why the prefix is validated before a process starts, kept as a test so
    /// the evidence travels with the rule rather than living only in a commit message.
    /// </summary>
    [Fact]
    public void AMalformedPrefixWouldInstallHalfTheInternet()
    {
        using var vector = Vector();
        var section = vector.RootElement.GetProperty("malformedPrefix");
        var installed = section.GetProperty("installedPrefix").GetString()!;
        Assert.False(string.IsNullOrEmpty(installed), "vector carried no evidence");
        // `route` reported success, and what it says it did names a different prefix than what it
        // did.
        Assert.Equal(0, section.GetProperty("exit").GetInt32());
        Assert.DoesNotContain(installed, section.GetProperty("stdout").GetString()!);
        Assert.True(PeerEgressMacosRouteCommands.ConflictFromTable(
            section.GetProperty("tableAfter").GetString(), installed).Present,
            $"{installed} is not in the table the malformed add left behind");
        Assert.False(PeerEgressMacosRouteCommands.ValidPrefix("203.0.113.0/33"),
            "the argument that installs half the internet is accepted");
    }

    /// <summary>
    /// The measurement that says not to cache, asserted so a cache cannot be added without the
    /// number that justifies it.
    /// </summary>
    [Fact]
    public void TheConflictCheckDoesNotCache()
    {
        using var vector = Vector();
        Assert.False(vector.RootElement.GetProperty("timings").GetProperty("cache").GetBoolean(),
            "the vector now expects a cached table; the commander does not keep one");
    }

    private static string[] Argv(JsonElement array) =>
        array.EnumerateArray().Select(entry => entry.GetString()!).ToArray();
}
