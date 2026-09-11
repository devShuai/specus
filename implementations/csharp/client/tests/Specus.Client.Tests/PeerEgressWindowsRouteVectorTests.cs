using System.Text.Json;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// Replays <c>peer-egress-windows-routes-v1.json</c> against the .NET Windows route parsers.
/// </summary>
/// <remarks>
/// The cases marked sampled in that file are literal output captured from a Windows 11 machine, not
/// transcribed from documentation, which is the part worth having: these parsers read a format
/// nobody controls, and reading it wrong means installing a route into nothing or deciding a prefix
/// is free when it is not.
///
/// <para>The expectations come from an independent reference parser in
/// <c>tools/protocol/generate_peer_egress_windows_route_vectors.py</c>, so agreement is independent
/// agreement rather than three copies of one mistake.</para>
/// </remarks>
public class PeerEgressWindowsRouteVectorTests
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

    [Fact]
    public void WindowsRouteParsingMatchesTheSharedVector()
    {
        using var vector = ReadVector("peer-egress-windows-routes-v1.json");
        var root = vector.RootElement;
        Assert.Equal(PeerEgressWindowsRouteCommands.OnLinkNextHop,
            root.GetProperty("onLinkNextHop").GetString());

        var find = root.GetProperty("routeFind");
        Assert.True(find.GetArrayLength() > 0, "vector carried no find cases");
        foreach (var testCase in find.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var hop = PeerEgressWindowsRouteCommands.ParseRouteFind(
                testCase.GetProperty("output").GetString());
            var expect = testCase.GetProperty("expect");
            if (!expect.GetProperty("parsed").GetBoolean())
            {
                Assert.True(hop is null, name);
                continue;
            }
            Assert.True(hop is not null, name);
            Assert.Equal(expect.GetProperty("gateway").GetString(), hop!.Value.Gateway);
            Assert.Equal(expect.GetProperty("interfaceIndex").GetInt32(), hop.Value.InterfaceIndex);
        }

        var show = root.GetProperty("routeShow");
        Assert.True(show.GetArrayLength() > 0, "vector carried no show cases");
        foreach (var testCase in show.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var existing = PeerEgressWindowsRouteCommands.ParseRouteShow(
                testCase.GetProperty("output").GetString());
            var expect = testCase.GetProperty("expect");
            Assert.Equal(expect.GetProperty("present").GetBoolean(), existing.Present);
            Assert.Equal(expect.GetProperty("description").GetString(), existing.Description);
        }

        var errors = root.GetProperty("commandErrors");
        Assert.True(errors.GetArrayLength() > 0, "vector carried no error cases");
        foreach (var testCase in errors.EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("expect").GetProperty("failure").GetString(),
                PeerEgressWindowsRouteCommands.ParseCommandFailure(
                    testCase.GetProperty("output").GetString()));
        }
    }

    /// <summary>
    /// The scripts are asserted as text, not only by what comes back from running them. Three
    /// runtimes each embedding their own PowerShell string is how two of them end up writing to a
    /// different policy store than the third, with nothing in the parsed output to show it.
    /// </summary>
    [Fact]
    public void WindowsRouteScriptsMatchTheSharedVector()
    {
        using var vector = ReadVector("peer-egress-windows-routes-v1.json");
        var scripts = vector.RootElement.GetProperty("scripts");
        Assert.True(scripts.GetProperty("showRoutes").GetArrayLength() > 0,
            "vector carried no script cases");

        foreach (var testCase in scripts.GetProperty("showRoutes").EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("expect").GetString(),
                PeerEgressWindowsRouteCommands.ShowRoutesScript(
                    StringsOf(testCase.GetProperty("prefixes"))));
        }
        foreach (var testCase in scripts.GetProperty("findRoutes").EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("expect").GetString(),
                PeerEgressWindowsRouteCommands.FindRoutesScript(
                    StringsOf(testCase.GetProperty("addresses"))));
        }
        foreach (var testCase in scripts.GetProperty("installRoute").EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("expect").GetString(),
                PeerEgressWindowsRouteCommands.InstallRouteScript(
                    testCase.GetProperty("cidr").GetString()!,
                    testCase.GetProperty("interfaceIndex").GetInt32(),
                    testCase.GetProperty("gateway").GetString()));
        }
        foreach (var testCase in scripts.GetProperty("removeRoute").EnumerateArray())
        {
            Assert.Equal(testCase.GetProperty("expect").GetString(),
                PeerEgressWindowsRouteCommands.RemoveRouteScript(
                    testCase.GetProperty("cidr").GetString()!));
        }

        // The arguments that must never reach a script. They arrive inside one command string
        // rather than as argv entries, so a quote in a prefix is a second command.
        foreach (var testCase in scripts.GetProperty("rejectedArguments").EnumerateArray())
        {
            var value = testCase.GetProperty("value").GetString()!;
            var prefix = testCase.GetProperty("kind").GetString() == "prefix";
            Assert.Throws<ArgumentException>(() => prefix
                ? PeerEgressWindowsRouteCommands.ShowRoutesScript([value])
                : PeerEgressWindowsRouteCommands.FindRoutesScript([value]));
        }
    }

    /// <summary>
    /// A batched query writes one line per input, including an empty result, which is what lets the
    /// lines be matched back to the prefixes that were asked about.
    /// </summary>
    [Fact]
    public void ScriptLinesSurviveBothLineEndings()
    {
        var lines = PeerEgressWindowsRouteCommands.SplitScriptLines(
            "[]\r\n[{\"InterfaceIndex\":3}]\r\n");
        Assert.Equal(2, lines.Count);
        Assert.Equal("[]", lines[0]);
        Assert.Empty(PeerEgressWindowsRouteCommands.SplitScriptLines("\n\n"));
    }

    private static List<string> StringsOf(JsonElement array) =>
        [.. array.EnumerateArray().Select(entry => entry.GetString()!)];

    /// <summary>
    /// The adapter name is the one argument that cannot be whitelisted -- it comes from
    /// configuration and may legitimately hold spaces and non-ASCII characters -- so it is the one
    /// place the escape is load-bearing rather than unreachable.
    /// </summary>
    [Fact]
    public void WindowsInterfaceLookupMatchesTheSharedVector()
    {
        using var vector = ReadVector("peer-egress-windows-routes-v1.json");
        var root = vector.RootElement;
        var scripts = root.GetProperty("scripts");
        Assert.True(scripts.GetProperty("interfaceIndex").GetArrayLength() > 0,
            "vector carried no interface cases");

        foreach (var testCase in scripts.GetProperty("interfaceIndex").EnumerateArray())
        {
            var expected = testCase.GetProperty("expect").GetString()!;
            Assert.Equal(expected, PeerEgressWindowsRouteCommands.InterfaceIndexScript(
                testCase.GetProperty("adapter").GetString()));
            // Nothing a script selects may be anything but ASCII. The child process writes stdout
            // in the console code page, and in GBK the low byte of a character can be a backslash:
            // a name echoed back into the JSON can break the document.
            Assert.EndsWith("Select-Object InterfaceIndex)", expected);
        }
        Assert.Equal(scripts.GetProperty("showAllRoutes").GetString(),
            PeerEgressWindowsRouteCommands.ShowAllRoutesScript());

        foreach (var testCase in root.GetProperty("interfaceIndexParse").EnumerateArray())
        {
            var index = PeerEgressWindowsRouteCommands.ParseInterfaceIndex(
                testCase.GetProperty("output").GetString());
            var expect = testCase.GetProperty("expect");
            Assert.Equal(expect.GetProperty("found").GetBoolean()
                ? expect.GetProperty("interfaceIndex").GetInt32()
                : 0, index);
        }
        Assert.True(root.GetProperty("outputEncoding").GetProperty("consoleCodePage").GetInt32() > 0,
            "vector lost the sampled console code page");
    }

    /// <summary>
    /// The sampled cases are why this vector is worth more than a set of invented strings, so
    /// losing them should fail rather than quietly leave a file of guesses behind.
    /// </summary>
    [Fact]
    public void TheVectorKeepsItsSampledCases()
    {
        using var vector = ReadVector("peer-egress-windows-routes-v1.json");
        var sampled = 0;
        foreach (var section in new[] { "routeFind", "routeShow", "commandErrors" })
        {
            foreach (var testCase in vector.RootElement.GetProperty(section).EnumerateArray())
            {
                if (testCase.TryGetProperty("sampled", out var flag) && flag.GetBoolean())
                {
                    sampled++;
                }
            }
        }
        Assert.True(sampled >= 10, $"vector carries {sampled} sampled cases, want at least 10");
    }
}
