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
        Assert.True(sampled >= 9, $"vector carries {sampled} sampled cases, want at least 9");
    }
}
