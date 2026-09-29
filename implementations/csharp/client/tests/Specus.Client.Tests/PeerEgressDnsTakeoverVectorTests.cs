using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// The pure parts of the system DNS takeover, bound to every section of
/// <c>peer-egress-dns-takeover-v1.json</c>: what is read out of each platform's tools, what is
/// decided from it, the exact commands, and giving back over somebody else's change.
/// </summary>
public class PeerEgressDnsTakeoverVectorTests
{
    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-dns-takeover-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-dns-takeover-v1.json");
    }

    private static List<string> Strings(JsonElement array) => [.. array.EnumerateArray().Select(item => item.GetString()!)];

    private static string? Text(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static Ipv4Cidr Cidr(string text)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var value), text);
        return value;
    }

    [Fact]
    public void ConstantsMatchTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        Assert.Equal(PeerEgressDnsTakeoverRules.NrptComment, root.GetProperty("nrptComment").GetString());
        Assert.Equal(PeerEgressDnsTakeoverRules.ResolvConfWritten, root.GetProperty("resolvConfWritten").GetString());
        Assert.Equal(PeerEgressDnsTakeoverRules.ResolvedStubs, Strings(root.GetProperty("resolvedStubs")));
        Assert.Equal(PeerEgressDnsTakeoverRules.WindowsReadServers, root.GetProperty("windowsReadServers").GetString());
        Assert.Equal(PeerEgressDnsTakeoverRules.WindowsReadNrpt, root.GetProperty("windowsReadNrpt").GetString());
    }

    [Fact]
    public void ReadingMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        foreach (var testCase in root.GetProperty("parseResolvectl").EnumerateArray())
        {
            Assert.True(Strings(testCase.GetProperty("servers")).SequenceEqual(PeerEgressDnsTakeoverRules.ParseResolvectl(
                testCase.GetProperty("output").GetString(), testCase.GetProperty("tunnel").GetString()!)), Text(testCase, "name"));
        }
        foreach (var testCase in root.GetProperty("parseResolvConf").EnumerateArray())
        {
            Assert.True(Strings(testCase.GetProperty("servers")).SequenceEqual(
                PeerEgressDnsTakeoverRules.ParseResolvConf(testCase.GetProperty("text").GetString())), Text(testCase, "name"));
        }
        var services = root.GetProperty("parseMacServices");
        Assert.Equal(Strings(services.GetProperty("services")),
            PeerEgressDnsTakeoverRules.ParseMacServices(services.GetProperty("output").GetString()));
        foreach (var testCase in root.GetProperty("parseMacDnsServers").EnumerateArray())
        {
            Assert.True(Strings(testCase.GetProperty("servers")).SequenceEqual(
                PeerEgressDnsTakeoverRules.ParseMacDnsServers(testCase.GetProperty("output").GetString())), Text(testCase, "name"));
        }
        foreach (var testCase in root.GetProperty("parseScutil").EnumerateArray())
        {
            Assert.True(Strings(testCase.GetProperty("servers")).SequenceEqual(
                PeerEgressDnsTakeoverRules.ParseScutil(testCase.GetProperty("output").GetString())), Text(testCase, "name"));
        }
        foreach (var testCase in root.GetProperty("parseWindowsServers").EnumerateArray())
        {
            Assert.True(Strings(testCase.GetProperty("servers")).SequenceEqual(PeerEgressDnsTakeoverRules.ParseWindowsServers(
                testCase.GetProperty("json").GetString(), testCase.GetProperty("tunnelIndex").GetInt64())), Text(testCase, "name"));
        }
        foreach (var testCase in root.GetProperty("parseWindowsNrpt").EnumerateArray())
        {
            Assert.True(testCase.GetProperty("foreignRoot").GetBoolean()
                == PeerEgressDnsTakeoverRules.ParseWindowsNrpt(testCase.GetProperty("json").GetString()), Text(testCase, "name"));
        }
    }

    [Fact]
    public void DecidingMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        foreach (var testCase in root.GetProperty("linuxMode").EnumerateArray())
        {
            var (mode, reason) = PeerEgressDnsTakeoverRules.LinuxMode(testCase.GetProperty("resolvectlOk").GetBoolean(),
                Strings(testCase.GetProperty("resolvConfServers")), testCase.GetProperty("resolvConfIsSymlink").GetBoolean());
            var expectedMode = Text(testCase, "mode") switch
            {
                "resolved" => PeerEgressDnsTakeoverRules.PlatformResolved,
                "resolvconf" => PeerEgressDnsTakeoverRules.PlatformResolvConf,
                var other => other,
            };
            Assert.True(expectedMode == mode && Text(testCase, "reason") == reason, $"{Text(testCase, "name")}: {mode} {reason}");
        }
        var pool = Cidr(root.GetProperty("fakeIpCidr").GetString()!);
        var mesh = Cidr(root.GetProperty("meshCidr").GetString()!);
        foreach (var testCase in root.GetProperty("upstreams").EnumerateArray())
        {
            var name = Text(testCase, "name");
            var (upstreams, reason) = PeerEgressDnsTakeoverRules.ClassifyUpstreams(Strings(testCase.GetProperty("servers")),
                Strings(testCase.GetProperty("virtualAddresses")), pool, mesh);
            if (Text(testCase, "code") is { } code)
            {
                Assert.Equal(PeerEgressDnsTakeover.CodeRefused, code);
                Assert.True(Text(testCase, "reason") == reason && upstreams is null, $"{name}: {reason}");
            }
            else
            {
                Assert.True(reason is null && Strings(testCase.GetProperty("upstreams")).SequenceEqual(upstreams!),
                    $"{name}: {reason} {string.Join(",", upstreams ?? [])}");
            }
        }
    }

    /// <summary>A step as the vector writes it: an argv array, or an object naming a file or service action.</summary>
    private static string Describe(JsonElement step) =>
        step.ValueKind == JsonValueKind.Array
            ? "run " + string.Join(" | ", Strings(step))
            : step.TryGetProperty("write", out var write) ? $"write {write.GetString()} <{step.GetProperty("content").GetString()}>"
            : step.TryGetProperty("restore", out var restore) ? "restore " + restore.GetString()
            : "restore-service " + step.GetProperty("restore-service").GetString();

    private static string Describe(PeerEgressDnsStep step) =>
        step.Argv is { } argv ? "run " + string.Join(" | ", argv)
        : step.Write is { } write ? $"write {write} <{step.Content}>"
        : step.Restore is { } restore ? "restore " + restore
        : "restore-service " + step.RestoreService;

    [Fact]
    public void PlansMatchTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("plan").EnumerateArray())
        {
            var platform = testCase.GetProperty("platform").GetString()!;
            var plan = PeerEgressDnsTakeoverRules.Plan(platform, testCase.GetProperty("listen").GetString()!,
                Text(testCase, "tunnel") ?? "specus0",
                testCase.TryGetProperty("services", out var services) ? Strings(services) : null);
            Assert.NotNull(plan);
            Assert.Equal(testCase.GetProperty("apply").EnumerateArray().Select(Describe), plan.Apply.Select(Describe));
            Assert.Equal(testCase.GetProperty("revert").EnumerateArray().Select(Describe), plan.Revert.Select(Describe));
        }
        Assert.Null(PeerEgressDnsTakeoverRules.Plan("plan9", "198.18.0.1", "specus0", null));
    }

    [Fact]
    public void GivingBackMatchesTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        foreach (var testCase in root.GetProperty("revertResolvConf").EnumerateArray())
        {
            var (restore, warning) = PeerEgressDnsTakeoverRules.RevertResolvConf(testCase.GetProperty("current").GetString());
            var action = testCase.GetProperty("action").GetString();
            Assert.True((action == "restore") == restore, Text(testCase, "name"));
            Assert.Equal(Text(testCase, "warning"), warning);
            if (restore)
            {
                // What is written back is the original the journal kept.
                Assert.Equal(testCase.GetProperty("original").GetString(), testCase.GetProperty("content").GetString());
            }
        }
        var listen = root.GetProperty("listen").GetString()!;
        foreach (var testCase in root.GetProperty("revertMacService").EnumerateArray())
        {
            var (command, warning) = PeerEgressDnsTakeoverRules.RevertMacService(testCase.GetProperty("service").GetString()!,
                Strings(testCase.GetProperty("current")), Strings(testCase.GetProperty("original")), listen);
            if (testCase.GetProperty("action").GetString() == "restore")
            {
                Assert.Equal(Strings(testCase.GetProperty("command")), command);
                Assert.Null(warning);
            }
            else
            {
                Assert.Null(command);
                Assert.Equal(Text(testCase, "warning"), warning);
            }
        }
    }
}
