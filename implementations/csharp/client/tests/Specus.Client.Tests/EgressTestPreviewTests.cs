using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Client.Cli;
using Specus.Client.Configuration;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// egress test with a name (protocol/spec/peer-egress-dns.md, 预演一个域名): the five lines, the
/// data, the order the reasons for domain rules being out of force are given in, and the refusals,
/// through the preview the command, the local page and the desktop page share.
/// </summary>
public sealed class EgressTestPreviewTests : IDisposable
{
    private const string Credentials = "\"serverBaseUrl\":\"http://127.0.0.1:1\",\"apiKey\":\"key\",\"secret\":\"secret\"";

    private const string SystemDns = "  result: resolved by the system's DNS; egress test <that address> previews where it goes";

    private const string Forwarded = "  dns: forwarded to the system's DNS; the address it returns is then decided by the IPv4 rules";

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-test-" + Guid.NewGuid().ToString("N"));

    public EgressTestPreviewTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }

    private static PeerEgressRule Rule(string match, string action, long? egress = null, bool? enabled = null) =>
        new() { Match = match, Action = action, EgressClientId = egress, Enabled = enabled };

    /// <summary>An exact egress rule, a suffix block rule, an exact direct rule under it, and an address rule.</summary>
    private static List<PeerEgressRule> Rules() =>
    [
        Rule("example.com", "egress", 42),
        Rule("*.example.com", "block"),
        Rule("direct.example.com", "direct"),
        Rule("203.0.113.0/24", "egress", 7),
    ];

    private static SpecusClientConfig Config(bool takeover = true, bool dns = true, string pool = "198.18.0.0/15",
        List<PeerEgressRule>? rules = null) => new()
    {
        PeerEgressEnabled = takeover,
        PeerEgressDnsTakeover = dns,
        PeerEgressFakeIpCidr = pool,
        PeerEgressRules = rules ?? Rules(),
    };

    private static (List<string> Lines, Dictionary<string, object?> Data) Preview(SpecusClientConfig config, string address)
    {
        Assert.Null(EgressEdit.AddressProblem(address));
        var lines = new List<string>();
        var data = EgressEdit.Preview("c.jsonc", config, address, lines);
        return (lines, data);
    }

    [Fact]
    public void WithDomainRulesInForceEachActionSaysWhereTheNameGoes()
    {
        var config = Config();
        var (lines, data) = Preview(config, "Example.COM.");
        Assert.Equal(
        [
            "Preview for example.com from the configuration (no connection is made)",
            "  takeover: on | dns takeover: on",
            "  rule: [0] example.com egress 42",
            "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name",
            "  result: through egress 42, which resolves the name itself",
        ], lines);
        Assert.Equal(["configPath", "address", "kind", "takeover", "dnsTakeover", "matchedRuleIndex", "ruleAction",
            "egressClientId", "dns", "result"], data.Keys);
        Assert.Equal(("c.jsonc", "example.com", "domain", true, true, 0, "egress", 42L, "fake", "egress"),
            ((string)data["configPath"]!, (string)data["address"]!, (string)data["kind"]!, (bool)data["takeover"]!,
                (bool)data["dnsTakeover"]!, (int)data["matchedRuleIndex"]!, (string)data["ruleAction"]!,
                (long)data["egressClientId"]!, (string)data["dns"]!, (string)data["result"]!));

        (lines, data) = Preview(config, "a.b.example.com");
        Assert.Equal(
        [
            "  rule: [1] *.example.com block",
            "  dns: answered with a fake IP from 198.18.0.0/15",
            "  result: blocked",
        ], lines[2..]);
        Assert.Equal(["configPath", "address", "kind", "takeover", "dnsTakeover", "matchedRuleIndex", "ruleAction",
            "dns", "result"], data.Keys);
        Assert.Equal((1, "block", "fake", "block"),
            ((int)data["matchedRuleIndex"]!, (string)data["ruleAction"]!, (string)data["dns"]!, (string)data["result"]!));

        // The exact direct rule wins over the suffix that also covers it, and is not taken over.
        (lines, data) = Preview(config, "direct.example.com");
        Assert.Equal(["  rule: [2] direct.example.com direct", Forwarded, SystemDns], lines[2..]);
        Assert.Equal((2, "direct", "forward", "direct"),
            ((int)data["matchedRuleIndex"]!, (string)data["ruleAction"]!, (string)data["dns"]!, (string)data["result"]!));
        Assert.False(data.ContainsKey("resultWithTakeover"));

        (lines, data) = Preview(config, "example.org");
        Assert.Equal(["  rule: none", Forwarded, SystemDns], lines[2..]);
        Assert.Equal(["configPath", "address", "kind", "takeover", "dnsTakeover", "matchedRuleIndex", "dns", "result"], data.Keys);
        Assert.Equal((-1, "forward", "direct"), ((int)data["matchedRuleIndex"]!, (string)data["dns"]!, (string)data["result"]!));
    }

    [Fact]
    public void ThePoolInTheDnsLineIsTheConfiguredOne()
    {
        var (lines, _) = Preview(Config(pool: "10.64.0.0/16"), "x.example.com");
        Assert.Equal("  dns: answered with a fake IP from 10.64.0.0/16", lines[3]);
    }

    /// <summary>
    /// Out of force, the reason is the first that holds of the master switch, the DNS switch and the
    /// pool; the dns line follows phase two as config validate judges it, with the master switch on.
    /// </summary>
    [Theory]
    [InlineData(false, true, "198.18.0.0/15", "takeover is off",
        "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name", "fake")]
    [InlineData(true, false, "198.18.0.0/15", "dns takeover is off",
        "  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS", "local")]
    [InlineData(true, true, "100.96.0.0/16", "peerEgressFakeIpCidr is not usable",
        "  dns: not taken over (peerEgressFakeIpCidr is not usable), so the name is resolved by the system's DNS", "local")]
    [InlineData(true, true, "198.18.0.0/25", "peerEgressFakeIpCidr is not usable",
        "  dns: not taken over (peerEgressFakeIpCidr is not usable), so the name is resolved by the system's DNS", "local")]
    [InlineData(false, false, "not a pool", "takeover is off",
        "  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS", "local")]
    [InlineData(false, true, "not a pool", "takeover is off",
        "  dns: not taken over (peerEgressFakeIpCidr is not usable), so the name is resolved by the system's DNS", "local")]
    [InlineData(true, false, "not a pool", "dns takeover is off",
        "  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS", "local")]
    public void ADomainRuleOutOfForceSaysWhyAndWhatItWouldDo(bool takeover, bool dns, string pool, string reason,
        string dnsLine, string dnsData)
    {
        var config = Config(takeover, dns, pool);
        var (lines, data) = Preview(config, "example.com");
        Assert.Equal(
        [
            "Preview for example.com from the configuration (no connection is made)",
            $"  takeover: {(takeover ? "on" : "off")} | dns takeover: {(dns ? "on" : "off")}",
            "  rule: [0] example.com egress 42",
            dnsLine,
            $"  result: domain rules are not in force ({reason}); with them on: through egress 42, which resolves the name itself",
        ], lines);
        Assert.Equal(["configPath", "address", "kind", "takeover", "dnsTakeover", "matchedRuleIndex", "ruleAction",
            "egressClientId", "dns", "result", "resultWithTakeover"], data.Keys);
        Assert.Equal((dnsData, "direct", "egress", 0, 42L), ((string)data["dns"]!, (string)data["result"]!,
            (string)data["resultWithTakeover"]!, (int)data["matchedRuleIndex"]!, (long)data["egressClientId"]!));

        (lines, data) = Preview(config, "www.example.com");
        Assert.Equal($"  result: domain rules are not in force ({reason}); with them on: blocked", lines[4]);
        Assert.Equal(("direct", "block"), ((string)data["result"]!, (string)data["resultWithTakeover"]!));

        // Nothing to be in force for: a direct rule or no rule reads the same either way.
        foreach (var name in new[] { "direct.example.com", "example.net" })
        {
            (lines, data) = Preview(config, name);
            Assert.Equal(SystemDns, lines[4]);
            Assert.Equal("direct", data["result"]);
            Assert.False(data.ContainsKey("resultWithTakeover"));
            Assert.Equal(dnsData == "fake" ? Forwarded : dnsLine, lines[3]);
        }
    }

    [Fact]
    public void ARuleNotInForceForItsOwnSakeClaimsNothing()
    {
        var rules = new List<PeerEgressRule>
        {
            Rule("*.b.example.com", "egress", 42, enabled: false),
            Rule("a.b.example.com", "egress"),
            Rule("*.example.com", "block"),
            Rule("*.example.com", "egress", 9),
        };
        var (lines, data) = Preview(Config(rules: rules), "a.b.example.com");
        // Switched off, and an egress rule with no egress: the first suffix of the two equal ones wins.
        Assert.Equal("  rule: [2] *.example.com block", lines[2]);
        Assert.Equal(2, data["matchedRuleIndex"]);

        rules[0] = rules[0] with { Enabled = null };
        (lines, _) = Preview(Config(rules: rules), "a.b.example.com");
        Assert.Equal("  rule: [0] *.b.example.com egress 42", lines[2]);
    }

    [Fact]
    public void AnAddressSaysWhatKindItIs()
    {
        var (lines, data) = Preview(Config(), "203.0.113.9");
        Assert.Equal("Preview for 203.0.113.9 from the configuration (no connection is made; --connect PORT tests one)", lines[0]);
        Assert.Equal("  result: through egress 7", lines[^1]);
        Assert.Equal(["configPath", "address", "kind", "takeover", "matchedRuleIndex", "ruleAction", "egressClientId", "result"],
            data.Keys);
        Assert.Equal("address", data["kind"]);
    }

    [Theory]
    [InlineData("203.0.113.9", null)]
    [InlineData("example.com", null)]
    [InlineData("Example.COM.", null)]
    [InlineData("xn--fiqs8s.example", null)]
    [InlineData("a-b.1.example", null)]
    [InlineData("bad_name.example", EgressEdit.NameProblem)]
    [InlineData("例子.测试", EgressEdit.NameProblem)]
    [InlineData("例子.com", EgressEdit.NameProblem)]
    [InlineData("examKple.com", EgressEdit.NameProblem)]
    [InlineData("*.example.com", EgressEdit.NameProblem)]
    [InlineData("example", EgressEdit.NameProblem)]
    [InlineData("-a.example.com", EgressEdit.NameProblem)]
    [InlineData("a..example.com", EgressEdit.NameProblem)]
    [InlineData("", "ADDRESS must be an IPv4 address.")]
    [InlineData("300.1.1.1", "ADDRESS must be an IPv4 address.")]
    [InlineData("203.0.113.0/24", "ADDRESS must be an IPv4 address.")]
    [InlineData("2001:db8::1", "ADDRESS must be an IPv4 address.")]
    [InlineData("1.2.3.4.", "ADDRESS must be an IPv4 address.")]
    public void OnlyAnAddressOrANameARuleCanMatchIsPreviewed(string address, string? problem)
    {
        Assert.Equal(problem, EgressEdit.AddressProblem(address));
    }

    // ----------------------------------------------------------------------------------------------
    // The local page's route and the command, on a file.

    private string WriteConfig(string extra)
    {
        var path = Path.Combine(_directory, "egress test.jsonc");
        File.WriteAllText(path, "{" + Credentials + extra + "}\n");
        return path;
    }

    private const string PhaseTwoFile = ",\"peerEgressEnabled\":true,\"peerEgressDnsTakeover\":true,"
        + "\"peerEgressRules\":[{\"match\":\"example.com\",\"action\":\"egress\",\"egressClientId\":42}]";

    [Fact]
    public void TheLocalPagePreviewsANameAndRefusesWhatTheCommandRefuses()
    {
        var path = WriteConfig(PhaseTwoFile);
        var data = EgressEdit.UiTest(path, new JsonObject { ["address"] = "Example.COM." });
        Assert.Equal(("domain", "example.com", "fake", "egress", 42L, 1),
            ((string)data["kind"]!, (string)data["address"]!, (string)data["dns"]!, (string)data["result"]!,
                (long)data["egressClientId"]!, (int)data["schemaVersion"]!));
        Assert.Equal("address", EgressEdit.UiTest(path, new JsonObject { ["address"] = "203.0.113.9" })["kind"]);

        // A wildcard is how a rule is written, not a name anything looks up.
        foreach (var unusable in new[] { "bad_name.example", "*.example.com" })
        {
            var failure = Assert.Throws<LocalUi.Failure>(() => EgressEdit.UiTest(path, new JsonObject { ["address"] = unusable }));
            Assert.Equal((422, EgressEdit.NameProblem), (failure.Status, failure.Message));
        }
        var refused = Assert.Throws<LocalUi.Failure>(() =>
            EgressEdit.UiTest(path, new JsonObject { ["address"] = "example.com", ["connect"] = 443 }));
        Assert.Equal((422, EgressEdit.ConnectNeedsAddress), (refused.Status, refused.Message));
    }

    [Fact]
    public async Task TheCommandPrintsFiveLinesAndRefusesAConnectionToAName()
    {
        var path = WriteConfig(PhaseTwoFile);
        var (code, output, _) = await Cli("egress", "test", "example.com", "--config", path);
        Assert.Equal(0, code);
        Assert.Equal(
        [
            "Preview for example.com from the configuration (no connection is made)",
            "  takeover: on | dns takeover: on",
            "  rule: [0] example.com egress 42",
            "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name",
            "  result: through egress 42, which resolves the name itself",
        ], output.TrimEnd('\n').Split('\n'));

        (code, output, _) = await Cli("egress", "test", "WWW.example.com.", "--config", path, "--json");
        Assert.Equal(0, code);
        using (var json = JsonDocument.Parse(output))
        {
            var data = json.RootElement.GetProperty("data");
            Assert.Equal(["configPath", "address", "kind", "takeover", "dnsTakeover", "matchedRuleIndex", "dns", "result"],
                data.EnumerateObject().Select(field => field.Name));
            Assert.Equal("www.example.com", data.GetProperty("address").GetString());
            Assert.Equal(-1, data.GetProperty("matchedRuleIndex").GetInt32());
            Assert.Equal("forward", data.GetProperty("dns").GetString());
        }

        var errors = "";
        (code, _, errors) = await Cli("egress", "test", "example.com", "--connect", "443", "--config", path);
        Assert.Equal(2, code);
        Assert.Equal(EgressEdit.ConnectNeedsAddress + "\n", errors);
        foreach (var unusable in new[] { "bad_name.example", "*.example.com" })
        {
            (code, _, errors) = await Cli("egress", "test", unusable, "--config", path);
            Assert.Equal(2, code);
            Assert.Equal(EgressEdit.NameProblem + "\n", errors);
        }
        (code, output, _) = await Cli("egress", "test", "bad_name.example", "--config", path, "--json");
        Assert.Equal(2, code);
        using (var json = JsonDocument.Parse(output))
        {
            Assert.Equal(EgressEdit.NameProblem, json.RootElement.GetProperty("error").GetString());
        }
    }

    /// <summary>Runs the built client; the state directory is a test's own, never the user's.</summary>
    private async Task<(int Code, string Output, string Errors)> Cli(params string[] args)
    {
        var start = new System.Diagnostics.ProcessStartInfo("dotnet")
        {
            WorkingDirectory = _directory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment["SPECUS_CLI_STATE_DIR"] = Path.Combine(_directory, "state");
        start.Environment["HOME"] = _directory;
        start.Environment["USERPROFILE"] = _directory;
        start.ArgumentList.Add(typeof(Specus.Client.Control.SpecusControlClient).Assembly.Location);
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }
        using var process = System.Diagnostics.Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, (await output).Replace("\r\n", "\n"), (await errors).Replace("\r\n", "\n"));
    }
}
