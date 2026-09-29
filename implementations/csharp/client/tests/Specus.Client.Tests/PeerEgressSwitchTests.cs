using System.Text.Json;
using Specus.Client.Cli;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// The consumer's master switch, <c>peerEgressEnabled</c>, off: the rules are kept, none is in force,
/// and each says why. Bound to the <c>consumerDisabled</c> section of the shared rules vector, which
/// the Go and Java clients read too.
/// </summary>
public class PeerEgressSwitchTests
{
    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-rules-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-rules-v1.json");
    }

    private static List<PeerEgressRule> Rules(JsonDocument vector) =>
        vector.RootElement.GetProperty("rules").EnumerateArray()
            .Select(node => JsonSerializer.Deserialize<PeerEgressRule>(node.GetRawText())!)
            .ToList();

    [Fact]
    public void EveryRuleIsOutOfForceAndSaysWhyWithTheSwitchOff()
    {
        using var vector = Vector();
        var rules = Rules(vector);
        var section = vector.RootElement.GetProperty("consumerDisabled");
        Assert.Equal(rules.Count, section.GetProperty("ruleCodes").GetArrayLength());

        var listed = PeerEgressStatus.SwitchedOffRules(rules);
        foreach (var want in section.GetProperty("ruleCodes").EnumerateArray())
        {
            var entry = listed[want.GetProperty("index").GetInt32()];
            Assert.Equal(false, entry["inForce"]);
            Assert.Equal(want.GetProperty("code").GetString(), entry["code"]);
        }
        // Off, the reconcile hands the engine no rules at all; nothing it is asked about matches.
        var mesh = vector.RootElement.GetProperty("meshCidr").GetString();
        foreach (var testCase in section.GetProperty("cases").EnumerateArray())
        {
            var decision = PeerEgressRules.Match([], testCase.GetProperty("destination").GetString()!, mesh);
            Assert.Equal(testCase.GetProperty("expect").GetProperty("action").GetString(), decision.Action);
            Assert.False(decision.Matched);
        }
    }

    [Fact]
    public void TheStatusSectionKeepsTheRulesAndTheCommandSaysTakeoverIsOff()
    {
        using var vector = Vector();
        var rules = Rules(vector);
        var status = PeerEgressStatus.Section(null, [], PeerEgressApplyOutcome.None, null, false, rules);
        var consumer = (Dictionary<string, object?>)status["consumer"]!;
        Assert.Equal(false, consumer["enabled"]);
        Assert.Equal(false, consumer["active"]);

        using var parsed = JsonDocument.Parse(JsonSerializer.Serialize(status));
        var lines = EgressView.Lines(parsed.RootElement);
        Assert.Equal($"  consumer: takeover off | {rules.Count} rules saved, none in force (peerEgressEnabled is false)",
            lines[0]);
    }

    [Fact]
    public void RulesKeptWithTheSwitchOffAreWarnedAboutOnce()
    {
        const string json = """
            {"peerEgressRules":[
              {"match":"203.0.113.0/24","action":"egress","egressClientId":42},
              {"match":"198.51.100.0/24","action":"block","enabled":false}]}
            """;
        var config = JsonSerializer.Deserialize<SpecusClientConfig>(json)!;
        var warnings = new List<string>();
        ConfigDiagnostics.Report(json, config, warnings.Add);
        Assert.Equal(["peerEgressRules has 2 rule(s) but peerEgressEnabled is false: none is in force"], warnings);
    }
}
