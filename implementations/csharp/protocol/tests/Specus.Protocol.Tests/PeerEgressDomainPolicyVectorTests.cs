using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Replays the egress half of <c>peer-egress-domain-policy-v1.json</c>: the domain rules an egress
/// keeps from a pushed <c>egress-config</c>, and what it decides for a flow that carries a name.
/// </summary>
/// <remarks>
/// Every case goes through the real decoder and the real judgment layer, not a policy assembled in
/// the test, so a field the decoder drops or a match it fails to normalise shows up as a wrong code.
/// The <c>management</c> half is what a server stores and is not read here.
/// </remarks>
public class PeerEgressDomainPolicyVectorTests
{
    private static JsonDocument ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "protocol", "test-vectors", "peer-egress-domain-policy-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-domain-policy-v1.json");
    }

    /// <summary>A case's own config when it carries one, the top-level config otherwise.</summary>
    private static PeerEgressPolicy PolicyFor(JsonElement vector, JsonElement testCase)
    {
        var config = testCase.TryGetProperty("config", out var own) ? own : vector.GetProperty("config");
        var decoded = PeerEgressConfigMessage.Decode(config.GetRawText());
        Assert.True(decoded is not null, $"{testCase.GetProperty("name").GetString()}: the config was refused");
        return decoded!.Policy;
    }

    [Fact]
    public void AuthorizationOfNamedFlowsMatchesSharedVector()
    {
        using var document = ReadVector();
        var vector = document.RootElement;
        var cases = vector.GetProperty("authorize");
        Assert.True(cases.GetArrayLength() > 0, "the vector carried no authorize cases");

        var named = 0;
        var unnamed = 0;
        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var request = testCase.GetProperty("request").Deserialize<PeerEgressRequest>()!;
            if (request.Name is null)
            {
                unnamed++;
            }
            else
            {
                named++;
            }
            // The vector's forced-deny list is the default one, mesh network included.
            var decision = PeerEgressAuthorization.Authorize(
                request, PolicyFor(vector, testCase), true, PeerEgressContext.Default);
            var expected = testCase.GetProperty("code").GetString();
            Assert.True(expected == decision.Code, $"{name}: expected {expected}, got {decision.Code}");
            Assert.True((expected == PeerEgressCodes.Allowed) == decision.Allowed, $"{name}: allowed");
        }
        // The point of the vector is the name, and the case without one is what proves a domain rule
        // never grants an address. A rewrite that lost either would otherwise pass here unnoticed.
        Assert.True(named > 0, "no case carried a name");
        Assert.True(unnamed > 0, "no case arrived without a name");
    }

    /// <summary>
    /// What the decoder keeps: a match normalised, an unreadable entry skipped without taking the
    /// readable ones with it, and an absent or non-array field read as no rules.
    /// </summary>
    [Fact]
    public void DomainRulesDecodeAsTheReferenceKeepsThem()
    {
        using var document = ReadVector();
        var vector = document.RootElement;

        var top = PeerEgressConfigMessage.Decode(vector.GetProperty("config").GetRawText())!.Policy;
        Assert.Equal(["example.com", "*.cdn.example", "api.example.org"], top.DomainRules.Select(rule => rule.Match));
        Assert.Equal(["tcp", "udp"], top.DomainRules[1].Protocols);
        Assert.Equal([[443, 443]], top.DomainRules[1].PortRanges);

        var cases = vector.GetProperty("authorize").EnumerateArray()
            .ToDictionary(testCase => testCase.GetProperty("name").GetString()!);
        var skipped = PolicyFor(vector, cases["unreadable-entries-skipped"]);
        Assert.Equal(["example.com"], skipped.DomainRules.Select(rule => rule.Match));
        Assert.Empty(PolicyFor(vector, cases["absent-domain-rules"]).DomainRules);
        Assert.Empty(PolicyFor(vector, cases["domain-rules-not-an-array"]).DomainRules);
        Assert.Empty(PolicyFor(vector, cases["wildcard-entry-grants-nothing"]).DomainRules);
    }
}
