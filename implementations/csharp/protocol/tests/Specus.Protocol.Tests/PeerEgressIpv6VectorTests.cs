using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Binds the IPv6 spelling and IPv6 rules to the <c>ipv6Prefixes</c> and <c>ipv6</c> sections of
/// protocol/test-vectors/peer-egress-rules-v1.json, the sections the Go and Java implementations read.
/// </summary>
public sealed class PeerEgressIpv6VectorTests
{
    [Fact]
    public void SpellingMatchesSharedVector()
    {
        using var vector = ReadVector();
        var prefixes = vector.RootElement.GetProperty("ipv6Prefixes");
        var accept = prefixes.GetProperty("accept").EnumerateArray().ToList();
        var reject = prefixes.GetProperty("reject").EnumerateArray().ToList();
        Assert.NotEmpty(accept);
        Assert.NotEmpty(reject);
        foreach (var testCase in accept)
        {
            var text = testCase.GetProperty("text").GetString()!;
            var address = testCase.GetProperty("address").GetString()!;
            var length = testCase.GetProperty("prefixLength").GetInt32();
            Assert.True(Ipv6Cidr.TryParse(text, out var cidr, out var hadLength), text);
            Assert.Equal(address, Ipv6Cidr.FormatAddress(cidr.Network));
            Assert.Equal(length, cidr.PrefixLength);
            // The canonical form reads back as the same address.
            Assert.True(Ipv6Cidr.TryParseAddress(address, out var again), address);
            Assert.Equal(cidr.Network, again);
            // What a server stores: the canonical address, with the length only when it was written.
            Assert.Equal(hadLength ? $"{address}/{length}" : address, Ipv6Cidr.StoredDestinationCidr(text));
        }
        foreach (var testCase in reject)
        {
            var text = testCase.GetProperty("text").GetString()!;
            Assert.False(Ipv6Cidr.TryParse(text, out _), text);
            Assert.Null(Ipv6Cidr.StoredDestinationCidr(text));
        }
    }

    [Fact]
    public void RulesMatchSharedVectorWithAnIpv6DataPlane()
    {
        using var vector = ReadVector();
        var section = vector.RootElement.GetProperty("ipv6");
        var rules = Rules(section);
        var refused = section.GetProperty("refusedRules").EnumerateArray()
            .ToDictionary(entry => entry.GetProperty("index").GetInt32(), entry => entry.GetProperty("code").GetString());
        for (var index = 0; index < rules.Count; index++)
        {
            Assert.Equal(refused.GetValueOrDefault(index),
                PeerEgressRules.Validate(rules[index], PeerEgressRules.DefaultMeshCidr, null, carriesIpv6: true));
        }
        foreach (var testCase in section.GetProperty("cases").EnumerateArray())
        {
            AssertMatch(testCase, PeerEgressRules.Match(rules, testCase.GetProperty("destination").GetString(),
                PeerEgressRules.DefaultMeshCidr, null, carriesIpv6: true));
        }
        foreach (var testCase in section.GetProperty("configValidation").EnumerateArray())
        {
            var rule = testCase.GetProperty("rule").Deserialize<PeerEgressRule>()!;
            var code = testCase.GetProperty("code");
            Assert.Equal(code.ValueKind == JsonValueKind.Null ? null : code.GetString(),
                PeerEgressRules.Validate(rule, PeerEgressRules.DefaultMeshCidr, null, carriesIpv6: true));
        }
    }

    /// <summary>
    /// What every client does today: the same list with no IPv6 data plane, through the production
    /// entry points, so turning <see cref="PeerEgressRules.ConsumerCarriesIpv6"/> on without the data
    /// plane fails here.
    /// </summary>
    [Fact]
    public void Ipv6RulesAreNotInForceWithoutAnIpv6DataPlane()
    {
        using var vector = ReadVector();
        var section = vector.RootElement.GetProperty("ipv6");
        var rules = Rules(section);
        var without = section.GetProperty("withoutIpv6DataPlane");
        foreach (var entry in without.GetProperty("ruleCodes").EnumerateArray())
        {
            var code = entry.GetProperty("code");
            Assert.Equal(code.ValueKind == JsonValueKind.Null ? null : code.GetString(),
                PeerEgressRules.Validate(rules[entry.GetProperty("index").GetInt32()], PeerEgressRules.DefaultMeshCidr));
        }
        foreach (var testCase in without.GetProperty("cases").EnumerateArray())
        {
            AssertMatch(testCase, PeerEgressRules.Match(rules, testCase.GetProperty("destination").GetString(),
                PeerEgressRules.DefaultMeshCidr));
        }
    }

    private static List<PeerEgressRule> Rules(JsonElement section)
    {
        var rules = section.GetProperty("rules").EnumerateArray()
            .Select(rule => rule.Deserialize<PeerEgressRule>()!).ToList();
        Assert.NotEmpty(rules);
        for (var position = 0; position < rules.Count; position++)
        {
            Assert.Equal(position, rules[position].Index);
        }
        return rules;
    }

    private static void AssertMatch(JsonElement testCase, PeerEgressRuleMatch match)
    {
        var expect = testCase.GetProperty("expect");
        var destination = testCase.GetProperty("destination").GetString();
        Assert.Equal(expect.GetProperty("action").GetString(), match.Action);
        var index = expect.GetProperty("matchedRuleIndex");
        Assert.True((index.ValueKind == JsonValueKind.Null ? -1 : index.GetInt32()) == match.MatchedRuleIndex, destination);
        if (expect.TryGetProperty("egressClientId", out var egress))
        {
            Assert.Equal(egress.GetInt64(), match.EgressClientId);
        }
    }

    private static JsonDocument ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-rules-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
        }
        throw new FileNotFoundException("peer-egress-rules-v1.json");
    }
}
