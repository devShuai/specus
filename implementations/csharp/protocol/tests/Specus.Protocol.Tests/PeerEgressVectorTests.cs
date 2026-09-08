using System.Text.Json;
using System.Text.Json.Serialization;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Binds this implementation to the shared vectors under protocol/test-vectors.
/// </summary>
/// <remarks>
/// The assertions check the returned code, not just allow versus deny: a runtime that denies for
/// the wrong reason still leaves an operator unable to tell a revoked ACL from a closed port.
/// </remarks>
public sealed class PeerEgressVectorTests
{
    [Fact]
    public void AuthorizationMatchesSharedVector()
    {
        var vector = ReadVector<AuthzVector>("peer-egress-authz-v1.json");
        Assert.NotEmpty(vector.Cases);
        var context = ContextFor(vector);
        foreach (var testCase in vector.Cases)
        {
            var decision = PeerEgressAuthorization.Authorize(testCase.Request, vector.Policy, true, context);
            Assert.Equal(testCase.Expect.Code, decision.Code);
            Assert.Equal(testCase.Expect.Allowed, decision.Allowed);
        }
    }

    [Fact]
    public void PolicyVariantsMatchSharedVector()
    {
        var vector = ReadVector<AuthzVector>("peer-egress-authz-v1.json");
        Assert.NotEmpty(vector.PolicyVariantCases);
        var context = ContextFor(vector);
        foreach (var testCase in vector.PolicyVariantCases)
        {
            var policy = vector.Policy;
            var overrides = testCase.PolicyOverride;
            if (overrides is not null)
            {
                policy = policy with
                {
                    Enabled = overrides.Enabled ?? policy.Enabled,
                    Scope = overrides.Scope ?? policy.Scope,
                    DestinationRules = overrides.DestinationRules ?? policy.DestinationRules,
                };
            }
            var decision = PeerEgressAuthorization.Authorize(
                testCase.Request, policy, testCase.PeerAclAllows ?? true, context);
            Assert.Equal(testCase.Expect.Code, decision.Code);
        }
    }

    /// <summary>
    /// The vector policy deliberately contains a 0.0.0.0/0 rule. Every address the vector declares
    /// as forced-deny must still be refused through it.
    /// </summary>
    [Fact]
    public void ForcedDenyDestinationsSurviveABroadAllowRule()
    {
        var vector = ReadVector<AuthzVector>("peer-egress-authz-v1.json");
        Assert.Contains(vector.Policy.DestinationRules, rule => rule.Cidr == "0.0.0.0/0");

        var context = ContextFor(vector);
        var denied = vector.ForcedDenyCidrs.Concat(vector.CloudMetadataCidrs).ToArray();
        Assert.NotEmpty(denied);
        foreach (var text in denied)
        {
            Assert.True(Ipv4Cidr.TryParse(text, out var cidr), text);
            var decision = PeerEgressAuthorization.Authorize(
                new PeerEgressRequest
                {
                    ConsumerClientId = 1,
                    DestinationIp = Ipv4Cidr.FormatAddress(cidr.Network),
                    DestinationPort = 443,
                    Protocol = "tcp",
                },
                vector.Policy, true, context);
            Assert.Equal(PeerEgressCodes.ForbiddenDestination, decision.Code);
        }
    }

    [Fact]
    public void RuleMatchingMatchesSharedVector()
    {
        var vector = ReadVector<RulesVector>("peer-egress-rules-v1.json");
        Assert.NotEmpty(vector.Rules);
        foreach (var testCase in vector.Cases)
        {
            var match = PeerEgressRules.Match(vector.Rules, testCase.Destination);
            Assert.Equal(testCase.Expect.Action, match.Action);
            if (testCase.Expect.MatchedRuleIndex is null)
            {
                Assert.False(match.Matched, testCase.Name);
                continue;
            }
            Assert.Equal(testCase.Expect.MatchedRuleIndex.Value, match.MatchedRuleIndex);
            if (testCase.Expect.EgressClientId is not null)
            {
                Assert.Equal(testCase.Expect.EgressClientId, match.EgressClientId);
            }
        }
    }

    [Fact]
    public void RuleValidationMatchesSharedVector()
    {
        var vector = ReadVector<RulesVector>("peer-egress-rules-v1.json");
        var mesh = string.IsNullOrWhiteSpace(vector.MeshCidr) ? PeerEgressRules.DefaultMeshCidr : vector.MeshCidr;
        foreach (var rule in vector.Rules)
        {
            Assert.Null(PeerEgressRules.Validate(rule, mesh));
        }
        Assert.NotEmpty(vector.ConfigValidation);
        foreach (var testCase in vector.ConfigValidation)
        {
            Assert.Equal(testCase.Code, PeerEgressRules.Validate(testCase.Rule, mesh));
        }
    }

    /// <summary>
    /// Boundary sweep shared by every runtime.
    /// </summary>
    /// <remarks>
    /// The hand-written cases document intent; this exists to catch a runtime that agrees on the
    /// documented examples but diverges one address or one port away from a boundary. Every runtime
    /// runs the same sweep against the same policy, so a disagreement here is a disagreement about
    /// the rules rather than about the fixture.
    /// </remarks>
    [Fact]
    public void CrossLanguageBoundarySweepMatchesSharedVector()
    {
        var vector = ReadVector<AuthzVector>("peer-egress-authz-v1.json");
        Assert.True(vector.CrossLanguageCases.Count >= 100,
            $"cross-language sweep carried only {vector.CrossLanguageCases.Count} cases");
        var context = ContextFor(vector);
        foreach (var testCase in vector.CrossLanguageCases)
        {
            var decision = PeerEgressAuthorization.Authorize(testCase.Request, vector.Policy, true, context);
            Assert.Equal(testCase.Expect.Code, decision.Code);
            Assert.Equal(testCase.Expect.Allowed, decision.Allowed);
        }
    }

    /// <summary>
    /// The mesh network reaches the implementation through the deployment context rather than the
    /// static list, so it is lifted back out of the vector forced-deny set by its prefix length.
    /// </summary>
    private static PeerEgressContext ContextFor(AuthzVector vector)
    {
        var mesh = PeerEgressRules.DefaultMeshCidr;
        foreach (var text in vector.ForcedDenyCidrs)
        {
            if (Ipv4Cidr.TryParse(text, out var cidr) && cidr.PrefixLength == 11)
            {
                mesh = text;
            }
        }
        return new PeerEgressContext { MeshCidr = mesh };
    }

    private static T ReadVector<T>(string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (!File.Exists(candidate))
            {
                continue;
            }
            return JsonSerializer.Deserialize<T>(File.ReadAllText(candidate))
                ?? throw new InvalidDataException($"{name} decoded to null");
        }
        throw new FileNotFoundException($"cannot locate {name}");
    }

    private sealed record Expectation
    {
        [JsonPropertyName("allowed")]
        public bool Allowed { get; init; }

        [JsonPropertyName("code")]
        public string Code { get; init; } = string.Empty;
    }

    private sealed record AuthzVector
    {
        [JsonPropertyName("forcedDenyCidrs")]
        public IReadOnlyList<string> ForcedDenyCidrs { get; init; } = [];

        [JsonPropertyName("cloudMetadataCidrs")]
        public IReadOnlyList<string> CloudMetadataCidrs { get; init; } = [];

        [JsonPropertyName("lanCidrs")]
        public IReadOnlyList<string> LanCidrs { get; init; } = [];

        [JsonPropertyName("policy")]
        public PeerEgressPolicy Policy { get; init; } = new();

        [JsonPropertyName("cases")]
        public IReadOnlyList<AuthzCase> Cases { get; init; } = [];

        [JsonPropertyName("crossLanguageCases")]
        public IReadOnlyList<AuthzCase> CrossLanguageCases { get; init; } = [];

        [JsonPropertyName("policyVariantCases")]
        public IReadOnlyList<PolicyVariantCase> PolicyVariantCases { get; init; } = [];
    }

    private sealed record AuthzCase
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("request")]
        public PeerEgressRequest Request { get; init; } = new();

        [JsonPropertyName("expect")]
        public Expectation Expect { get; init; } = new();
    }

    private sealed record PolicyOverride
    {
        [JsonPropertyName("enabled")]
        public bool? Enabled { get; init; }

        [JsonPropertyName("scope")]
        public string? Scope { get; init; }

        [JsonPropertyName("destinationRules")]
        public IReadOnlyList<PeerEgressDestinationRule>? DestinationRules { get; init; }
    }

    private sealed record PolicyVariantCase
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("policyOverride")]
        public PolicyOverride? PolicyOverride { get; init; }

        [JsonPropertyName("peerAclAllows")]
        public bool? PeerAclAllows { get; init; }

        [JsonPropertyName("request")]
        public PeerEgressRequest Request { get; init; } = new();

        [JsonPropertyName("expect")]
        public Expectation Expect { get; init; } = new();
    }

    private sealed record RulesVector
    {
        [JsonPropertyName("meshCidr")]
        public string MeshCidr { get; init; } = string.Empty;

        [JsonPropertyName("rules")]
        public IReadOnlyList<PeerEgressRule> Rules { get; init; } = [];

        [JsonPropertyName("cases")]
        public IReadOnlyList<RuleCase> Cases { get; init; } = [];

        [JsonPropertyName("configValidation")]
        public IReadOnlyList<ValidationCase> ConfigValidation { get; init; } = [];
    }

    private sealed record RuleCase
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("destination")]
        public string Destination { get; init; } = string.Empty;

        [JsonPropertyName("expect")]
        public RuleExpectation Expect { get; init; } = new();
    }

    private sealed record RuleExpectation
    {
        [JsonPropertyName("action")]
        public string Action { get; init; } = string.Empty;

        [JsonPropertyName("matchedRuleIndex")]
        public int? MatchedRuleIndex { get; init; }

        [JsonPropertyName("egressClientId")]
        public long? EgressClientId { get; init; }
    }

    private sealed record ValidationCase
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("rule")]
        public PeerEgressRule Rule { get; init; } = new();

        [JsonPropertyName("code")]
        public string Code { get; init; } = string.Empty;
    }
}
