using System.Text.Json.Serialization;

namespace Specus.Protocol.PeerEgress;

/// <summary>One entry of an egress policy allowlist.</summary>
public sealed record PeerEgressDestinationRule
{
    [JsonPropertyName("cidr")]
    public string Cidr { get; init; } = string.Empty;

    [JsonPropertyName("protocols")]
    public IReadOnlyList<string> Protocols { get; init; } = [];

    [JsonPropertyName("portRanges")]
    public IReadOnlyList<int[]> PortRanges { get; init; } = [];
}

/// <summary>Limits that keep an egress node from acting as an open proxy.</summary>
public sealed record PeerEgressLimits
{
    [JsonPropertyName("maxConcurrentFlows")]
    public int MaxConcurrentFlows { get; init; }

    [JsonPropertyName("maxFlowsPerConsumer")]
    public int MaxFlowsPerConsumer { get; init; }

    [JsonPropertyName("idleTimeoutSeconds")]
    public int IdleTimeoutSeconds { get; init; }
}

/// <summary>The egress-side authorization policy owned by the server.</summary>
public sealed record PeerEgressPolicy
{
    [JsonPropertyName("egressClientId")]
    public long EgressClientId { get; init; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; }

    [JsonPropertyName("allowedConsumerClientIds")]
    public IReadOnlyList<long> AllowedConsumerClientIds { get; init; } = [];

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = PeerEgressAuthorization.ScopePublic;

    [JsonPropertyName("destinationRules")]
    public IReadOnlyList<PeerEgressDestinationRule> DestinationRules { get; init; } = [];

    [JsonPropertyName("limits")]
    public PeerEgressLimits Limits { get; init; } = new();
}

/// <summary>One flow-open attempt, evaluated before any socket is created.</summary>
public sealed record PeerEgressRequest
{
    [JsonPropertyName("consumerClientId")]
    public long ConsumerClientId { get; init; }

    [JsonPropertyName("destinationIp")]
    public string DestinationIp { get; init; } = string.Empty;

    [JsonPropertyName("destinationPort")]
    public int DestinationPort { get; init; }

    [JsonPropertyName("protocol")]
    public string Protocol { get; init; } = string.Empty;

    [JsonPropertyName("hop")]
    public bool Hop { get; init; }

    [JsonPropertyName("activeFlowsForConsumer")]
    public int ActiveFlowsForConsumer { get; init; }

    [JsonPropertyName("activeFlowsTotal")]
    public int ActiveFlowsTotal { get; init; }

    /// <summary>
    /// Networks owned by this node's own tunnel or virtual interfaces. Forwarding into one of them
    /// would loop back into this node's own capture path.
    /// </summary>
    [JsonPropertyName("localInterfaceCidrs")]
    public IReadOnlyList<string> LocalInterfaceCidrs { get; init; } = [];
}

/// <summary>The outcome of an authorization evaluation.</summary>
public readonly record struct PeerEgressDecision(bool Allowed, string Code);

/// <summary>Deployment-wide additions to the forced-deny list.</summary>
public sealed record PeerEgressContext
{
    public string MeshCidr { get; init; } = PeerEgressRules.DefaultMeshCidr;

    /// <summary>The control, STUN and TURN endpoint addresses for this deployment.</summary>
    public IReadOnlyList<string> DeploymentDenyCidrs { get; init; } = [];

    /// <summary>The context for a deployment on the default mesh network.</summary>
    public static PeerEgressContext Default { get; } = new();
}

/// <summary>One entry of egress-catalog.</summary>
/// <remarks>
/// The catalogue deliberately omits the egress node's destination allowlist. A consumer does not
/// need it to route, and shipping it would hand every peer a map of that node's reachable network.
/// </remarks>
public sealed record PeerEgressCatalogEntry
{
    [JsonPropertyName("clientId")]
    public long ClientId { get; init; }

    [JsonPropertyName("clientName")]
    public string ClientName { get; init; } = string.Empty;

    [JsonPropertyName("online")]
    public bool Online { get; init; }

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = PeerEgressAuthorization.ScopePublic;

    [JsonPropertyName("protocols")]
    public IReadOnlyList<string> Protocols { get; init; } = [];

    [JsonPropertyName("domainTargetCapable")]
    public bool DomainTargetCapable { get; init; }

    [JsonPropertyName("ipv6TargetCapable")]
    public bool Ipv6TargetCapable { get; init; }
}
