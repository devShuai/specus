using System.Net;

namespace Specus.StunServer;

public enum StunEndpointId
{
    Primary,
    PrimaryAlternatePort,
    AlternatePrimaryPort,
    Alternate,
}

public sealed record StunEndpoint(StunEndpointId Id, IPEndPoint Bind, IPEndPoint Advertised);

public sealed class StunTopology
{
    private static readonly StunEndpointId[] EndpointOrder =
    [
        StunEndpointId.Primary,
        StunEndpointId.PrimaryAlternatePort,
        StunEndpointId.AlternatePrimaryPort,
        StunEndpointId.Alternate,
    ];

    private readonly IReadOnlyDictionary<StunEndpointId, StunEndpoint> _endpoints;

    private StunTopology(IReadOnlyDictionary<StunEndpointId, StunEndpoint> endpoints, bool supportsRfc5780)
    {
        _endpoints = endpoints;
        SupportsRfc5780 = supportsRfc5780;
    }

    public bool SupportsRfc5780 { get; }

    public static StunTopology Basic(StunEndpoint primary, StunEndpoint? alternatePort)
    {
        ValidateEndpoint(primary, StunEndpointId.Primary);
        var endpoints = new Dictionary<StunEndpointId, StunEndpoint>
        {
            [StunEndpointId.Primary] = primary,
        };
        if (alternatePort is not null)
        {
            ValidateEndpoint(alternatePort, StunEndpointId.PrimaryAlternatePort);
            if (!primary.Bind.Address.Equals(alternatePort.Bind.Address)
                || !primary.Advertised.Address.Equals(alternatePort.Advertised.Address)
                || primary.Bind.Port == alternatePort.Bind.Port)
            {
                throw new ArgumentException(
                    "basic topology alternate endpoint must use the primary IP and a distinct port");
            }
            endpoints[alternatePort.Id] = alternatePort;
        }
        return new StunTopology(endpoints, false);
    }

    public static StunTopology Rfc5780(
        StunEndpoint primary,
        StunEndpoint primaryAlternatePort,
        StunEndpoint alternatePrimaryPort,
        StunEndpoint alternate)
    {
        ValidateEndpoint(primary, StunEndpointId.Primary);
        ValidateEndpoint(primaryAlternatePort, StunEndpointId.PrimaryAlternatePort);
        ValidateEndpoint(alternatePrimaryPort, StunEndpointId.AlternatePrimaryPort);
        ValidateEndpoint(alternate, StunEndpointId.Alternate);
        if (primary.Bind.Address.Equals(IPAddress.Any)
            || primary.Bind.Address.Equals(IPAddress.IPv6Any)
            || alternatePrimaryPort.Bind.Address.Equals(IPAddress.Any)
            || alternatePrimaryPort.Bind.Address.Equals(IPAddress.IPv6Any))
        {
            throw new ArgumentException("RFC 5780 requires two explicit bind IP addresses");
        }
        if (primary.Bind.Address.Equals(alternatePrimaryPort.Bind.Address)
            || primary.Advertised.Address.Equals(alternatePrimaryPort.Advertised.Address))
        {
            throw new ArgumentException("RFC 5780 requires two distinct bind and advertised IP addresses");
        }
        if (primary.Advertised.AddressFamily != alternatePrimaryPort.Advertised.AddressFamily)
        {
            throw new ArgumentException("RFC 5780 endpoints must use the same address family");
        }
        if (!primary.Bind.Address.Equals(primaryAlternatePort.Bind.Address)
            || !primary.Advertised.Address.Equals(primaryAlternatePort.Advertised.Address)
            || !alternatePrimaryPort.Bind.Address.Equals(alternate.Bind.Address)
            || !alternatePrimaryPort.Advertised.Address.Equals(alternate.Advertised.Address))
        {
            throw new ArgumentException("RFC 5780 endpoints in each address slot must share an IP");
        }
        if (primary.Bind.Port != alternatePrimaryPort.Bind.Port
            || primaryAlternatePort.Bind.Port != alternate.Bind.Port
            || primary.Bind.Port == primaryAlternatePort.Bind.Port)
        {
            throw new ArgumentException("RFC 5780 requires the same two distinct ports on both IP addresses");
        }
        return new StunTopology(
            new Dictionary<StunEndpointId, StunEndpoint>
            {
                [primary.Id] = primary,
                [primaryAlternatePort.Id] = primaryAlternatePort,
                [alternatePrimaryPort.Id] = alternatePrimaryPort,
                [alternate.Id] = alternate,
            },
            true);
    }

    public StunEndpoint Endpoint(StunEndpointId id) =>
        _endpoints.TryGetValue(id, out var endpoint)
            ? endpoint
            : throw new ArgumentException($"STUN endpoint is not configured: {id}");

    public IReadOnlyList<StunEndpoint> Endpoints() => EndpointOrder
        .Where(_endpoints.ContainsKey)
        .Select(id => _endpoints[id])
        .ToList();

    public StunEndpointId ResponseEndpoint(StunEndpointId incoming, ChangeRequest request)
    {
        _ = Endpoint(incoming);
        if (!SupportsRfc5780 || (!request.ChangeIp && !request.ChangePort))
        {
            return incoming;
        }
        var alternateAddress = incoming is StunEndpointId.AlternatePrimaryPort or StunEndpointId.Alternate;
        var alternatePort = incoming is StunEndpointId.PrimaryAlternatePort or StunEndpointId.Alternate;
        if (request.ChangeIp)
        {
            alternateAddress = !alternateAddress;
        }
        if (request.ChangePort)
        {
            alternatePort = !alternatePort;
        }
        return EndpointId(alternateAddress, alternatePort);
    }

    public StunEndpointId? OtherEndpoint(StunEndpointId incoming)
    {
        if (!SupportsRfc5780)
        {
            return null;
        }
        var alternateAddress = incoming is StunEndpointId.AlternatePrimaryPort or StunEndpointId.Alternate;
        var alternatePort = incoming is StunEndpointId.PrimaryAlternatePort or StunEndpointId.Alternate;
        var id = EndpointId(!alternateAddress, !alternatePort);
        return _endpoints.ContainsKey(id) ? id : null;
    }

    public StunEndpointId? LegacyAlternatePortEndpoint(StunEndpointId incoming)
    {
        var id = incoming switch
        {
            StunEndpointId.Primary => StunEndpointId.PrimaryAlternatePort,
            StunEndpointId.PrimaryAlternatePort => StunEndpointId.Primary,
            StunEndpointId.AlternatePrimaryPort => StunEndpointId.Alternate,
            StunEndpointId.Alternate => StunEndpointId.AlternatePrimaryPort,
            _ => throw new ArgumentOutOfRangeException(nameof(incoming)),
        };
        return _endpoints.ContainsKey(id) ? id : null;
    }

    public string Describe() => string.Join(
        ", ",
        Endpoints().Select(endpoint =>
            $"{endpoint.Id}[bind={endpoint.Bind}, advertised={endpoint.Advertised}]"));

    private static StunEndpointId EndpointId(bool alternateAddress, bool alternatePort) =>
        (alternateAddress, alternatePort) switch
        {
            (true, true) => StunEndpointId.Alternate,
            (true, false) => StunEndpointId.AlternatePrimaryPort,
            (false, true) => StunEndpointId.PrimaryAlternatePort,
            _ => StunEndpointId.Primary,
        };

    private static void ValidateEndpoint(StunEndpoint endpoint, StunEndpointId expected)
    {
        if (endpoint.Id != expected)
        {
            throw new ArgumentException($"expected endpoint {expected} but got {endpoint.Id}");
        }
        if (endpoint.Bind.Port is <= 0 or > 65535
            || endpoint.Advertised.Port != endpoint.Bind.Port
            || endpoint.Bind.AddressFamily != endpoint.Advertised.AddressFamily
            || endpoint.Advertised.Address.Equals(IPAddress.Any)
            || endpoint.Advertised.Address.Equals(IPAddress.IPv6Any))
        {
            throw new ArgumentException($"endpoint {expected} is invalid");
        }
    }
}

public sealed record StunProtectionConfig(
    int SourceRatePerSecond,
    int SourceBurst,
    int GlobalRatePerSecond,
    int GlobalBurst,
    int MaxTrackedSources,
    int SourceIdleSeconds,
    int MaxPacketBytes,
    int MaxPaddingResponseBytes)
{
    public static StunProtectionConfig Default { get; } =
        new(100, 200, 10_000, 20_000, 65_536, 300, 65_507, 1_472);
}

public sealed record StunMetricsConfig(IPAddress BindAddress, int Port)
{
    public bool Enabled => Port > 0;
}

public sealed record StunServerConfig(
    StunTopology Topology,
    string Software,
    bool LegacySingleIpOtherAddress,
    StunProtectionConfig Protection,
    StunMetricsConfig Metrics)
{
    public const string DefaultSoftware = "specus-rfc5780-stun";

    public static StunServerConfig FromEnvironment() =>
        FromDictionary(Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(
                entry => Convert.ToString(entry.Key) ?? string.Empty,
                entry => Convert.ToString(entry.Value) ?? string.Empty,
                StringComparer.Ordinal));

    public static StunServerConfig FromDictionary(IReadOnlyDictionary<string, string> environment)
    {
        var primaryPort = Integer(environment, "STUN_PRIMARY_PORT", 3478, 1, 65535);
        var alternatePort = Integer(environment, "STUN_ALTERNATE_PORT", 3479, 0, 65535);
        if (alternatePort == primaryPort)
        {
            throw new ArgumentException("STUN_ALTERNATE_PORT must differ from STUN_PRIMARY_PORT");
        }

        var primaryBind = ResolveAddress(Value(environment, "STUN_PRIMARY_BIND_ADDRESS", "0.0.0.0"));
        var primaryPublicText = Value(environment, "STUN_PRIMARY_PUBLIC_ADDRESS", string.Empty);
        if (string.IsNullOrWhiteSpace(primaryPublicText))
        {
            if (primaryBind.Equals(IPAddress.Any) || primaryBind.Equals(IPAddress.IPv6Any))
            {
                throw new ArgumentException(
                    "STUN_PRIMARY_PUBLIC_ADDRESS is required when STUN_PRIMARY_BIND_ADDRESS is wildcard");
            }
            primaryPublicText = primaryBind.ToString();
        }
        var primaryPublic = ResolveAddress(primaryPublicText);

        var alternateBindText = Value(environment, "STUN_ALTERNATE_BIND_ADDRESS", string.Empty);
        var alternatePublicText = Value(environment, "STUN_ALTERNATE_PUBLIC_ADDRESS", string.Empty);
        var alternateConfigured = !string.IsNullOrWhiteSpace(alternateBindText)
            || !string.IsNullOrWhiteSpace(alternatePublicText);
        if (alternateConfigured
            && (string.IsNullOrWhiteSpace(alternateBindText)
                || string.IsNullOrWhiteSpace(alternatePublicText)))
        {
            throw new ArgumentException(
                "STUN_ALTERNATE_BIND_ADDRESS and STUN_ALTERNATE_PUBLIC_ADDRESS must be configured together");
        }

        StunTopology topology;
        if (alternateConfigured)
        {
            if (alternatePort == 0)
            {
                throw new ArgumentException(
                    "STUN_ALTERNATE_PORT must be enabled for RFC 5780 four-endpoint mode");
            }
            var alternateBind = ResolveAddress(alternateBindText);
            var alternatePublic = ResolveAddress(alternatePublicText);
            topology = StunTopology.Rfc5780(
                Endpoint(StunEndpointId.Primary, primaryBind, primaryPublic, primaryPort),
                Endpoint(StunEndpointId.PrimaryAlternatePort, primaryBind, primaryPublic, alternatePort),
                Endpoint(StunEndpointId.AlternatePrimaryPort, alternateBind, alternatePublic, primaryPort),
                Endpoint(StunEndpointId.Alternate, alternateBind, alternatePublic, alternatePort));
        }
        else
        {
            topology = StunTopology.Basic(
                Endpoint(StunEndpointId.Primary, primaryBind, primaryPublic, primaryPort),
                alternatePort == 0
                    ? null
                    : Endpoint(
                        StunEndpointId.PrimaryAlternatePort,
                        primaryBind,
                        primaryPublic,
                        alternatePort));
        }

        var defaults = StunProtectionConfig.Default;
        var protection = new StunProtectionConfig(
            Integer(environment, "STUN_RATE_LIMIT_PER_SECOND", defaults.SourceRatePerSecond, 1, 1_000_000),
            Integer(environment, "STUN_RATE_LIMIT_BURST", defaults.SourceBurst, 1, 2_000_000),
            Integer(environment, "STUN_GLOBAL_RATE_LIMIT_PER_SECOND", defaults.GlobalRatePerSecond, 1, 10_000_000),
            Integer(environment, "STUN_GLOBAL_RATE_LIMIT_BURST", defaults.GlobalBurst, 1, 20_000_000),
            Integer(environment, "STUN_MAX_TRACKED_SOURCES", defaults.MaxTrackedSources, 1, 1_000_000),
            Integer(environment, "STUN_SOURCE_IDLE_SECONDS", defaults.SourceIdleSeconds, 1, 86_400),
            Integer(environment, "STUN_MAX_PACKET_BYTES", defaults.MaxPacketBytes, StunMessage.HeaderBytes, 65_507),
            Integer(
                environment,
                "STUN_MAX_PADDING_RESPONSE_BYTES",
                defaults.MaxPaddingResponseBytes,
                0,
                65_503));
        var metrics = new StunMetricsConfig(
            ResolveAddress(Value(environment, "STUN_METRICS_BIND_ADDRESS", "127.0.0.1")),
            Integer(environment, "STUN_METRICS_PORT", 9_108, 0, 65_535));
        return new StunServerConfig(
            topology,
            Value(environment, "STUN_SOFTWARE", DefaultSoftware),
            Boolean(environment, "STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS", false),
            protection,
            metrics);
    }

    public string Describe() =>
        $"mode={(Topology.SupportsRfc5780 ? "rfc5780" : "basic")}, software={Software}, "
        + $"endpoints={Topology.Describe()}, source={Protection.SourceRatePerSecond}/s "
        + $"burst={Protection.SourceBurst}, global={Protection.GlobalRatePerSecond}/s "
        + $"burst={Protection.GlobalBurst}, trackedSources={Protection.MaxTrackedSources}, "
        + $"metrics={(Metrics.Enabled ? new IPEndPoint(Metrics.BindAddress, Metrics.Port) : "disabled")}";

    private static StunEndpoint Endpoint(
        StunEndpointId id,
        IPAddress bindAddress,
        IPAddress publicAddress,
        int port) =>
        new(id, new IPEndPoint(bindAddress, port), new IPEndPoint(publicAddress, port));

    private static IPAddress ResolveAddress(string value)
    {
        var text = value.Trim();
        if (IPAddress.TryParse(text, out var address))
        {
            return address;
        }
        return Dns.GetHostAddresses(text).FirstOrDefault()
            ?? throw new ArgumentException($"cannot resolve address: {value}");
    }

    private static int Integer(
        IReadOnlyDictionary<string, string> environment,
        string name,
        int fallback,
        int minimum,
        int maximum)
    {
        var raw = Value(environment, name, fallback.ToString(System.Globalization.CultureInfo.InvariantCulture));
        if (!int.TryParse(
                raw,
                System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture,
                out var parsed))
        {
            throw new ArgumentException($"{name} must be an integer: {raw}");
        }
        if (parsed < minimum || parsed > maximum)
        {
            throw new ArgumentException($"{name} must be between {minimum} and {maximum}");
        }
        return parsed;
    }

    private static bool Boolean(
        IReadOnlyDictionary<string, string> environment,
        string name,
        bool fallback)
    {
        var raw = Value(environment, name, fallback.ToString()).ToLowerInvariant();
        return raw switch
        {
            "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => throw new ArgumentException($"{name} must be true or false: {raw}"),
        };
    }

    private static string Value(
        IReadOnlyDictionary<string, string> environment,
        string name,
        string fallback) =>
        environment.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : fallback;
}
