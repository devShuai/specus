namespace Specus.Protocol.HttpRoute;

/// <summary>
/// Why an HTTP route stream failed before its response OPEN, as a capable client reports it in
/// <c>metadata.failure</c> of the NAT RST (protocol/spec/service-connectivity-check.md section 6).
/// </summary>
/// <remarks>
/// The set is closed. A client leaves the key out for anything it cannot place, and a server
/// reports such a reset as <c>TARGET_UNVERIFIED</c>; it trusts the key only from a session that
/// announced <see cref="CapabilityVersion"/>. The RST <c>value</c> and <c>reason</c> stay as they
/// were, so servers that do not know the key keep working unchanged.
/// </remarks>
public static class HttpRouteFailure
{
    /// <summary>
    /// <c>environment.clientHttpRouteCapabilities.version</c> of a client that classifies these
    /// resets and never makes up a response head.
    /// </summary>
    public const int CapabilityVersion = 1;

    /// <summary>The RST metadata key, next to <c>reason</c>.</summary>
    public const string MetadataKey = "failure";

    /// <summary>The configuration snapshot has no such route, or it has no target.</summary>
    public const string RouteNotLoaded = "route-not-loaded";

    /// <summary>The route exists but the target built from it cannot be used.</summary>
    public const string TargetInvalid = "target-invalid";

    /// <summary>The TCP connect was refused.</summary>
    public const string ConnectRefused = "connect-refused";

    /// <summary>The client's own connect timeout expired.</summary>
    public const string ConnectTimeout = "connect-timeout";

    /// <summary>The target host name did not resolve, or resolved to no usable address.</summary>
    public const string DnsFailed = "dns-failed";

    /// <summary>The TLS handshake, or the certificate or host name check, failed.</summary>
    public const string TlsFailed = "tls-failed";

    /// <summary>No route to the host or network, or the connect was reset.</summary>
    public const string Unreachable = "unreachable";

    /// <summary>Connected, but the target closed before the response head or sent an invalid one.</summary>
    public const string ProtocolError = "protocol-error";

    /// <summary>Every value, in the order of the specification's table.</summary>
    public static IReadOnlyList<string> All { get; } =
    [
        RouteNotLoaded, TargetInvalid, ConnectRefused, ConnectTimeout,
        DnsFailed, TlsFailed, Unreachable, ProtocolError,
    ];
}
