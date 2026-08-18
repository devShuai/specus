using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Security;

/// <summary>
/// The single entry point for resolving the real client address. Rate limiting, pairing, uploads,
/// WebSocket tickets and same-network discovery all share it.
///
/// <para>Forwarded headers are honoured only when the connection peer belongs to a configured
/// trusted proxy CIDR. With no trusted proxies (the default) X-Forwarded-For and X-Real-IP are
/// ignored entirely, so a direct client cannot rewrite its own source address by sending headers.</para>
///
/// <para>For trusted peers X-Forwarded-For is walked right to left: trailing trusted hops are
/// skipped and the first untrusted address is the real client. Malformed entries are discarded.</para>
/// </summary>
public sealed class ClientAddressResolver
{
    /// <summary>Fallback when no address can be resolved; same-network grouping excludes it.</summary>
    public const string Unknown = "unknown";

    private readonly List<(IPAddress Network, int PrefixLength)> _trustedProxies = new();

    public ClientAddressResolver(IOptions<SpecusOptions> options, ILogger<ClientAddressResolver> logger)
    {
        foreach (var value in SplitTrustedProxies(options.Value.TrustedProxies))
        {
            var range = ParseRange(value);
            if (range is null)
            {
                logger.LogWarning("[trusted-proxy] ignoring invalid trusted proxy CIDR: {Value}", value);
                continue;
            }
            _trustedProxies.Add(range.Value);
        }
        if (_trustedProxies.Count > 0)
        {
            logger.LogInformation("[trusted-proxy] forwarding enabled: {Count} range(s)", _trustedProxies.Count);
        }
    }

    /// <summary>Test/helper seam that takes the CIDR list directly.</summary>
    public static ClientAddressResolver ForRanges(IEnumerable<string> trustedProxies) =>
        new(Options.Create(new SpecusOptions { TrustedProxies = string.Join(',', trustedProxies) }),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ClientAddressResolver>.Instance);

    public string Resolve(HttpContext? context)
    {
        if (context is null)
        {
            return Unknown;
        }
        var peerAddress = context.Connection.RemoteIpAddress;
        // Kestrel reports loopback/dual-stack peers as IPv4-mapped IPv6; compare and report the
        // plain IPv4 form so configuration and stored addresses stay consistent across languages.
        var normalizedPeer = peerAddress is null ? "" : Normalize(Unmap(peerAddress).ToString());
        if (!IsTrustedProxy(normalizedPeer))
        {
            // Untrusted source: forwarded headers take no part in the decision.
            return string.IsNullOrEmpty(normalizedPeer) ? Unknown : normalizedPeer;
        }
        var forwarded = ResolveForwarded(
            context.Request.Headers["X-Forwarded-For"].FirstOrDefault(),
            context.Request.Headers["X-Real-IP"].FirstOrDefault());
        if (!string.IsNullOrEmpty(forwarded))
        {
            return forwarded;
        }
        return string.IsNullOrEmpty(normalizedPeer) ? Unknown : normalizedPeer;
    }

    private string ResolveForwarded(string? forwardedFor, string? realIp)
    {
        // X-Forwarded-For carries the full chain: walk right to left for the first untrusted hop.
        if (!string.IsNullOrWhiteSpace(forwardedFor))
        {
            var hops = forwardedFor.Split(',');
            for (var index = hops.Length - 1; index >= 0; index--)
            {
                var candidate = Normalize(hops[index]);
                if (string.IsNullOrEmpty(candidate) || !IPAddress.TryParse(candidate, out _))
                {
                    continue;
                }
                if (!IsTrustedProxy(candidate))
                {
                    return candidate;
                }
            }
        }
        // Whole chain trusted, or no XFF at all: fall back to the proxy's single-value override.
        var realIpCandidate = Normalize(realIp);
        return IPAddress.TryParse(realIpCandidate, out _) ? realIpCandidate : "";
    }

    private bool IsTrustedProxy(string address)
    {
        if (_trustedProxies.Count == 0
            || string.IsNullOrEmpty(address)
            || !IPAddress.TryParse(address, out var ip))
        {
            return false;
        }
        ip = Unmap(ip);
        foreach (var (network, prefixLength) in _trustedProxies)
        {
            if (Contains(network, prefixLength, ip))
            {
                return true;
            }
        }
        return false;
    }

    private static bool Contains(IPAddress network, int prefixLength, IPAddress candidate)
    {
        if (network.AddressFamily != candidate.AddressFamily)
        {
            return false;
        }
        var networkBytes = network.GetAddressBytes();
        var candidateBytes = candidate.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        for (var index = 0; index < fullBytes; index++)
        {
            if (networkBytes[index] != candidateBytes[index])
            {
                return false;
            }
        }
        var remainingBits = prefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }
        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[fullBytes] & mask) == (candidateBytes[fullBytes] & mask);
    }

    private static (IPAddress Network, int PrefixLength)? ParseRange(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }
        var slash = trimmed.IndexOf('/');
        var host = Normalize(slash < 0 ? trimmed : trimmed[..slash]);
        if (!IPAddress.TryParse(host, out var network))
        {
            return null;
        }
        network = Unmap(network);
        var maxPrefix = network.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        if (slash < 0)
        {
            return (network, maxPrefix);
        }
        if (!int.TryParse(trimmed[(slash + 1)..].Trim(), out var prefix)
            || prefix < 0
            || prefix > maxPrefix)
        {
            return null;
        }
        return (network, prefix);
    }

    private static IEnumerable<string> SplitTrustedProxies(string? configured) =>
        (configured ?? string.Empty)
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Trims whitespace, strips IPv6 brackets and drops any zone id.</summary>
    private static string Normalize(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return "";
        }
        if (trimmed.StartsWith('['))
        {
            var end = trimmed.IndexOf(']');
            if (end > 0)
            {
                trimmed = trimmed[1..end];
            }
        }
        var zone = trimmed.IndexOf('%');
        return zone > 0 ? trimmed[..zone] : trimmed;
    }

    /// <summary>IPv4-mapped IPv6 addresses compare as plain IPv4, matching Java/Go behaviour.</summary>
    private static IPAddress Unmap(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
