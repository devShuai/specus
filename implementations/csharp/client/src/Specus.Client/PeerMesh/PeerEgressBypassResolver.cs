using System.Net;
using System.Net.Sockets;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Turning the hosts the tunnel's transport talks to into addresses a bypass route can pin.
/// </summary>
/// <remarks>
/// The forced-deny list the egress role enforces takes literals only, because a resolution taken at
/// policy time can differ from the one a connect uses and a block that looks enforced is worse than
/// none. A bypass is the other way round. Its failure mode is a missing route, which sends the
/// control connection into the tunnel it carries; an extra /32 for an address the server no longer
/// answers on costs nothing. So hostnames are resolved here, and every address they resolve to is
/// pinned.
///
/// <para>Resolution is cached for a minute. The list is recomputed every few seconds, and asking the
/// resolver each time would turn a periodic tick into a periodic DNS query for every endpoint.</para>
/// </remarks>
/// <param name="lookup">How a name is resolved, or null for the system resolver. Injected so the cache can be driven without a network.</param>
internal sealed class PeerEgressBypassResolver(Func<string, IPAddress[]>? lookup = null)
{
    /// <summary>How long a lookup's answer, or its failure, stands in for the next.</summary>
    public const long ResolveTtlMillis = 60_000L;

    /// <summary>The addresses behind the entries, and the hosts whose lookup failed.</summary>
    public sealed record Resolution(IReadOnlyList<string> Addresses, IReadOnlyList<string> Failed);

    /// <param name="Addresses6">
    /// The IPv6 answers, in RFC 5952 form, for a consumer with the IPv6 data plane. Kept apart: the
    /// IPv4 answer is what <see cref="Resolve"/> has always returned.
    /// </param>
    private sealed record Answer(IReadOnlyList<string> Addresses, bool Failed, long AtMillis,
        IReadOnlyList<string> Addresses6);

    private readonly Func<string, IPAddress[]> _lookup = lookup ?? Dns.GetHostAddresses;
    private readonly Dictionary<string, Answer> _cache = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>
    /// Returns the IPv4 addresses behind each entry, in input order without duplicates, and the
    /// hosts whose lookup failed so the caller can say so once.
    /// </summary>
    /// <remarks>
    /// An entry may be a URL, a host with a port, or a bare host or literal. Anything unreadable is
    /// skipped rather than refused: the list comes from runtime discovery, not from configuration,
    /// and one unreadable entry must not cost the others their route.
    /// </remarks>
    public Resolution Resolve(IEnumerable<string?> entries, long nowMillis)
    {
        var addresses = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var failed = new List<string>();
        lock (_gate)
        {
            foreach (var entry in entries)
            {
                var host = HostOf(entry);
                if (host.Length == 0)
                {
                    continue;
                }
                IReadOnlyList<string> resolved;
                if (Ipv4Cidr.TryParseAddress(host, out _))
                {
                    resolved = [host];
                }
                else
                {
                    var answer = LookupCached(host, nowMillis);
                    if (answer.Failed)
                    {
                        failed.Add(host);
                    }
                    resolved = answer.Addresses;
                }
                foreach (var address in resolved)
                {
                    if (seen.Add(address))
                    {
                        addresses.Add(address);
                    }
                }
            }
        }
        return new Resolution(addresses, failed);
    }

    /// <summary>
    /// Returns the IPv6 addresses behind each entry, in input order without duplicates and in RFC 5952
    /// form, for a consumer with the IPv6 data plane: an IPv6 rule can cover an endpoint the tunnel's
    /// transport uses as surely as an IPv4 one can. Failures are left to <see cref="Resolve"/>, which
    /// asks the same lookups and says so once.
    /// </summary>
    public IReadOnlyList<string> Resolve6(IEnumerable<string?> entries, long nowMillis)
    {
        var addresses = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        lock (_gate)
        {
            foreach (var entry in entries)
            {
                IReadOnlyList<string> resolved = [];
                if (Literal6(entry) is { } literal)
                {
                    resolved = [literal];
                }
                else if (HostOf(entry) is { Length: > 0 } host && !Ipv4Cidr.TryParseAddress(host, out _))
                {
                    resolved = LookupCached(host, nowMillis).Addresses6;
                }
                foreach (var address in resolved)
                {
                    if (seen.Add(address))
                    {
                        addresses.Add(address);
                    }
                }
            }
        }
        return addresses;
    }

    /// <summary>
    /// An IPv6 literal read out of a URL, a bracketed host with a port, or a bare address, in RFC 5952
    /// form; null for anything else. A zone is not an address a route can name, and neither is an
    /// IPv4-mapped one, which the IPv4 side covers.
    /// </summary>
    public static string? Literal6(string? entry)
    {
        var text = entry?.Trim() ?? string.Empty;
        if (text.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(text, UriKind.Absolute, out var parsed))
            {
                return null;
            }
            text = parsed.Host;
        }
        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']');
            if (close < 0)
            {
                return null;
            }
            text = text[1..close];
        }
        if (!Ipv6Cidr.TryParseAddress(text, out var address) || new Ipv6Cidr(address, Ipv6Cidr.MaxPrefix).Mapped)
        {
            return null;
        }
        return Ipv6Cidr.FormatAddress(address);
    }

    private Answer LookupCached(string host, long nowMillis)
    {
        if (_cache.TryGetValue(host, out var cached) && nowMillis - cached.AtMillis < ResolveTtlMillis)
        {
            return cached;
        }
        var resolved = new List<string>();
        var resolved6 = new List<string>();
        var failed = false;
        try
        {
            foreach (var address in _lookup(host))
            {
                // The IPv4 answers are what Resolve returns; the IPv6 ones are routed around only by
                // a consumer with the IPv6 data plane, through Resolve6.
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    resolved.Add(address.ToString());
                }
                else if (address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv4MappedToIPv6)
                {
                    // Kept apart, for Resolve6: the IPv4 answer is what Resolve has always returned.
                    resolved6.Add(Ipv6Cidr.FormatAddress(PeerEgressIpv6.FromAddress(address)));
                }
            }
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException or InvalidOperationException)
        {
            failed = true;
        }
        // A failure is cached too. Retrying a name that does not resolve on every tick would be the
        // same query storm the cache exists to prevent, and the next tick after the TTL will ask
        // again.
        var answer = new Answer(resolved, failed, nowMillis, resolved6);
        _cache[host] = answer;
        return answer;
    }

    /// <summary>
    /// The host in a URL, a host:port pair, or a bare host. Empty when there is nothing to resolve,
    /// which includes IPv6 literals: <see cref="Literal6"/> reads those.
    /// </summary>
    public static string HostOf(string? entry)
    {
        var trimmed = entry?.Trim() ?? string.Empty;
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }
        if (trimmed.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var parsed))
            {
                return string.Empty;
            }
            trimmed = parsed.Host;
        }
        if (trimmed.Length == 0 || trimmed[0] == '[')
        {
            return string.Empty;
        }
        var colon = trimmed.IndexOf(':', StringComparison.Ordinal);
        if (colon < 0)
        {
            return trimmed;
        }
        if (trimmed.IndexOf(':', colon + 1) >= 0)
        {
            // More than one colon is an unbracketed IPv6 literal, not a host and port.
            return string.Empty;
        }
        return trimmed[..colon];
    }
}
