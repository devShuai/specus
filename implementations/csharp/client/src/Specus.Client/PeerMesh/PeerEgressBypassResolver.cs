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

    private sealed record Answer(IReadOnlyList<string> Addresses, bool Failed, long AtMillis);

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

    private Answer LookupCached(string host, long nowMillis)
    {
        if (_cache.TryGetValue(host, out var cached) && nowMillis - cached.AtMillis < ResolveTtlMillis)
        {
            return cached;
        }
        var resolved = new List<string>();
        var failed = false;
        try
        {
            foreach (var address in _lookup(host))
            {
                // IPv4 only: the rules are IPv4 and so are the routes they install, so an IPv6
                // answer has nothing to be routed around.
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    resolved.Add(address.ToString());
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
        var answer = new Answer(resolved, failed, nowMillis);
        _cache[host] = answer;
        return answer;
    }

    /// <summary>
    /// The host in a URL, a host:port pair, or a bare host. Empty when there is nothing to resolve,
    /// which includes IPv6 literals: the routes are IPv4.
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
