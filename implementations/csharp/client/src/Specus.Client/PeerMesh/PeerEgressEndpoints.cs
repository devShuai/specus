using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The addresses an egress must refuse: this deployment's own endpoints, and this host's own
/// networks.
/// </summary>
/// <remarks>
/// Forwarding a consumer's traffic to the control connection, STUN, TURN or the relay would let a
/// peer reach the infrastructure through the egress it is only supposed to reach the internet
/// through. Forwarding into one of this host's own networks would loop back into its capture path,
/// or reach a service the consumer was never authorised to see.
///
/// <para>Shared vector: the <c>deploymentEndpoints</c> section of
/// <c>protocol/test-vectors/peer-egress-control-v1.json</c>.</para>
/// </remarks>
internal static class PeerEgressEndpoints
{
    /// <summary>
    /// Turns this deployment's endpoints into the /32 prefixes the forced-deny list needs.
    /// </summary>
    /// <remarks>
    /// Only literal addresses are added. A hostname would have to be resolved here, and a
    /// resolution taken at policy time can differ from the one the connect uses, which would make
    /// the block look enforced when it is not.
    /// </remarks>
    public static IReadOnlyList<string> DeploymentDenyCidrs(
        string? serverBaseUrl, string? stunHost, string? turnHost, string? relayAddress)
    {
        var denied = new List<string>(4);
        AppendHost(denied, AuthorityOf(serverBaseUrl));
        AppendHost(denied, stunHost);
        AppendHost(denied, turnHost);
        AppendHost(denied, relayAddress);
        return denied;
    }

    /// <summary>The authority of a URL, or empty for anything that is not one.</summary>
    private static string AuthorityOf(string? url)
    {
        var trimmed = url?.Trim() ?? string.Empty;
        if (trimmed.Length == 0 || !Uri.TryCreate(trimmed, UriKind.Absolute, out var parsed))
        {
            return string.Empty;
        }
        var authority = parsed.Authority;
        // Userinfo is not part of the host.
        var at = authority.LastIndexOf('@');
        return at < 0 ? authority : authority[(at + 1)..];
    }

    private static void AppendHost(List<string> denied, string? host)
    {
        var candidate = StripPort(host);
        if (Ipv4Cidr.TryParseAddress(candidate, out _))
        {
            denied.Add(candidate + "/32");
        }
    }

    /// <summary>Removes a <c>:port</c> suffix, leaving an IPv6 literal in brackets alone.</summary>
    private static string StripPort(string? host)
    {
        var trimmed = host?.Trim() ?? string.Empty;
        if (trimmed.Length == 0 || trimmed[0] == '[')
        {
            return trimmed;
        }
        var colon = trimmed.IndexOf(':', StringComparison.Ordinal);
        if (colon < 0 || trimmed.IndexOf(':', colon + 1) >= 0)
        {
            // No port, or more than one colon, which means an unbracketed IPv6 literal rather than
            // a host and port.
            return trimmed;
        }
        return trimmed[..colon];
    }

    /// <summary>
    /// The IPv4 networks this host itself owns.
    /// </summary>
    /// <remarks>
    /// Enumerated at policy time rather than cached, because an interface can appear after start-up
    /// and a stale list is a hole rather than an inconvenience.
    /// </remarks>
    public static IReadOnlyList<string> LocalInterfaceCidrs()
    {
        var networks = new List<string>();
        try
        {
            foreach (var device in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var address in device.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork)
                    {
                        continue;
                    }
                    var prefix = address.PrefixLength;
                    if (prefix < 0 || prefix > 32
                        || !Ipv4Cidr.TryParseAddress(address.Address.ToString(), out var value))
                    {
                        continue;
                    }
                    networks.Add(NetworkOf(value, prefix));
                }
            }
        }
        catch (NetworkInformationException)
        {
            // An interface list this host will not hand over is not a reason to fail; the rest of
            // the forced-deny list still applies.
            return [];
        }
        return networks;
    }

    /// <summary>Masks an address down to its network and renders it as a prefix.</summary>
    public static string NetworkOf(uint address, int prefixLength)
    {
        var mask = prefixLength == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLength);
        return Ipv4Cidr.FormatAddress(address & mask) + "/" + prefixLength;
    }
}
