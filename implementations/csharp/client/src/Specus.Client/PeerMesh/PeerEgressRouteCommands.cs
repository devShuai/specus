namespace Specus.Client.PeerMesh;

/// <summary>
/// Where a bypass address has to be sent to stay off the tunnel.
/// </summary>
/// <param name="Gateway">
/// Empty for an on-link destination, which is normal on a directly attached network and is not a
/// failure to parse.
/// </param>
internal readonly record struct PeerEgressRouteHop(string Gateway, string Device);

/// <summary>Whether a prefix already has a route, and the line describing it.</summary>
internal readonly record struct PeerEgressExistingRoute(bool Present, string Description);

/// <summary>
/// Reading what the platform's routing tools say.
/// </summary>
/// <remarks>
/// Kept free of any platform guard on purpose. These parsers depend on output formats nobody
/// controls, which makes them the part most likely to be wrong, and a Linux-only file would leave
/// them untested everywhere the developer and most of CI actually run.
///
/// <para>Shared fixtures: the <c>routeCommands</c> section of
/// <c>protocol/test-vectors/peer-egress-routes-v1.json</c>.</para>
/// </remarks>
internal static class PeerEgressRouteCommands
{
    private static readonly char[] Whitespace = [' ', '\t', '\r'];

    /// <summary>
    /// Reads one <c>ip route get &lt;address&gt;</c> line, returning null when there is no usable
    /// hop.
    /// </summary>
    /// <remarks>
    /// Two shapes matter. Through a router:
    /// <c>1.2.3.4 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000</c>. Directly attached:
    /// <c>10.0.0.5 dev eth0 src 10.0.0.5</c>. The second has no via, and treating that as a parse
    /// failure would refuse to bypass anything on the local network.
    /// </remarks>
    public static PeerEgressRouteHop? ParseRouteGet(string? output)
    {
        if (output is null)
        {
            return null;
        }
        foreach (var line in output.Split('\n'))
        {
            var fields = line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length == 0)
            {
                continue;
            }
            // A destination that cannot be reached is reported as a route rather than as an error,
            // so it has to be recognised here or it would be read as one.
            if (fields[0] is "unreachable" or "prohibit" or "blackhole")
            {
                return null;
            }
            var gateway = string.Empty;
            var device = string.Empty;
            for (var index = 0; index + 1 < fields.Length; index++)
            {
                if (fields[index] == "via")
                {
                    gateway = fields[index + 1];
                }
                else if (fields[index] == "dev")
                {
                    device = fields[index + 1];
                }
            }
            if (device.Length > 0)
            {
                return new PeerEgressRouteHop(gateway, device);
            }
        }
        return null;
    }

    /// <summary>
    /// Reads <c>ip route show exact &lt;cidr&gt;</c>.
    /// </summary>
    /// <remarks>
    /// Empty output means no route for that exact prefix, which is what lets one be installed.
    /// Anything else is described back to the operator verbatim, because a summary of somebody
    /// else's routing is less useful to them than the line they can go and look at.
    /// </remarks>
    public static PeerEgressExistingRoute ParseShowExact(string? output)
    {
        foreach (var line in (output ?? string.Empty).Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length > 0)
            {
                return new PeerEgressExistingRoute(true, trimmed);
            }
        }
        return new PeerEgressExistingRoute(false, string.Empty);
    }

    /// <summary>
    /// Reports whether a hop leads through the named interface.
    /// </summary>
    /// <remarks>
    /// Used to refuse pinning a bypass address to the tunnel itself. That happens on a reapply,
    /// once a rule's route is already installed and covers the address: asking the system where to
    /// send it then answers "through the tunnel", and installing that would route the tunnel's own
    /// transport into the tunnel.
    /// </remarks>
    public static bool HopIsDevice(PeerEgressRouteHop hop, string? device)
    {
        var wanted = device?.Trim() ?? string.Empty;
        return wanted.Length > 0
            && string.Equals(hop.Device.Trim(), wanted, StringComparison.OrdinalIgnoreCase);
    }
}
