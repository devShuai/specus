using System.Globalization;
using Specus.Protocol.PeerEgress;

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
    /// That happens once a rule's route is already installed and covers the address: asking the
    /// system where to send it then answers "through the tunnel", and installing that would route
    /// the tunnel's own transport into the tunnel. The commander reads the table instead.
    /// </remarks>
    public static bool HopIsDevice(PeerEgressRouteHop hop, string? device)
    {
        var wanted = device?.Trim() ?? string.Empty;
        return wanted.Length > 0
            && string.Equals(hop.Device.Trim(), wanted, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reads the main table, for a bypass hop <c>ip route get</c> could not give.</summary>
    public static string[] ShowMainTableArgs() => ["-4", "route", "show", "table", "main"];

    private static readonly HashSet<string> LeadsNowhere = ["blackhole", "unreachable", "prohibit", "throw"];
    private static readonly HashSet<string> NotForwarding = ["local", "broadcast", "anycast", "multicast", "nat"];

    /// <summary>Reads <c>ip -4 route show table main</c> into candidate routes.</summary>
    /// <remarks>
    /// Sampled rather than assumed, in network namespaces with a real TUN: a multipath route prints
    /// its destination alone followed by indented nexthop lines, two routes on one prefix are printed
    /// lowest metric first but the metric is what counts, and every line ends with a space. A route
    /// that leads nowhere -- blackhole, unreachable, prohibit, throw -- stays a candidate with no
    /// interface, so the address it covers is not reached some other way. The first nexthop of a
    /// multipath route is the one taken; one whose next hops cannot be read is not usable. A dead
    /// route is not usable; linkdown is, as the kernel uses it too.
    ///
    /// <para>Shared vector: <c>protocol/test-vectors/peer-egress-socket-binding-v1.json</c>, linux.</para>
    /// </remarks>
    public static List<PeerEgressBindRoute> ParseRouteTable(string? output)
    {
        var routes = new List<PeerEgressBindRoute>();
        var pending = -1;
        var deviceless = new List<int>();
        foreach (var line in (output ?? string.Empty).Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            var fields = line.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            if (line[0] is ' ' or '\t')
            {
                if (fields[0] == "nexthop" && pending >= 0 && routes[pending].Interface.Length == 0)
                {
                    var route = routes[pending];
                    var gateway = route.Gateway;
                    var device = "";
                    for (var index = 1; index + 1 < fields.Length; index++)
                    {
                        if (fields[index] == "via" && Ipv4Cidr.TryParseAddress(fields[index + 1], out _))
                        {
                            gateway = fields[index + 1];
                        }
                        else if (fields[index] == "dev")
                        {
                            device = fields[index + 1];
                        }
                    }
                    routes[pending] = route with { Interface = device, Gateway = gateway };
                }
                continue;
            }
            pending = -1;
            if (NotForwarding.Contains(fields[0]))
            {
                continue;
            }
            var nowhere = LeadsNowhere.Contains(fields[0]);
            var start = nowhere ? 1 : 0;
            if (start >= fields.Length || PrefixOf(fields[start]) is not { } prefix)
            {
                continue;
            }
            string deviceName = "", gatewayAddress = "";
            long metric = 0;
            var usable = true;
            for (var index = start + 1; index < fields.Length; index++)
            {
                if (fields[index] == "dead")
                {
                    usable = false;
                }
                if (index + 1 >= fields.Length)
                {
                    continue;
                }
                switch (fields[index])
                {
                    case "via" when Ipv4Cidr.TryParseAddress(fields[index + 1], out _):
                        gatewayAddress = fields[index + 1];
                        break;
                    case "dev":
                        deviceName = fields[index + 1];
                        break;
                    case "metric" when long.TryParse(fields[index + 1], NumberStyles.None, CultureInfo.InvariantCulture, out var value):
                        metric = value;
                        break;
                }
            }
            if (nowhere)
            {
                deviceName = "";
                gatewayAddress = "";
            }
            else if (deviceName.Length == 0)
            {
                pending = routes.Count;
                deviceless.Add(pending);
            }
            routes.Add(new PeerEgressBindRoute(prefix, deviceName, gatewayAddress, metric, usable));
        }
        foreach (var index in deviceless)
        {
            if (routes[index].Interface.Length == 0)
            {
                routes[index] = routes[index] with { Usable = false };
            }
        }
        return routes;
    }

    private static string? PrefixOf(string text)
    {
        if (text == "default")
        {
            return "0.0.0.0/0";
        }
        var slash = text.IndexOf('/');
        if (!Ipv4Cidr.TryParseAddress(slash < 0 ? text : text[..slash], out var address))
        {
            return null;
        }
        var length = 32;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out length)
            || length > 32))
        {
            return null;
        }
        var mask = length == 0 ? 0u : uint.MaxValue << (32 - length);
        return Ipv4Cidr.FormatAddress(address & mask) + "/" + length.ToString(CultureInfo.InvariantCulture);
    }
}
