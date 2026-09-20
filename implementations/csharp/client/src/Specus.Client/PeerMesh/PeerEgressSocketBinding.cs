using System.Buffers.Binary;
using System.Globalization;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// One route read from the platform's table: considered for the interface an egress socket is bound
/// to, and for where a consumer's bypass route points.
/// </summary>
/// <param name="Prefix">The IPv4 prefix, masked.</param>
/// <param name="Interface">The decimal interface index on Windows, the interface name elsewhere; empty for a Linux route that leads nowhere.</param>
/// <param name="Gateway">The next hop, or empty for on-link.</param>
/// <param name="Metric">The effective metric: on Windows the route's plus its interface's, on Linux the route's own, on macOS zero.</param>
/// <param name="Usable">False for a route the system would not use for an unbound socket.</param>
internal readonly record struct PeerEgressBindRoute(string Prefix, string Interface, string Gateway, long Metric, bool Usable);

/// <param name="InterfaceIndex">The interface index.</param>
/// <param name="Prefix">The IPv4 prefix, masked.</param>
/// <param name="NextHop">The address as written, 0.0.0.0 for on-link, or empty when it is not IPv4.</param>
/// <param name="Metric">The route's own metric.</param>
internal readonly record struct PeerEgressWindowsForwardRow(long InterfaceIndex, string Prefix, string NextHop, long Metric);

internal readonly record struct PeerEgressWindowsInterfaceRow(long InterfaceIndex, long Metric, bool Connected,
    bool DisableDefaultRoutes);

/// <summary>One owned route the table no longer carries as installed.</summary>
/// <param name="Existing">Describes the row that holds the prefix now, for a conflict.</param>
internal sealed record PeerEgressRouteDrift(PeerEgressRoute Route, string Reason, string Action, string Existing);

/// <summary>
/// Choosing the interface an egress socket is bound to, and reading the tables that choice is made from.
/// </summary>
/// <remarks>
/// The egress opens a real socket to the target on a consumer's behalf. If that socket followed this
/// node's own tunnel routes -- which a node that is also a consumer has, for its own rules -- the
/// forwarded traffic would go back into the mesh instead of out of the machine. On Windows and macOS
/// the socket is bound to the interface the operating system would have picked had the tunnel's
/// routes not been there: <c>IP_UNICAST_IF</c> and <c>IP_BOUND_IF</c>. Neither needs elevation, and
/// the stack enforces both -- bound to an interface with no route to the destination, connect fails
/// rather than leaving by another one. That is also why the interface has to be chosen per
/// destination: binding everything to the default route's interface would break every target reached
/// through a second NIC or another VPN.
///
/// <para>Everything here is pure and pinned by
/// <c>protocol/test-vectors/peer-egress-socket-binding-v1.json</c>; the calls that fetch the tables and
/// set the options are in <see cref="PeerEgressSocketBinder"/>.</para>
/// </remarks>
internal static class PeerEgressSocketBinding
{
    /// <summary><c>IP_UNICAST_IF</c>, at level <c>IPPROTO_IP</c>.</summary>
    public const int WindowsIpUnicastIf = 31;

    /// <summary><c>IP_BOUND_IF</c>, at level <c>IPPROTO_IP</c>.</summary>
    public const int MacosIpBoundIf = 25;

    public const int IpProtoIp = 0;

    // The layouts of MIB_IPFORWARD_ROW2 and MIB_IPINTERFACE_ROW on 64-bit Windows, measured against
    // Get-NetRoute and Get-NetIPInterface and checked against them again on every Windows CI run.
    public const int WindowsTableHeader = 8;
    public const int WindowsForwardRowSize = 104;
    public const int WindowsInterfaceRowSize = 168;
    private const int ForwardInterfaceIndex = 8;
    private const int ForwardPrefixFamily = 12;
    private const int ForwardPrefixAddress = 16;
    private const int ForwardPrefixLength = 40;
    private const int ForwardNextHopFamily = 44;
    private const int ForwardNextHopAddress = 48;
    private const int ForwardMetric = 84;
    private const int InterfaceFamily = 0;
    private const int InterfaceIndex = 16;
    private const int InterfaceMetric = 148;
    private const int InterfaceConnected = 156;
    private const int InterfaceDisableDefaultRoutes = 166;
    private const int AfInet = 2;

    /// <summary>
    /// A macOS route scoped to its interface. The kernel only uses one for a socket already bound to
    /// that interface, so for choosing one it is not a candidate.
    /// </summary>
    private const string MacosScopedFlag = "I";

    /// <summary>
    /// A macOS route whose Gateway column is a gateway (RTF_GATEWAY). Without it the column says
    /// where the interface is: link#N, a MAC address, an interface name, or the address of a loopback
    /// or point-to-point peer -- 127 prints 127.0.0.1 there.
    /// </summary>
    private const string MacosGatewayFlag = "G";

    /// <summary>Windows writes an on-link next hop as this address.</summary>
    private const string WindowsOnLink = "0.0.0.0";

    /// <summary>
    /// The interface for a socket to <paramref name="destination"/> with the tunnel's routes left
    /// out, or null when nothing else leads there.
    /// </summary>
    /// <remarks>
    /// Longest prefix, then the lowest metric, then the route listed first. The tunnel is compared by
    /// exact equality -- utun30 is not utun3 -- and an empty tunnel leaves nothing out. Null means the
    /// dial is refused rather than left unbound, because an unbound socket is exactly the one that
    /// would follow the tunnel route.
    /// </remarks>
    public static string? Select(IReadOnlyList<PeerEgressBindRoute> routes, string? tunnel, string destination) =>
        SelectRoute(routes, tunnel, [], destination)?.Interface;

    /// <summary>Where a bypass route for <paramref name="destination"/> points, or null.</summary>
    /// <remarks>
    /// Null both when nothing but the tunnel leads there and when the winning route leads nowhere:
    /// pinning a bypass through some other route would reach an address the table deliberately does
    /// not.
    /// </remarks>
    public static PeerEgressBindRoute? SelectBypassHop(IReadOnlyList<PeerEgressBindRoute> routes, string? tunnel,
        IReadOnlyCollection<string> owned, string destination) =>
        SelectRoute(routes, tunnel, owned, destination) is { } chosen && chosen.Interface.Length > 0 ? chosen : null;

    /// <summary>Where a bypass goes when the platform's own query answered with the tunnel.</summary>
    /// <remarks>
    /// The query is asked first everywhere because it knows things a reading of the table does not --
    /// policy routing on Linux above all. But once a rule's route covers the address the query can
    /// only see that route, and that is exactly when a bypass is needed; so the table is read and the
    /// choice made with the tunnel left out.
    /// </remarks>
    public static PeerEgressBindRoute BypassHopFromTable(string address, string? tunnel,
        Func<IReadOnlyList<PeerEgressBindRoute>> read)
    {
        IReadOnlyList<PeerEgressBindRoute> routes;
        try
        {
            routes = read();
        }
        catch (Exception failed) when (failed is not PeerEgressNoPhysicalRouteException)
        {
            throw new IOException($"resolve bypass hop for {address} past the tunnel: {failed.Message}", failed);
        }
        // The bypass's own /32 is left out too. When one is being put back after a network change,
        // the stale row is still in the table naming the old gateway, and it would win the lookup
        // for its own address.
        return SelectBypassHop(routes, tunnel, [address + "/32"], address)
            ?? throw new PeerEgressNoPhysicalRouteException(address);
    }

    // ---- drift ---------------------------------------------------------------------------------
    //
    // Finding the consumer's own routes gone or moved after the machine changed networks. An
    // interface that goes down takes its routes with it; a machine back from sleep on another
    // network keeps a bypass naming a gateway that is no longer the way out. The journal still says
    // the route is there, so the table is read on the consumer's tick and compared with what it
    // owns. Shared vector: the drift section.

    /// <summary>No row for the prefix that could be ours.</summary>
    public const string DriftMissing = "missing";

    /// <summary>A row for the prefix exists but is not the one this feature would install now.</summary>
    public const string DriftMoved = "moved";

    /// <summary>Take the route out and put it back, resolving its hop afresh.</summary>
    public const string DriftReinstall = "reinstall";

    /// <summary>The prefix is somebody else's now: reported and given up, not taken.</summary>
    public const string DriftConflict = "conflict";

    /// <summary>
    /// Compares what this feature owns with the table.
    /// </summary>
    /// <remarks>
    /// A tunnel route is present when a row for its prefix names the tunnel. It cannot change
    /// interface on its own, so a row on another interface is somebody else's: the prefix is theirs
    /// now, and it is reported rather than taken.
    ///
    /// <para>A bypass is compared with where the table would send the address now, with this
    /// feature's own routes left out -- the tunnel's and every owned prefix, the bypass itself
    /// included, or it would choose itself and look right. Absent, or present with a different
    /// interface or gateway, it is reinstalled. Present with nothing better outside the tunnel, it
    /// is left: the route that is there is the best there is.</para>
    /// </remarks>
    public static IReadOnlyList<PeerEgressRouteDrift> Drifts(
        IReadOnlyList<PeerEgressRoute> owned, IReadOnlyList<PeerEgressBindRoute> table, string tunnel)
    {
        var prefixes = owned.Select(route => route.Cidr).ToList();
        var found = new List<PeerEgressRouteDrift>();
        foreach (var route in owned)
        {
            var rows = table.Where(row => row.Prefix == route.Cidr).ToList();
            if (route.Kind == PeerEgressRouteKind.Tun)
            {
                if (rows.Any(row => row.Interface == tunnel))
                {
                    continue;
                }
                found.Add(rows.Count == 0
                    ? new PeerEgressRouteDrift(route, DriftMissing, DriftReinstall, string.Empty)
                    : new PeerEgressRouteDrift(route, DriftMoved, DriftConflict, Describe(rows[0])));
                continue;
            }
            var address = route.Cidr.EndsWith("/32", StringComparison.Ordinal) ? route.Cidr[..^3] : route.Cidr;
            var hop = SelectBypassHop(table, tunnel, prefixes, address);
            var present = rows.Where(row => row.Interface != tunnel).ToList();
            if (present.Count == 0)
            {
                found.Add(new PeerEgressRouteDrift(route, DriftMissing, DriftReinstall, string.Empty));
            }
            else if (hop is { } chosen && (present[0].Interface != chosen.Interface || present[0].Gateway != chosen.Gateway))
            {
                found.Add(new PeerEgressRouteDrift(route, DriftMoved, DriftReinstall, string.Empty));
            }
        }
        return found;
    }

    /// <summary>Renders a row the way an operator would read it in a conflict.</summary>
    internal static string Describe(PeerEgressBindRoute row) =>
        row.Gateway.Length == 0
            ? $"{row.Prefix} dev {row.Interface}"
            : $"{row.Prefix} via {row.Gateway} dev {row.Interface}";

    /// <summary>
    /// The route a packet to <paramref name="destination"/> would take with this feature's own routes
    /// left out: the tunnel's, and any prefix in <paramref name="owned"/>.
    /// </summary>
    public static PeerEgressBindRoute? SelectRoute(IReadOnlyList<PeerEgressBindRoute> routes, string? tunnel,
        IReadOnlyCollection<string> owned, string destination)
    {
        if (!Ipv4Cidr.TryParseAddress(destination, out var address))
        {
            return null;
        }
        PeerEgressBindRoute? best = null;
        var bestBits = -1;
        foreach (var route in routes)
        {
            if (!route.Usable || (!string.IsNullOrEmpty(tunnel) && route.Interface == tunnel)
                || owned.Contains(route.Prefix))
            {
                continue;
            }
            if (!Ipv4Cidr.TryParse(route.Prefix, out var prefix) || !prefix.Contains(address))
            {
                continue;
            }
            var bits = prefix.PrefixLength;
            // Strictly better only, so a full tie keeps the route listed first.
            if (bits > bestBits || (bits == bestBits && route.Metric < best!.Value.Metric))
            {
                best = route;
                bestBits = bits;
            }
        }
        return best;
    }

    private static uint Mask(int bits) => bits == 0 ? 0 : uint.MaxValue << (32 - bits);

    /// <summary>
    /// Cuts a MIB table into rows: a ULONG count, padding to offset 8, then the rows. Null when the
    /// buffer is shorter than the count claims -- reading the rows it does hold would be reading a
    /// table that is not the one the system returned.
    /// </summary>
    private static List<ReadOnlyMemory<byte>>? Rows(byte[]? raw, int size)
    {
        if (raw is null || raw.Length < WindowsTableHeader)
        {
            return null;
        }
        ulong count = BinaryPrimitives.ReadUInt32LittleEndian(raw);
        if ((ulong)raw.Length < (ulong)WindowsTableHeader + count * (ulong)size)
        {
            return null;
        }
        var rows = new List<ReadOnlyMemory<byte>>((int)count);
        for (var i = 0; i < (int)count; i++)
        {
            rows.Add(new ReadOnlyMemory<byte>(raw, WindowsTableHeader + i * size, size));
        }
        return rows;
    }

    /// <summary>The IPv4 rows of a MIB_IPFORWARD_TABLE2, prefixes masked. Null when the table is refused.</summary>
    public static List<PeerEgressWindowsForwardRow>? ParseWindowsForwardTable(byte[]? raw)
    {
        var rows = Rows(raw, WindowsForwardRowSize);
        if (rows is null)
        {
            return null;
        }
        var parsed = new List<PeerEgressWindowsForwardRow>();
        foreach (var memory in rows)
        {
            var row = memory.Span;
            if (BinaryPrimitives.ReadUInt16LittleEndian(row[ForwardPrefixFamily..]) != AfInet)
            {
                continue;
            }
            int length = row[ForwardPrefixLength];
            if (length > 32)
            {
                continue;
            }
            // The address bytes are in network order inside a little-endian row.
            var address = BinaryPrimitives.ReadUInt32BigEndian(row[ForwardPrefixAddress..]) & Mask(length);
            var nextHop = BinaryPrimitives.ReadUInt16LittleEndian(row[ForwardNextHopFamily..]) == AfInet
                ? Ipv4Cidr.FormatAddress(BinaryPrimitives.ReadUInt32BigEndian(row[ForwardNextHopAddress..]))
                : "";
            parsed.Add(new PeerEgressWindowsForwardRow(
                BinaryPrimitives.ReadUInt32LittleEndian(row[ForwardInterfaceIndex..]),
                Ipv4Cidr.FormatAddress(address) + "/" + length.ToString(CultureInfo.InvariantCulture),
                nextHop,
                BinaryPrimitives.ReadUInt32LittleEndian(row[ForwardMetric..])));
        }
        return parsed;
    }

    /// <summary>The IPv4 rows of a MIB_IPINTERFACE_TABLE. Null when the table is refused.</summary>
    public static List<PeerEgressWindowsInterfaceRow>? ParseWindowsInterfaceTable(byte[]? raw)
    {
        var rows = Rows(raw, WindowsInterfaceRowSize);
        if (rows is null)
        {
            return null;
        }
        var parsed = new List<PeerEgressWindowsInterfaceRow>();
        foreach (var memory in rows)
        {
            var row = memory.Span;
            if (BinaryPrimitives.ReadUInt16LittleEndian(row[InterfaceFamily..]) != AfInet)
            {
                continue;
            }
            parsed.Add(new PeerEgressWindowsInterfaceRow(
                BinaryPrimitives.ReadUInt32LittleEndian(row[InterfaceIndex..]),
                BinaryPrimitives.ReadUInt32LittleEndian(row[InterfaceMetric..]),
                row[InterfaceConnected] != 0,
                row[InterfaceDisableDefaultRoutes] != 0));
        }
        return parsed;
    }

    /// <summary>Joins the two Windows tables into candidate routes.</summary>
    /// <remarks>
    /// Windows ranks two routes of equal length by the route's metric plus its interface's. A route
    /// on an interface that is not connected is not used, nor is a default route on an interface that
    /// sets DisableDefaultRoutes -- which a VPN does to keep its default from taking over. A route
    /// whose interface has no IPv4 row is not used either: nothing says it is up.
    /// </remarks>
    public static List<PeerEgressBindRoute> WindowsRoutes(IReadOnlyList<PeerEgressWindowsForwardRow> forward,
        IReadOnlyList<PeerEgressWindowsInterfaceRow> interfaces)
    {
        var byIndex = new Dictionary<long, PeerEgressWindowsInterfaceRow>();
        foreach (var row in interfaces)
        {
            byIndex[row.InterfaceIndex] = row;
        }
        var routes = new List<PeerEgressBindRoute>(forward.Count);
        foreach (var row in forward)
        {
            var metric = row.Metric;
            var usable = false;
            if (byIndex.TryGetValue(row.InterfaceIndex, out var iface))
            {
                metric += iface.Metric;
                usable = iface.Connected && !(row.Prefix == "0.0.0.0/0" && iface.DisableDefaultRoutes);
            }
            routes.Add(new PeerEgressBindRoute(row.Prefix,
                row.InterfaceIndex.ToString(CultureInfo.InvariantCulture),
                row.NextHop == WindowsOnLink ? "" : row.NextHop, metric, usable));
        }
        return routes;
    }

    /// <summary>Candidate routes from <c>netstat -rn -f inet</c>, as the route commander reads it.</summary>
    public static List<PeerEgressBindRoute> MacosRoutes(string? table)
    {
        var routes = new List<PeerEgressBindRoute>();
        foreach (var row in PeerEgressMacosRouteCommands.ParseTable(table))
        {
            var gateway = row.Flags.Contains(MacosGatewayFlag, StringComparison.Ordinal)
                && Ipv4Cidr.TryParseAddress(row.Gateway, out _)
                    ? row.Gateway
                    : "";
            routes.Add(new PeerEgressBindRoute(row.Prefix, row.Netif, gateway, 0,
                !row.Flags.Contains(MacosScopedFlag, StringComparison.Ordinal)));
        }
        return routes;
    }

    /// <summary>
    /// The <c>IP_UNICAST_IF</c> value: the index in network byte order. In host order setsockopt
    /// refuses it outright; macOS takes the same kind of value in host order, which is why the two
    /// are spelled out rather than shared.
    /// </summary>
    public static byte[] WindowsUnicastInterfaceOption(long index)
    {
        var value = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(value, (uint)index);
        return value;
    }

    /// <summary>The <c>IP_BOUND_IF</c> value: the index as a host-order int.</summary>
    public static byte[] MacosBoundInterfaceOption(long index) => BitConverter.GetBytes((uint)index);
}
