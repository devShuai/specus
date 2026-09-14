using System.Buffers.Binary;
using System.Globalization;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>One route considered for the interface an egress socket is bound to.</summary>
/// <param name="Prefix">The IPv4 prefix, masked.</param>
/// <param name="Interface">The decimal interface index on Windows, the interface name on macOS.</param>
/// <param name="Metric">The effective metric: on Windows the route's plus its interface's, on macOS zero.</param>
/// <param name="Usable">False for a route the system would not use for an unbound socket.</param>
internal readonly record struct PeerEgressBindRoute(string Prefix, string Interface, long Metric, bool Usable);

internal readonly record struct PeerEgressWindowsForwardRow(long InterfaceIndex, string Prefix, long Metric);

internal readonly record struct PeerEgressWindowsInterfaceRow(long InterfaceIndex, long Metric, bool Connected,
    bool DisableDefaultRoutes);

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
    /// The interface for a socket to <paramref name="destination"/> with the tunnel's routes left
    /// out, or null when nothing else leads there.
    /// </summary>
    /// <remarks>
    /// Longest prefix, then the lowest metric, then the route listed first. The tunnel is compared by
    /// exact equality -- utun30 is not utun3 -- and an empty tunnel leaves nothing out. Null means the
    /// dial is refused rather than left unbound, because an unbound socket is exactly the one that
    /// would follow the tunnel route.
    /// </remarks>
    public static string? Select(IReadOnlyList<PeerEgressBindRoute> routes, string? tunnel, string destination)
    {
        if (!Ipv4Cidr.TryParseAddress(destination, out var address))
        {
            return null;
        }
        PeerEgressBindRoute? best = null;
        var bestBits = -1;
        foreach (var route in routes)
        {
            if (!route.Usable || (!string.IsNullOrEmpty(tunnel) && route.Interface == tunnel))
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
        return best?.Interface;
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
            parsed.Add(new PeerEgressWindowsForwardRow(
                BinaryPrimitives.ReadUInt32LittleEndian(row[ForwardInterfaceIndex..]),
                Ipv4Cidr.FormatAddress(address) + "/" + length.ToString(CultureInfo.InvariantCulture),
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
                row.InterfaceIndex.ToString(CultureInfo.InvariantCulture), metric, usable));
        }
        return routes;
    }

    /// <summary>Candidate routes from <c>netstat -rn -f inet</c>, as the route commander reads it.</summary>
    public static List<PeerEgressBindRoute> MacosRoutes(string? table)
    {
        var routes = new List<PeerEgressBindRoute>();
        foreach (var row in PeerEgressMacosRouteCommands.ParseTable(table))
        {
            routes.Add(new PeerEgressBindRoute(row.Prefix, row.Netif, 0,
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
