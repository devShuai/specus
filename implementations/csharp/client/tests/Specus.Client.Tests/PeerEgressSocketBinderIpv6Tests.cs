using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Binding egress sockets to IPv6 targets (protocol/spec/peer-egress.md, IPv6 数据面, 出站 socket): the
/// choice and the option encodings from synthetic tables on every platform, and on Windows and macOS
/// the real IPv6 table and real sockets to ::1. The choice and the encodings are not in
/// peer-egress-socket-binding-v1.json yet.
/// </summary>
public partial class PeerEgressSocketBinderTests
{
    /// <summary>
    /// The IPv6 choice follows the IPv4 rules -- longest prefix, then metric, then the route listed
    /// first, the tunnel and unusable routes left out -- and never mixes the families.
    /// </summary>
    [Theory]
    [InlineData("2400:cb00::1", "5")] // the default with the lower metric
    [InlineData("2001:db8:9::1", "6")] // a longer prefix beats a lower metric
    [InlineData("2001:db8:1::c8", "6")] // the tunnel's /48 is left out
    [InlineData("2001:db8:2::1", "6")] // so is an unusable route
    [InlineData("2001:db8:3::1", "8")] // a full tie keeps the route listed first
    [InlineData("203.0.113.10", "4")] // an IPv4 destination sees only IPv4 routes
    [InlineData("::ffff:a00:1", null)] // an IPv4-mapped destination is neither
    [InlineData("::ffff:10.0.0.1", null)]
    [InlineData("fe80::1%eth0", null)] // nor is a zoned one
    public void Ipv6RoutesAreSelectedByTheSameRules(string destination, string? expected)
    {
        PeerEgressBindRoute[] routes =
        [
            new("0.0.0.0/0", "4", "", 0, true),
            new("::/0", "3", "", 50, true),
            new("::/0", "5", "", 20, true),
            new("2001:db8::/32", "6", "", 99, true),
            new("2001:db8:1::/48", "tun", "", 0, true),
            new("2001:db8:2::/48", "7", "", 0, false),
            new("2001:db8:3::/48", "8", "", 5, true),
            new("2001:db8:3::/48", "9", "", 5, true),
        ];
        Assert.Equal(expected, PeerEgressSocketBinding.Select(routes, "tun", destination));
    }

    [Fact]
    public void ADefaultRouteCoversOnlyItsOwnFamily()
    {
        Assert.Null(PeerEgressSocketBinding.Select([new("::/0", "3", "", 0, true)], "", "203.0.113.10"));
        Assert.Null(PeerEgressSocketBinding.Select([new("0.0.0.0/0", "4", "", 0, true)], "", "2001:db8::1"));
    }

    /// <summary>
    /// The binder reads the table of the target's family, and with nothing outside the tunnel refuses
    /// the dial as it does for IPv4, rather than leaving the socket unbound.
    /// </summary>
    [Fact]
    public void TheBinderChoosesFromTheTargetsFamily()
    {
        var binder = new PeerEgressSocketBinder(() => "utun3",
            () => [new PeerEgressBindRoute("0.0.0.0/0", "en0", "", 0, true)],
            name => name, apply: null,
            routes6: () =>
            [
                new PeerEgressBindRoute("::/0", "en1", "", 0, true),
                new PeerEgressBindRoute("2001:db8:1::/48", "utun3", "", 0, true),
            ]);
        Assert.Equal("en0", binder.Choose("203.0.113.10"));
        Assert.Equal("en1", binder.Choose("2001:db8::10"));
        // The tunnel's own route covers it, so the default outside the tunnel is what is left.
        Assert.Equal("en1", binder.Choose("2001:db8:1::c8"));

        binder.Routes6 = () => [new PeerEgressBindRoute("::/0", "utun3", "", 0, true)];
        Assert.Throws<PeerEgressNoPhysicalRouteException>(() => binder.Choose("2001:db8::10"));
        // An IPv4-mapped target goes through the IPv4 table, where nothing contains it.
        Assert.Throws<PeerEgressNoPhysicalRouteException>(() => binder.Choose("::ffff:203.0.113.10"));
        binder.Routes6 = null;
        Assert.Throws<InvalidOperationException>(() => binder.Choose("2001:db8::10"));
    }

    // The layout of MIB_IPFORWARD_ROW2 and MIB_IPINTERFACE_ROW on 64-bit Windows, written out here
    // rather than borrowed from the parser, so a wrong offset there cannot agree with itself.
    private const int ForwardIndex = 8;
    private const int ForwardPrefixFamily = 12;
    private const int ForwardPrefixAddress6 = 20;
    private const int ForwardPrefixLength = 40;
    private const int ForwardNextHopFamily = 44;
    private const int ForwardNextHopAddress6 = 52;
    private const int ForwardMetric = 84;

    /// <summary>One MIB_IPFORWARD_ROW2 the way GetIpForwardTable2(AF_INET6) lays it out.</summary>
    private static byte[] ForwardRow6(uint index, string prefix, string nextHop, uint metric)
    {
        var row = new byte[PeerEgressSocketBinding.WindowsForwardRowSize];
        var slash = prefix.IndexOf('/');
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(ForwardIndex), index);
        BinaryPrimitives.WriteUInt16LittleEndian(row.AsSpan(ForwardPrefixFamily), PeerEgressSocketBinding.AfInet6);
        IPAddress.Parse(prefix[..slash]).GetAddressBytes().CopyTo(row, ForwardPrefixAddress6);
        row[ForwardPrefixLength] = byte.Parse(prefix[(slash + 1)..]);
        BinaryPrimitives.WriteUInt16LittleEndian(row.AsSpan(ForwardNextHopFamily), PeerEgressSocketBinding.AfInet6);
        IPAddress.Parse(nextHop).GetAddressBytes().CopyTo(row, ForwardNextHopAddress6);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(ForwardMetric), metric);
        return row;
    }

    private static byte[] InterfaceRow(int family, uint index, uint metric, bool connected, bool disableDefault)
    {
        var row = new byte[PeerEgressSocketBinding.WindowsInterfaceRowSize];
        BinaryPrimitives.WriteUInt16LittleEndian(row, (ushort)family);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(16), index);
        BinaryPrimitives.WriteUInt32LittleEndian(row.AsSpan(148), metric);
        row[156] = connected ? (byte)1 : (byte)0;
        row[166] = disableDefault ? (byte)1 : (byte)0;
        return row;
    }

    private static byte[] MibTable(params byte[][] rows)
    {
        var table = new byte[PeerEgressSocketBinding.WindowsTableHeader + rows.Sum(row => row.Length)];
        BinaryPrimitives.WriteUInt32LittleEndian(table, (uint)rows.Length);
        var offset = PeerEgressSocketBinding.WindowsTableHeader;
        foreach (var row in rows)
        {
            row.CopyTo(table, offset);
            offset += row.Length;
        }
        return table;
    }

    /// <summary>
    /// The IPv6 rows of the two Windows tables: the address eight bytes into its SOCKADDR_IN6, a length
    /// up to 128, each interface's IPv6 row on its own, and DisableDefaultRoutes applied to ::/0.
    /// </summary>
    [Fact]
    public void WindowsIpv6TablesParse()
    {
        var ipv4Row = new byte[PeerEgressSocketBinding.WindowsForwardRowSize];
        BinaryPrimitives.WriteUInt16LittleEndian(ipv4Row.AsSpan(ForwardPrefixFamily), PeerEgressSocketBinding.AfInet);
        var tooLong = ForwardRow6(3, "2001:db8::/64", "::", 0);
        tooLong[ForwardPrefixLength] = 129;
        var hostBits = ForwardRow6(3, "2001:db8:5::/64", "::", 7);
        hostBits[ForwardPrefixAddress6 + 15] = 1;

        var forward = PeerEgressSocketBinding.ParseWindowsForwardTable6(MibTable(
            ForwardRow6(3, "::/0", "fe80::1", 0),
            ForwardRow6(3, "2001:db8::/32", "::", 256),
            ForwardRow6(1, "::1/128", "::", 256),
            ForwardRow6(7, "2001:db8:7::/48", "::", 16),
            ForwardRow6(9, "::/0", "fe80::9", 0),
            ForwardRow6(11, "2001:db8:11::/48", "::", 0),
            ipv4Row, tooLong, hostBits));
        Assert.NotNull(forward);
        var interfaces = PeerEgressSocketBinding.ParseWindowsInterfaceTable6(MibTable(
            InterfaceRow(PeerEgressSocketBinding.AfInet, 3, 99, true, false),
            InterfaceRow(PeerEgressSocketBinding.AfInet6, 3, 20, true, false),
            InterfaceRow(PeerEgressSocketBinding.AfInet6, 1, 75, true, false),
            InterfaceRow(PeerEgressSocketBinding.AfInet6, 7, 5, false, false),
            InterfaceRow(PeerEgressSocketBinding.AfInet6, 9, 1, true, true)));
        Assert.NotNull(interfaces);
        Assert.Equal(4, interfaces.Count);

        var routes = PeerEgressSocketBinding.WindowsRoutes(forward, interfaces);
        Assert.Equal(
        [
            new PeerEgressBindRoute("::/0", "3", "fe80::1", 20, true),
            new PeerEgressBindRoute("2001:db8::/32", "3", "", 276, true),
            new PeerEgressBindRoute("::1/128", "1", "", 331, true),
            new PeerEgressBindRoute("2001:db8:7::/48", "7", "", 21, false),
            new PeerEgressBindRoute("::/0", "9", "fe80::9", 1, false),
            new PeerEgressBindRoute("2001:db8:11::/48", "11", "", 0, false),
            new PeerEgressBindRoute("2001:db8:5::/64", "3", "", 27, true),
        ], routes);
        Assert.Equal("3", PeerEgressSocketBinding.Select(routes, "", "2400:cb00::1"));

        // The IPv4 readers of the same bytes find nothing of their own, and the IPv6 ones nothing in an IPv4 row.
        Assert.Empty(PeerEgressSocketBinding.ParseWindowsForwardTable(MibTable(ForwardRow6(3, "::/0", "::", 0)))!);
        Assert.Empty(PeerEgressSocketBinding.ParseWindowsForwardTable6(MibTable(ipv4Row))!);
        Assert.Null(PeerEgressSocketBinding.ParseWindowsForwardTable6([1, 0, 0, 0, 0, 0, 0, 0]));
    }

    /// <summary><c>IPV6_UNICAST_IF</c> takes the index in host order, the opposite of <c>IP_UNICAST_IF</c>.</summary>
    [Fact]
    public void TheIpv6OptionsAreHostOrder()
    {
        Assert.Equal(BitConverter.GetBytes(12u), PeerEgressSocketBinding.WindowsUnicastInterfaceOption6(12));
        if (BitConverter.IsLittleEndian)
        {
            Assert.NotEqual(PeerEgressSocketBinding.WindowsUnicastInterfaceOption(12),
                PeerEgressSocketBinding.WindowsUnicastInterfaceOption6(12));
        }
        Assert.Equal(BitConverter.GetBytes(12u), PeerEgressSocketBinding.MacosBoundInterfaceOption(12));
        Assert.Equal(31, PeerEgressSocketBinding.WindowsIpv6UnicastIf);
        Assert.Equal(125, PeerEgressSocketBinding.MacosIpv6BoundIf);
        Assert.Equal(41, PeerEgressSocketBinding.IpProtoIpv6);
    }

    /// <summary>
    /// netstat -rn on macOS, both sections. Only "Internet6:" is read, destinations normalised --
    /// default, host routes without a length, zones dropped -- and a route scoped to its interface is
    /// not a candidate.
    /// </summary>
    [Fact]
    public void MacosIpv6RoutesParse()
    {
        const string table = """
            Routing tables

            Internet:
            Destination        Gateway            Flags               Netif Expire
            default            192.168.1.1        UGScg                 en0
            127                127.0.0.1          UCS                   lo0

            Internet6:
            Destination                             Gateway                                 Flags               Netif Expire
            default                                 fe80::%utun0                            UGcIg               utun0
            default                                 fe80::1%en0                             UGcg                  en0
            ::1                                     ::1                                     UHL                   lo0
            2001:db8:1::/64                         link#6                                  UC                    en0
            2001:db8:1::1                           a4:83:e7:0:0:1                          UHLWIi                en0
            fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0
            fe80::1%lo0                             link#1                                  UHLI                  lo0
            ff00::/8                                ::1                                     UmCI                  lo0
            2001:db8:2::/48                         utun4                                   USc                 utun4
            """;
        var routes = PeerEgressSocketBinding.MacosRoutes6(table);
        Assert.Equal(
        [
            new PeerEgressBindRoute("::/0", "utun0", "", 0, false),
            new PeerEgressBindRoute("::/0", "en0", "", 0, true),
            new PeerEgressBindRoute("::1/128", "lo0", "", 0, true),
            new PeerEgressBindRoute("2001:db8:1::/64", "en0", "", 0, true),
            new PeerEgressBindRoute("2001:db8:1::1/128", "en0", "", 0, false),
            new PeerEgressBindRoute("fe80::/64", "lo0", "", 0, false),
            new PeerEgressBindRoute("fe80::1/128", "lo0", "", 0, false),
            new PeerEgressBindRoute("ff00::/8", "lo0", "", 0, false),
            new PeerEgressBindRoute("2001:db8:2::/48", "utun4", "", 0, true),
        ], routes);
        Assert.Equal("en0", PeerEgressSocketBinding.Select(routes, "utun4", "2400:cb00::1"));
        Assert.Equal("en0", PeerEgressSocketBinding.Select(routes, "utun4", "2001:db8:2::10")); // utun4 is this node's tunnel
        Assert.Equal("lo0", PeerEgressSocketBinding.Select(routes, "utun4", "::1"));
        // The IPv4 reading of the same output is unchanged by the IPv6 section.
        Assert.Equal(2, PeerEgressSocketBinding.MacosRoutes(table).Count);

        foreach (var (text, expected) in new[]
                 {
                     ("default", "::/0"), ("2001:DB8::/32", "2001:db8::/32"), ("2001:db8::1/64", "2001:db8::/64"),
                     ("fe80::%en0/64", "fe80::/64"), ("192.168.1", ""), ("2001:db8::/129", ""), ("2001:db8::/064", ""),
                     ("link#6", ""),
                 })
        {
            Assert.True(expected == PeerEgressMacosRouteCommands.NormalisePrefix6(text), $"{text} normalised wrongly");
        }
        Assert.Equal(["netstat", "-rn", "-f", "inet6"], PeerEgressMacosRouteCommands.ShowTableArgs6());
    }

    // ---- the real IPv6 table and real sockets, on Windows and macOS --------------------------------

    private static int LoopbackIndex6() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .First(candidate => candidate.NetworkInterfaceType == NetworkInterfaceType.Loopback
                && candidate.OperationalStatus is OperationalStatus.Up or OperationalStatus.Unknown)
            .GetIPProperties().GetIPv6Properties().Index;

    /// <summary>
    /// Reads <c>IPV6_UNICAST_IF</c> or <c>IPV6_BOUND_IF</c> back. Both come back in host order, as they
    /// went in.
    /// </summary>
    private static int BoundInterface6(Socket socket)
    {
        var value = new byte[4];
        socket.GetRawSocketOption(PeerEgressSocketBinding.IpProtoIpv6,
            OperatingSystem.IsWindows() ? PeerEgressSocketBinding.WindowsIpv6UnicastIf : PeerEgressSocketBinding.MacosIpv6BoundIf,
            value);
        return BitConverter.ToInt32(value);
    }

    /// <summary>A TCP listener on ::1, or null on a host without IPv6 loopback.</summary>
    private static TcpListener? ListenIpv6()
    {
        try
        {
            var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();
            return listener;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    /// <summary>A dial to ::1 is bound to the loopback interface with the IPv6 option, chosen from the IPv6 table.</summary>
    [Fact]
    public void AnIpv6DialIsBoundToTheInterfaceItChose()
    {
        if (!Supported || ListenIpv6() is not { } server)
        {
            return;
        }
        try
        {
            var expected = LoopbackIndex6();
            var binder = PeerEgressSocketBinder.ForPlatform(() => "");
            var target = (IPEndPoint)server.LocalEndpoint;
            using (var stream = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp))
            {
                binder.Bind(stream, target);
                stream.Connect(target);
                Assert.Equal(expected, BoundInterface6(stream));
            }
            using (var datagram = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp))
            {
                binder.Bind(datagram, target);
                datagram.Connect(target);
                Assert.Equal(expected, BoundInterface6(datagram));
            }
        }
        finally
        {
            server.Stop();
        }
    }

    /// <summary>With only the tunnel's IPv6 routes leading to a target, the dial is refused, as for IPv4.</summary>
    [Fact]
    public void AnIpv6DialIsRefusedWhenOnlyTheTunnelLeadsThere()
    {
        if (!Supported || ListenIpv6() is not { } server)
        {
            return;
        }
        try
        {
            var name = LoopbackTunnelName();
            var binder = PeerEgressSocketBinder.ForPlatform(() => name);
            var key = binder.TunnelKey(name);
            Assert.False(string.IsNullOrEmpty(key), $"the loopback interface {name} did not resolve to a table key");
            var loopbackRoutes = binder.Routes6!().Where(route => route.Interface == key).ToList();
            Assert.Equal(key, PeerEgressSocketBinding.Select(loopbackRoutes, "", "::1"));
            binder.Routes6 = () => loopbackRoutes;

            var dialer = new PeerEgressSocketDialer(binder);
            var port = ((IPEndPoint)server.LocalEndpoint).Port;
            foreach (var protocol in new[] { "tcp", "udp" })
            {
                Assert.Throws<PeerEgressNoPhysicalRouteException>(() => dialer.Dial(protocol, "::1", port, 2000).Dispose());
            }
        }
        finally
        {
            server.Stop();
        }
    }

    /// <summary>
    /// The stack holds an IPv6 socket to the interface the IPv6 option names: told that ::1 is behind
    /// another interface, the binder's TCP cannot connect and its UDP cannot deliver.
    /// </summary>
    /// <remarks>
    /// The other interface is any with a usable IPv6 route outside loopback; the link-local prefix
    /// every IPv6 interface has is enough, so this runs without IPv6 connectivity. Like the IPv4 test
    /// it fails if the option is never set, and the UDP half sends a correctly bound datagram first so
    /// that silence cannot pass for enforcement.
    /// </remarks>
    [Fact]
    public void AnIpv6SocketIsHeldToTheBoundInterface()
    {
        if (!Supported || ListenIpv6() is not { } server)
        {
            return;
        }
        var real = PeerEgressSocketBinder.ForPlatform(() => "");
        var routes = real.Routes6!();
        var loopbackKey = real.TunnelKey(LoopbackTunnelName());
        var other = PeerEgressSocketBinding.Select(routes, loopbackKey, "2001:db8::1")
            ?? PeerEgressSocketBinding.Select(routes, loopbackKey, "fe80::1");
        Assert.True(other is not null, "no interface but loopback carries an IPv6 route; this test needs one to bind to");
        var lying = PeerEgressSocketBinder.ForPlatform(() => "");
        lying.Routes6 = () => [new PeerEgressBindRoute("::1/128", other!, "", 0, true)];

        try
        {
            var port = ((IPEndPoint)server.LocalEndpoint).Port;
            var failure = Record.Exception(() => new PeerEgressSocketDialer(lying).Dial("tcp", "::1", port, 2000).Dispose());
            Assert.True(failure is not null, $"tcp reached ::1 while bound to {other}");
            Assert.False(failure is PeerEgressNoPhysicalRouteException,
                "tcp was refused before any socket existed, so nothing was tested");
        }
        finally
        {
            server.Stop();
        }

        using var listener = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        listener.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        Assert.True(Delivers(real, listener, "::1", "control6") == "delivered",
            "udp bound to loopback did not deliver either, so silence would prove nothing");
        Assert.False(Delivers(lying, listener, "::1", "misbound6") == "delivered",
            $"udp reached ::1 while bound to {other}");
    }

    /// <summary>
    /// On Windows the native IPv6 readings agree with Get-NetRoute and Get-NetIPInterface, as the IPv4
    /// ones do: the same rows asked for AF_INET6, where the address sits four bytes further into each
    /// SOCKADDR_INET.
    /// </summary>
    [Fact]
    public void OnWindowsTheNativeIpv6TablesMatchGetNetRoute()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var forward = PeerEgressSocketBinding.ParseWindowsForwardTable6(PeerEgressSocketBinder.Windows.Table(
            forward: true, PeerEgressSocketBinding.WindowsForwardRowSize, PeerEgressSocketBinding.AfInet6));
        var interfaces = PeerEgressSocketBinding.ParseWindowsInterfaceTable6(PeerEgressSocketBinder.Windows.Table(
            forward: false, PeerEgressSocketBinding.WindowsInterfaceRowSize, PeerEgressSocketBinding.AfInet6));
        Assert.NotNull(forward);
        Assert.NotNull(interfaces);
        Assert.NotEmpty(forward);
        Assert.NotEmpty(interfaces);

        var nativeRoutes = forward.Select(row => $"{row.InterfaceIndex} {row.Prefix} {row.NextHop} {row.Metric}").Order().ToList();
        var cmdletRoutes = PowerShell("ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv6 "
                + "-PolicyStore ActiveStore -ErrorAction SilentlyContinue|Select-Object "
                + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)")
            .EnumerateArray()
            .Select(row => $"{row.GetProperty("InterfaceIndex").GetInt64()} "
                + $"{Canonical(row.GetProperty("DestinationPrefix").GetString()!)} "
                + $"{PeerEgressRuntime.FormatTarget(IPAddress.Parse(row.GetProperty("NextHop").GetString()!))} "
                + $"{row.GetProperty("RouteMetric").GetInt64()}")
            .Order().ToList();
        Assert.Equal(cmdletRoutes, nativeRoutes);

        var nativeInterfaces = interfaces.Select(row => $"{row.InterfaceIndex} {row.Metric} {row.Connected}").Order().ToList();
        var cmdletInterfaces = PowerShell("ConvertTo-Json -Compress -InputObject @(Get-NetIPInterface -AddressFamily IPv6 "
                + "-ErrorAction SilentlyContinue|Select-Object InterfaceIndex,InterfaceMetric,"
                + "@{n='Connected';e={[string]$_.ConnectionState -eq 'Connected'}})")
            .EnumerateArray()
            .Select(row => $"{row.GetProperty("InterfaceIndex").GetInt64()} {row.GetProperty("InterfaceMetric").GetInt64()} "
                + $"{row.GetProperty("Connected").GetBoolean()}")
            .Order().ToList();
        Assert.Equal(cmdletInterfaces, nativeInterfaces);
    }

    /// <summary>A prefix as Get-NetRoute writes it, in the RFC 5952 form the parser writes, host bits masked.</summary>
    private static string Canonical(string prefix)
    {
        var slash = prefix.IndexOf('/');
        var bits = int.Parse(prefix[(slash + 1)..]);
        var address = BinaryPrimitives.ReadUInt128BigEndian(IPAddress.Parse(prefix[..slash]).GetAddressBytes());
        var mask = bits == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - bits);
        return Ipv6Cidr.FormatAddress(address & mask) + "/" + bits;
    }
}
