using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>The egress socket binding, against real sockets and the real routing table.</summary>
/// <remarks>
/// No network is needed. 127.0.0.1 is reachable only through the loopback interface, and a socket the
/// stack holds to any other interface cannot reach it -- which is what turns "the option was set" into
/// "the option is doing something". Each test returns early everywhere but Windows and macOS.
/// </remarks>
public class PeerEgressSocketBinderTests
{
    private static bool Supported => OperatingSystem.IsWindows() || OperatingSystem.IsMacOS();

    private static int LoopbackIndex()
    {
        var loopback = NetworkInterface.GetAllNetworkInterfaces()
            .First(candidate => candidate.NetworkInterfaceType == NetworkInterfaceType.Loopback
                && candidate.OperationalStatus is OperationalStatus.Up or OperationalStatus.Unknown);
        return loopback.GetIPProperties().GetIPv4Properties().Index;
    }

    /// <summary>
    /// The loopback interface as the platform's table names it. The Windows adapter alias is not
    /// localised, so it can be spelled here.
    /// </summary>
    private static string LoopbackTunnelName() => OperatingSystem.IsWindows() ? "Loopback Pseudo-Interface 1" : "lo0";

    /// <summary>
    /// Reads the binding back. On Windows it comes back in host order although it has to go in in
    /// network order: bound to loopback, whose index is 1, getsockopt returns 01 00 00 00.
    /// </summary>
    private static int BoundInterface(Socket socket)
    {
        var value = new byte[4];
        socket.GetRawSocketOption(PeerEgressSocketBinding.IpProtoIp,
            OperatingSystem.IsWindows() ? PeerEgressSocketBinding.WindowsIpUnicastIf : PeerEgressSocketBinding.MacosIpBoundIf,
            value);
        return BitConverter.ToInt32(value);
    }

    [Fact]
    public void ADialIsBoundToTheInterfaceItChose()
    {
        if (!Supported)
        {
            return;
        }
        var expected = LoopbackIndex();
        var binder = PeerEgressSocketBinder.ForPlatform(() => "");
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        var target = (IPEndPoint)server.LocalEndpoint;

        using (var stream = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            binder.Bind(stream, target);
            stream.Connect(target);
            Assert.Equal(expected, BoundInterface(stream));
        }
        using (var datagram = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            binder.Bind(datagram, target);
            datagram.Connect(target);
            Assert.Equal(expected, BoundInterface(datagram));
        }
    }

    /// <summary>
    /// When the tunnel's routes are the only ones leading to a destination, the dial is refused rather
    /// than left unbound.
    /// </summary>
    /// <remarks>
    /// The tunnel is named by the loopback interface's real name, so this also proves the name
    /// resolves to the key the table carries. The table is cut down to the loopback routes: in the
    /// real one the default route covers 127.0.0.1 too.
    /// </remarks>
    [Fact]
    public void ADialIsRefusedWhenOnlyTheTunnelLeadsThere()
    {
        if (!Supported)
        {
            return;
        }
        var name = LoopbackTunnelName();
        var binder = PeerEgressSocketBinder.ForPlatform(() => name);
        var key = binder.TunnelKey(name);
        Assert.False(string.IsNullOrEmpty(key), $"the loopback interface {name} did not resolve to a table key");
        var loopbackRoutes = binder.Routes!().Where(route => route.Interface == key).ToList();
        Assert.Equal(key, PeerEgressSocketBinding.Select(loopbackRoutes, "", "127.0.0.1"));
        binder.Routes = () => loopbackRoutes;

        var dialer = new PeerEgressSocketDialer(binder);
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        var port = ((IPEndPoint)server.LocalEndpoint).Port;
        foreach (var protocol in new[] { "tcp", "udp" })
        {
            Assert.Throws<PeerEgressNoPhysicalRouteException>(() => dialer.Dial(protocol, "127.0.0.1", port, 2000).Dispose());
        }
    }

    /// <summary>The stack holds the socket to the interface it was bound to.</summary>
    /// <remarks>
    /// The binder is handed a table claiming 127.0.0.0/8 is behind a physical interface. An unbound
    /// socket would reach 127.0.0.1 anyway; a bound one cannot. This is the test that fails if the
    /// option is never set, and it goes through the dialer, so it also fails if the dialer never asks
    /// the binder.
    /// </remarks>
    [Fact]
    public void TheSocketIsHeldToTheBoundInterface()
    {
        if (!Supported)
        {
            return;
        }
        var real = PeerEgressSocketBinder.ForPlatform(() => "");
        var loopbackKey = real.TunnelKey(LoopbackTunnelName());
        var physical = PeerEgressSocketBinding.Select(real.Routes!(), loopbackKey, "192.0.2.1");
        Assert.True(physical is not null, "no default route outside loopback; this test needs working networking");

        var lying = PeerEgressSocketBinder.ForPlatform(() => "");
        lying.Routes = () => [new PeerEgressBindRoute("127.0.0.0/8", physical!, 0, true)];
        var dialer = new PeerEgressSocketDialer(lying);
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        var port = ((IPEndPoint)server.LocalEndpoint).Port;
        foreach (var protocol in new[] { "tcp", "udp" })
        {
            var failure = Record.Exception(() => dialer.Dial(protocol, "127.0.0.1", port, 2000).Dispose());
            Assert.True(failure is not null, $"{protocol} reached 127.0.0.1 while bound to {physical}");
            Assert.False(failure is PeerEgressNoPhysicalRouteException,
                $"{protocol} was refused before any socket existed, so nothing was tested");
        }
    }

    /// <summary>
    /// On Windows the native table readings agree with Get-NetRoute and Get-NetIPInterface, which is
    /// what keeps the offsets honest on the machine running the tests.
    /// </summary>
    [Fact]
    public void OnWindowsTheNativeTablesMatchGetNetRoute()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var forward = PeerEgressSocketBinding.ParseWindowsForwardTable(
            PeerEgressSocketBinder.Windows.Table(forward: true, PeerEgressSocketBinding.WindowsForwardRowSize));
        var interfaces = PeerEgressSocketBinding.ParseWindowsInterfaceTable(
            PeerEgressSocketBinder.Windows.Table(forward: false, PeerEgressSocketBinding.WindowsInterfaceRowSize));
        Assert.NotNull(forward);
        Assert.NotNull(interfaces);

        var nativeRoutes = forward.Select(row => $"{row.InterfaceIndex} {row.Prefix} {row.Metric}").Order().ToList();
        var cmdletRoutes = PowerShell("ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 "
                + "-PolicyStore ActiveStore -ErrorAction SilentlyContinue|Select-Object "
                + "InterfaceIndex,DestinationPrefix,RouteMetric)")
            .EnumerateArray()
            .Select(row => $"{row.GetProperty("InterfaceIndex").GetInt64()} {row.GetProperty("DestinationPrefix").GetString()} "
                + $"{row.GetProperty("RouteMetric").GetInt64()}")
            .Order().ToList();
        Assert.NotEmpty(nativeRoutes);
        Assert.Equal(cmdletRoutes, nativeRoutes);

        var nativeInterfaces = interfaces.Select(row => $"{row.InterfaceIndex} {row.Metric} {row.Connected}").Order().ToList();
        var cmdletInterfaces = PowerShell("ConvertTo-Json -Compress -InputObject @(Get-NetIPInterface -AddressFamily IPv4 "
                + "-ErrorAction SilentlyContinue|Select-Object InterfaceIndex,InterfaceMetric,"
                + "@{n='Connected';e={[string]$_.ConnectionState -eq 'Connected'}})")
            .EnumerateArray()
            .Select(row => $"{row.GetProperty("InterfaceIndex").GetInt64()} {row.GetProperty("InterfaceMetric").GetInt64()} "
                + $"{row.GetProperty("Connected").GetBoolean()}")
            .Order().ToList();
        Assert.Equal(cmdletInterfaces, nativeInterfaces);
    }

    private static JsonElement PowerShell(string script)
    {
        var start = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-Command", script })
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        Assert.True(process.WaitForExit(TimeSpan.FromSeconds(60)), "powershell did not finish");
        using var document = JsonDocument.Parse(output);
        return document.RootElement.Clone();
    }
}
