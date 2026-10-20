using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// The IPv6 data plane against a real Linux TUN and a real <c>ip -6</c>: the device's derived address,
/// a device on which IPv6 is disabled, and the route commander's IPv6 routes.
/// </summary>
/// <remarks>
/// Part of <see cref="LinuxTunDeviceTests"/> so they run one at a time under the same gate and the
/// same CI step: one of them turns IPv6 off for new interfaces while it runs, which no other test
/// creating an interface may see. The namespace's IPv4 main table is left empty, which the device
/// replacement test checks before it starts.
/// </remarks>
public sealed partial class LinuxTunDeviceTests
{
    private static readonly Lazy<string> Namespace6 = new(BuildNamespace6);

    /// <summary>
    /// Adds IPv6 to the namespace once per process: a dummy eth0 with an address and a default route
    /// through a link-local gateway as a router advertisement would leave it, a blackhole, and a TUN
    /// for the commander's routes to point at. Nothing IPv4 goes in the main table. Returns why it
    /// could not, or "".
    /// </summary>
    private static string BuildNamespace6()
    {
        string[][] steps =
        [
            ["link", "set", "lo", "up"],
            ["link", "add", "eth0", "type", "dummy"],
            ["link", "set", "eth0", "up"],
            ["-6", "addr", "add", "2001:db8:64::7/64", "dev", "eth0", "nodad"],
            ["-6", "route", "add", "default", "via", "fe80::1", "dev", "eth0"],
            ["-6", "route", "add", "blackhole", "2001:db8:dead::/48"],
            ["tuntap", "add", "dev", "specus6", "mode", "tun"],
            ["link", "set", "specus6", "up"],
        ];
        foreach (var step in steps)
        {
            var (code, output) = Ip(step);
            if (code != 0)
            {
                return "ip " + string.Join(' ', step) + ": " + output;
            }
        }
        return "";
    }

    private static void RequireNamespace6()
    {
        Assert.True(string.IsNullOrWhiteSpace(Ip("-4", "route", "show", "table", "main").Output),
            "the main routing table is not empty: this test only runs in a namespace built for it");
        Assert.True(Namespace6.Value.Length == 0, Namespace6.Value);
    }

    private static (int Code, string Output) Ip(params string[] arguments)
    {
        var start = new ProcessStartInfo("ip") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output);
    }

    private static string IpOutput(params string[] arguments)
    {
        var (code, output) = Ip(arguments);
        Assert.True(code == 0, "ip " + string.Join(' ', arguments) + ": " + output);
        return output;
    }

    private static PeerEgressRoute Route(string cidr, PeerEgressRouteKind kind) =>
        new(cidr, kind, kind == PeerEgressRouteKind.Bypass ? "bypass" : "rule:" + cidr);

    /// <summary>
    /// The device takes its derived address, and a socket that sends to a destination routed into it
    /// leaves with that address as its source: what the data plane's source check expects.
    /// </summary>
    [LinuxTunFact]
    public async Task ATunTakesItsDerivedIpv6Address()
    {
        RequireNamespace6();
        Assert.True(PeerEgressIpv6Plane.PlatformCarriesIpv6, "Linux has the IPv6 data plane");
        const string virtualIp = "100.96.0.43";
        var config = new SpecusClientConfig { PeerMeshTunName = "specustest6", PeerMeshMtu = 1280, PeerEgressEnabled = true };
        var device = new LinuxTunPeerVirtualDevice(config, new PeerMeshConfig { VirtualIp = virtualIp, Cidr = "100.96.0.0/11" },
            NullLogger.Instance);
        var packets = new System.Collections.Concurrent.BlockingCollection<byte[]>();
        await device.StartAsync(packet =>
        {
            packets.Add(packet);
            return ValueTask.CompletedTask;
        }, CancellationToken.None);
        var commander = new LinuxPeerEgressRouteCommander(device.Name);
        var rule = Route("2001:db8:7::/48", PeerEgressRouteKind.Tun);
        try
        {
            var (ready, reason) = device.Ipv6Ready();
            Assert.True(ready, "the device does not report carrying IPv6: " + reason);
            Assert.True(PeerEgressMeshAddress.TryDerive(virtualIp, out var derived));
            var address = Ipv6Cidr.FormatAddress(derived);
            Assert.Contains(address + "/128", IpOutput("-6", "address", "show", "dev", device.Name));
            Assert.Contains("mtu 1280", IpOutput("link", "show", "dev", device.Name));
            commander.Install(rule);

            var destination = IPAddress.Parse("2001:db8:7::1");
            var sender = Task.Run(async () =>
            {
                for (var round = 0; round < 3; round++)
                {
                    try
                    {
                        using var socket = new UdpClient(AddressFamily.InterNetworkV6);
                        await socket.SendAsync("ipv6"u8.ToArray(), new IPEndPoint(destination, 9));
                    }
                    catch (SocketException)
                    {
                        // Tried again.
                    }
                    await Task.Delay(200);
                }
            });
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (true)
            {
                var packet = packets.Take(deadline.Token);
                if (packet.Length < PeerEgressIpv6.HeaderBytes || packet[0] >> 4 != 6
                    || PeerEgressIpv6.DestinationOf(packet) != PeerEgressIpv6.FromAddress(destination))
                {
                    continue;
                }
                Assert.Equal(address, Ipv6Cidr.FormatAddress(PeerEgressIpv6.SourceOf(packet)));
                break;
            }
            await sender;
        }
        finally
        {
            try
            {
                commander.Remove(rule);
            }
            catch (InvalidOperationException)
            {
                // Not installed, or gone with the device.
            }
            await device.DisposeAsync();
        }
        Assert.Equal((false, "the TUN is closed"), device.Ipv6Ready());
    }

    /// <summary>
    /// On a TUN where IPv6 is disabled the address cannot be assigned: the device stays up for IPv4
    /// and reports no IPv6 data plane, with the kernel's reason.
    /// </summary>
    [LinuxTunFact]
    public async Task ATunWithoutIpv6ReportsNoIpv6DataPlane()
    {
        RequireNamespace6();
        const string sysctl = "/proc/sys/net/ipv6/conf/default/disable_ipv6";
        File.WriteAllText(sysctl, "1");
        try
        {
            var config = new SpecusClientConfig { PeerMeshTunName = "specustest6x", PeerMeshMtu = 1280, PeerEgressEnabled = true };
            var device = new LinuxTunPeerVirtualDevice(config, new PeerMeshConfig { VirtualIp = "100.96.0.44", Cidr = "100.96.0.0/11" },
                NullLogger.Instance);
            await device.StartAsync(_ => ValueTask.CompletedTask, CancellationToken.None);
            try
            {
                Assert.Equal("UP", device.Status);
                var (ready, reason) = device.Ipv6Ready();
                Assert.False(ready);
                Assert.Contains("could not be assigned", reason);
                Assert.Contains("100.96.0.44/32", IpOutput("-4", "address", "show", "dev", device.Name));
            }
            finally
            {
                await device.DisposeAsync();
            }
        }
        finally
        {
            File.WriteAllText(sysctl, "0");
        }
    }

    /// <summary>A consumer that is switched off gives the TUN no IPv6 address, and says why.</summary>
    [LinuxTunFact]
    public async Task ATunOfAConsumerSwitchedOffIsGivenNoIpv6Address()
    {
        RequireNamespace6();
        var config = new SpecusClientConfig { PeerMeshTunName = "specustest6o", PeerMeshMtu = 1280 };
        var device = new LinuxTunPeerVirtualDevice(config, new PeerMeshConfig { VirtualIp = "100.96.0.45", Cidr = "100.96.0.0/11" },
            NullLogger.Instance);
        await device.StartAsync(_ => ValueTask.CompletedTask, CancellationToken.None);
        try
        {
            Assert.Equal((false, PeerEgressIpv6Plane.NotAsked), device.Ipv6Ready());
            Assert.DoesNotContain("fd53:", IpOutput("-6", "address", "show", "dev", device.Name));
        }
        finally
        {
            await device.DisposeAsync();
        }
    }

    /// <summary>
    /// An IPv6 bypass for an address a rule has already routed into the tunnel goes out the physical
    /// gateway, which for IPv6 is link-local. <c>ip -6 route get</c> can only answer with the tunnel --
    /// asserted first, so the test cannot pass by never reaching the fallback -- and the bypass has to
    /// come from the IPv6 table with the tunnel left out.
    /// </summary>
    [LinuxTunFact]
    public void TheCommanderInstallsAnIpv6BypassUnderItsOwnTunnelRoute()
    {
        RequireNamespace6();
        var commander = new LinuxPeerEgressRouteCommander("specus6");
        var rule = Route("2001:db8:1::/48", PeerEgressRouteKind.Tun);
        var bypass = Route("2001:db8:1::9/128", PeerEgressRouteKind.Bypass);
        commander.Install(rule);
        try
        {
            Assert.Equal("specus6", PeerEgressRouteCommands.ParseRouteGet(IpOutput("-6", "route", "get", "2001:db8:1::9"))?.Device);
            commander.Install(bypass);
            Assert.Contains("via fe80::1 dev eth0", IpOutput("-6", "route", "show", "exact", "2001:db8:1::9/128"));
            Assert.Equal("eth0", PeerEgressRouteCommands.ParseRouteGet(IpOutput("-6", "route", "get", "2001:db8:1::9"))?.Device);

            // The table this feature reads sees both, written as it writes them.
            var table = commander.Table6();
            Assert.Equal("specus6", table.Tunnel);
            Assert.Empty(PeerEgressSocketBinding.Drifts([bypass, rule], table.Routes, table.Tunnel));
            Assert.Equal(PeerEgressSocketBinding.DriftMissing, Assert.Single(PeerEgressSocketBinding.Drifts(
                [Route("2001:db8:1:1::/64", PeerEgressRouteKind.Tun)], table.Routes, table.Tunnel)).Reason);
        }
        finally
        {
            commander.Remove(bypass);
            commander.Remove(rule);
        }
        Assert.True(string.IsNullOrWhiteSpace(IpOutput("-6", "route", "show", "exact", "2001:db8:1::9/128")
            + IpOutput("-6", "route", "show", "exact", "2001:db8:1::/48")), "routes left behind");
    }

    /// <summary>Behind a blackhole there is nothing to pin a bypass to: refused, and nothing installed.</summary>
    [LinuxTunFact]
    public void TheCommanderRefusesAnIpv6BypassOnlyABlackholeWouldCarry()
    {
        RequireNamespace6();
        var commander = new LinuxPeerEgressRouteCommander("specus6");
        var rule = Route("2001:db8:dead::/49", PeerEgressRouteKind.Tun);
        commander.Install(rule);
        try
        {
            Assert.Throws<PeerEgressNoPhysicalRouteException>(() =>
                commander.Install(Route("2001:db8:dead::9/128", PeerEgressRouteKind.Bypass)));
            Assert.True(string.IsNullOrWhiteSpace(IpOutput("-6", "route", "show", "exact", "2001:db8:dead::9/128")),
                "a bypass was installed anyway");
        }
        finally
        {
            commander.Remove(rule);
        }
    }

    /// <summary>
    /// The installer puts back IPv6 routes the table lost, beside an IPv4 one it owns, reading each
    /// family's table.
    /// </summary>
    [LinuxTunFact]
    public void TheInstallerRepairsIpv6RoutesTheTableLost()
    {
        RequireNamespace6();
        var journal = Path.Combine(Path.GetTempPath(), "specus-linux-ipv6-" + Guid.NewGuid().ToString("N") + ".json");
        var installer = new PeerEgressRouteInstaller(new LinuxPeerEgressRouteCommander("specus6"), journal);
        var rule = Route("2001:db8:2::/48", PeerEgressRouteKind.Tun);
        var bypass = Route("2001:db8:2::9/128", PeerEgressRouteKind.Bypass);
        try
        {
            var applied = installer.Apply([bypass, rule]);
            Assert.Null(applied.Error);
            Assert.Equal(2, applied.Added.Count);
            var healthy = installer.Repair();
            Assert.True(healthy.TableError is null && healthy.Repaired.Count == 0, healthy.TableError?.Message);

            IpOutput("-6", "route", "del", "2001:db8:2::/48");
            IpOutput("-6", "route", "del", "2001:db8:2::9/128");
            var result = installer.Repair();
            Assert.Null(result.TableError);
            Assert.Null(result.Error);
            Assert.Equal(2, result.Repaired.Count);
            Assert.Contains("dev specus6", IpOutput("-6", "route", "show", "exact", "2001:db8:2::/48"));
            Assert.Contains("via fe80::1 dev eth0", IpOutput("-6", "route", "show", "exact", "2001:db8:2::9/128"));
            Assert.Empty(installer.Repair().Repaired);
        }
        finally
        {
            installer.WithdrawAll();
        }
    }

    /// <summary>Somebody else's IPv6 route on a prefix is reported as theirs, and a free prefix is not.</summary>
    [LinuxTunFact]
    public void TheCommanderReportsSomebodyElsesIpv6Route()
    {
        RequireNamespace6();
        IpOutput("-6", "route", "add", "2001:db8:5::/48", "dev", "eth0");
        try
        {
            var commander = new LinuxPeerEgressRouteCommander("specus6");
            var conflict = commander.Conflict(Route("2001:db8:5::/48", PeerEgressRouteKind.Tun));
            Assert.True(conflict.Present);
            Assert.StartsWith("2001:db8:5::/48 dev eth0", conflict.Existing);
            Assert.False(commander.Conflict(Route("2001:db8:6::/48", PeerEgressRouteKind.Tun)).Present);
        }
        finally
        {
            Ip("-6", "route", "del", "2001:db8:5::/48");
        }
    }
}
