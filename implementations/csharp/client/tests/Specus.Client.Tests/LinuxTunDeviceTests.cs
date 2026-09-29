using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// The Linux TUN device itself, against a real interface.
/// </summary>
/// <remarks>
/// It creates interfaces, so it runs under the same gate as the Go route and TUN tests:
/// SPECUS_ROUTE_MUTATION_TEST=1, as root inside a network namespace whose main table is empty.
/// CI runs it as `sudo unshare -n` in peer-egress-linux.yml. Anywhere else it is skipped.
/// </remarks>
public sealed class LinuxTunDeviceTests
{
    // A device replaced under the same interface name has to be able to take that name at once. The
    // old device's reader held a reference to its handle while it polled, so disposing it returned
    // with the descriptor still open and the replacement's TUNSETIFF failed with EBUSY -- about one
    // rebuild in forty, which is how a consumer occasionally came back from a server restart with no
    // device at all. A hundred rounds make a regression all but certain to show.
    [LinuxTunFact]
    public async Task ADeviceReplacedUnderTheSameNameStartsEveryTime()
    {
        Assert.True(string.IsNullOrWhiteSpace(await RunAsync("ip", "-4", "route", "show", "table", "main")),
            "the main routing table is not empty: this test only runs in a namespace built for it");
        await RunAsync("ip", "link", "set", "lo", "up");
        var config = new SpecusClientConfig { PeerMeshTunName = "specusrebuild0", PeerMeshMtu = 1280 };
        var peerMesh = new PeerMeshConfig { VirtualIp = "100.96.0.50", Cidr = "100.96.0.0/11" };

        IPeerVirtualDevice? device = null;
        for (var round = 0; round < 100; round++)
        {
            if (device is not null)
            {
                await device.DisposeAsync();
            }
            device = new LinuxTunPeerVirtualDevice(config, peerMesh, NullLogger.Instance);
            await device.StartAsync(_ => ValueTask.CompletedTask, CancellationToken.None);
            Assert.Equal("UP", device.Status);
        }
        await device!.DisposeAsync();
    }

    private static async Task<string> RunAsync(string file, params string[] arguments)
    {
        var start = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        return output;
    }
}

/// <summary>A fact that runs only where the Linux TUN tests may create interfaces.</summary>
public sealed class LinuxTunFactAttribute : FactAttribute
{
    public LinuxTunFactAttribute()
    {
        if (!OperatingSystem.IsLinux()
            || Environment.GetEnvironmentVariable("SPECUS_ROUTE_MUTATION_TEST") != "1")
        {
            Skip = "set SPECUS_ROUTE_MUTATION_TEST=1 and run as root inside `unshare -n` to let this create interfaces";
        }
    }
}
