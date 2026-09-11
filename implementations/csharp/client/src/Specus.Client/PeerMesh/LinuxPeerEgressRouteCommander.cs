using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The Linux routing table.
/// </summary>
/// <remarks>
/// Routes are added, never replaced. The installer checks for a conflict first, but
/// <c>ip route add</c> failing on an existing prefix is the backstop: replacing would mean quietly
/// winning an argument with the user's own routing, which phase one does not do.
///
/// <para>Choosing between this and the Windows table lives in
/// <see cref="PeerEgressRouteCommanders"/>.</para>
/// </remarks>
internal sealed class LinuxPeerEgressRouteCommander(string? tun) : IPeerEgressRouteCommander
{
    /// <summary>How long to wait for one <c>ip</c> invocation before giving up on it.</summary>
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Where each bypass address goes, resolved before any tunnel route exists.
    /// </summary>
    /// <remarks>
    /// Resolving again later would ask the system a question this feature has already changed the
    /// answer to: once a rule's route covers the address, <c>ip route get</c> says "through the
    /// tunnel", and installing that would route the tunnel's own transport into the tunnel.
    /// </remarks>
    private readonly Dictionary<string, PeerEgressRouteHop> _hops = [];

    public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route)
    {
        string output;
        try
        {
            output = RunForOutput("ip", ["route", "show", "exact", route.Cidr]);
        }
        catch (Exception)
        {
            // Unable to ask. Reporting no conflict lets the add proceed, and `ip route add` refuses
            // an existing prefix anyway, so the install path still fails safe.
            return PeerEgressRouteConflictCheck.None;
        }
        var existing = PeerEgressRouteCommands.ParseShowExact(output);
        return existing.Present
            ? new PeerEgressRouteConflictCheck(true, existing.Description)
            : PeerEgressRouteConflictCheck.None;
    }

    public void Install(PeerEgressRoute route)
    {
        if (route.Kind == PeerEgressRouteKind.Bypass)
        {
            InstallBypass(route);
            return;
        }
        if (string.IsNullOrWhiteSpace(tun))
        {
            throw new InvalidOperationException("no TUN interface to route into");
        }
        RunForOutput("ip", ["route", "add", route.Cidr, "dev", tun]);
    }

    private void InstallBypass(PeerEgressRoute route)
    {
        var address = route.Cidr.EndsWith("/32", StringComparison.Ordinal)
            ? route.Cidr[..^3]
            : route.Cidr;
        if (!_hops.TryGetValue(address, out var hop))
        {
            var resolved = PeerEgressRouteCommands.ParseRouteGet(RunForOutput("ip", ["route", "get", address]));
            if (resolved is null)
            {
                throw new InvalidOperationException($"no route to {address} to bypass through");
            }
            if (PeerEgressRouteCommands.HopIsDevice(resolved.Value, tun))
            {
                // Pinning it to the tunnel would send the transport through the thing it carries.
                throw new InvalidOperationException($"bypass for {address} already resolves to the tunnel");
            }
            hop = resolved.Value;
            _hops[address] = hop;
        }
        RunForOutput("ip", hop.Gateway.Length == 0
            ? ["route", "add", route.Cidr, "dev", hop.Device]
            : ["route", "add", route.Cidr, "via", hop.Gateway, "dev", hop.Device]);
    }

    public void Remove(PeerEgressRoute route) => RunForOutput("ip", ["route", "del", route.Cidr]);

    private static string RunForOutput(string program, string[] arguments)
    {
        var start = new ProcessStartInfo(program)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException($"{program} did not start");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        if (!process.WaitForExit(CommandTimeout))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{program} {string.Join(' ', arguments)} did not finish");
        }
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"{program} {string.Join(' ', arguments)} failed: {output.Trim()}");
        }
        return output;
    }
}

/// <summary>
/// The platforms without route takeover: macOS, and anything else this runs on.
/// </summary>
/// <remarks>
/// Refusing rather than doing nothing: a consumer that silently installed no routes would send
/// every destination out locally while reporting that its rules were applied, which is the leak
/// this whole feature exists to prevent.
/// </remarks>
internal sealed class UnsupportedPeerEgressRouteCommander : IPeerEgressRouteCommander
{
    private const string Message = "egress route takeover is not implemented on this platform";

    public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) => PeerEgressRouteConflictCheck.None;

    public void Install(PeerEgressRoute route) => throw new PlatformNotSupportedException(Message);

    public void Remove(PeerEgressRoute route) => throw new PlatformNotSupportedException(Message);
}
