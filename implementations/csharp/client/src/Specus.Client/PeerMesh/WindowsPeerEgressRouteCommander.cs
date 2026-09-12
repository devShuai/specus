using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Specus.Client.PeerMesh;

/// <summary>
/// Picking the routing table for the platform this process is running on.
/// </summary>
/// <remarks>
/// Its own type rather than a factory hanging off one of the platforms: with Linux and Windows both
/// implemented, a <c>ForPlatform</c> living on the Linux commander would be a Linux class deciding
/// whether to build a Windows one.
/// </remarks>
internal static class PeerEgressRouteCommanders
{
    /// <summary>The commander for the platform this process is running on.</summary>
    public static IPeerEgressRouteCommander ForPlatform(string? tun)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return new LinuxPeerEgressRouteCommander(tun);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new WindowsPeerEgressRouteCommander(tun);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return new MacosPeerEgressRouteCommander(tun);
        }
        return new UnsupportedPeerEgressRouteCommander();
    }
}

/// <summary>
/// The Windows routing table.
/// </summary>
/// <remarks>
/// Routes are added, never replaced, same as Linux: the installer checks for a conflict first, and
/// <c>New-NetRoute</c> failing on an existing prefix is the backstop.
///
/// <para>Everything this class sends and reads is built and parsed by
/// <see cref="PeerEgressWindowsRouteCommands"/>, which three runtimes share and
/// <c>peer-egress-windows-routes-v1.json</c> pins. What is left here is running the process and
/// caching what does not need asking twice.</para>
/// </remarks>
internal sealed class WindowsPeerEgressRouteCommander(string? tun) : IPeerEgressRouteCommander
{
    /// <summary>
    /// How long to wait for one PowerShell invocation.
    /// </summary>
    /// <remarks>
    /// The same ten seconds Linux allows <c>ip</c>, even though a PowerShell process is three
    /// orders of magnitude more expensive to start: the point of the limit is to catch a hang, not
    /// to police a budget.
    /// </remarks>
    private const int CommandTimeout = 10_000;

    /// <summary>
    /// How long one read of the whole routing table answers for.
    /// </summary>
    /// <remarks>
    /// The conflict check is asked once per prefix being added, and reading the table per prefix
    /// would cost 419 ms each. Caching it turns one apply into one read. The lifetime is what keeps
    /// that from becoming a stale answer across applies: within a single apply the cache holds,
    /// between applies it is certainly gone. An apply that runs longer than this pays for one extra
    /// read, which is a slowdown rather than a wrong answer -- while an unbounded cache would
    /// eventually miss a route somebody else installed hours ago and turn a refusable conflict into
    /// a failed install that rolls the whole plan back.
    /// </remarks>
    private static readonly TimeSpan TableCacheLifetime = TimeSpan.FromSeconds(5);

    /// <summary>
    /// The interface index for the TUN adapter, resolved once.
    /// </summary>
    /// <remarks>
    /// Routing needs the index and the client only has the name, and the name cannot be sent back
    /// out of PowerShell safely -- see the note in <see cref="PeerEgressWindowsRouteCommands"/>.
    /// </remarks>
    private int _tunIndex;

    /// <summary>One read of the whole routing table, and when it was taken.</summary>
    private string _table = "";
    private long _tableAt;

    /// <summary>
    /// Where each bypass address goes, resolved before any tunnel route exists.
    /// </summary>
    /// <remarks>
    /// Resolved one address at a time rather than in one batch, unlike the conflict check. The
    /// bypass list is the control endpoint, STUN, TURN and the peer addresses -- single digits in
    /// practice -- and each one is resolved once and then cached. Batching them would mean the
    /// installer telling the commander what is coming, which is a change to an interface three
    /// runtimes and their tests share. Worth revisiting if the list ever grows with the mesh.
    /// </remarks>
    private readonly Dictionary<string, PeerEgressWindowsRouteHop> _hops = [];

    public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route)
    {
        if (_table.Length == 0
            || Stopwatch.GetElapsedTime(_tableAt) > TableCacheLifetime)
        {
            string output;
            try
            {
                output = Run(PeerEgressWindowsRouteCommands.ShowAllRoutesScript());
            }
            catch (Exception)
            {
                // Unable to ask. Reporting no conflict lets the add proceed, and New-NetRoute
                // refuses an existing prefix anyway, so the install path still fails safe.
                return PeerEgressRouteConflictCheck.None;
            }
            _table = output;
            _tableAt = Stopwatch.GetTimestamp();
        }
        var existing = PeerEgressWindowsRouteCommands.ConflictFromTable(_table, route.Cidr);
        return existing.Present
            ? new PeerEgressRouteConflictCheck(true, existing.Description)
            : PeerEgressRouteConflictCheck.None;
    }

    public void Install(PeerEgressRoute route)
    {
        // Checked before anything is run: an argument the script builder would refuse must
        // not cost a process first, and on this platform that refusal is what keeps a prefix
        // from becoming a second command.
        if (!PeerEgressWindowsRouteCommands.ValidPrefix(route.Cidr))
        {
            throw new ArgumentException(
                $"refusing to build a route command from this argument: {route.Cidr}",
                nameof(route));
        }
        if (route.Kind == PeerEgressRouteKind.Bypass)
        {
            InstallBypass(route);
            return;
        }
        if (string.IsNullOrWhiteSpace(tun))
        {
            throw new InvalidOperationException("no TUN interface to route into");
        }
        Apply(
            PeerEgressWindowsRouteCommands.InstallRouteScript(route.Cidr, TunnelIndex(), null),
            $"install {route.Cidr}");
    }

    private void InstallBypass(PeerEgressRoute route)
    {
        var address = route.Cidr.EndsWith("/32", StringComparison.Ordinal)
            ? route.Cidr[..^3]
            : route.Cidr;
        if (!_hops.TryGetValue(address, out var hop))
        {
            var output = Run(PeerEgressWindowsRouteCommands.FindRoutesScript([address]));
            var resolved = PeerEgressWindowsRouteCommands.ParseRouteFind(output);
            if (resolved is null)
            {
                throw new InvalidOperationException($"no route to {address} to bypass through");
            }
            if (_tunIndex > 0 && resolved.Value.InterfaceIndex == _tunIndex)
            {
                // Pinning it to the tunnel would send the transport through the thing it
                // carries. Compared by index rather than by name, because the name is the one
                // thing that cannot come back out of PowerShell intact.
                throw new InvalidOperationException(
                    $"bypass for {address} already resolves to the tunnel");
            }
            hop = resolved.Value;
            _hops[address] = hop;
        }
        Apply(
            PeerEgressWindowsRouteCommands.InstallRouteScript(
                route.Cidr, hop.InterfaceIndex, hop.Gateway),
            $"install bypass {route.Cidr}");
    }

    public void Remove(PeerEgressRoute route)
    {
        if (!PeerEgressWindowsRouteCommands.ValidPrefix(route.Cidr))
        {
            throw new ArgumentException(
                $"refusing to build a route command from this argument: {route.Cidr}",
                nameof(route));
        }
        Apply(PeerEgressWindowsRouteCommands.RemoveRouteScript(route.Cidr), $"remove {route.Cidr}");
    }

    /// <summary>Resolves the TUN adapter's interface index, once.</summary>
    private int TunnelIndex()
    {
        if (_tunIndex > 0)
        {
            return _tunIndex;
        }
        var output = Run(PeerEgressWindowsRouteCommands.InterfaceIndexScript(tun));
        var index = PeerEgressWindowsRouteCommands.ParseInterfaceIndex(output);
        if (index <= 0)
        {
            throw new InvalidOperationException($"no adapter named {tun} to route into");
        }
        _tunIndex = index;
        return index;
    }

    /// <summary>Runs a script whose failures come back as JSON on stdout.</summary>
    private void Apply(string script, string what)
    {
        string output;
        Exception? runFailure = null;
        try
        {
            output = Run(script);
        }
        catch (Exception failed)
        {
            // Held rather than rethrown: the script describes its own failures on stdout, and
            // that description is more use than the exit status that came with it.
            output = failed.Message ?? "";
            runFailure = failed;
        }
        var failure = PeerEgressWindowsRouteCommands.ParseCommandFailure(output);
        if (failure == PeerEgressWindowsRouteCommands.FailurePermissionDenied)
        {
            // Named rather than folded into the generic failure: the fix is to run elevated, and
            // an operator retrying a permissions error learns nothing from the attempt.
            throw new UnauthorizedAccessException(
                $"{what} needs administrator rights: changing the routing table is not permitted "
                + "for this process");
        }
        if (failure == PeerEgressWindowsRouteCommands.FailureOther)
        {
            throw new InvalidOperationException($"{what} failed: {output.Trim()}");
        }
        // Nothing classified as a failure. A removal that found no such prefix lands here on
        // purpose: the route is not in the table, which is what the caller asked for.
        if (runFailure is not null && string.IsNullOrWhiteSpace(output))
        {
            throw runFailure;
        }
    }

    /// <summary>Executes one PowerShell script and returns its stdout.</summary>
    /// <remarks>
    /// stdout and stderr are kept apart, unlike the Linux commander which merges them. The scripts
    /// catch their own failures and write them as JSON on stdout; PowerShell's own uncaught errors
    /// go to stderr. Merging would splice non-JSON text into the document and every parser here
    /// would see only "could not read it", which is the answer that means "no conflict, go ahead".
    ///
    /// <para>Exit codes are not consulted unless stdout is empty. A script that failed exits 1
    /// after describing itself on stdout, and that description is what the caller needs.</para>
    /// </remarks>
    private static string Run(string script)
    {
        var start = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-Command", script })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("powershell did not start");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(CommandTimeout))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("powershell did not finish");
        }
        if (process.ExitCode != 0 && string.IsNullOrWhiteSpace(output))
        {
            throw new InvalidOperationException(
                $"powershell exited {process.ExitCode}: {error.Trim()}");
        }
        return output;
    }
}
