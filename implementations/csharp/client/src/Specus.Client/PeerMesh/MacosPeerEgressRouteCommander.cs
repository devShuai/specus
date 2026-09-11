using System.Diagnostics;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The macOS routing table.
/// </summary>
/// <remarks>
/// Routes are added, never replaced, same as Linux and Windows: the installer checks for a conflict
/// first, and <c>route add</c> refusing an existing prefix is the backstop.
///
/// <para>Everything this class sends and reads is built and parsed by
/// <see cref="PeerEgressMacosRouteCommands"/>, which three runtimes share and
/// <c>peer-egress-macos-routes-v1.json</c> pins. What is left here is running the process.</para>
///
/// <para>Choosing between this and the other two lives in
/// <see cref="PeerEgressRouteCommanders"/>.</para>
/// </remarks>
internal sealed class MacosPeerEgressRouteCommander(string? tun) : IPeerEgressRouteCommander
{
    /// <summary>
    /// How long to wait for one <c>route</c> or <c>netstat</c> invocation.
    /// </summary>
    /// <remarks>
    /// The same ten seconds Linux allows <c>ip</c>, and for the same reason: it is there to catch a
    /// hang, not to police a budget. The readings themselves have a median of 25 ms.
    /// </remarks>
    private const int CommandTimeout = 10_000;

    /// <summary>
    /// Where each bypass address goes, resolved before any tunnel route exists.
    /// </summary>
    /// <remarks>
    /// Resolving again later would ask the system a question this feature has already changed the
    /// answer to: once a rule's route covers the address, <c>route -n get</c> answers "through the
    /// tunnel", and installing that would route the tunnel's own transport into the tunnel.
    /// </remarks>
    private readonly Dictionary<string, PeerEgressRouteHop> _hops = [];

    /// <summary>Reads the whole table, every time it is asked.</summary>
    /// <remarks>
    /// No cache, which is where this parts company with the Windows commander. That one holds one
    /// read for five seconds because a PowerShell query costs 419 ms and a plan of twenty prefixes
    /// would otherwise spend eight seconds asking. Here <c>netstat -rn -f inet</c> has a median of
    /// 25 ms against 3 ms for a process that does nothing, so twenty reads cost half a second: a
    /// cache would buy a saving that is not there, in exchange for a window in which the answer is
    /// stale.
    ///
    /// <para>The whole table rather than a query per prefix because there is no query per prefix to
    /// make. <c>route -n get</c> does a longest-prefix lookup, so on any machine with a default
    /// route it answers "yes, reachable" for every prefix nobody owns.</para>
    /// </remarks>
    public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route)
    {
        string stdout;
        try
        {
            (stdout, _) = Run(PeerEgressMacosRouteCommands.ShowTableArgs());
        }
        catch (Exception unableToAsk) when (unableToAsk is not OutOfMemoryException)
        {
            // Reporting no conflict lets the add proceed, and `route add` refuses an existing
            // prefix anyway, so the install path still fails safe.
            return PeerEgressRouteConflictCheck.None;
        }
        var existing = PeerEgressMacosRouteCommands.ConflictFromTable(stdout, route.Cidr);
        return existing.Present
            ? new PeerEgressRouteConflictCheck(true, existing.Description)
            : PeerEgressRouteConflictCheck.None;
    }

    public void Install(PeerEgressRoute route)
    {
        // Checked before anything is run. On this platform that check is not defence in depth: a
        // prefix of 203.0.113.0/33 is accepted by `route`, which prints a success line naming
        // 203.0.113.0, exits 0, and installs 128.0/1 -- half the IPv4 address space pointed at the
        // gateway. Nothing in the output says so, so nothing downstream could catch it.
        if (!PeerEgressMacosRouteCommands.ValidPrefix(route.Cidr))
        {
            throw new ArgumentException(
                $"{PeerEgressMacosRouteCommands.Refusal}: {route.Cidr}", nameof(route));
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
        Apply(PeerEgressMacosRouteCommands.InstallInterfaceArgs(route.Cidr, tun),
            $"install {route.Cidr}");
    }

    /// <summary>Pins one address to the physical path.</summary>
    /// <remarks>
    /// The TUN has to carry an IPv4 address before any route can point at it, which is a macOS
    /// requirement rather than a general one: the same <c>route add -net ... -interface utun3</c>
    /// reports "Network is unreachable" while that interface has only a link-local IPv6 address,
    /// and succeeds once it has an IPv4 one. Nothing here enforces it -- the caller brings the
    /// interface up before applying a plan -- but it is why an install can fail in a way that is
    /// neither a conflict nor a permissions problem.
    /// </remarks>
    private void InstallBypass(PeerEgressRoute route)
    {
        var address = route.Cidr.EndsWith("/32", StringComparison.Ordinal)
            ? route.Cidr[..^3]
            : route.Cidr;
        if (!_hops.TryGetValue(address, out var hop))
        {
            var (stdout, stderr) = Run(PeerEgressMacosRouteCommands.FindRouteArgs(address));
            var resolved = PeerEgressMacosRouteCommands.ParseRouteGet(stdout, stderr)
                ?? throw new InvalidOperationException(
                    $"no route to {address} to bypass through");
            if (PeerEgressRouteCommands.HopIsDevice(resolved, tun))
            {
                // Pinning it to the tunnel would send the transport through the thing it carries.
                throw new InvalidOperationException(
                    $"bypass for {address} already resolves to the tunnel");
            }
            _hops[address] = resolved;
            hop = resolved;
        }
        var command = hop.Gateway.Length == 0
            ? PeerEgressMacosRouteCommands.InstallInterfaceArgs(route.Cidr, hop.Device)
            : PeerEgressMacosRouteCommands.InstallGatewayArgs(route.Cidr, hop.Gateway);
        Apply(command, $"install bypass {route.Cidr}");
    }

    public void Remove(PeerEgressRoute route) =>
        Apply(PeerEgressMacosRouteCommands.RemoveArgs(route.Cidr), $"remove {route.Cidr}");

    /// <summary>Runs a mutation and decides whether it worked.</summary>
    /// <remarks>
    /// The exit status is not consulted, because <c>route</c> returns 0 when it fails: for a prefix
    /// that already exists, for a prefix that is not in the table, for an interface with no address
    /// and for a missing argument. Only a malformed address gets a non-zero status. What it does do
    /// is leave stderr empty on success.
    /// </remarks>
    private static void Apply(string[] command, string what)
    {
        var (stdout, stderr) = Run(command);
        var failure = PeerEgressMacosRouteCommands.ClassifyFailure(stdout, stderr);
        if (failure == PeerEgressMacosRouteCommands.FailurePermissionDenied)
        {
            // Named rather than folded into the generic failure: the fix is to run elevated, and an
            // operator retrying a permissions error learns nothing from the attempt.
            throw new InvalidOperationException(
                $"{what} needs root: changing the routing table is not permitted for this process");
        }
        if (failure == PeerEgressMacosRouteCommands.FailureOther)
        {
            var detail = stdout.Trim();
            if (detail.Length == 0)
            {
                detail = stderr.Trim();
            }
            throw new InvalidOperationException($"{what} failed: {detail}");
        }
        // Nothing classified as a failure. A removal that found no such prefix lands here on
        // purpose: the route is not in the table, which is what the caller asked for.
    }

    /// <summary>Runs one command and returns both streams.</summary>
    /// <remarks>
    /// Not merged, unlike the Linux commander. The classification depends on which stream said
    /// what: <c>route</c> annotates the operation on stdout and names the error on stderr, and every
    /// successful mutation leaves stderr empty. Merging them would throw away the only signal that
    /// separates a failed add from a successful one on a platform where both exit 0.
    ///
    /// <para>The streams are read one after the other rather than by a reader each, which is safe
    /// because of what these two commands write: <c>route</c> puts at most a line on stderr and
    /// <c>netstat</c> puts nothing there, orders of magnitude below the pipe buffer. A command that
    /// could fill that buffer while this was still draining stdout would need a task per
    /// stream.</para>
    /// </remarks>
    private static (string Stdout, string Stderr) Run(string[] command)
    {
        var start = new ProcessStartInfo(command[0])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in command[1..])
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException($"{command[0]} did not start");
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(CommandTimeout))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{command[0]} did not finish");
        }
        return (stdout, stderr);
    }
}
