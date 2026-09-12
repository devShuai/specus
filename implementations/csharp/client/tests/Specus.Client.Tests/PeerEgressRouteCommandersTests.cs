using System.Runtime.InteropServices;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// Which routing table this process ends up talking to, and what the Windows and macOS ones refuse
/// before they talk to anything.
/// </summary>
/// <remarks>
/// These assertions are worth more than they look because CI runs the suite on ubuntu, windows and
/// macOS: every branch of the platform choice is exercised for real, on the platform it claims,
/// rather than all three being asserted from one machine's point of view.
/// </remarks>
public class PeerEgressRouteCommandersTests
{
    [Fact]
    public void TheCommanderMatchesThePlatformThisIsRunningOn()
    {
        var commander = PeerEgressRouteCommanders.ForPlatform("specus0");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Assert.IsType<LinuxPeerEgressRouteCommander>(commander);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Assert.IsType<WindowsPeerEgressRouteCommander>(commander);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            Assert.IsType<MacosPeerEgressRouteCommander>(commander);
        }
        else
        {
            // Anything else: refusing beats installing nothing while reporting that the rules were
            // applied, which would send every destination out locally.
            Assert.IsType<UnsupportedPeerEgressRouteCommander>(commander);
        }
    }

    [Fact]
    public void APlatformWithoutTakeoverRefusesRatherThanDoingNothing()
    {
        var commander = new UnsupportedPeerEgressRouteCommander();
        var route = new PeerEgressRoute("203.0.113.0/24", PeerEgressRouteKind.Tun,
            "rule:203.0.113.0/24");

        // No conflict, because there is no table being read -- but neither install nor remove may
        // quietly succeed.
        Assert.False(commander.Conflict(route).Present);
        Assert.Throws<PlatformNotSupportedException>(() => commander.Install(route));
        Assert.Throws<PlatformNotSupportedException>(() => commander.Remove(route));
    }

    /// <summary>
    /// What the argument check says when it refuses, so a refusal is told apart from a failure.
    /// </summary>
    private const string Refusal = "refusing to build a route command from this argument";

    /// <summary>
    /// The Windows commander refuses an argument the script builder would refuse, and refuses it
    /// before starting a process.
    /// </summary>
    /// <remarks>
    /// Runs on every platform: the check happens in shared code, ahead of anything that would need
    /// powershell.exe to exist. That is the point of doing it in this order -- a prefix carrying a
    /// quote is a second PowerShell command, and paying half a second to look up an interface index
    /// before rejecting it would be the wrong way round.
    ///
    /// <para>Asserted on what the exception says rather than on how long the call took. Elapsed
    /// time cannot tell these apart: a second PowerShell process starts in well under the 175 ms
    /// the first one costs once its module is warm, so a run that happened can look exactly like
    /// one that did not.</para>
    /// </remarks>
    [Fact]
    public void TheWindowsCommanderRefusesAnInjectedPrefixBeforeRunningAnything()
    {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        var injected = new PeerEgressRoute(
            "10.0.0.0/8';Remove-NetRoute -DestinationPrefix '0.0.0.0/0",
            PeerEgressRouteKind.Tun, "rule:injected");

        Assert.Contains(Refusal,
            Assert.Throws<ArgumentException>(() => commander.Install(injected)).Message);
        Assert.Contains(Refusal,
            Assert.Throws<ArgumentException>(() => commander.Remove(injected)).Message);
    }

    [Fact]
    public void TheWindowsCommanderRefusesAMalformedPrefix()
    {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        foreach (var cidr in new[] { "10.0.0.0", "10.0.0.0/33", "10.0.0.256/24", "" })
        {
            var route = new PeerEgressRoute(cidr, PeerEgressRouteKind.Tun, $"rule:{cidr}");
            Assert.Contains(Refusal,
                Assert.Throws<ArgumentException>(() => commander.Install(route)).Message);
            Assert.Contains(Refusal,
                Assert.Throws<ArgumentException>(() => commander.Remove(route)).Message);
        }
    }

    /// <summary>The conflict check cannot report a conflict it was unable to look up.</summary>
    /// <remarks>
    /// Asserted on every platform because the shape matters more than the platform: on a machine
    /// where the query cannot run at all, the answer has to be "no conflict" so the install itself
    /// gets to refuse an existing prefix. The alternative, treating an unreadable table as a
    /// conflict, would disable every rule on any machine where the lookup broke.
    /// </remarks>
    [Fact]
    public void TheWindowsConflictCheckFailsOpenWhenItCannotAsk()
    {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        var route = new PeerEgressRoute("203.0.113.0/24", PeerEgressRouteKind.Tun,
            "rule:203.0.113.0/24");
        var conflict = commander.Conflict(route);
        // On Windows this really reads the table and 203.0.113.0/24 is not in it; on Linux the
        // query cannot run. Both answers are the same, which is what this is asserting.
        Assert.False(conflict.Present);
        Assert.Equal("", conflict.Existing);
    }

    /// <summary>
    /// The macOS commander refuses an argument the builders would refuse, before starting a
    /// process.
    /// </summary>
    /// <remarks>
    /// Runs on every platform: the check happens in shared code, ahead of anything that needs
    /// <c>route</c> to exist. The prefix that matters is 203.0.113.0/33 -- <c>route</c> accepts it,
    /// prints a success line naming 203.0.113.0, exits 0, and installs 128.0/1, which is half the
    /// IPv4 address space pointed at the gateway. Only the routing table says so, so this check is
    /// not defence in depth on this platform; it is the defence.
    /// </remarks>
    [Fact]
    public void TheMacosCommanderRefusesAMalformedPrefixBeforeRunningAnything()
    {
        var commander = new MacosPeerEgressRouteCommander("utun3");
        foreach (var cidr in new[] { "203.0.113.0/33", "203.0.113.0", "203.0.113.256/24",
            "010.0.113.0/24", "-net", "" })
        {
            var route = new PeerEgressRoute(cidr, PeerEgressRouteKind.Tun, $"rule:{cidr}");
            Assert.Contains(Refusal,
                Assert.Throws<ArgumentException>(() => commander.Install(route)).Message);
            Assert.Contains(Refusal,
                Assert.Throws<ArgumentException>(() => commander.Remove(route)).Message);
        }
    }

    /// <summary>On macOS, a prefix that is certainly taken is reported as taken.</summary>
    /// <remarks>
    /// Goes all the way to the operating system: it runs netstat, reads the whole table, normalises
    /// the destination column and finds the default route. Any machine with working networking has
    /// one, CI runners included; if this fails on a machine that has one, the reading is wrong
    /// rather than the assumption.
    /// </remarks>
    [Fact]
    public void OnMacosTheDefaultRouteIsFoundAsAConflict()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return;
        }
        var commander = new MacosPeerEgressRouteCommander("utun3");
        var conflict = commander.Conflict(
            new PeerEgressRoute("0.0.0.0/0", PeerEgressRouteKind.Tun, "rule:0.0.0.0/0"));
        Assert.True(conflict.Present, "the default route was not reported as a conflict");
        Assert.StartsWith("0.0.0.0/0 ", conflict.Existing);
        Assert.Contains("netif ", conflict.Existing);
    }

    /// <summary>
    /// On macOS, an install that cannot work reports that rather than reporting success.
    /// </summary>
    /// <remarks>
    /// The most useful thing here that needs no privileges, and the one the Windows side has no
    /// equivalent of. <c>route</c> answers a non-root caller with "must be root to alter routing
    /// table" on stderr, exit 77, and nothing at all on stdout -- so this exercises the real
    /// binary, the real streams and the real classification, and it is the one case where a
    /// classifier that read only stdout would call the failure a success.
    /// </remarks>
    [Fact]
    public void OnMacosAnInstallWithoutRootFailsRatherThanReportingSuccess()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || Environment.UserName == "root")
        {
            return;
        }
        var commander = new MacosPeerEgressRouteCommander("lo0");
        var route = new PeerEgressRoute("203.0.113.0/24", PeerEgressRouteKind.Tun,
            "rule:203.0.113.0/24");
        var failure = Assert.Throws<InvalidOperationException>(() => commander.Install(route));
        Assert.Contains("needs root", failure.Message);
        // And the route is not there, which is the claim the error is making.
        Assert.False(commander.Conflict(route).Present, "203.0.113.0/24 was installed anyway");
    }

    /// <summary>On Windows, a prefix that is certainly taken is reported as taken.</summary>
    /// <remarks>
    /// The one assertion here that goes all the way to the operating system: it starts PowerShell,
    /// reads the whole routing table, parses it and finds the default route. Every other test in
    /// this class stops before the process boundary, and the install path cannot be exercised at
    /// all without administrator rights, so this is where the query side gets proven end to end
    /// rather than only against fixtures.
    ///
    /// <para>Any machine with working networking has a default route, CI runners included. If this
    /// ever fails on a machine that has one, the reading is wrong, not the assumption.</para>
    /// </remarks>
    [Fact]
    public void OnWindowsTheDefaultRouteIsFoundAsAConflict()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        var conflict = commander.Conflict(
            new PeerEgressRoute("0.0.0.0/0", PeerEgressRouteKind.Tun, "rule:0.0.0.0/0"));
        Assert.True(conflict.Present, "the default route was not reported as a conflict");
        Assert.StartsWith("0.0.0.0/0 ", conflict.Existing);
        Assert.Contains("ifIndex ", conflict.Existing);
    }
}
