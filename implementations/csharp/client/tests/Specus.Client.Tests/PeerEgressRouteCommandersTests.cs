using System.Runtime.InteropServices;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// Which routing table this process ends up talking to, and what the Windows one refuses before it
/// talks to anything.
/// </summary>
/// <remarks>
/// These assertions are worth more than they look because CI runs the suite on both ubuntu and
/// windows: the two branches of the platform choice are each exercised for real, on the platform
/// they claim, rather than both being asserted from one machine's point of view.
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
        else
        {
            // macOS and anything else: refusing beats installing nothing while reporting that the
            // rules were applied, which would send every destination out locally.
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
