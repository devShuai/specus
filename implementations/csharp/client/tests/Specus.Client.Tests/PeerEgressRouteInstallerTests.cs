using System.Text.Json;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

/// <summary>
/// Route installation and the journal.
/// </summary>
/// <remarks>
/// The routing table is injected, so the paths that matter here -- a failed install halfway
/// through, a prefix somebody else already owns, a journal left by a process that was killed -- are
/// driven deterministically instead of waiting for a machine to be in the wrong state.
///
/// <para>The journal's on-disk shape is asserted against the shared vector rather than against this
/// class's own output, because a round trip through one implementation agrees with whatever that
/// implementation happens to write.</para>
/// </remarks>
public class PeerEgressRouteInstallerTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-routes-" + Guid.NewGuid().ToString("N"));

    private string JournalPath => Path.Combine(_directory, "egress-routes.json");

    public PeerEgressRouteInstallerTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
        GC.SuppressFinalize(this);
    }

    private sealed class FakeCommander : IPeerEgressRouteCommander
    {
        public Dictionary<string, PeerEgressRoute> Table { get; } = [];
        public Dictionary<string, string> Foreign { get; } = [];
        public Dictionary<string, Exception> InstallErr { get; } = [];
        public Dictionary<string, Exception> RemoveErr { get; } = [];
        public List<string> InstallLog { get; } = [];
        public List<string> RemoveLog { get; } = [];

        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) =>
            Foreign.TryGetValue(route.Cidr, out var existing)
                ? new PeerEgressRouteConflictCheck(true, existing)
                : PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
            if (InstallErr.TryGetValue(route.Cidr, out var failure))
            {
                throw failure;
            }
            Table[route.Cidr] = route;
            InstallLog.Add(route.Cidr);
        }

        public void Remove(PeerEgressRoute route)
        {
            if (RemoveErr.TryGetValue(route.Cidr, out var failure))
            {
                throw failure;
            }
            Table.Remove(route.Cidr);
            RemoveLog.Add(route.Cidr);
        }
    }

    private static PeerEgressRoute Tun(string cidr) =>
        new(cidr, PeerEgressRouteKind.Tun, "rule:" + cidr);

    private static PeerEgressRoute Bypass(string cidr) =>
        new(cidr, PeerEgressRouteKind.Bypass, "bypass");

    private static JsonDocument ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "protocol", "test-vectors", "peer-egress-routes-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-routes-v1.json");
    }

    [Fact]
    public void AppliesAndWithdraws()
    {
        var commander = new FakeCommander();
        var installer = new PeerEgressRouteInstaller(commander, JournalPath);

        var result = installer.Apply([Bypass("198.51.100.7/32"), Tun("203.0.113.0/24")]);
        Assert.Null(result.Error);
        Assert.Equal(2, result.Added.Count);
        Assert.Equal(2, commander.Table.Count);
        Assert.True(File.Exists(JournalPath), "the journal was not written");

        // The bypass entry is installed first, so the transport that carries the tunnel keeps
        // working before anything is pointed into it.
        Assert.Equal(["198.51.100.7/32", "203.0.113.0/24"], commander.InstallLog);

        installer.WithdrawAll();
        Assert.Empty(commander.Table);
        Assert.False(File.Exists(JournalPath), "the journal survived a full withdrawal");
    }

    /// <summary>
    /// A failure halfway through a rule set must not leave the machine routing some traffic into a
    /// tunnel that was never finished being set up.
    /// </summary>
    [Fact]
    public void RollsBackAPartialInstall()
    {
        var commander = new FakeCommander();
        commander.InstallErr["203.0.113.0/24"] = new IOException("no such device");
        var installer = new PeerEgressRouteInstaller(commander, JournalPath);

        var result = installer.Apply([Bypass("198.51.100.7/32"), Tun("203.0.113.0/24")]);

        Assert.NotNull(result.Error);
        Assert.True(result.RolledBack, "a failed install was not rolled back");
        Assert.Empty(result.Added);
        Assert.True(commander.Table.Count == 0, "the earlier route of this call was left installed");
        Assert.Empty(installer.Installed);
    }

    /// <summary>
    /// Only this call's additions come back out. Routes from earlier calls are still wanted, and a
    /// failure now is not a reason to tear down a configuration that was working a minute ago.
    /// </summary>
    [Fact]
    public void RollbackSparesEarlierRoutes()
    {
        var commander = new FakeCommander();
        var installer = new PeerEgressRouteInstaller(commander, JournalPath);
        Assert.Null(installer.Apply([Tun("203.0.113.0/24")]).Error);

        commander.InstallErr["192.0.2.0/24"] = new IOException("no such device");
        var result = installer.Apply([Tun("203.0.113.0/24"), Tun("192.0.2.0/24")]);

        Assert.True(result.RolledBack);
        Assert.True(commander.Table.ContainsKey("203.0.113.0/24"), "an earlier route was withdrawn");
        Assert.True(installer.Owns("203.0.113.0/24"), "an earlier route left the journal");
    }

    /// <summary>
    /// One contested prefix should not disable every other rule, and the operator is told which of
    /// their own routes is in the way rather than having it silently replaced.
    /// </summary>
    [Fact]
    public void RefusesConflictsAndKeepsGoing()
    {
        var commander = new FakeCommander();
        commander.Foreign["203.0.113.0/24"] = "203.0.113.0/24 via 10.0.0.1 dev eth0";
        var installer = new PeerEgressRouteInstaller(commander, JournalPath);

        var result = installer.Apply([Tun("203.0.113.0/24"), Tun("192.0.2.0/24")]);

        Assert.Single(result.Conflicts);
        Assert.Equal("203.0.113.0/24 via 10.0.0.1 dev eth0", result.Conflicts[0].Existing);
        Assert.Single(result.Added);
        Assert.True(commander.Table.ContainsKey("192.0.2.0/24"), "the uncontested route was not installed");
        Assert.False(installer.Owns("203.0.113.0/24"), "a refused prefix was recorded as ours");
    }

    /// <summary>
    /// A restart has to take back what the previous run installed, and only that. Withdrawing
    /// somebody else's route is worse than leaving our own behind.
    /// </summary>
    [Fact]
    public void WithdrawsAJournalFromAPreviousRun()
    {
        var commander = new FakeCommander();
        var previous = new PeerEgressRouteInstaller(commander, JournalPath);
        Assert.Null(previous.Apply([Bypass("198.51.100.7/32"), Tun("203.0.113.0/24")]).Error);
        // Something the user installed, which the journal never mentions.
        commander.Table["10.0.0.0/8"] = Tun("10.0.0.0/8");

        var restarted = new PeerEgressRouteInstaller(commander, JournalPath);
        restarted.Load();
        Assert.Equal(2, restarted.Installed.Count);
        restarted.WithdrawAll();

        Assert.True(commander.Table.ContainsKey("10.0.0.0/8"), "a foreign route was withdrawn");
        Assert.Single(commander.Table);
        Assert.False(File.Exists(JournalPath), "the journal survived a full withdrawal");
    }

    /// <summary>
    /// A missing journal is the ordinary first run. Refusing to start gains nothing, and the
    /// alternative to an empty set is guessing which of the machine's routes might have been ours.
    /// </summary>
    [Fact]
    public void TreatsAMissingJournalAsEmpty()
    {
        var installer = new PeerEgressRouteInstaller(new FakeCommander(), JournalPath);
        installer.Load();
        Assert.Empty(installer.Installed);
    }

    /// <summary>
    /// The journal another runtime wrote has to be readable, or its routes stay in the table
    /// forever.
    /// </summary>
    [Fact]
    public void ReadsAndWritesTheSharedJournal()
    {
        using var vector = ReadVector();
        var journal = vector.RootElement.GetProperty("journal");
        var text = journal.GetProperty("text").GetString()!;
        Assert.False(string.IsNullOrEmpty(text), "routes vector carried no journal text");

        var expected = journal.GetProperty("routes").EnumerateArray()
            .Select(node => new PeerEgressRoute(
                node.GetProperty("cidr").GetString()!,
                PeerEgressRoutePlanner.KindFromWireName(node.GetProperty("kind").GetString()),
                node.GetProperty("origin").GetString()!))
            .ToList();

        File.WriteAllText(JournalPath, text);
        var reader = new PeerEgressRouteInstaller(new FakeCommander(), JournalPath);
        reader.Load();
        Assert.Equal(expected, reader.Installed);

        // And back out as the same bytes, so a Go or Java consumer reads what this one wrote.
        Assert.Equal(text, PeerEgressRouteInstaller.Render(expected));
    }

    /// <summary>
    /// Every refusal leaves the installed set empty. Adopting a journal that could not be read
    /// would mean withdrawing prefixes by guess, and treating it as empty would mean the routes it
    /// describes are never taken back at all.
    /// </summary>
    [Fact]
    public void RefusesTheJournalsTheVectorRejects()
    {
        using var vector = ReadVector();
        var rejects = vector.RootElement.GetProperty("journal").GetProperty("rejects");
        Assert.True(rejects.GetArrayLength() > 0, "routes vector carried no journal rejects");

        foreach (var reject in rejects.EnumerateArray())
        {
            var name = reject.GetProperty("name").GetString()!;
            File.WriteAllText(JournalPath, reject.GetProperty("text").GetString());
            var installer = new PeerEgressRouteInstaller(new FakeCommander(), JournalPath);
            Assert.True(Record.Exception(installer.Load) is not null, $"{name}: the journal was accepted");
            Assert.True(installer.Installed.Count == 0, name);
        }
    }
}
