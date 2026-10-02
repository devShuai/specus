using System.Text.Json;
using Microsoft.Extensions.Logging;
using Specus.Client.Cli;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// The system DNS takeover run end to end against a fake machine: taking over and giving back on
/// each platform, refusals, a failure halfway, a give-back that fails, a journal a killed run left,
/// somebody else's change kept, the network changing, the mesh wiring and status, and the two
/// commands. Nothing here touches the DNS of the machine the tests run on.
/// </summary>
public sealed class PeerEgressDnsTakeoverTests : IDisposable
{
    private const string Listen = "198.18.0.1";
    private const string Tunnel = "specus0";
    private const string ResolvConf = PeerEgressDnsTakeoverRules.ResolvConfPath;
    private const long T0 = 1_800_000_000_000L;

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-dns-takeover-" + Guid.NewGuid().ToString("N"));

    private PeerEgressMesh? _mesh;

    public PeerEgressDnsTakeoverTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        _mesh?.Dispose();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }

    private string JournalPath => Path.Combine(_directory, "egress-dns-journal.json");

    private static Ipv4Cidr Cidr(string text)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var value), text);
        return value;
    }

    private static PeerEgressDnsTakeoverRequest Request(bool poolRoute = true) =>
        new(Listen, Tunnel, Cidr("198.18.0.0/15"), Cidr("100.96.0.0/11"), poolRoute);

    /// <summary>A machine that answers as each test sets it up, and remembers every command and write.</summary>
    private sealed class FakeMachine : IPeerEgressDnsHost
    {
        private readonly List<string> _ran = [];

        public string Platform { get; set; } = "linux";

        public Dictionary<string, string> Files { get; } = [];

        public HashSet<string> Symlinks { get; } = [];

        public HashSet<string> Links { get; } = [Tunnel];

        public Dictionary<string, long> Indexes { get; } = [];

        public List<string> TunnelAddresses { get; set; } = [];

        public string Fingerprint { get; set; } = "eth0|192.168.1.20";

        /// <summary>Command lines, joined by spaces, that start with one of these fail.</summary>
        public HashSet<string> Failing { get; } = [];

        /// <summary>The output of a command line, joined by spaces, for those that print something.</summary>
        public Dictionary<string, string> Outputs { get; } = [];

        /// <summary>macOS: the services in order and the DNS each has, <c>Empty</c> for DHCP's.</summary>
        public List<string> MacServices { get; } = [];

        public Dictionary<string, List<string>> MacDns { get; } = [];

        /// <summary>Called before each command runs, for a test that looks at the machine at that moment.</summary>
        public Action<string>? BeforeRun { get; set; }

        /// <summary>The process ids a client runs as, by the fresh CLI state it publishes.</summary>
        public Func<int, bool> Running { get; set; } = _ => false;

        public List<string> Ran
        {
            get
            {
                lock (_ran)
                {
                    return [.. _ran];
                }
            }
        }

        public string Run(IReadOnlyList<string> argv)
        {
            var line = string.Join(' ', argv);
            lock (_ran)
            {
                _ran.Add(line);
            }
            BeforeRun?.Invoke(line);
            if (Failing.Any(prefix => line.StartsWith(prefix, StringComparison.Ordinal)))
            {
                throw new PeerEgressDnsCommandException(argv, $"Failed: {argv[0]} refused this\nsecond line", $"{argv[0]} exited 1");
            }
            if (argv[0] == "networksetup")
            {
                switch (argv[1])
                {
                    case "-listallnetworkservices":
                        return "An asterisk (*) denotes that a network service is disabled.\n" + string.Join("\n", MacServices) + "\n";
                    case "-getdnsservers":
                        var current = MacDns[argv[2]];
                        return current is ["Empty"] ? $"There aren't any DNS Servers set on {argv[2]}.\n" : string.Join("\n", current) + "\n";
                    case "-setdnsservers":
                        MacDns[argv[2]] = [.. argv.Skip(3)];
                        return "";
                }
            }
            return Outputs.GetValueOrDefault(line, "");
        }

        public string? ReadFile(string path) => Files.GetValueOrDefault(path);

        public void WriteFile(string path, string content) => Files[path] = content;

        public bool IsSymlink(string path) => Symlinks.Contains(path);

        public bool LinkExists(string name) => Links.Contains(name);

        public long InterfaceIndex(string name) => Indexes.GetValueOrDefault(name);

        public IReadOnlyList<string> TunnelInterfaceAddresses(string ownTunnel) => TunnelAddresses;

        public string NetworkFingerprint(string ownTunnel) => Fingerprint;

        public bool ClientRunning(int pid) => Running(pid);
    }

    private sealed class Warnings : ILogger
    {
        private readonly List<string> _lines = [];

        public List<string> Lines
        {
            get
            {
                lock (_lines)
                {
                    return [.. _lines];
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (_lines)
            {
                _lines.Add(formatter(state, exception));
            }
        }
    }

    /// <summary>Linux with systemd-resolved behind its stub.</summary>
    private static FakeMachine Resolved(string links = "Global: 1.1.1.1\nLink 2 (eth0): 192.168.1.1\nLink 3 (specus0): 198.18.0.1\n")
    {
        var machine = new FakeMachine();
        machine.Files[ResolvConf] = "nameserver 127.0.0.53\noptions edns0\n";
        machine.Symlinks.Add(ResolvConf);
        machine.Outputs["resolvectl dns"] = links;
        return machine;
    }

    /// <summary>Linux without systemd-resolved: a plain /etc/resolv.conf.</summary>
    private static FakeMachine ResolvConfFile(string text = "nameserver 192.168.1.1\n")
    {
        var machine = new FakeMachine();
        machine.Files[ResolvConf] = text;
        machine.Failing.Add("resolvectl dns");
        return machine;
    }

    private PeerEgressDnsTakeover Takeover(FakeMachine machine, ILogger? logger = null) =>
        new(machine, JournalPath, logger, pid: 4242);

    private PeerEgressDnsJournal? Journal() => PeerEgressDnsJournal.Read(JournalPath);

    // ----------------------------------------------------------------------------------------------
    // Taking over and giving back
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public void SystemdResolvedIsTakenOverAndGivenBack()
    {
        var machine = Resolved();
        string? journalWhenApplying = null;
        machine.BeforeRun = line =>
        {
            if (line == $"resolvectl dns {Tunnel} {Listen}")
            {
                journalWhenApplying = Journal()?.State;
            }
        };
        var takeover = Takeover(machine);
        takeover.Engage(Request(), T0);

        // The journal was on disk, pending, before the first change.
        Assert.Equal(PeerEgressDnsJournal.StatePending, journalWhenApplying);
        Assert.Equal(new PeerEgressDnsTakeoverStatus(true, null, null, null, PeerEgressDnsJournal.StateCommitted), takeover.Status);
        Assert.Equal(["1.1.1.1", "192.168.1.1"], takeover.HeldUpstreams);
        var journal = Journal()!;
        Assert.Equal(PeerEgressDnsJournal.StateCommitted, journal.State);
        Assert.Equal(PeerEgressDnsTakeoverRules.PlatformResolved, journal.Platform);
        Assert.Equal(4242, journal.Pid);
        Assert.Equal(Listen, journal.Listen);
        Assert.Equal(Tunnel, journal.Tunnel);
        Assert.Equal(T0, journal.StartedAtUnixMs);
        Assert.Equal(["resolvectl dns", $"resolvectl dns {Tunnel} {Listen}", $"resolvectl domain {Tunnel} ~.", "resolvectl flush-caches"],
            machine.Ran);

        takeover.Release("the test is done");
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran[^2..]);
        Assert.Null(Journal());
        Assert.Equal(PeerEgressDnsTakeoverStatus.Idle, takeover.Status);
        Assert.Null(takeover.HeldUpstreams);
    }

    /// <summary>
    /// Without systemd-resolved the file is rewritten and the original kept in the journal; given
    /// back, the original returns, unless somebody wrote the file after us, whose version is kept.
    /// </summary>
    [Fact]
    public void ResolvConfIsRewrittenAndOnlyOurOwnVersionIsGivenBack()
    {
        var machine = ResolvConfFile();
        var takeover = Takeover(machine);
        takeover.Engage(Request(), T0);
        Assert.True(takeover.Status.Takeover);
        Assert.Equal(PeerEgressDnsTakeoverRules.ResolvConfWritten, machine.Files[ResolvConf]);
        Assert.Equal("nameserver 192.168.1.1\n", Journal()!.ResolvConf);
        Assert.Equal(PeerEgressDnsTakeoverRules.PlatformResolvConf, Journal()!.Platform);
        takeover.Release("done");
        Assert.Equal("nameserver 192.168.1.1\n", machine.Files[ResolvConf]);

        var warnings = new Warnings();
        takeover = Takeover(machine, warnings);
        takeover.Engage(Request(), T0);
        machine.Files[ResolvConf] = "nameserver 10.0.0.1\n";
        takeover.Release("done");
        Assert.Equal("nameserver 10.0.0.1\n", machine.Files[ResolvConf]);
        Assert.Null(Journal());
        Assert.Contains(warnings.Lines, line => line.Contains(PeerEgressDnsTakeoverRules.WarningResolvConfChanged, StringComparison.Ordinal));
    }

    /// <summary>
    /// macOS: every enabled service points at the responder; given back, each still pointing only
    /// there gets exactly what it had, Empty included, and one somebody changed is left alone.
    /// </summary>
    [Fact]
    public void MacosServicesAreTakenOverAndOnlyUnchangedOnesGivenBack()
    {
        var machine = new FakeMachine { Platform = "macos" };
        machine.MacServices.AddRange(["Wi-Fi", "*Bluetooth PAN", "Ethernet"]);
        machine.MacDns["Wi-Fi"] = ["Empty"];
        machine.MacDns["Ethernet"] = ["1.1.1.1"];
        machine.Outputs["scutil --dns"] = "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n";
        var warnings = new Warnings();
        var takeover = Takeover(machine, warnings);
        takeover.Engage(Request(), T0);

        Assert.True(takeover.Status.Takeover);
        Assert.Equal(["192.168.1.1"], takeover.HeldUpstreams);
        Assert.Equal([Listen], machine.MacDns["Wi-Fi"]);
        Assert.Equal([Listen], machine.MacDns["Ethernet"]);
        Assert.Equal(["Wi-Fi: Empty", "Ethernet: 1.1.1.1"],
            Journal()!.Services!.Select(service => service.Name + ": " + string.Join(",", service.Servers)));
        Assert.Contains("dscacheutil -flushcache", machine.Ran);

        machine.MacDns["Ethernet"] = ["9.9.9.9"];
        takeover.Release("done");
        Assert.Equal(["Empty"], machine.MacDns["Wi-Fi"]);
        Assert.Equal(["9.9.9.9"], machine.MacDns["Ethernet"]);
        Assert.Contains("killall -HUP mDNSResponder", machine.Ran[^1]);
        Assert.Contains(warnings.Lines, line => line.Contains(PeerEgressDnsTakeoverRules.WarningServiceChanged, StringComparison.Ordinal));
        Assert.Null(Journal());
    }

    /// <summary>Windows: an NRPT rule for the root, the tunnel's own server skipped when reading upstreams.</summary>
    [Fact]
    public void WindowsAddsAnNrptRuleAndRemovesIt()
    {
        var machine = new FakeMachine { Platform = "windows" };
        machine.Indexes[Tunnel] = 17;
        var readServers = string.Join(' ', PeerEgressDnsTakeoverRules.PowerShell(PeerEgressDnsTakeoverRules.WindowsReadServers));
        machine.Outputs[readServers] =
            """[{"InterfaceAlias":"Ethernet","InterfaceIndex":12,"ServerAddresses":["192.168.1.1","8.8.8.8"]},"""
            + """{"InterfaceAlias":"specus0","InterfaceIndex":17,"ServerAddresses":["198.18.0.1"]}]""";
        var takeover = Takeover(machine);
        takeover.Engage(Request(), T0);
        Assert.True(takeover.Status.Takeover);
        Assert.Equal(["192.168.1.1", "8.8.8.8"], takeover.HeldUpstreams);
        var plan = PeerEgressDnsTakeoverRules.Plan(PeerEgressDnsTakeoverRules.PlatformWindows, Listen, Tunnel, null)!;
        Assert.Equal(string.Join(' ', plan.Apply[0].Argv!), machine.Ran[^1]);
        takeover.Release("done");
        Assert.Equal(string.Join(' ', plan.Revert[0].Argv!), machine.Ran[^1]);

        // Somebody else's rule for the root: the takeover is refused before anything is written.
        var occupied = new FakeMachine { Platform = "windows" };
        occupied.Outputs[string.Join(' ', PeerEgressDnsTakeoverRules.PowerShell(PeerEgressDnsTakeoverRules.WindowsReadNrpt))] =
            """{"Namespace":".","Comment":"","NameServers":"10.0.0.1"}""";
        var refused = Takeover(occupied);
        refused.Engage(Request(), T0);
        Assert.Equal(PeerEgressDnsTakeover.CodeRefused, refused.Status.Code);
        Assert.Equal(PeerEgressDnsTakeoverRules.RefusedNrptRoot, refused.Status.Reason);
        Assert.Null(Journal());
    }

    public static TheoryData<string, string> Refusals => new()
    {
        { "loopback", PeerEgressDnsTakeoverRules.RefusedLoopback },
        { "tunnel", PeerEgressDnsTakeoverRules.RefusedVirtual },
        { "ipv6-only", PeerEgressDnsTakeoverRules.RefusedNoUpstream },
        { "managed", PeerEgressDnsTakeoverRules.RefusedResolvConfManaged },
        { "unsupported", PeerEgressDnsTakeoverRules.RefusedUnsupported },
        { "no-pool-route", PeerEgressDnsTakeoverRules.RefusedPoolRoute },
    };

    /// <summary>A refusal changes nothing and writes no journal; the status names it.</summary>
    [Theory]
    [MemberData(nameof(Refusals))]
    public void ARefusalChangesNothing(string situation, string reason)
    {
        var machine = situation switch
        {
            "loopback" => ResolvConfFile("nameserver 127.0.0.1\nnameserver 8.8.8.8\n"),
            "tunnel" => ResolvConfFile("nameserver 10.8.0.1\n"),
            "ipv6-only" => ResolvConfFile("nameserver 2001:db8::53\n"),
            "managed" => ResolvConfFile(),
            "unsupported" => new FakeMachine { Platform = "freebsd" },
            _ => Resolved(),
        };
        if (situation == "tunnel")
        {
            machine.TunnelAddresses = ["10.8.0.1"];
        }
        if (situation == "managed")
        {
            machine.Symlinks.Add(ResolvConf);
        }
        var takeover = Takeover(machine);
        takeover.Engage(Request(poolRoute: situation != "no-pool-route"), T0);
        Assert.Equal(new PeerEgressDnsTakeoverStatus(false, PeerEgressDnsTakeover.CodeRefused, reason, null,
            PeerEgressDnsJournal.StateNone), takeover.Status);
        Assert.Null(Journal());
        Assert.DoesNotContain(machine.Ran, line => line.StartsWith($"resolvectl dns {Tunnel}", StringComparison.Ordinal));
        if (machine.Files.TryGetValue(ResolvConf, out var file))
        {
            Assert.NotEqual(PeerEgressDnsTakeoverRules.ResolvConfWritten, file);
        }
    }

    /// <summary>A read that fails has changed nothing: the takeover fails, and no journal is written.</summary>
    [Fact]
    public void AFailedReadFailsWithoutAJournal()
    {
        var machine = new FakeMachine { Platform = "macos" };
        machine.Failing.Add("networksetup -listallnetworkservices");
        var takeover = Takeover(machine);
        takeover.Engage(Request(), T0);
        Assert.Equal(new PeerEgressDnsTakeoverStatus(false, PeerEgressDnsTakeover.CodeFailed, null,
            "Failed: networksetup refused this", PeerEgressDnsJournal.StateNone), takeover.Status);
        Assert.Null(Journal());
        Assert.Equal(["networksetup -listallnetworkservices"], machine.Ran);
    }

    /// <summary>
    /// A step that fails halfway: the whole give-back runs, the journal goes, the status carries the
    /// first line the command printed, and the next attempt waits its interval.
    /// </summary>
    [Fact]
    public void AFailureHalfwayIsGivenBackInFull()
    {
        var machine = Resolved();
        machine.Failing.Add("resolvectl domain");
        var takeover = Takeover(machine);
        takeover.Engage(Request(), T0);

        Assert.Equal(new PeerEgressDnsTakeoverStatus(false, PeerEgressDnsTakeover.CodeFailed, null,
            "Failed: resolvectl refused this", PeerEgressDnsJournal.StateNone), takeover.Status);
        Assert.Null(Journal());
        Assert.Equal([$"resolvectl dns {Tunnel} {Listen}", $"resolvectl domain {Tunnel} ~.", $"resolvectl revert {Tunnel}",
            "resolvectl flush-caches"], machine.Ran.Skip(1));
        Assert.Null(takeover.HeldUpstreams);

        var ran = machine.Ran.Count;
        takeover.Engage(Request(), T0 + PeerEgressDnsTakeover.RetryMs - 1);
        Assert.Equal(ran, machine.Ran.Count);
        machine.Failing.Clear();
        takeover.Engage(Request(), T0 + PeerEgressDnsTakeover.RetryMs);
        Assert.True(takeover.Status.Takeover);
    }

    /// <summary>
    /// A give-back that fails keeps the journal, the only record of what to put back; the next
    /// attempt gives that back first.
    /// </summary>
    [Fact]
    public void AGiveBackThatFailsKeepsTheJournal()
    {
        var machine = Resolved();
        machine.Failing.Add("resolvectl domain");
        machine.Failing.Add("resolvectl revert");
        var takeover = Takeover(machine);
        takeover.Engage(Request(), T0);
        Assert.Equal(PeerEgressDnsTakeover.CodeFailed, takeover.Status.Code);
        Assert.Equal(PeerEgressDnsJournal.StatePending, takeover.Status.Journal);
        Assert.Equal(PeerEgressDnsJournal.StatePending, Journal()!.State);

        machine.Failing.Clear();
        var before = machine.Ran.Count;
        takeover.Engage(Request(), T0 + PeerEgressDnsTakeover.RetryMs);
        var after = machine.Ran.Skip(before).ToList();
        Assert.Equal($"resolvectl revert {Tunnel}", after[0]);
        Assert.True(takeover.Status.Takeover);
        Assert.Equal(PeerEgressDnsJournal.StateCommitted, Journal()!.State);
    }

    /// <summary>
    /// A journal a killed run left is given back before anything else, whatever state it is in; a
    /// tunnel that went with the process has nothing left to revert. One that cannot be given back
    /// stays.
    /// </summary>
    [Fact]
    public void AJournalAKilledRunLeftIsGivenBackFirst()
    {
        PeerEgressDnsJournal.Write(JournalPath, new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StateCommitted,
            Platform = PeerEgressDnsTakeoverRules.PlatformResolved,
            Pid = 999,
            Listen = Listen,
            Tunnel = Tunnel,
            Upstreams = ["192.168.1.1"],
        });
        var machine = Resolved();
        Takeover(machine).RecoverLeftover();
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran);
        Assert.Null(Journal());

        PeerEgressDnsJournal.Write(JournalPath, new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StatePending,
            Platform = PeerEgressDnsTakeoverRules.PlatformResolved,
            Pid = 999,
            Listen = Listen,
            Tunnel = Tunnel,
        });
        var gone = Resolved();
        gone.Links.Clear();
        Takeover(gone).RecoverLeftover();
        Assert.Equal(["resolvectl flush-caches"], gone.Ran);
        Assert.Null(Journal());

        PeerEgressDnsJournal.Write(JournalPath, new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StateCommitted,
            Platform = PeerEgressDnsTakeoverRules.PlatformResolved,
            Pid = 999,
            Listen = Listen,
            Tunnel = Tunnel,
        });
        var stuck = Resolved();
        stuck.Failing.Add("resolvectl revert");
        var takeover = Takeover(stuck);
        takeover.RecoverLeftover();
        Assert.Equal(PeerEgressDnsJournal.StateCommitted, Journal()!.State);
        Assert.Equal(PeerEgressDnsTakeover.CodeFailed, takeover.Status.Code);
        Assert.Contains("resolvectl revert specus0", takeover.Status.Error, StringComparison.Ordinal);
    }

    /// <summary>
    /// A journal whose process id runs but publishes no CLI state is a leftover: after a crash and a
    /// reboot the id most likely belongs to another program. It is given back at start and before a
    /// takeover, and so is one with this process's own id whatever the check says.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AReusedProcessIdIsGivenBack(bool own)
    {
        // The test process runs, but it is no client: it publishes no state of its own.
        var pid = own ? 4242 : Environment.ProcessId;
        var machine = Resolved();
        machine.Running = _ => own;
        var takeover = Takeover(machine);
        WriteResolvedJournal(pid);
        takeover.RecoverLeftover();
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran);
        Assert.Null(Journal());

        WriteResolvedJournal(pid);
        takeover.Engage(Request(), T0);
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran[2..4]);
        Assert.True(takeover.Status.Takeover);
        Assert.Equal(4242, Journal()!.Pid);
    }

    /// <summary>
    /// A journal another running client owns -- its process publishes fresh CLI state -- is that
    /// client's live takeover. It is left alone at start and before a takeover, which fails naming
    /// the client and is tried again after the interval; once that client is gone the journal is a
    /// leftover like any other.
    /// </summary>
    [Fact]
    public void ARunningClientsJournalIsLeftAlone()
    {
        WriteResolvedJournal(777);
        var machine = Resolved();
        var running = true;
        machine.Running = pid => running && pid == 777;
        var takeover = Takeover(machine);
        takeover.RecoverLeftover();
        Assert.Empty(machine.Ran);
        Assert.Equal(777, Journal()!.Pid);

        takeover.Engage(Request(), T0);
        Assert.Empty(machine.Ran);
        Assert.Equal(777, Journal()!.Pid);
        Assert.Equal(new PeerEgressDnsTakeoverStatus(false, PeerEgressDnsTakeover.CodeFailed, null,
            "the system DNS is taken over by another running client (PID 777)", PeerEgressDnsJournal.StateNone), takeover.Status);
        // Nothing of it is this run's: with phase two stopped there is nothing to report.
        takeover.Idle("test");
        Assert.Equal(PeerEgressDnsTakeoverStatus.Idle, takeover.Status);
        takeover.Engage(Request(), T0);
        Assert.Empty(machine.Ran);

        // That client is killed: its state goes stale, and the attempt after the interval gives its
        // journal back and takes over.
        running = false;
        takeover.Engage(Request(), T0 + PeerEgressDnsTakeover.RetryMs - 1);
        Assert.Empty(machine.Ran);
        takeover.Engage(Request(), T0 + PeerEgressDnsTakeover.RetryMs);
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran[..2]);
        Assert.True(takeover.Status.Takeover);
        Assert.Equal(4242, Journal()!.Pid);
    }

    /// <summary>
    /// A client runs as a process id when fresh state from that process is in the state directory:
    /// the status command's rule, for any configuration and runtime, matched on the id inside.
    /// </summary>
    [Fact]
    public void AClientRunsWhileItPublishesFreshState()
    {
        var root = Path.Combine(_directory, "state");
        var self = Environment.ProcessId;
        Assert.False(CliState.ClientRunning(self, root));
        CliState.EnsureRoot(root);
        // Named for another process: the id inside is what counts.
        PublishState(root, "java-0123-1.json", self, DateTimeOffset.UtcNow);
        Assert.True(CliState.ClientRunning(self, root));
        Assert.False(CliState.ClientRunning(self + 1, root));
        Assert.False(CliState.ClientRunning(0, root));

        PublishState(root, "java-0123-1.json", self, DateTimeOffset.UtcNow.AddSeconds(-6));
        Assert.False(CliState.ClientRunning(self, root));
        PublishState(root, "java-0123-1.json", self, DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.False(CliState.ClientRunning(self, root));
        PublishState(root, "java-0123-1.json", self, DateTimeOffset.UtcNow, schemaVersion: 2);
        Assert.False(CliState.ClientRunning(self, root));
        // No such process: an id Windows never hands out and far above any Unix pid_max.
        PublishState(root, "dotnet-4567-1.json", int.MaxValue, DateTimeOffset.UtcNow);
        Assert.False(CliState.ClientRunning(int.MaxValue, root));
        if (!OperatingSystem.IsWindows())
        {
            PublishState(root, "go-89ab-1.json", self, DateTimeOffset.UtcNow);
            File.SetUnixFileMode(Path.Combine(root, "go-89ab-1.json"),
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            Assert.False(CliState.ClientRunning(self, root));
        }
    }

    /// <summary>Writes a state file the way a running client does: private, in the state directory.</summary>
    private static void PublishState(string root, string name, int pid, DateTimeOffset at, int schemaVersion = 1)
    {
        var path = Path.Combine(root, name);
        File.WriteAllText(path, JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["schemaVersion"] = schemaVersion,
            ["pid"] = pid,
            ["updatedAtUnixMs"] = at.ToUnixTimeMilliseconds(),
            ["configPath"] = Path.Combine(root, "another.jsonc"),
            ["processRunning"] = true,
        }));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        CliState.ProtectNewFile(path);
    }

    [Fact]
    public void TheNetworkIsComparedEveryTenSeconds()
    {
        var machine = Resolved();
        var takeover = Takeover(machine);
        Assert.False(takeover.NetworkChanged(Tunnel, T0));
        machine.Fingerprint = "wlan0|10.0.0.20";
        Assert.False(takeover.NetworkChanged(Tunnel, T0 + PeerEgressDnsTakeover.NetworkCheckMs - 1));
        Assert.True(takeover.NetworkChanged(Tunnel, T0 + PeerEgressDnsTakeover.NetworkCheckMs));
        Assert.False(takeover.NetworkChanged(Tunnel, T0 + 2 * PeerEgressDnsTakeover.NetworkCheckMs));
    }

    [Fact]
    public void TunnelInterfacesAndTheFingerprintFollowTheSpec()
    {
        PeerEgressDnsInterface[] interfaces =
        [
            new("eth0", 6, false, ["192.168.1.20"]),
            new("tun0", 0, true, ["10.8.0.2"]),
            new(Tunnel, 131, true, ["100.96.0.7"]),
            new("utun4", 0, false, ["10.9.0.2"]),
            new("vEthernet", 53, false, ["172.20.0.1"]),
        ];
        Assert.Equal(["10.8.0.2"], PeerEgressDnsSystem.TunnelAddresses("linux", interfaces, Tunnel));
        Assert.Equal(["10.9.0.2"], PeerEgressDnsSystem.TunnelAddresses("macos", interfaces, Tunnel));
        Assert.Equal(["172.20.0.1"], PeerEgressDnsSystem.TunnelAddresses("windows", interfaces, Tunnel));

        var routes = PeerEgressDnsSystem.LinuxDefaultRoutes(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            + "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
            + "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
            + "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n");
        Assert.Equal(2, routes.Count);
        Assert.Equal("eth0|10.0.0.1,192.168.1.20",
            PeerEgressDnsSystem.Fingerprint(routes, Tunnel, [Address("192.168.1.20"), Address("10.0.0.1"), Address("192.168.1.20")]));
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), dotted);
        return value;
    }

    // ----------------------------------------------------------------------------------------------
    // The mesh
    // ----------------------------------------------------------------------------------------------

    private sealed class Host(string directory, FakeMachine machine) : IPeerEgressMeshHost
    {
        public bool Takeover { get; set; } = true;

        public List<string> Interfaces { get; set; } = ["192.168.1.0/24"];

        public bool DnsTakeover => Takeover;

        public IPeerEgressDnsHost? DnsSystem => machine;

        public string? DnsJournalPath => Path.Combine(directory, "egress-dns-journal.json");

        public IReadOnlyList<string> LocalInterfaceNetworks() => Interfaces;

        public IReadOnlyList<string> LocalInterfaceAddresses() => [];

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task WriteToDeviceAsync(byte[] packet) => Task.CompletedTask;

        public string TunName => Tunnel;

        public string MeshCidr => PeerEgressRules.DefaultMeshCidr;

        public string VirtualIp => "100.96.0.7";

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => [];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");
    }

    /// <summary>A routing table where something else may already own the pool's prefix.</summary>
    private sealed class Commander(bool poolTaken = false) : IPeerEgressRouteCommander
    {
        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) =>
            poolTaken && route.Origin == PeerEgressRoutePlanner.FakeIpPoolOrigin
                ? new PeerEgressRouteConflictCheck(true, "198.18.0.0/15 via 192.0.2.1 dev tun9")
                : PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
        }

        public void Remove(PeerEgressRoute route)
        {
        }
    }

    private PeerEgressMesh MeshFor(Host host, bool poolTaken = false)
    {
        _mesh = new PeerEgressMesh(host, commander: new Commander(poolTaken));
        return _mesh;
    }

    private static JsonElement Dns(PeerEgressMesh mesh) =>
        JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer").GetProperty("dns");

    /// <summary>
    /// With phase two running the mesh takes the system's DNS over, the responder forwards to what
    /// the takeover recorded, and the status says so in the order the spec lists.
    /// </summary>
    [Fact]
    public void TheMeshTakesOverAndTheResponderForwardsToTheRecordedUpstreams()
    {
        var machine = Resolved();
        var mesh = MeshFor(new Host(_directory, machine));
        mesh.Reconcile([], T0);

        var dns = Dns(mesh);
        Assert.Equal(["active", "takeover", "listen", "pool", "mappings", "quarantined", "upstreams", "journal", "queries"],
            dns.EnumerateObject().Select(field => field.Name));
        Assert.True(dns.GetProperty("active").GetBoolean());
        Assert.True(dns.GetProperty("takeover").GetBoolean());
        Assert.Equal("committed", dns.GetProperty("journal").GetString());
        Assert.Equal(["1.1.1.1", "192.168.1.1"], dns.GetProperty("upstreams").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal(["1.1.1.1", "192.168.1.1"], mesh.DnsResponder!.Upstreams.Select(upstream => upstream.ToString()));

        mesh.WithdrawRoutes();
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran[^2..]);
        Assert.False(File.Exists(Path.Combine(_directory, "egress-dns-journal.json")));
    }

    /// <summary>
    /// A new network: the takeover is given back and taken again from what the new network hands
    /// out; one whose addresses fall in the pool stops phase two and gives the DNS back.
    /// </summary>
    [Fact]
    public void ANetworkChangeTakesOverAgainAndAPoolClashStopsPhaseTwo()
    {
        var machine = Resolved();
        var host = new Host(_directory, machine);
        var mesh = MeshFor(host);
        mesh.Reconcile([], T0);
        Assert.Equal(["1.1.1.1", "192.168.1.1"], Dns(mesh).GetProperty("upstreams").EnumerateArray().Select(item => item.GetString()));

        machine.Fingerprint = "wlan0|10.0.0.20";
        machine.Outputs["resolvectl dns"] = "Global:\nLink 4 (wlan0): 10.0.0.1\n";
        mesh.Reconcile([], T0 + 5000);
        Assert.Equal(["1.1.1.1", "192.168.1.1"], Dns(mesh).GetProperty("upstreams").EnumerateArray().Select(item => item.GetString()));
        var before = machine.Ran.Count;
        mesh.Reconcile([], T0 + PeerEgressDnsTakeover.NetworkCheckMs);
        var ran = machine.Ran.Skip(before).ToList();
        Assert.Equal($"resolvectl revert {Tunnel}", ran[0]);
        Assert.Contains($"resolvectl dns {Tunnel} {Listen}", ran);
        Assert.Equal(["10.0.0.1"], Dns(mesh).GetProperty("upstreams").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal(["10.0.0.1"], mesh.DnsResponder!.Upstreams.Select(upstream => upstream.ToString()));

        host.Interfaces = ["198.18.5.0/24"];
        machine.Fingerprint = "wlan1|198.18.5.20";
        mesh.Reconcile([], T0 + 2 * PeerEgressDnsTakeover.NetworkCheckMs);
        var dns = Dns(mesh);
        Assert.False(dns.GetProperty("active").GetBoolean());
        Assert.False(dns.GetProperty("takeover").GetBoolean());
        Assert.Equal(PeerEgressCodes.FakeIpPoolInvalid, dns.GetProperty("code").GetString());
        Assert.Equal("none", dns.GetProperty("journal").GetString());
        Assert.Null(mesh.FakeIpPool);
        Assert.False(File.Exists(Path.Combine(_directory, "egress-dns-journal.json")));
    }

    /// <summary>A pool route somebody else owns: phase two runs, the system's DNS is not pointed at a responder nothing reaches.</summary>
    [Fact]
    public void ThePoolRouteNotInstalledRefusesTheTakeover()
    {
        var machine = Resolved();
        var mesh = MeshFor(new Host(_directory, machine), poolTaken: true);
        mesh.Reconcile([], T0);
        var dns = Dns(mesh);
        Assert.True(dns.GetProperty("active").GetBoolean());
        Assert.False(dns.GetProperty("takeover").GetBoolean());
        Assert.Equal(PeerEgressDnsTakeover.CodeRefused, dns.GetProperty("code").GetString());
        Assert.Equal(PeerEgressDnsTakeoverRules.RefusedPoolRoute, dns.GetProperty("reason").GetString());
        Assert.DoesNotContain(machine.Ran, line => line.StartsWith("resolvectl", StringComparison.Ordinal));
    }

    /// <summary>The first reconcile gives back what a killed run left, with the switch off as well.</summary>
    [Fact]
    public void TheFirstReconcileGivesBackALeftJournalWithTheSwitchOff()
    {
        PeerEgressDnsJournal.Write(Path.Combine(_directory, "egress-dns-journal.json"), new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StateCommitted,
            Platform = PeerEgressDnsTakeoverRules.PlatformResolved,
            Pid = 999,
            Listen = Listen,
            Tunnel = Tunnel,
        });
        var machine = Resolved();
        var mesh = MeshFor(new Host(_directory, machine) { Takeover = false });
        mesh.Reconcile([], T0);
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran);
        Assert.False(File.Exists(Path.Combine(_directory, "egress-dns-journal.json")));
        Assert.False(JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer").TryGetProperty("dns", out _));
    }

    /// <summary>The first reconcile leaves alone a journal another running client owns, and says why it does not take over.</summary>
    [Fact]
    public void TheFirstReconcileLeavesARunningClientsJournal()
    {
        var journal = Path.Combine(_directory, "egress-dns-journal.json");
        PeerEgressDnsJournal.Write(journal, new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StateCommitted,
            Platform = PeerEgressDnsTakeoverRules.PlatformResolved,
            Pid = 777,
            Listen = Listen,
            Tunnel = Tunnel,
        });
        var machine = Resolved();
        machine.Running = pid => pid == 777;
        var mesh = MeshFor(new Host(_directory, machine));
        mesh.Reconcile([], T0);
        Assert.Empty(machine.Ran);
        Assert.Equal(777, PeerEgressDnsJournal.Read(journal)!.Pid);
        var dns = Dns(mesh);
        Assert.True(dns.GetProperty("active").GetBoolean());
        Assert.False(dns.GetProperty("takeover").GetBoolean());
        Assert.Equal(PeerEgressDnsTakeover.CodeFailed, dns.GetProperty("code").GetString());
        Assert.Equal("the system DNS is taken over by another running client (PID 777)", dns.GetProperty("error").GetString());
        Assert.Equal("none", dns.GetProperty("journal").GetString());
    }

    // ----------------------------------------------------------------------------------------------
    // The commands
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public void TheCommandsParse()
    {
        var restore = ClientCliOptions.Parse(["egress", "dns", "restore", "--force"]);
        Assert.Equal("egress dns restore", restore.Command);
        Assert.True(restore.Egress.Force);
        Assert.Equal("egress dns status", ClientCliOptions.Parse(["egress", "dns", "status", "--config", "c.jsonc"]).Command);
        Assert.Throws<ArgumentException>(() => ClientCliOptions.Parse(["egress", "dns", "status", "--force"]));
        Assert.Throws<ArgumentException>(() => ClientCliOptions.Parse(["egress", "dns", "flush"]));
        Assert.Contains("egress dns restore [--force]", ClientCliOptions.HelpText, StringComparison.Ordinal);
    }

    private void WriteResolvedJournal(int pid) => PeerEgressDnsJournal.Write(JournalPath, new PeerEgressDnsJournal
    {
        State = PeerEgressDnsJournal.StateCommitted,
        Platform = PeerEgressDnsTakeoverRules.PlatformResolved,
        Pid = pid,
        Listen = Listen,
        Tunnel = Tunnel,
        Upstreams = ["192.168.1.1"],
    });

    /// <summary>
    /// restore: nothing to do is success; the client that took over still running is refused unless
    /// forced; a step that fails is named and keeps the journal.
    /// </summary>
    [Fact]
    public void RestoreGivesBackWhatTheJournalSays()
    {
        var restore = ClientCliOptions.Parse(["egress", "dns", "restore"]);
        var machine = Resolved();
        var nothing = EgressDns.Restore(restore, JournalPath, machine, _ => false);
        Assert.Equal(0, nothing.Code);
        Assert.Equal($"No DNS takeover journal at {JournalPath}; there is nothing to restore.", nothing.Message);

        WriteResolvedJournal(4242);
        var live = EgressDns.Restore(restore, JournalPath, machine, pid => pid == 4242);
        Assert.Equal(1, live.Code);
        Assert.Equal("The client that took over the system DNS (PID 4242) is still running, and gives it back itself when it stops. "
            + "Stop it, or set peerEgressDnsTakeover to false and restart it. --force skips this check, for when that PID now belongs to another client.",
            live.Message);
        Assert.Empty(machine.Ran);
        Assert.NotNull(Journal());

        machine.Failing.Add("resolvectl revert");
        var failed = EgressDns.Restore(ClientCliOptions.Parse(["egress", "dns", "restore", "--force"]), JournalPath, machine,
            pid => pid == 4242);
        Assert.Equal(1, failed.Code);
        Assert.Equal($"Giving the system DNS back failed at resolvectl revert {Tunnel}: Failed: resolvectl refused this. "
            + "The journal is kept; fix what the step reports and run egress dns restore again.", failed.Message);
        // Every step is tried even after one fails.
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran);
        Assert.NotNull(Journal());

        machine.Failing.Clear();
        var forced = EgressDns.Restore(ClientCliOptions.Parse(["egress", "dns", "restore", "--force"]), JournalPath, machine,
            pid => pid == 4242);
        Assert.Equal(0, forced.Code);
        Assert.Equal("System DNS given back (linux-resolved, taken over by PID 4242); journal removed.", forced.Message);
        using var data = JsonDocument.Parse(JsonSerializer.Serialize(forced.Data));
        Assert.Equal(JournalPath, data.RootElement.GetProperty("journal").GetString());
        Assert.True(data.RootElement.GetProperty("restored").GetBoolean());
        Assert.Null(Journal());
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran[^2..]);
    }

    /// <summary>
    /// A journal whose process id may well run but publishes no fresh state is given back without
    /// --force: since a reboot that id most likely belongs to another program.
    /// </summary>
    [Fact]
    public void RestoreGivesBackAReusedProcessIdWithoutForce()
    {
        WriteResolvedJournal(4242);
        var machine = Resolved();
        var answer = EgressDns.Restore(ClientCliOptions.Parse(["egress", "dns", "restore"]), JournalPath, machine, _ => false);
        Assert.Equal(0, answer.Code);
        Assert.Equal("System DNS given back (linux-resolved, taken over by PID 4242); journal removed.", answer.Message);
        Assert.Equal([$"resolvectl revert {Tunnel}", "resolvectl flush-caches"], machine.Ran);
        Assert.Null(Journal());
    }

    /// <summary>
    /// restore through the real command line knows the client by the state it publishes. The test
    /// process stands in for the client that took over: its process id runs, yet without its state
    /// restore goes on to give back; with fresh state it is refused. The journal names a platform no
    /// client knows how to give back, so even the first never touches this machine's DNS.
    /// </summary>
    [Fact]
    public async Task RestoreKnowsTheClientByItsState()
    {
        var state = Path.Combine(_directory, "state");
        var journal = Path.Combine(_directory, ".specus", "egress-dns-journal.json");
        PeerEgressDnsJournal.Write(journal, new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StateCommitted,
            Platform = "specus-test-none",
            Pid = Environment.ProcessId,
            Listen = Listen,
            Tunnel = Tunnel,
        });
        var (code, _, errors) = await Cli(["egress", "dns", "restore"], state);
        Assert.Equal(1, code);
        Assert.StartsWith("Giving the system DNS back failed at the journal names platform 'specus-test-none'", errors, StringComparison.Ordinal);

        CliState.EnsureRoot(state);
        PublishState(state, "go-0123-1.json", Environment.ProcessId, DateTimeOffset.UtcNow);
        (code, _, errors) = await Cli(["egress", "dns", "restore"], state);
        Assert.Equal(1, code);
        Assert.StartsWith($"The client that took over the system DNS (PID {Environment.ProcessId}) is still running", errors,
            StringComparison.Ordinal);
        Assert.Equal(Environment.ProcessId, PeerEgressDnsJournal.Read(journal)!.Pid);
    }

    /// <summary>restore over somebody else's resolv.conf keeps theirs and says so.</summary>
    [Fact]
    public void RestoreKeepsSomebodyElsesChange()
    {
        PeerEgressDnsJournal.Write(JournalPath, new PeerEgressDnsJournal
        {
            State = PeerEgressDnsJournal.StateCommitted,
            Platform = PeerEgressDnsTakeoverRules.PlatformResolvConf,
            Pid = 4242,
            Listen = Listen,
            Tunnel = Tunnel,
            ResolvConf = "nameserver 192.168.1.1\n",
        });
        var machine = ResolvConfFile("nameserver 10.0.0.1\n");
        var answer = EgressDns.Restore(ClientCliOptions.Parse(["egress", "dns", "restore"]), JournalPath, machine, _ => false);
        Assert.Equal(0, answer.Code);
        Assert.Equal("System DNS given back (linux-resolvconf, taken over by PID 4242); journal removed.", answer.Message);
        Assert.Contains(answer.Warnings!, line => line.Contains(PeerEgressDnsTakeoverRules.WarningResolvConfChanged, StringComparison.Ordinal));
        Assert.Equal("nameserver 10.0.0.1\n", machine.Files[ResolvConf]);
        Assert.Null(Journal());
    }

    /// <summary>status reads a running client's state and the journal, and works with neither there.</summary>
    [Fact]
    public void StatusReadsTheStateAndTheJournal()
    {
        var options = ClientCliOptions.Parse(["egress", "dns", "status", "--config", "c.jsonc"]);
        var alone = EgressDns.Status(options, "c.jsonc", JournalPath, _ => [], _ => false);
        Assert.Equal(0, alone.Code);
        Assert.Equal("No running client for this config.\njournal: none (the system DNS is not taken over)", alone.Message);
        using (var data = JsonDocument.Parse(JsonSerializer.Serialize(alone.Data)))
        {
            Assert.Equal(["configPath", "instances", "journal"], data.RootElement.EnumerateObject().Select(field => field.Name));
            Assert.Equal(JournalPath, data.RootElement.GetProperty("journal").GetProperty("path").GetString());
            Assert.Equal("none", data.RootElement.GetProperty("journal").GetProperty("state").GetString());
        }
        Assert.Equal(2, EgressDns.Status(options, "c.jsonc", JournalPath, _ => throw new IOException("not private"), _ => false).Code);

        WriteResolvedJournal(4242);
        using var state = JsonDocument.Parse("""
            {"pid": 4242, "egress": {"consumer": {"dns": {"active": true, "takeover": false, "listen": "198.18.0.1",
             "pool": "198.18.0.0/15", "mappings": 3, "quarantined": 1, "upstreams": [], "journal": "none",
             "queries": {"answered": 0, "forwarded": 0, "failed": 0},
             "code": "EGRESS_DNS_TAKEOVER_REFUSED", "reason": "system-dns-loopback"}}}}
            """);
        var running = EgressDns.Status(options, "c.jsonc", JournalPath, _ => [state.RootElement.Clone()], pid => pid == 4242);
        Assert.Equal(0, running.Code);
        var lines = running.Message.Split('\n');
        Assert.Equal("PID 4242 | DNS takeover: off (EGRESS_DNS_TAKEOVER_REFUSED: system-dns-loopback)", lines[0]);
        Assert.Contains("  upstreams: none", lines);
        Assert.Contains("  mappings: 3 of 131069 (0.0%), 1 resting", lines);
        Assert.Contains("journal: committed (PID 4242, linux-resolved, upstreams 192.168.1.1)", lines);
        Assert.Equal(131069, EgressDns.Capacity("198.18.0.0/15"));
        // Restore is suggested only when no client runs as the journal's process id, whichever
        // configuration that client runs.
        var other = EgressDns.Status(options, "c.jsonc", JournalPath, _ => [], _ => false);
        Assert.EndsWith("journal: committed (PID 4242, linux-resolved, upstreams 192.168.1.1); egress dns restore gives it back",
            other.Message, StringComparison.Ordinal);
        var elsewhere = EgressDns.Status(options, "c.jsonc", JournalPath, _ => [], pid => pid == 4242);
        Assert.EndsWith("journal: committed (PID 4242, linux-resolved, upstreams 192.168.1.1)", elsewhere.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// egress dns enable|disable through the real command line, on a configuration file in a
    /// temporary directory: the notice every time it is turned on, refused without --yes, and the
    /// lines the spec gives.
    /// </summary>
    [Fact]
    public async Task EnableAndDisableWriteTheSwitch()
    {
        var path = Path.Combine(_directory, "dns edit.jsonc");
        await File.WriteAllTextAsync(path, "{\n  // kept across edits\n  \"serverBaseUrl\": \"http://127.0.0.1:1\",\n"
            + "  \"apiKey\": \"key\",\n  \"secret\": \"secret\"\n}\n");
        var notice = EgressEdit.DnsEnableNotice.ToList();

        var (code, output, errors) = await Cli("egress", "dns", "enable", "--config", path);
        Assert.Equal(2, code);
        Assert.Equal([.. notice, "Not changed. Re-run with --yes to confirm."], errors.TrimEnd('\n').Split('\n'));
        Assert.DoesNotContain("peerEgressDnsTakeover", await File.ReadAllTextAsync(path), StringComparison.Ordinal);

        (code, output, _) = await Cli("egress", "dns", "enable", "--yes", "--config", path);
        Assert.Equal(0, code);
        Assert.Equal([.. notice, "Warning: peerEgressEnabled is false, so domain rules take effect only after egress enable.",
            $"Saved {path}. A running client applies the change after a restart.", "dns takeover: on (pool 198.18.0.0/15)"],
            output.TrimEnd('\n').Split('\n'));
        var text = await File.ReadAllTextAsync(path);
        Assert.Contains("\"peerEgressDnsTakeover\": true", text, StringComparison.Ordinal);
        Assert.Contains("// kept across edits", text, StringComparison.Ordinal);

        (code, output, _) = await Cli("egress", "dns", "disable", "--config", path, "--json");
        Assert.Equal(0, code);
        using var json = JsonDocument.Parse(output);
        var data = json.RootElement.GetProperty("data");
        Assert.Equal(["configPath", "dnsTakeover", "pool"], data.EnumerateObject().Select(field => field.Name));
        Assert.False(data.GetProperty("dnsTakeover").GetBoolean());
        Assert.Contains("\"peerEgressDnsTakeover\": false", await File.ReadAllTextAsync(path), StringComparison.Ordinal);

        // Said and written again whatever the file already holds: the notice is part of turning it on.
        (code, output, _) = await Cli("egress", "dns", "disable", "--config", path);
        Assert.Equal(0, code);
        Assert.Equal([$"Saved {path}. A running client applies the change after a restart.", "dns takeover: off"],
            output.TrimEnd('\n').Split('\n'));
        (code, _, errors) = await Cli("egress", "dns", "enable", "--config", path);
        Assert.Equal(2, code);
        (code, output, _) = await Cli("egress", "dns", "enable", "--yes", "--config", path);
        Assert.Equal(0, code);
        (code, output, _) = await Cli("egress", "dns", "enable", "--yes", "--config", path);
        Assert.Equal(0, code);
        Assert.Equal(notice, output.Split('\n').Take(4));
        Assert.EndsWith("dns takeover: on (pool 198.18.0.0/15)\n", output, StringComparison.Ordinal);

        var state = Path.Combine(_directory, "state");
        (code, output, _) = await Cli(["egress", "dns", "status", "--config", path], state);
        Assert.Equal(0, code);
        Assert.StartsWith("No running client for this config.\n", output, StringComparison.Ordinal);
    }

    /// <summary>Runs the built client; the state directory is a test's own, never the user's.</summary>
    private Task<(int Code, string Output, string Errors)> Cli(params string[] args) => Cli(args, Path.Combine(_directory, "state"));

    private async Task<(int Code, string Output, string Errors)> Cli(string[] args, string stateDirectory)
    {
        var start = new System.Diagnostics.ProcessStartInfo("dotnet")
        {
            WorkingDirectory = _directory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment["SPECUS_CLI_STATE_DIR"] = stateDirectory;
        // The journal is looked for under the home directory, which is the test's own here.
        start.Environment["HOME"] = _directory;
        start.Environment["USERPROFILE"] = _directory;
        start.ArgumentList.Add(typeof(Specus.Client.Control.SpecusControlClient).Assembly.Location);
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }
        using var process = System.Diagnostics.Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await process.WaitForExitAsync(timeout.Token);
        return (process.ExitCode, (await output).Replace("\r\n", "\n"), (await errors).Replace("\r\n", "\n"));
    }

    /// <summary>
    /// A PowerShell script whose exit code says success but whose stderr says otherwise has failed.
    /// Runs a harmless script that only writes to stderr, on Windows where PowerShell is.
    /// </summary>
    [Fact]
    public void PowerShellErrorsBehindAZeroExitAreFailures()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        var failure = Assert.Throws<PeerEgressDnsCommandException>(() => new PeerEgressDnsSystem().Run(
            PeerEgressDnsTakeoverRules.PowerShell("[Console]::Error.WriteLine('the rule was not added'); exit 0")));
        Assert.Equal("the rule was not added", PeerEgressDnsTakeover.FirstLine(failure));
        Assert.Equal("ok", new PeerEgressDnsSystem().Run(PeerEgressDnsTakeoverRules.PowerShell("Write-Output ok")).Trim());
    }

    [Fact]
    public void TheHelpStatesWhatDomainRulesCannotSee()
    {
        Assert.Contains("Domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect "
            + "to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules.", ClientCliOptions.HelpText, StringComparison.Ordinal);
        Assert.Equal("egress dns enable", ClientCliOptions.Parse(["egress", "dns", "enable", "--yes", "--config", "c.jsonc"]).Command);
        Assert.Throws<ArgumentException>(() => ClientCliOptions.Parse(["egress", "dns", "disable", "--yes"]));
    }

    /// <summary>
    /// The upstreams are set when the journal commits and kept after the DNS is given back, so a
    /// resolver pointed at the listen address by hand still forwards.
    /// </summary>
    [Fact]
    public void RecordedUpstreamsOutliveTheTakeover()
    {
        var takeover = Takeover(Resolved());
        Assert.Null(takeover.RecordedUpstreams);
        takeover.Engage(Request(), T0);
        takeover.Release("done");
        Assert.Null(takeover.HeldUpstreams);
        Assert.Equal(["1.1.1.1", "192.168.1.1"], takeover.RecordedUpstreams);
    }
}
