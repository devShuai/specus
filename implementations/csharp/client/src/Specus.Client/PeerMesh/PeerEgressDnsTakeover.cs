using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// What the system DNS takeover needs from the machine. Injected so the tests run every path of the
/// takeover against fakes; nothing in them may change the DNS of the machine they run on.
/// </summary>
internal interface IPeerEgressDnsHost
{
    /// <summary><c>linux</c>, <c>macos</c>, <c>windows</c>, or anything else, which is not supported.</summary>
    string Platform { get; }

    /// <summary>
    /// Runs a command line without a shell and returns what it printed. A command that fails throws
    /// <see cref="PeerEgressDnsCommandException"/> carrying what it printed.
    /// </summary>
    string Run(IReadOnlyList<string> argv);

    /// <summary>A file's text, or null when there is no such file.</summary>
    string? ReadFile(string path);

    void WriteFile(string path, string content);

    bool IsSymlink(string path);

    /// <summary>Whether a network interface of that name is there.</summary>
    bool LinkExists(string name);

    /// <summary>A network interface's index, or 0 when there is none of that name.</summary>
    long InterfaceIndex(string name);

    /// <summary>
    /// The IPv4 addresses of this machine's tunnel-type interfaces other than <paramref name="ownTunnel"/>:
    /// a system DNS server at one of them is some other tunnel's resolver.
    /// </summary>
    IReadOnlyList<string> TunnelInterfaceAddresses(string ownTunnel);

    /// <summary>The network as the change check compares it: the default route's interface and every local IPv4 address.</summary>
    string NetworkFingerprint(string ownTunnel);
}

/// <summary>A command that failed, with what it printed.</summary>
internal sealed class PeerEgressDnsCommandException(IReadOnlyList<string> argv, string output, string message)
    : IOException(message)
{
    public IReadOnlyList<string> Argv { get; } = argv;

    public string Output { get; } = output;
}

/// <summary>One macOS network service the takeover changed, with the DNS it had.</summary>
internal sealed record PeerEgressDnsService(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("servers")] IReadOnlyList<string> Servers);

/// <summary>
/// The record, on disk, of a takeover: everything needed to give it back after a crash
/// (protocol/spec/peer-egress-dns.md, section six, 事务日志).
/// </summary>
internal sealed record PeerEgressDnsJournal
{
    public const int CurrentVersion = 1;
    public const string StateNone = "none";
    public const string StatePending = "pending";
    public const string StateCommitted = "committed";

    [JsonPropertyName("version")] public int Version { get; init; } = CurrentVersion;
    [JsonPropertyName("state")] public string State { get; init; } = StatePending;
    [JsonPropertyName("platform")] public string Platform { get; init; } = string.Empty;
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("listen")] public string Listen { get; init; } = string.Empty;
    [JsonPropertyName("tunnel")] public string Tunnel { get; init; } = string.Empty;
    [JsonPropertyName("upstreams")] public IReadOnlyList<string> Upstreams { get; init; } = [];
    [JsonPropertyName("startedAtUnixMs")] public long StartedAtUnixMs { get; init; }

    /// <summary>The original <c>/etc/resolv.conf</c>, for <c>linux-resolvconf</c>.</summary>
    [JsonPropertyName("resolvConf")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ResolvConf { get; init; }

    /// <summary>The services changed and what each had, for <c>macos</c>.</summary>
    [JsonPropertyName("services")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<PeerEgressDnsService>? Services { get; init; }

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    /// <summary>Beside the route install record, in the same private directory.</summary>
    public static string DefaultPath => Path.Combine(Home(), ".specus", "egress-dns-journal.json");

    /// <summary>
    /// The user's home as the other clients find it: <c>USERPROFILE</c> on Windows and <c>HOME</c>
    /// elsewhere when set, the system's answer otherwise. .NET asks Windows directly and would
    /// otherwise look somewhere else than the Go client for the same user's journal.
    /// </summary>
    private static string Home()
    {
        var variable = Environment.GetEnvironmentVariable(OperatingSystem.IsWindows() ? "USERPROFILE" : "HOME");
        return string.IsNullOrWhiteSpace(variable) ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) : variable;
    }

    /// <summary>The journal, or null when there is none. One that cannot be read throws: it is the only record of what to put back.</summary>
    public static PeerEgressDnsJournal? Read(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }
        var journal = JsonSerializer.Deserialize<PeerEgressDnsJournal>(File.ReadAllText(path), Options)
                      ?? throw new InvalidDataException("the DNS takeover journal is empty");
        if (journal.Version != CurrentVersion)
        {
            throw new InvalidDataException($"the DNS takeover journal is version {journal.Version}, not {CurrentVersion}");
        }
        return journal;
    }

    /// <summary>
    /// Written the way the route install record is: to a private temporary file and renamed into
    /// place, so a crash mid-write cannot leave half a journal describing less than was done.
    /// </summary>
    public static void Write(string path, PeerEgressDnsJournal journal) =>
        SecretFileWriter.WriteSecret(path, JsonSerializer.Serialize(journal, Options) + "\n");

    public static void Delete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}

/// <summary>What the mesh asks for while phase two runs.</summary>
/// <param name="PoolRouteInstalled">
/// The pool's route is in the table. Without it nothing sent to a fake address reaches this feature,
/// the responder's own address included.
/// </param>
internal readonly record struct PeerEgressDnsTakeoverRequest(string Listen, string Tunnel, Ipv4Cidr Pool, Ipv4Cidr Mesh,
    bool PoolRouteInstalled)
{
    public string Key => $"{Listen}|{Tunnel}|{Pool}|{Mesh}";
}

/// <summary>What the status reports about the takeover.</summary>
/// <param name="Takeover">The system's DNS points at the responder now: the journal is committed.</param>
/// <param name="Code"><c>EGRESS_DNS_TAKEOVER_REFUSED</c> with a reason, or <c>EGRESS_DNS_TAKEOVER_FAILED</c> with an error.</param>
/// <param name="Journal"><c>none</c>, <c>pending</c> or <c>committed</c>.</param>
internal sealed record PeerEgressDnsTakeoverStatus(bool Takeover, string? Code, string? Reason, string? Error, string Journal)
{
    public static PeerEgressDnsTakeoverStatus Idle { get; } = new(false, null, null, null, PeerEgressDnsJournal.StateNone);
}

/// <summary>
/// Pointing the system's DNS at the responder, and putting it back (protocol/spec/peer-egress-dns.md,
/// section six).
/// </summary>
/// <remarks>
/// This is the one place the feature changes the user's system configuration, so it is built around
/// being able to undo itself from any point. The journal is written before anything is touched,
/// with everything giving back needs; the takeover is marked committed only when every step
/// succeeded; any failure runs the whole give-back, which is safe whatever part of the takeover
/// happened; and a journal found at start is given back before anything else, which is how a
/// killed process's takeover is undone. Giving back leaves alone what somebody else wrote after us.
///
/// <para>Not safe for concurrent use except for <see cref="Status"/>: the mesh drives it under its
/// plan lock.</para>
/// </remarks>
internal sealed class PeerEgressDnsTakeover
{
    /// <summary>How often the network is compared with the one the takeover was made on.</summary>
    internal const long NetworkCheckMs = 10_000;

    /// <summary>
    /// How long a refused or failed takeover waits before the system is read again, unless the
    /// network or the request changed first. Reading runs commands, and the answer seldom changes
    /// by itself between ticks.
    /// </summary>
    internal const long RetryMs = 60_000;

    public const string CodeRefused = "EGRESS_DNS_TAKEOVER_REFUSED";
    public const string CodeFailed = "EGRESS_DNS_TAKEOVER_FAILED";

    private readonly IPeerEgressDnsHost _host;
    private readonly string _path;
    private readonly ILogger? _logger;
    private readonly int _pid;
    private readonly object _statusGate = new();
    private PeerEgressDnsTakeoverStatus _status = PeerEgressDnsTakeoverStatus.Idle;

    private PeerEgressDnsJournal? _held;
    private string _attemptKey = "";
    private long _attemptAtMs;
    private string? _network;
    private long _networkAtMs;
    private string? _refusalLogged;

    public PeerEgressDnsTakeover(IPeerEgressDnsHost host, string journalPath, ILogger? logger = null, int? pid = null)
    {
        _host = host;
        _path = journalPath;
        _logger = logger;
        _pid = pid ?? Environment.ProcessId;
    }

    public PeerEgressDnsTakeoverStatus Status
    {
        get
        {
            lock (_statusGate)
            {
                return _status;
            }
        }
    }

    private void SetStatus(PeerEgressDnsTakeoverStatus status)
    {
        lock (_statusGate)
        {
            _status = status;
        }
    }

    /// <summary>The upstreams of the takeover in place, which the responder forwards to; null when none is.</summary>
    public IReadOnlyList<string>? HeldUpstreams => _held?.Upstreams;

    /// <summary>
    /// The upstreams of the last takeover this process committed, kept after it is given back: a
    /// user who points the DNS at the listen address by hand still has queries forwarded somewhere
    /// real. Null before any takeover committed.
    /// </summary>
    public IReadOnlyList<string>? RecordedUpstreams { get; private set; }

    /// <summary>
    /// Gives back a takeover a previous run left, pending or committed, before this run decides
    /// anything. A killed process never gave back; this is where it happens.
    /// </summary>
    public void RecoverLeftover()
    {
        PeerEgressDnsJournal? journal;
        try
        {
            journal = PeerEgressDnsJournal.Read(_path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            _logger?.LogWarning("[peer-egress-dns] takeover journal left in place, it cannot be read: {Error}", error.Message);
            SetStatus(new PeerEgressDnsTakeoverStatus(false, CodeFailed, null, FirstLine(error), PeerEgressDnsJournal.StatePending));
            return;
        }
        if (journal is null)
        {
            return;
        }
        if (Revert(_host, _path, journal, _logger) is { } failure)
        {
            _logger?.LogWarning(
                "[peer-egress-dns] system DNS left taken over by process {Pid} not given back; the journal stays for the next start or `egress dns restore`: {Error}",
                journal.Pid, failure);
            SetStatus(new PeerEgressDnsTakeoverStatus(false, CodeFailed, null, failure, journal.State));
            return;
        }
        _logger?.LogInformation("[peer-egress-dns] system DNS left taken over by process {Pid} given back", journal.Pid);
    }

    /// <summary>
    /// Takes the system's DNS over for a request, or keeps it. Called on every reconcile while
    /// phase two runs; a refusal or failure is tried again after <see cref="RetryMs"/>, or at once
    /// when the request changes.
    /// </summary>
    public void Engage(PeerEgressDnsTakeoverRequest request, long nowMs)
    {
        if (_held is { } held)
        {
            if (request.PoolRouteInstalled && held.Listen == request.Listen && held.Tunnel == request.Tunnel)
            {
                return;
            }
            // The pool's route went, or the responder moved: the system would be sending its
            // queries where nothing answers.
            Release("the pool's route or the listen address changed");
        }
        if (!request.PoolRouteInstalled)
        {
            // Checked every time without reading anything, so the takeover follows the route in.
            ForgetAttempt();
            Refuse(PeerEgressDnsTakeoverRules.RefusedPoolRoute);
            return;
        }
        if (request.Key == _attemptKey && nowMs >= _attemptAtMs && nowMs - _attemptAtMs < RetryMs)
        {
            return;
        }
        _attemptKey = request.Key;
        _attemptAtMs = nowMs;
        Attempt(request, nowMs);
    }

    /// <summary>Makes the next <see cref="Engage"/> try at once: what the last attempt found may no longer hold.</summary>
    public void ForgetAttempt()
    {
        _attemptKey = "";
        _attemptAtMs = 0;
    }

    /// <summary>
    /// Whether the network changed since the last reading, read at most every
    /// <see cref="NetworkCheckMs"/>. The first reading is the baseline.
    /// </summary>
    public bool NetworkChanged(string ownTunnel, long nowMs)
    {
        if (_network is not null && nowMs >= _networkAtMs && nowMs - _networkAtMs < NetworkCheckMs)
        {
            return false;
        }
        string current;
        try
        {
            current = _host.NetworkFingerprint(ownTunnel);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return false;
        }
        _networkAtMs = nowMs;
        var previous = _network;
        _network = current;
        return previous is not null && previous != current;
    }

    /// <summary>
    /// Gives back the takeover in place, if there is one. Nothing is refused or failed by that, so
    /// the status keeps no code, unless giving back itself failed.
    /// </summary>
    public void Release(string why)
    {
        if (_held is not { } journal)
        {
            return;
        }
        _held = null;
        // Whatever let go of it, the next engage takes over again at once rather than waiting out
        // the interval of an attempt that succeeded.
        ForgetAttempt();
        if (Revert(_host, _path, journal, _logger) is { } failure)
        {
            // Kept, and so is the knowledge that it is: the next start, or the command, tries
            // again. Pretending it was given back would lose the only record of what to restore.
            _logger?.LogWarning("[peer-egress-dns] system DNS not fully given back ({Why}); the journal stays: {Error}", why, failure);
            SetStatus(new PeerEgressDnsTakeoverStatus(false, CodeFailed, null, failure, journal.State));
            return;
        }
        _logger?.LogInformation("[peer-egress-dns] system DNS given back ({Why})", why);
        SetStatus(PeerEgressDnsTakeoverStatus.Idle);
    }

    /// <summary>
    /// The takeover while phase two is not running: nothing held, nothing to report, except a
    /// give-back that failed and left its journal behind.
    /// </summary>
    public void Idle(string why)
    {
        Release(why);
        var status = Status;
        if (!(status.Code == CodeFailed && status.Journal != PeerEgressDnsJournal.StateNone))
        {
            SetStatus(PeerEgressDnsTakeoverStatus.Idle);
        }
        ForgetAttempt();
        _refusalLogged = null;
    }

    private void Refuse(string reason)
    {
        if (_refusalLogged != reason)
        {
            _refusalLogged = reason;
            _logger?.LogWarning("[peer-egress-dns] system DNS not taken over: {Reason}; the responder answers whoever is pointed at it",
                reason);
        }
        SetStatus(new PeerEgressDnsTakeoverStatus(false, CodeRefused, reason, null, PeerEgressDnsJournal.StateNone));
    }

    private void Fail(string error, string journal)
    {
        _refusalLogged = null;
        SetStatus(new PeerEgressDnsTakeoverStatus(false, CodeFailed, null, error, journal));
    }

    /// <summary>Reads the system, decides, and takes over.</summary>
    private void Attempt(PeerEgressDnsTakeoverRequest request, long nowMs)
    {
        // A journal still on disk is a give-back that failed. It is the only record of what the
        // system had, so it is given back first and never written over.
        PeerEgressDnsJournal? leftover;
        try
        {
            leftover = PeerEgressDnsJournal.Read(_path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            Fail("the takeover journal cannot be read: " + FirstLine(error), PeerEgressDnsJournal.StatePending);
            return;
        }
        if (leftover is not null && Revert(_host, _path, leftover, _logger) is { } leftoverFailure)
        {
            Fail("an earlier takeover is still to be given back: " + leftoverFailure, leftover.State);
            return;
        }

        var journal = new PeerEgressDnsJournal
        {
            Pid = _pid,
            Listen = request.Listen,
            Tunnel = request.Tunnel,
            StartedAtUnixMs = nowMs,
        };
        string? reason;
        List<string>? servers;
        try
        {
            (journal, servers, reason) = ReadSystem(journal);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException
                                          or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _logger?.LogWarning("[peer-egress-dns] system DNS not taken over, reading it failed: {Error}", FirstLine(error));
            Fail(FirstLine(error), PeerEgressDnsJournal.StateNone);
            return;
        }
        List<string>? upstreams = null;
        if (reason is null)
        {
            (upstreams, reason) = PeerEgressDnsTakeoverRules.ClassifyUpstreams(servers!,
                [.. _host.TunnelInterfaceAddresses(request.Tunnel)], request.Pool, request.Mesh);
        }
        if (reason is not null)
        {
            Refuse(reason);
            return;
        }
        journal = journal with { Upstreams = upstreams! };

        // Written before anything is changed: whatever happens from here, the record of what to
        // put back is on disk first.
        try
        {
            PeerEgressDnsJournal.Write(_path, journal);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("[peer-egress-dns] system DNS not taken over, the journal could not be written: {Error}", error.Message);
            Fail(FirstLine(error), PeerEgressDnsJournal.StateNone);
            return;
        }
        SetStatus(new PeerEgressDnsTakeoverStatus(false, null, null, null, PeerEgressDnsJournal.StatePending));

        var plan = PeerEgressDnsTakeoverRules.Plan(journal.Platform, journal.Listen, journal.Tunnel,
            journal.Services?.Select(service => service.Name).ToList())!;
        string? failure = null;
        foreach (var step in plan.Apply)
        {
            try
            {
                RunStep(_host, step);
            }
            catch (Exception error) when (IsStepFailure(error))
            {
                failure = FirstLine(error);
                break;
            }
        }
        if (failure is null)
        {
            journal = journal with { State = PeerEgressDnsJournal.StateCommitted };
            try
            {
                PeerEgressDnsJournal.Write(_path, journal);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                failure = "recording the takeover as done: " + FirstLine(error);
            }
        }
        if (failure is not null)
        {
            // The whole give-back, whatever part of the takeover happened: it is safe from any point.
            _logger?.LogWarning("[peer-egress-dns] system DNS takeover failed, giving back: {Error}", failure);
            var state = PeerEgressDnsJournal.StateNone;
            if (Revert(_host, _path, journal, _logger) is { } revertFailure)
            {
                _logger?.LogWarning("[peer-egress-dns] giving back the failed takeover failed too; the journal stays: {Error}", revertFailure);
                state = journal.State;
            }
            Fail(failure, state);
            return;
        }
        _held = journal;
        RecordedUpstreams = journal.Upstreams;
        _refusalLogged = null;
        SetStatus(new PeerEgressDnsTakeoverStatus(true, null, null, null, PeerEgressDnsJournal.StateCommitted));
        // Said every time, as egress enable says it: this is the one change to the system's own
        // configuration, and the person running the client should never have to discover it.
        _logger?.LogWarning(
            "[peer-egress-dns] system DNS now points at {Listen} ({Platform}), forwarding to {Upstreams}; it is given back when the client stops, or by `egress dns restore`",
            journal.Listen, journal.Platform, string.Join(", ", journal.Upstreams));
    }

    /// <summary>
    /// Reads the platform's DNS: the servers the upstreams come from and what giving back will need
    /// (into the journal), or the reason the takeover is refused. A read that fails throws.
    /// </summary>
    private (PeerEgressDnsJournal Journal, List<string>? Servers, string? Reason) ReadSystem(PeerEgressDnsJournal journal)
    {
        switch (_host.Platform)
        {
            case "linux":
            {
                string? resolvectl = null;
                try
                {
                    resolvectl = _host.Run(["resolvectl", "dns"]);
                }
                catch (Exception error) when (IsStepFailure(error))
                {
                    // Not running, or not installed: /etc/resolv.conf is what applications use.
                }
                var conf = _host.ReadFile(PeerEgressDnsTakeoverRules.ResolvConfPath) ?? string.Empty;
                var symlink = _host.IsSymlink(PeerEgressDnsTakeoverRules.ResolvConfPath);
                var (mode, reason) = PeerEgressDnsTakeoverRules.LinuxMode(resolvectl is not null,
                    PeerEgressDnsTakeoverRules.ParseResolvConf(conf), symlink);
                if (reason is not null)
                {
                    return (journal, null, reason);
                }
                if (mode == PeerEgressDnsTakeoverRules.PlatformResolved)
                {
                    return (journal with { Platform = mode }, PeerEgressDnsTakeoverRules.ParseResolvectl(resolvectl, journal.Tunnel), null);
                }
                return (journal with { Platform = mode!, ResolvConf = conf }, PeerEgressDnsTakeoverRules.ParseResolvConf(conf), null);
            }
            case "macos":
            {
                var services = new List<PeerEgressDnsService>();
                foreach (var service in PeerEgressDnsTakeoverRules.ParseMacServices(
                             _host.Run(["networksetup", "-listallnetworkservices"])))
                {
                    services.Add(new PeerEgressDnsService(service,
                        PeerEgressDnsTakeoverRules.ParseMacDnsServers(_host.Run(["networksetup", "-getdnsservers", service]))));
                }
                var servers = PeerEgressDnsTakeoverRules.ParseScutil(_host.Run(["scutil", "--dns"]));
                return (journal with { Platform = PeerEgressDnsTakeoverRules.PlatformMacos, Services = services }, servers, null);
            }
            case "windows":
            {
                if (PeerEgressDnsTakeoverRules.ParseWindowsNrpt(
                        _host.Run(PeerEgressDnsTakeoverRules.PowerShell(PeerEgressDnsTakeoverRules.WindowsReadNrpt))))
                {
                    return (journal, null, PeerEgressDnsTakeoverRules.RefusedNrptRoot);
                }
                // The tunnel's own index, so its server -- the responder -- is not read back as an upstream.
                var servers = PeerEgressDnsTakeoverRules.ParseWindowsServers(
                    _host.Run(PeerEgressDnsTakeoverRules.PowerShell(PeerEgressDnsTakeoverRules.WindowsReadServers)),
                    _host.InterfaceIndex(journal.Tunnel));
                return (journal with { Platform = PeerEgressDnsTakeoverRules.PlatformWindows }, servers, null);
            }
            default:
                return (journal, null, PeerEgressDnsTakeoverRules.RefusedUnsupported);
        }
    }

    private static void RunStep(IPeerEgressDnsHost host, PeerEgressDnsStep step)
    {
        if (step.Write is { } path)
        {
            host.WriteFile(path, step.Content ?? string.Empty);
            return;
        }
        host.Run(step.Argv!);
    }

    private static bool IsStepFailure(Exception error) =>
        error is IOException or UnauthorizedAccessException or InvalidOperationException
            or System.ComponentModel.Win32Exception;

    /// <summary>
    /// Gives a takeover back as its journal describes, and deletes the journal when every step
    /// succeeded; null then, otherwise the first step that failed and why. Every step is tried even
    /// after one fails, so as much is given back as can be, and the journal is kept for another
    /// try. Somebody else's change is kept, with a warning: a resolv.conf that no longer holds what
    /// we wrote, a macOS service that no longer points at the responder alone.
    /// </summary>
    public static string? Revert(IPeerEgressDnsHost host, string path, PeerEgressDnsJournal journal, ILogger? logger)
    {
        var plan = PeerEgressDnsTakeoverRules.Plan(journal.Platform, journal.Listen, journal.Tunnel,
            journal.Services?.Select(service => service.Name).ToList());
        if (plan is null)
        {
            return $"the journal names platform '{journal.Platform}', which this client cannot give back";
        }
        string? failed = null;
        foreach (var step in plan.Revert)
        {
            var what = Describe(step);
            try
            {
                if (step.Restore is { } file)
                {
                    var (restore, warning) = PeerEgressDnsTakeoverRules.RevertResolvConf(host.ReadFile(file));
                    if (restore)
                    {
                        host.WriteFile(file, journal.ResolvConf ?? string.Empty);
                    }
                    else
                    {
                        logger?.LogWarning("[peer-egress-dns] {File} was changed by someone else during the takeover and is kept as it is ({Warning})",
                            file, warning);
                    }
                }
                else if (step.RestoreService is { } service)
                {
                    var original = journal.Services?.FirstOrDefault(entry => entry.Name == service)?.Servers
                                   ?? [PeerEgressDnsTakeoverRules.MacEmpty];
                    var current = PeerEgressDnsTakeoverRules.ParseMacDnsServers(host.Run(["networksetup", "-getdnsservers", service]));
                    var (command, warning) = PeerEgressDnsTakeoverRules.RevertMacService(service, current, original, journal.Listen);
                    if (command is null)
                    {
                        logger?.LogWarning("[peer-egress-dns] the DNS of {Service} was changed by someone else during the takeover and is kept as it is ({Warning})",
                            service, warning);
                        continue;
                    }
                    what = string.Join(' ', command);
                    host.Run(command);
                }
                else
                {
                    var argv = step.Argv!;
                    if (journal.Platform == PeerEgressDnsTakeoverRules.PlatformResolved && argv.Count > 2 && argv[1] == "revert"
                        && !host.LinkExists(journal.Tunnel))
                    {
                        // Link settings live and die with the link: with the tunnel gone there is
                        // nothing left to revert, and asking resolvectl about a link it cannot find
                        // would keep the journal forever.
                        continue;
                    }
                    host.Run(argv);
                }
            }
            catch (Exception error) when (IsStepFailure(error))
            {
                failed ??= what + ": " + FirstLine(error);
            }
        }
        if (failed is not null)
        {
            return failed;
        }
        try
        {
            PeerEgressDnsJournal.Delete(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return "delete " + path + ": " + FirstLine(error);
        }
        return null;
    }

    private static string Describe(PeerEgressDnsStep step) =>
        step.Argv is { } argv ? string.Join(' ', argv)
        : step.Write is { } write ? "write " + write
        : step.Restore is { } restore ? "restore " + restore
        : "restore " + step.RestoreService;

    /// <summary>
    /// The line a failure is reported by: the first line a command printed, which usually says why,
    /// or the error's own message when it printed nothing.
    /// </summary>
    internal static string FirstLine(Exception error)
    {
        var text = error is PeerEgressDnsCommandException command && command.Output.Trim().Length > 0
            ? command.Output
            : error.Message;
        return text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n')
            .Select(line => line.Trim()).FirstOrDefault(line => line.Length > 0) ?? error.GetType().Name;
    }
}
