using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Cli;

/// <summary>
/// <c>egress dns status</c> and <c>egress dns restore</c> (protocol/spec/peer-egress-dns.md, section
/// six, 命令). Neither needs the client to be running: the status reads the state file and the
/// journal, and the restore gives back what the journal describes. The pinned lines are written
/// exactly as the spec gives them, since the CLI matrix holds all three clients to them.
/// </summary>
internal static class EgressDns
{
    /// <summary>
    /// A command's exit code, its JSON data, the text a person reads, and lines for standard error
    /// that are not part of the result: warnings about somebody else's change, kept apart so the
    /// result reads the same in every runtime.
    /// </summary>
    internal readonly record struct Answer(int Code, object? Data, string Message, IReadOnlyList<string>? Warnings = null);

    internal static int Run(ClientCliOptions options, string configPath)
    {
        var answer = options.Command == "egress dns restore"
            ? Restore(options, PeerEgressDnsJournal.DefaultPath, new PeerEgressDnsSystem(), ProcessRunning)
            : Status(options, configPath, PeerEgressDnsJournal.DefaultPath, CliState.Fresh);
        foreach (var warning in answer.Warnings ?? [])
        {
            Console.Error.WriteLine("Warning: " + warning);
        }
        return CliOutput.Result(options.Json, options.Command, answer.Code, answer.Data, answer.Message);
    }

    /// <summary>Whether a process with that ID runs now. It may be another program that reused the ID; --force is for that.</summary>
    internal static bool ProcessRunning(int pid)
    {
        if (pid <= 0)
        {
            return false;
        }
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Gives back the takeover the journal describes: 0 when there was nothing to give back or it
    /// was all given back, 1 when the client that made it still runs (without --force) or a step
    /// failed, which is named.
    /// </summary>
    internal static Answer Restore(ClientCliOptions options, string journalPath, IPeerEgressDnsHost host, Func<int, bool> running)
    {
        PeerEgressDnsJournal? journal;
        try
        {
            journal = PeerEgressDnsJournal.Read(journalPath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return new Answer(1, new { journal = journalPath, restored = false },
                $"The DNS takeover journal at {journalPath} cannot be read ({error.Message}); it is kept as it is.");
        }
        if (journal is null)
        {
            return new Answer(0, new { journal = journalPath, restored = false },
                $"No DNS takeover journal at {journalPath}; there is nothing to restore.");
        }
        if (!options.Egress.Force && journal.Pid != Environment.ProcessId && running(journal.Pid))
        {
            return new Answer(1, new { journal = journalPath, restored = false, pid = journal.Pid },
                $"The client that took over the system DNS (PID {journal.Pid}) is still running, and gives it back itself when it stops. "
                + "Stop it, or set peerEgressDnsTakeover to false and restart it. --force skips this check, for when that PID now belongs to another process.");
        }
        var warnings = new Collector();
        var failure = PeerEgressDnsTakeover.Revert(host, journalPath, journal, warnings);
        if (failure is not null)
        {
            return new Answer(1,
                new { journal = journalPath, restored = false, platform = journal.Platform, pid = journal.Pid, step = failure, warnings = warnings.Lines },
                $"Giving the system DNS back failed at {failure}. The journal is kept; fix what the step reports and run egress dns restore again.",
                warnings.Lines);
        }
        return new Answer(0,
            new { journal = journalPath, restored = true, platform = journal.Platform, pid = journal.Pid, warnings = warnings.Lines },
            $"System DNS given back ({journal.Platform}, taken over by PID {journal.Pid}); journal removed.",
            warnings.Lines);
    }

    /// <summary>
    /// Whether the system's DNS is taken over, and why not; the upstreams, the journal, the mappings
    /// and how full the pool is. From the running client's state when there is one, and from the
    /// journal either way.
    /// </summary>
    internal static Answer Status(ClientCliOptions options, string configPath, string journalPath,
        Func<string, List<JsonElement>> fresh)
    {
        PeerEgressDnsJournal? journal = null;
        string? journalError = null;
        try
        {
            journal = PeerEgressDnsJournal.Read(journalPath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            journalError = error.Message;
        }
        List<JsonElement> states;
        try
        {
            states = fresh(configPath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return new Answer(2, null,
                "Unsafe or unreadable local state. Use an owner-only local directory via SPECUS_CLI_STATE_DIR.");
        }

        var lines = new List<string>();
        var instances = new List<object>();
        foreach (var state in states)
        {
            var pid = state.TryGetProperty("pid", out var id) && id.TryGetInt32(out var value) ? value : 0;
            var dns = Child(Child(Child(state, "egress"), "consumer"), "dns");
            instances.Add(new Dictionary<string, object?> { ["pid"] = pid, ["dns"] = dns });
            lines.AddRange(InstanceLines(pid, dns));
        }
        if (states.Count == 0)
        {
            lines.Add("No running client for this config.");
        }
        lines.Add(journal is null
            ? journalError is null
                ? "journal: none (the system DNS is not taken over)"
                : $"journal: unreadable ({journalError})"
            : $"journal: {journal.State} (PID {journal.Pid}, {journal.Platform}, upstreams {Join(journal.Upstreams)})"
              + (states.Count == 0 ? "; egress dns restore gives it back" : ""));
        var journalData = new Dictionary<string, object?>
        {
            ["path"] = journalPath,
            ["state"] = journal?.State ?? PeerEgressDnsJournal.StateNone,
        };
        if (journal is not null)
        {
            journalData["platform"] = journal.Platform;
            journalData["pid"] = journal.Pid;
            journalData["listen"] = journal.Listen;
            journalData["upstreams"] = journal.Upstreams;
        }
        if (journalError is not null)
        {
            journalData["error"] = journalError;
        }
        var data = new Dictionary<string, object?>
        {
            ["configPath"] = configPath,
            ["instances"] = instances,
            ["journal"] = journalData,
        };
        return new Answer(0, data, string.Join('\n', lines));
    }

    /// <summary>What a person reads about one running client: the takeover, why not, and how the pool is used.</summary>
    private static List<string> InstanceLines(int pid, JsonElement? dns)
    {
        if (dns is not { } section)
        {
            return [$"PID {pid} | DNS takeover: not configured (peerEgressDnsTakeover is off)"];
        }
        var code = Text(section, "code");
        string headline;
        if (Flag(section, "takeover"))
        {
            headline = $"on, system DNS points at {Text(section, "listen")}";
        }
        else if (!Flag(section, "active"))
        {
            headline = code.Length > 0 ? $"off, phase two is not running ({code})" : "off, phase two is not running";
        }
        else if (code.Length > 0)
        {
            var why = Text(section, "reason") is { Length: > 0 } reason ? reason : Text(section, "error");
            headline = $"off ({code}: {why})";
        }
        else
        {
            headline = "off, not taken over yet";
        }
        var lines = new List<string> { $"PID {pid} | DNS takeover: {headline}" };
        var upstreams = section.TryGetProperty("upstreams", out var list) && list.ValueKind == JsonValueKind.Array
            ? list.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()!).ToList()
            : [];
        lines.Add($"  upstreams: {(upstreams.Count == 0 ? "none" : string.Join(", ", upstreams))}");
        var mappings = Number(section, "mappings");
        var capacity = Capacity(Text(section, "pool"));
        // Formatted the same whatever the machine's culture: the output is read by scripts too.
        var used = (100.0 * mappings / Math.Max(capacity, 1)).ToString("0.0", CultureInfo.InvariantCulture);
        lines.Add(capacity > 0
            ? $"  mappings: {mappings} of {capacity} ({used}%), {Number(section, "quarantined")} resting"
            : $"  mappings: {mappings}, {Number(section, "quarantined")} resting");
        return lines;
    }

    /// <summary>How many addresses a pool can hand out: all but the network, listen and broadcast addresses.</summary>
    internal static long Capacity(string pool) =>
        Ipv4Cidr.TryParse(pool, out var cidr) && cidr.PrefixLength <= 30 ? (1L << (32 - cidr.PrefixLength)) - 3 : 0;

    private static string Join(IReadOnlyList<string> items) => items.Count == 0 ? "none" : string.Join(", ", items);

    private static JsonElement? Child(JsonElement? parent, string name) =>
        parent is { ValueKind: JsonValueKind.Object } present && present.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.Object
            ? value
            : null;

    private static bool Flag(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;

    private static string Text(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";

    private static long Number(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number)
            ? number
            : 0;

    /// <summary>Keeps what giving back warns about, to print with the result.</summary>
    private sealed class Collector : ILogger
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                Lines.Add(formatter(state, exception).Replace("[peer-egress-dns] ", "", StringComparison.Ordinal));
            }
        }
    }
}
