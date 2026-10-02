using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Specus.Client.Runtime;

namespace Specus.Client.Cli;

internal sealed class CliState : ISpecusClientObserver, IDisposable
{
    private readonly object _gate = new();
    private readonly string _config, _path;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _publisher;
    private string _phase = "http-login";
    private bool _authenticated, _ready;
    private object[] _peers = [], _services = [];

    /// <summary>
    /// Where the egress section comes from, set once the mesh exists.
    /// </summary>
    /// <remarks>
    /// Pulled at write time rather than pushed on change, unlike peers and services. Half of that
    /// section is live -- flow counts and refusal tallies -- and a pushed copy would be as old as
    /// the last mesh event, which on a quiet node is arbitrarily old.
    /// </remarks>
    internal Func<Dictionary<string, object?>>? EgressSource { get; set; }
    internal static string Root => Path.GetFullPath(Environment.GetEnvironmentVariable("SPECUS_CLI_STATE_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".specus-cli"));
    internal static string Prefix(string config) => "dotnet-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        OperatingSystem.IsWindows() ? config.ToLowerInvariant() : config))).ToLowerInvariant() + "-";

    internal CliState(string config)
    {
        _config = config;
        var root = EnsureRoot();
        _path = Path.Combine(root, Prefix(config) + Environment.ProcessId + ".json");
        Write();
        _publisher = PublishAsync();
    }
    internal static string EnsureRoot() => EnsureRoot(Root);

    internal static string EnsureRoot(string root)
    {
        if (!Directory.Exists(root))
        {
            if (OperatingSystem.IsWindows())
            {
                var security = new DirectorySecurity();
                var owner = WindowsIdentity.GetCurrent().User!;
                security.SetOwner(owner); security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(root).Create(security);
            }
            else Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        CheckPrivate(root);
        return root;
    }
    internal Dictionary<string, object> Snapshot()
    {
        lock (_gate) return new() { ["phase"] = _phase, ["controlAuthenticated"] = _authenticated,
            ["businessReady"] = _ready, ["peers"] = _authenticated ? _peers : [], ["services"] = _authenticated ? _services : [],
            ["egress"] = Egress() };
    }
    /// <summary>
    /// The egress section, or an empty object before the mesh exists.
    /// </summary>
    /// <remarks>
    /// Reported whether or not control is authenticated, unlike peers and services. Those describe
    /// what the server told us and are withheld until it has spoken; this describes this node's own
    /// configuration and its own routing table, which are facts about this machine either way.
    /// Withholding them would hide a rule that is not in force exactly when an operator is trying
    /// to find out why nothing works.
    ///
    /// <para>A source that throws must not take the state file with it: a status that stopped being
    /// published would cost an operator the peers and services sections too.</para>
    /// </remarks>
    private Dictionary<string, object?> Egress()
    {
        try
        {
            return EgressSource?.Invoke() ?? [];
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            return new Dictionary<string, object?> { ["error"] = error.Message };
        }
    }

    internal static void CheckPrivate(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("State must not be a link/reparse point");
        if (OperatingSystem.IsWindows())
        {
            FileSystemSecurity acl = Directory.Exists(path) ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
            var owner = WindowsIdentity.GetCurrent().User!;
            if (!owner.Equals(acl.GetOwner(typeof(SecurityIdentifier)))) throw new IOException("State owner mismatch");
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !owner.Equals(rule.IdentityReference)) throw new IOException("State must be owner-only");
        }
        else if ((File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0) throw new IOException("State must be owner-only; use chmod 700 for the directory, 600 for files");
    }
    // Call only for a new file in our already-private directory. Elevated Windows
    // tokens can otherwise assign Administrators as owner even with a private inherited DACL.
    internal static void ProtectNewFile(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var owner = WindowsIdentity.GetCurrent().User!; var acl = new FileSecurity();
            acl.SetOwner(owner); acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
        }
        CheckPrivate(path);
    }
    public void OnStatusChanged(SpecusClientStatusSnapshot snapshot)
    {
        lock (_gate) { _authenticated = snapshot.LoggedIn; _ready = snapshot.Phase == "RUNNING";
            _phase = _ready ? "ready" : _authenticated ? "control-authenticated" : snapshot.Phase == "HTTP_LOGIN" ? "http-login" : "connecting"; }
    }
    public void OnControlAuthenticated() { lock (_gate) { _phase = "control-authenticated"; _authenticated = true; _ready = false; } }
    public void OnPeerMeshChanged(SpecusPeerMeshSnapshot snapshot)
    {
        lock (_gate)
        {
            _peers = snapshot.Peers.Select(p => (object)new { clientName = p.ClientName, virtualIp = p.VirtualIp, online = p.Online }).ToArray();
            _services = snapshot.RemoteServices.Select(s => (object)new { publisher = s.PublisherClientName, name = s.Name,
                application = s.Application, accessTarget = s.AccessTarget is null ? "" : CliOutput.SafeUrl(s.AccessTarget), available = s.Openable }).ToArray();
        }
    }
    private void Write()
    {
        string json;
        lock (_gate) json = JsonSerializer.Serialize(new { schemaVersion = 1, configPath = _config, pid = Environment.ProcessId,
            processRunning = true, updatedAtUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), phase = _phase,
            controlAuthenticated = _authenticated, businessReady = _ready,
            businessReadinessScope = "control/data authenticated; target reachability not tested", peers = _authenticated ? _peers : [], services = _authenticated ? _services : [],
            egress = Egress() }, CliOutput.JsonOptions);
        var temporary = Path.Combine(Root, ".state-" + Guid.NewGuid().ToString("N"));
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var file = new FileStream(temporary, options))
            using (var writer = new StreamWriter(file, new UTF8Encoding(false))) writer.Write(json);
            ProtectNewFile(temporary);
            File.Move(temporary, _path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private async Task PublishAsync()
    {
        var failing = false;
        try
        {
            while (true)
            {
                await Task.Delay(1000, _stop.Token);
                failing = PublishOnce(Write, failing, Console.Error);
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>
    /// One publication, returning whether publishing is now failing. A failed write is no reason to
    /// stop: on Windows a reader holding the file open, or a virus scanner, makes the replace fail
    /// now and then, and giving up would leave every status query refused for the rest of the run.
    /// The failure is said once, with its reason, and so is the recovery.
    /// </summary>
    internal static bool PublishOnce(Action write, bool failing, TextWriter report)
    {
        try { write(); }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            if (!failing) report.WriteLine($"State publication failed ({error.GetType().Name}: {error.Message}); retrying every second, so status may be stale meanwhile.");
            return true;
        }
        if (failing) report.WriteLine("State publication recovered.");
        return false;
    }
    public void Dispose()
    {
        _stop.Cancel(); _publisher.GetAwaiter().GetResult(); _stop.Dispose();
        try { File.Delete(_path); } catch (IOException) { }
    }
    /// <summary>
    /// The state of every running client of this configuration that published within the last five
    /// seconds. Throws <see cref="IOException"/> or <see cref="UnauthorizedAccessException"/> when the
    /// state directory is not safe to read.
    /// </summary>
    internal static List<JsonElement> Fresh(string config)
    {
        var fresh = new List<JsonElement>();
        if (!Directory.Exists(Root)) return fresh;
        CheckPrivate(Root);
        var paths = Directory.GetFiles(Root, Prefix(config) + "*.json");
        if (paths.Length > 256) return fresh;
        foreach (var path in paths)
        {
            if (!File.Exists(path)) continue;
            CheckPrivate(path);
            if (new FileInfo(path).Length > 1024 * 1024) continue;
            try
            {
                using var file = JsonDocument.Parse(File.ReadAllText(path)); var data = file.RootElement;
                if (!string.Equals(data.GetProperty("configPath").GetString(), config,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) || FreshPid(data) is null) continue;
                fresh.Add(data.Clone());
            }
            catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or KeyNotFoundException or FileNotFoundException) { }
        }
        return fresh;
    }

    /// <summary>
    /// The process that published a state, when the state is fresh: format version 1, written in the
    /// last five seconds, by a process that is still alive; null otherwise. Throws as <see cref="JsonElement"/>
    /// and <see cref="Process.GetProcessById(int)"/> do for a state missing a field or naming no process.
    /// </summary>
    private static int? FreshPid(JsonElement data)
    {
        long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - data.GetProperty("updatedAtUnixMs").GetInt64();
        int pid = data.GetProperty("pid").GetInt32();
        if (age is < 0 or > 5000 || data.GetProperty("schemaVersion").GetInt32() != 1) return null;
        using var process = Process.GetProcessById(pid);
        return process.HasExited ? null : pid;
    }

    /// <summary>
    /// Whether a client runs as <paramref name="pid"/>: whether the state directory holds fresh state
    /// that process published, for any configuration and from any of the three runtimes, which share
    /// the directory.
    /// </summary>
    /// <remarks>
    /// It is what "the client that took over the system DNS still runs" means
    /// (protocol/spec/peer-egress-dns.md, section six, 事务日志): after a crash and a reboot a
    /// journal's process id most likely belongs to another program, and that program publishes no
    /// state here. A file that is not private is no evidence and is passed over; so is a directory
    /// that is missing or not safe.
    /// </remarks>
    internal static bool ClientRunning(int pid) => ClientRunning(pid, Root);

    internal static bool ClientRunning(int pid, string root)
    {
        if (pid <= 0) return false;
        try
        {
            if (!Directory.Exists(root)) return false;
            CheckPrivate(root);
            foreach (var path in Directory.GetFiles(root, "*.json"))
            {
                try
                {
                    CheckPrivate(path);
                    if (new FileInfo(path).Length > 1024 * 1024) continue;
                    using var file = JsonDocument.Parse(File.ReadAllText(path)); var data = file.RootElement;
                    // The id first: it costs nothing, and the process lookup is for the one that matches.
                    if (data.TryGetProperty("pid", out var id) && id.ValueKind == JsonValueKind.Number && id.TryGetInt32(out var published)
                        && published == pid && FreshPid(data) == pid) return true;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or ArgumentException
                    or InvalidOperationException or KeyNotFoundException or FormatException) { }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return false;
    }

    internal static int Query(string config, ClientCliOptions options)
    {
        try
        {
            var instances = new List<object>();
            foreach (var data in Fresh(config))
            {
                try
                {
                    if (options.Command == "status") instances.Add(data);
                    else instances.Add(new Dictionary<string, object> { ["pid"] = data.GetProperty("pid").GetInt32(), ["phase"] = data.GetProperty("phase").Clone(),
                        ["catalogAvailable"] = data.GetProperty("controlAuthenticated").Clone(), [options.Command] = data.GetProperty(options.Command).Clone() });
                }
                catch (Exception e) when (e is InvalidOperationException or KeyNotFoundException) { }
            }
            if (instances.Count == 0) return Missing();
            var result = new { instances };
            return CliOutput.Result(options.Json, options.Command, 0, result, CliOutput.StateSummary(options.Command, result));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        { return CliOutput.Result(options.Json, options.Command, 2, null, "Unsafe or unreadable local state. Use an owner-only local directory via SPECUS_CLI_STATE_DIR."); }
        int Missing() => CliOutput.Result(options.Json, options.Command, 5, new { instances = Array.Empty<object>() }, "No fresh running CLI state for this config. No login was attempted.");
    }
}
