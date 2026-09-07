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
    internal static string Root => Path.GetFullPath(Environment.GetEnvironmentVariable("SPECUS_CLI_STATE_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".specus-cli"));
    internal static string Prefix(string config) => "dotnet-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        OperatingSystem.IsWindows() ? config.ToLowerInvariant() : config))).ToLowerInvariant() + "-";

    internal CliState(string config)
    {
        _config = config;
        var root = Root;
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
        _path = Path.Combine(root, Prefix(config) + Environment.ProcessId + ".json");
        Write();
        _publisher = PublishAsync();
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
            businessReadinessScope = "control/data authenticated; target reachability not tested", peers = _authenticated ? _peers : [], services = _authenticated ? _services : [] }, CliOutput.JsonOptions);
        var temporary = Path.Combine(Root, ".state-" + Guid.NewGuid().ToString("N"));
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var file = new FileStream(temporary, options))
            using (var writer = new StreamWriter(file, new UTF8Encoding(false))) writer.Write(json);
            File.Move(temporary, _path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private async Task PublishAsync()
    {
        try { while (true) { await Task.Delay(1000, _stop.Token); Write(); } }
        catch (OperationCanceledException) { }
        catch (Exception) { Console.Error.WriteLine("State publication failed; status will become stale."); }
    }
    public void Dispose()
    {
        _stop.Cancel(); _publisher.GetAwaiter().GetResult(); _stop.Dispose();
        try { File.Delete(_path); } catch (IOException) { }
    }
    internal static int Query(string config, ClientCliOptions options)
    {
        try
        {
            if (!Directory.Exists(Root)) return Missing();
            CheckPrivate(Root);
            var paths = Directory.GetFiles(Root, Prefix(config) + "*.json");
            if (paths.Length > 256) return Missing();
            var instances = new List<object>();
            foreach (var path in paths)
            {
                if (!File.Exists(path)) continue;
                CheckPrivate(path);
                if (new FileInfo(path).Length > 1024 * 1024) continue;
                try
                {
                    using var file = JsonDocument.Parse(File.ReadAllText(path)); var data = file.RootElement;
                    long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - data.GetProperty("updatedAtUnixMs").GetInt64();
                    int pid = data.GetProperty("pid").GetInt32();
                    if (age is < 0 or > 5000 || !string.Equals(data.GetProperty("configPath").GetString(),config,
                        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) || data.GetProperty("schemaVersion").GetInt32() != 1) continue;
                    using var process = Process.GetProcessById(pid); if (process.HasExited) continue;
                    if (options.Command == "status") instances.Add(data.Clone());
                    else instances.Add(new Dictionary<string, object> { ["pid"] = pid, ["phase"] = data.GetProperty("phase").Clone(),
                        ["catalogAvailable"] = data.GetProperty("controlAuthenticated").Clone(), [options.Command] = data.GetProperty(options.Command).Clone() });
                }
                catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or KeyNotFoundException or FileNotFoundException) { }
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
