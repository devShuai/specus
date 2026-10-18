using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit.Abstractions;

namespace Specus.IntegrationTests;

// Actual server entry points and OS processes, not WebApplicationFactory hosts.
// All state belongs to this fixture. Keep it (including failure logs) for inspection.
internal sealed class OwnerTransferProcessFixture(ITestOutputHelper output) : IAsyncDisposable
{
    internal string DirectoryPath { get; } = CreateDirectoryPath();
    internal string ConnectionString => $"Data Source={Path.Combine(DirectoryPath, "shared.db")};Pooling=False";
    private readonly List<Node> _nodes = [];

    private static string CreateDirectoryPath()
    {
        var parent = Environment.GetEnvironmentVariable("SPECUS_PROCESS_TEST_ARTIFACT_DIR");
        return string.IsNullOrWhiteSpace(parent)
            ? Directory.CreateTempSubdirectory("specus-owner-process-").FullName
            : Directory.CreateDirectory(Path.Combine(parent, "specus-owner-process-" + Guid.NewGuid().ToString("N"))).FullName;
    }

    internal async Task<Node> StartAsync(string label)
    {
        var http = FreePort();
        var control = FreePort();
        while (control == http) control = FreePort();
        var dll = Path.Combine(AppContext.BaseDirectory, "Specus.Server.dll");
        Assert.True(File.Exists(dll), "the referenced server entry point must be built/copied");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet")
        {
            WorkingDirectory = DirectoryPath, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var key in start.Environment.Keys.Where(k => k.StartsWith("SPECUS", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("ConnectionStrings", StringComparison.OrdinalIgnoreCase)
            || k.StartsWith("ASPNETCORE", StringComparison.OrdinalIgnoreCase)
            || k.Equals("DOTNET_ENVIRONMENT", StringComparison.OrdinalIgnoreCase)
            || k.Equals("DOTNET_STARTUP_HOOKS", StringComparison.OrdinalIgnoreCase)).ToArray())
            start.Environment.Remove(key);
        // Specus:Env controls product defaults; the ASP.NET host environment is
        // independently production by default and correctly rejects plaintext.
        // This fixture is loopback-only development, not a production TLS claim.
        start.Environment["DOTNET_ENVIRONMENT"] = "Development";
        foreach (var argument in new[] { dll, $"--urls=http://127.0.0.1:{http}",
            $"--ConnectionStrings:Specus={ConnectionString}", "--Specus:Database:Provider=sqlite",
            "--Specus:Database:SeedDemoClient=false", "--Specus:Env=dev",
            $"--Specus:Netty:Port={control}", "--Specus:Netty:BindAddress=127.0.0.1",
            "--Specus:PeerMesh:Enabled=true", "--Specus:PeerMesh:StunTurnPort=0",
            "--Specus:Auth:Username=process-admin", "--Specus:Auth:Password=process-fixture-admin-password",
            "--Specus:Auth:JwtSecret=process-fixture-signing-key-not-production-20261017-0123456789",
            "--Specus:Auth:RegistrationEnabled=false", "--Logging:LogLevel:Default=Warning",
            "--Specus:ClientPackages:GithubReleaseFallbackEnabled=false" }) start.ArgumentList.Add(argument);
        var process = Process.Start(start) ?? throw new InvalidOperationException("server process did not start");
        var node = new Node(process, http, control, DirectoryPath, label);
        _nodes.Add(node);
        output.WriteLine("Owned node {0}: PID={1}, HTTP={2}, CONTROL={3}, evidence={4}", label, process.Id, http, control, DirectoryPath);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (true)
            {
                Assert.False(process.HasExited, "owned server exited before readiness");
                try
                {
                    using var response = await node.Http.GetAsync("/health", deadline.Token);
                    if (response.IsSuccessStatusCode) return node;
                }
                catch (HttpRequestException) { }
                await Task.Delay(20, deadline.Token);
            }
        }
        catch
        {
            await node.StopAsync();
            output.WriteLine(await File.ReadAllTextAsync(node.LogPath));
            throw;
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start(); return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public async ValueTask DisposeAsync()
    {
        var failures = new List<Exception>();
        foreach (var node in _nodes)
        {
            try { await node.StopAsync(); } catch (Exception error) { failures.Add(error); }
            finally { node.Http.Dispose(); }
        }
        output.WriteLine("All owned server processes stopped. Evidence retained: {0}", DirectoryPath);
        if (failures.Count > 0) throw new AggregateException("owned process cleanup failed", failures);
    }

    internal sealed class Node
    {
        internal Process Process { get; }
        internal HttpClient Http { get; }
        internal int ControlPort { get; }
        internal string LogPath { get; }
        private readonly Task<string> _stdout;
        private readonly Task<string> _stderr;
        private bool _stopped;
        internal Node(Process process, int http, int control, string directory, string label)
        {
            Process = process; ControlPort = control;
            Http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{http}"), Timeout = TimeSpan.FromSeconds(10) };
            LogPath = Path.Combine(directory, label + ".log");
            _stdout = process.StandardOutput.ReadToEndAsync(); _stderr = process.StandardError.ReadToEndAsync();
        }
        internal async Task StopAsync()
        {
            if (_stopped) return;
            if (!Process.HasExited) Process.Kill(entireProcessTree: true);
            await Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await File.WriteAllTextAsync(LogPath, (await _stdout) + "\nSTDERR:\n" + (await _stderr), Encoding.UTF8);
            _stopped = true; Process.Dispose();
        }
    }
}
