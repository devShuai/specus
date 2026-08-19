using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Nat;

namespace Specus.IntegrationTests;

/// <summary>
/// Spin up the C# server on a random TCP port + ephemeral SQLite, then drive the actual
/// Java specus-client jar against it. The HMAC handshake, framing, and idle/heartbeat all
/// run end-to-end through real Java code on the client side and real .NET code on the
/// server — the strongest protocol-parity assertion we can make at this phase.
/// </summary>
public sealed class JavaClientControlChannelTests : IAsyncLifetime
{
    private static readonly string RepoRoot = LocateRepoRoot();
    private static readonly string ClientJar = Path.Combine(RepoRoot,
        "implementations", "java", "client", "target", "specus-client-1.0.0-SNAPSHOT-exec.jar");

    private TestServerFixture? _server;
    private ClientAuthStub? _authStub;
    private string? _clientWorkDir;
    private Process? _clientProcess;
    private string? _javaExecutable;
    private string? _javaHome;
    private bool _skipped;

    public async Task InitializeAsync()
    {
        // Skip-mark: if the client jar isn't built we don't fail the suite — print and bail.
        // CI is expected to run `mvn -pl :specus-client -am package -DskipTests` before the
        // .NET tests so this branch only triggers in local dev where someone forgot.
        if (!File.Exists(ClientJar))
        {
            _skipped = true;
            return;
        }

        (_javaExecutable, _javaHome) = ResolveJava();
        if (_javaExecutable is null)
        {
            _skipped = true;
            return;
        }

        _server = await TestServerFixture.StartAsync();
        _authStub = ClientAuthStub.Start(_server);

        _clientWorkDir = Directory.CreateTempSubdirectory("specus-client-it-").FullName;
        var configPath = Path.Combine(_clientWorkDir, "client.jsonc");
        File.WriteAllText(configPath, JsonSerializer.Serialize(new
        {
            serverBaseUrl = _authStub.ServerBaseUrl,
            apiKey = DatabaseInitializer.DemoCredentialApiKey,
            secret = DatabaseInitializer.DemoCredentialSecret,
        }));
    }

    public async Task DisposeAsync()
    {
        if (_clientProcess is { HasExited: false })
        {
            try { _clientProcess.Kill(entireProcessTree: true); } catch { /* already gone */ }
            try { await _clientProcess.WaitForExitAsync(); } catch { /* same */ }
        }
        _clientProcess?.Dispose();

        if (_clientWorkDir is not null && Directory.Exists(_clientWorkDir))
        {
            try { Directory.Delete(_clientWorkDir, recursive: true); } catch { /* ignore */ }
        }
        if (_authStub is not null)
        {
            await _authStub.DisposeAsync();
        }
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task JavaClient_LoginsSuccessfullyAndStaysConnectedAcrossHeartbeats()
    {
        if (_skipped)
        {
            return;
        }
        Assert.NotNull(_server);
        Assert.NotNull(_clientWorkDir);

        _clientProcess = StartClient();

        // Wait up to 30s for the audit row to land with success=true. The Java client opens
        // the TCP connection, sends the LoginRequest immediately, and our server writes the
        // ConnectionRecord row right after AuthenticateAsync resolves.
        var record = await WaitForRecordAsync(success: true, TimeSpan.FromSeconds(30));
        Assert.True(record.Success);
        Assert.Equal(DatabaseInitializer.DemoClientName, record.ClientName);
        Assert.Null(record.DisconnectedAt);
        Assert.Null(record.DisconnectReason);

        // Stay alive long enough that the Java client's 5-second client-side heartbeats and
        // our 30-second writer-idle and 60-second reader-idle all get exercised. 70s is
        // enough to confirm the connection survives at least one full reader-idle window.
        await Task.Delay(TimeSpan.FromSeconds(70));

        // Re-read to confirm the row is still open — no IDLE_TIMEOUT, no protocol violation.
        var stillOpen = await GetLatestRecordAsync();
        Assert.NotNull(stillOpen);
        Assert.True(stillOpen!.Success);
        Assert.Null(stillOpen.DisconnectedAt);

        // Tear the client down cleanly.
        _clientProcess.Kill(entireProcessTree: true);
        await _clientProcess.WaitForExitAsync();

        // Audit row should now be stamped — most likely IO_ERROR or CLIENT_CLOSED depending
        // on which side's read sees EOF first. Both are acceptable as "connection ended".
        var closed = await WaitForDisconnectAsync(stillOpen.Id, TimeSpan.FromSeconds(15));
        Assert.NotNull(closed.DisconnectedAt);
        Assert.NotNull(closed.DisconnectReason);
    }

    [Fact(Timeout = 120_000)]
    public async Task JavaClient_RegistersTcpSpecusAndEchoesTraffic()
    {
        if (_skipped)
        {
            return;
        }
        Assert.NotNull(_server);
        Assert.NotNull(_clientWorkDir);

        await using var echo = await EchoServer.StartAsync();
        var remotePort = GetFreeTcpPort();
        await SeedSpecusMappingAsync(remotePort, echo.Port);

        _clientProcess = StartClient();

        var record = await WaitForRecordAsync(success: true, TimeSpan.FromSeconds(30));
        Assert.True(record.Success);

        var payload = Encoding.UTF8.GetBytes("phase3-echo-through-java-client");
        var echoed = await SendAndReceiveAsync(remotePort, payload, TimeSpan.FromSeconds(30));
        Assert.Equal(payload, echoed);
        await FlushTrafficAndAssertAsync(payload.Length);
    }

    private Process StartClient()
    {
        var psi = new ProcessStartInfo
        {
            FileName = _javaExecutable!,
            WorkingDirectory = _clientWorkDir!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        if (_javaHome is not null)
        {
            psi.Environment["JAVA_HOME"] = _javaHome;
        }
        psi.ArgumentList.Add("-Dlogging.level.com.theshuai=info");
        // The Java specus-client embeds a Spring Boot Tomcat fixed at 8087. Two integration
        // tests running in parallel both try to bind that port and the loser dies with
        // "APPLICATION FAILED TO START". Pin to ephemeral so any number of jars coexist.
        psi.ArgumentList.Add("-Dserver.port=0");
        psi.ArgumentList.Add("-jar");
        psi.ArgumentList.Add(ClientJar);

        var process = Process.Start(psi)
            ?? throw new InvalidOperationException("failed to start java client process");

        // Pipe child output to xUnit-visible writers so test failures show what the client did.
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine($"[client] {e.Data}"); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine($"[client!] {e.Data}"); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private async Task<ConnectionRecordView> WaitForRecordAsync(bool success, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var record = await GetLatestRecordAsync();
            if (record is not null && record.Success == success)
            {
                return record;
            }
            await Task.Delay(500);
        }
        throw new TimeoutException($"no connection record with success={success} appeared within {timeout}");
    }

    private async Task<ConnectionRecordView> WaitForDisconnectAsync(long recordId, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            using var scope = _server!.HostServices.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.ConnectionRecords.AsNoTracking().FirstOrDefaultAsync(r => r.Id == recordId);
            if (row is { DisconnectedAt: not null })
            {
                return new ConnectionRecordView(row.Id, row.ClientName, row.Success,
                    row.DisconnectedAt, row.DisconnectReason);
            }
            await Task.Delay(250);
        }
        throw new TimeoutException("connection record never closed");
    }

    private async Task<ConnectionRecordView?> GetLatestRecordAsync()
    {
        using var scope = _server!.HostServices.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var row = await db.ConnectionRecords
            .AsNoTracking()
            .OrderByDescending(r => r.Id)
            .FirstOrDefaultAsync();
        return row is null ? null
            : new ConnectionRecordView(row.Id, row.ClientName, row.Success,
                row.DisconnectedAt, row.DisconnectReason);
    }

    private async Task SeedSpecusMappingAsync(int listenPort, int targetPort)
    {
        using var scope = _server!.HostServices.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.SingleAsync(a => a.ClientName == DatabaseInitializer.DemoClientName);
        var now = DateTimeOffset.UtcNow;
        db.SpecusMappings.Add(new SpecusMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            ListenPort = listenPort,
            TargetAddress = "127.0.0.1",
            TargetPort = targetPort,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    private async Task FlushTrafficAndAssertAsync(int minimumBytes)
    {
        using var scope = _server!.HostServices.CreateScope();
        var traffic = scope.ServiceProvider.GetRequiredService<TrafficUsageService>();
        await traffic.FlushAsync(CancellationToken.None);

        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var row = await db.TrafficUsages.AsNoTracking().SingleOrDefaultAsync();
        Assert.NotNull(row);
        Assert.True(row!.UploadBytes >= minimumBytes);
        Assert.True(row.DownloadBytes >= minimumBytes);
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task<byte[]> SendAndReceiveAsync(int port, byte[] payload, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        Exception? lastError = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var client = new TcpClient();
                using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await client.ConnectAsync(IPAddress.Loopback, port, connectCts.Token);
                using var stream = client.GetStream();
                await stream.WriteAsync(payload);
                await stream.FlushAsync();

                var response = new byte[payload.Length];
                var offset = 0;
                using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                while (offset < response.Length)
                {
                    var read = await stream.ReadAsync(response.AsMemory(offset), readCts.Token);
                    if (read == 0)
                    {
                        throw new IOException("remote specus closed before echo completed");
                    }
                    offset += read;
                }
                return response;
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                lastError = ex;
                await Task.Delay(250);
            }
        }
        throw new TimeoutException($"remote specus on port {port} did not echo within {timeout}", lastError);
    }

    private static string LocateRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir, "pom.xml"))
                && Directory.Exists(Path.Combine(dir, "implementations", "java", "client")))
            {
                return dir;
            }
            dir = Path.GetDirectoryName(dir);
        }
        throw new InvalidOperationException("could not locate repo root from " + AppContext.BaseDirectory);
    }

    private static (string? Executable, string? JavaHome) ResolveJava()
    {
        var command = OperatingSystem.IsWindows() ? "java.exe" : "java";
        var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(javaHome))
        {
            var candidate = Path.Combine(javaHome, "bin", command);
            if (File.Exists(candidate))
            {
                return (candidate, javaHome);
            }
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var entry in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(entry, command);
            if (File.Exists(candidate))
            {
                return (candidate, null);
            }
        }

        return (null, null);
    }

    private sealed record ConnectionRecordView(long Id, string ClientName, bool Success,
        DateTimeOffset? DisconnectedAt, string? DisconnectReason);

    private sealed class EchoServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _shutdown = new();
        private readonly Task _acceptLoop;

        private EchoServer(TcpListener listener)
        {
            _listener = listener;
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _acceptLoop = Task.Run(AcceptLoopAsync);
        }

        public int Port { get; }

        public static Task<EchoServer> StartAsync()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return Task.FromResult(new EchoServer(listener));
        }

        public async ValueTask DisposeAsync()
        {
            _shutdown.Cancel();
            try { _listener.Stop(); } catch { /* already stopped */ }
            try { await _acceptLoop; } catch { /* shutdown path */ }
            _shutdown.Dispose();
        }

        private async Task AcceptLoopAsync()
        {
            while (!_shutdown.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_shutdown.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                _ = Task.Run(() => EchoAsync(client, _shutdown.Token));
            }
        }

        private static async Task EchoAsync(TcpClient client, CancellationToken cancellationToken)
        {
            using (client)
            {
                using var stream = client.GetStream();
                var buffer = new byte[8192];
                while (!cancellationToken.IsCancellationRequested)
                {
                    var read = await stream.ReadAsync(buffer, cancellationToken);
                    if (read == 0)
                    {
                        return;
                    }
                    await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    await stream.FlushAsync(cancellationToken);
                }
            }
        }
    }
}
