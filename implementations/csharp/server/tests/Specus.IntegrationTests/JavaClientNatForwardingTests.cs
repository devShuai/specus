using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Nat;

namespace Specus.IntegrationTests;

/// <summary>
/// End-to-end NAT TCP forwarding test. Spins up:
/// <list type="number">
/// <item>The C# server (control TCP + ephemeral SQLite).</item>
/// <item>A loopback TCP echo server pretending to be the user's upstream service.</item>
/// <item>The real Java specus-client jar pointed at the C# server + the echo upstream.</item>
/// </list>
///
/// <para>Then asserts the round trip — an external byte stream reaches the Java client, gets
/// forwarded to the echo server, comes back, and lands at the external socket. Also asserts
/// the server-side traffic counters picked up both directions. This exercises the full NAT
/// path on the server: REGISTER, external accept, CONNECTED, DATA (both directions), and
/// back-pressure flow control.</para>
/// </summary>
public sealed class JavaClientNatForwardingTests : IAsyncLifetime
{
    private static readonly string RepoRoot = LocateRepoRoot();
    private static readonly string ClientJar = Path.Combine(RepoRoot,
        "implementations", "java", "client", "target", "specus-client-exec.jar");
    private TestServerFixture? _server;
    private ClientAuthStub? _authStub;
    private string? _clientWorkDir;
    private EchoUpstreamServer? _echo;
    private int _remoteListenPort;
    private Process? _clientProcess;
    private string? _javaExecutable;
    private string? _javaHome;
    private TrafficUsageConcurrencyTests.SaveGate? _trafficGate;
    private Task? _heldFlush;

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
        _trafficGate?.Release();
        if (_clientProcess is { HasExited: false })
        {
            try { _clientProcess.Kill(entireProcessTree: true); } catch { /* already gone */ }
            try { await _clientProcess.WaitForExitAsync(); } catch { /* same */ }
        }
        _clientProcess?.Dispose();

        if (_echo is not null)
        {
            await _echo.DisposeAsync();
        }
        if (_clientWorkDir is not null && Directory.Exists(_clientWorkDir))
        {
            try { Directory.Delete(_clientWorkDir, recursive: true); } catch { /* ignore */ }
        }
        try
        {
            if (_heldFlush is not null) await _heldFlush.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            if (_authStub is not null) await _authStub.DisposeAsync();
            if (_server is not null) await _server.DisposeAsync();
        }
    }

    [Fact(Timeout = 180_000)]
    public Task ExternalClient_RoundTripsThroughJavaClientAndUpstreamEcho() => RoundTripAsync(holdFlush: false);

    [Fact(Timeout = 180_000)]
    public Task AFlushAlreadySavingTheFirstEchoCannotHideBytesFromTheNextEcho() => RoundTripAsync(holdFlush: true);

    private async Task RoundTripAsync(bool holdFlush)
    {
        if (!File.Exists(ClientJar))
        {
            Assert.False(Environment.GetEnvironmentVariable("SPECUS_REQUIRE_JAVA_CLIENT") == "1",
                "Build the Java client first: mvn -pl :specus-client -am package -DskipTests");
            return;
        }
        (_javaExecutable, _javaHome) = ResolveJava();
        if (_javaExecutable is null)
        {
            Assert.False(Environment.GetEnvironmentVariable("SPECUS_REQUIRE_JAVA_CLIENT") == "1",
                "Java 21 must be available through JAVA_HOME or PATH for cross-language tests");
            return;
        }

        if (holdFlush)
            _trafficGate = new TrafficUsageConcurrencyTests.SaveGate(resource: false,
                holdTimeout: TimeSpan.FromSeconds(60));
        _server = await TestServerFixture.StartAsync(
            holdFlush ? new Dictionary<string, string?> { ["Specus:Traffic:FlushIntervalMs"] = "3600000" } : null,
            _trafficGate is null ? null : services => services.ConfigureDbContext<SpecusDbContext>(
                (_, options) => options.AddInterceptors(_trafficGate)));
        if (holdFlush)
        {
            // An existing zero row makes the controlled overlap a read/modify/save case, not
            // an insertion-key conflict. No synthetic traffic is added to the byte threshold.
            await using var scope = _server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ClientAccounts.AsNoTracking().SingleAsync(
                row => row.ClientName == DatabaseInitializer.DemoClientName);
            db.TrafficUsages.Add(new TrafficUsage
            {
                TenantId = account.TenantId, ClientId = account.Id, ClientName = account.ClientName,
                UsageDate = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                UpdatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }
        _authStub = ClientAuthStub.Start(_server);
        _echo = new EchoUpstreamServer();

        // Pick an external listen port that's free. We let the kernel assign one by binding to 0
        // and immediately unbinding — leaves a tiny TOCTOU window but the OS rarely reuses the
        // ephemeral range inside the millisecond before we hand it to Java.
        _remoteListenPort = ProbeFreePort();
        await _server.SeedSpecusMappingAsync(_remoteListenPort, "127.0.0.1", _echo.BoundPort);

        _clientWorkDir = Directory.CreateTempSubdirectory("specus-client-nat-it-").FullName;
        File.WriteAllText(Path.Combine(_clientWorkDir, "client.jsonc"),
            JsonSerializer.Serialize(new
            {
                serverBaseUrl = _authStub.ServerBaseUrl,
                apiKey = DatabaseInitializer.DemoCredentialApiKey,
                secret = DatabaseInitializer.DemoCredentialSecret,
            }));

        _clientProcess = StartClient();

        // Wait until the server actually accepted a connection AND its NAT session registered
        // the specus. We can probe the per-port active-connection count via RemotePortServerManager
        // — there's at least a placeholder server for the port once REGISTER_RESULT arrives.
        var manager = (RemotePortServerManager)_server.HostServices
            .GetServices<Microsoft.Extensions.Hosting.IHostedService>()
            .First(s => s is RemotePortServerManager);
        await WaitForRegisteredPortAsync(manager, _remoteListenPort, TimeSpan.FromSeconds(45));

        // Now drive traffic: connect an external socket to the server's NAT listener and write
        // a payload, expecting the echo to come back within a few seconds.
        var payload = new byte[8 * 1024];
        Random.Shared.NextBytes(payload);

        using var external = new TcpClient();
        await external.ConnectAsync("127.0.0.1", _remoteListenPort);
        await external.GetStream().WriteAsync(payload);
        await external.GetStream().FlushAsync();

        using var received = new MemoryStream();
        var readBuf = new byte[4096];
        int totalRead = 0;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        using var payloadTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (totalRead < payload.Length && DateTime.UtcNow < deadline)
        {
            int got = await external.GetStream().ReadAsync(readBuf, payloadTimeout.Token);
            if (got == 0)
            {
                break;
            }
            received.Write(readBuf, 0, got);
            totalRead += got;
        }
        Assert.Equal(payload.Length, totalRead);
        Assert.Equal(payload, received.ToArray());
        await FinishEchoAsync(external, payloadTimeout.Token);
        if (_trafficGate is not null)
        {
            _trafficGate.Hold();
            _heldFlush = _server.FlushTrafficAsync();
            await _trafficGate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(((long)payload.Length, (long)payload.Length), _trafficGate.HeldTotals!.Value);
        }

        // Push enough sustained traffic to exercise the backpressure path. Send 1 MiB in
        // 16 KiB chunks and read each echo back; the control channel will periodically have to
        // pause/resume around the high-water mark. If pause/resume weren't wired correctly
        // either bytes would drop or the external socket would block forever on write.
        var burstSize = 1024 * 1024;
        var burst = new byte[burstSize];
        Random.Shared.NextBytes(burst);

        using var burstSocket = new TcpClient { NoDelay = true };
        await burstSocket.ConnectAsync("127.0.0.1", _remoteListenPort);
        var stream = burstSocket.GetStream();
        await stream.WriteAsync(burst);
        await stream.FlushAsync();

        var burstRead = new byte[burstSize];
        var readIdx = 0;
        var burstDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(60);
        using var burstTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        while (readIdx < burstSize && DateTime.UtcNow < burstDeadline)
        {
            int got = await stream.ReadAsync(burstRead.AsMemory(readIdx, burstSize - readIdx), burstTimeout.Token);
            if (got == 0)
            {
                break;
            }
            readIdx += got;
        }
        Assert.Equal(burstSize, readIdx);
        Assert.Equal(burst, burstRead);
        await FinishEchoAsync(burstSocket, burstTimeout.Token);

        // Flush traffic counters and assert both directions were accounted for.
        if (_trafficGate is not null)
            await VerifyPendingFlushAsync(payload.Length + burstSize);
        else
            await _server.FlushTrafficAsync();
        var (up, down) = await _server.ReadTrafficTotalsAsync(DatabaseInitializer.DemoClientName);
        Assert.True(up > 0, $"expected upload bytes > 0 (was {up})");
        Assert.True(down > 0, $"expected download bytes > 0 (was {down})");
        // Echo upstream means client → upstream and upstream → client carry the same bytes;
        // totals should at least match what we sent (we sent two streams totaling ~1 MiB + 8 KiB).
        Assert.True(up >= payload.Length + burstSize,
            $"upload bytes ({up}) should be >= payload + burst ({payload.Length + burstSize})");
        Assert.True(down >= payload.Length + burstSize,
            $"download bytes ({down}) should be >= payload + burst ({payload.Length + burstSize})");
        await using var totalsScope = _server.HostServices.CreateAsyncScope();
        var totalsDb = totalsScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var resource = await totalsDb.ResourceTrafficUsages.AsNoTracking().SingleAsync(
            row => row.ClientName == DatabaseInitializer.DemoClientName && row.ResourceKey == $"tcp:{_remoteListenPort}");
        Assert.True(resource.UploadBytes >= payload.Length + burstSize);
        Assert.True(resource.DownloadBytes >= payload.Length + burstSize);
        Console.WriteLine($"NAT accounting after both EOFs: heldFlush={holdFlush}, expected={payload.Length + burstSize}, "
            + $"client={up}/{down}, resource={resource.UploadBytes}/{resource.DownloadBytes}");
    }

    private static async Task FinishEchoAsync(TcpClient socket, CancellationToken remainingReadBudget)
    {
        // FIN follows all DATA on the NAT stream. EOF is therefore a real completion boundary
        // for its successful write/accounting callbacks, unlike merely receiving the last byte.
        var stream = socket.GetStream();
        socket.Client.Shutdown(SocketShutdown.Send);
        Assert.Equal(0, await stream.ReadAsync(new byte[1], remainingReadBudget));
    }

    private async Task VerifyPendingFlushAsync(long expected)
    {
        var gate = _trafficGate!;
        var manual = _server!.FlushTrafficAsync();
        try
        {
            await Task.WhenAny(manual, gate.SecondWriter.Task, Task.Delay(250));
            if (manual.IsCompletedSuccessfully)
            {
                var (up, down) = await _server.ReadTrafficTotalsAsync(DatabaseInitializer.DemoClientName);
                Console.WriteLine($"premature flush while first echo is unsaved: expected={expected}, actual={up}/{down}");
                Assert.True(up >= expected, $"premature upload ({up}) below complete echoes ({expected})");
                Assert.True(down >= expected, $"premature download ({down}) below complete echoes ({expected})");
            }
            Assert.False(gate.SecondWriter.Task.IsCompleted, "manual flush bypassed the earlier unsaved echo snapshot");
            Assert.False(manual.IsCompleted, "manual flush returned before its earlier snapshot became durable");
        }
        finally
        {
            gate.Release();
            await _heldFlush!.WaitAsync(TimeSpan.FromSeconds(5));
            await manual.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    private static async Task WaitForRegisteredPortAsync(RemotePortServerManager manager,
        int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (manager.HasBinding(port))
            {
                return;
            }
            await Task.Delay(200);
        }
        throw new TimeoutException($"port {port} never bound on server (timeout {timeout})");
    }

    private static int ProbeFreePort()
    {
        var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
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
        // Each child owns its snapshots; do not depend on or modify real user state.
        psi.Environment["SPECUS_CLI_STATE_DIR"] = Path.Combine(_clientWorkDir!, "state");
        psi.ArgumentList.Add("-Dlogging.level.com.theshuai=info");
        // The Java specus-client embeds a Spring Boot Tomcat fixed at 8087. Two integration
        // tests running in parallel both try to bind that port and the loser dies with
        // "APPLICATION FAILED TO START". Pin to ephemeral so any number of jars coexist.
        psi.ArgumentList.Add("-Dserver.port=0");
        psi.ArgumentList.Add("-jar");
        psi.ArgumentList.Add(ClientJar);

        var process = Process.Start(psi)
            ?? throw new InvalidOperationException("failed to start java client process");
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine($"[client] {e.Data}"); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) Console.WriteLine($"[client!] {e.Data}"); };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
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
}
