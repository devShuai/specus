using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
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

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync()
    {
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
        if (_authStub is not null)
        {
            await _authStub.DisposeAsync();
        }
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task ExternalClient_RoundTripsThroughJavaClientAndUpstreamEcho()
    {
        if (!File.Exists(ClientJar))
        {
            return;
        }
        (_javaExecutable, _javaHome) = ResolveJava();
        if (_javaExecutable is null)
        {
            return;
        }

        _server = await TestServerFixture.StartAsync();
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
        while (totalRead < payload.Length && DateTime.UtcNow < deadline)
        {
            int got = await external.GetStream().ReadAsync(readBuf);
            if (got == 0)
            {
                break;
            }
            received.Write(readBuf, 0, got);
            totalRead += got;
        }
        Assert.Equal(payload.Length, totalRead);
        Assert.Equal(payload, received.ToArray());

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
        while (readIdx < burstSize && DateTime.UtcNow < burstDeadline)
        {
            int got = await stream.ReadAsync(burstRead.AsMemory(readIdx, burstSize - readIdx));
            if (got == 0)
            {
                break;
            }
            readIdx += got;
        }
        Assert.Equal(burstSize, readIdx);
        Assert.Equal(burst, burstRead);

        // Flush traffic counters and assert both directions were accounted for.
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
