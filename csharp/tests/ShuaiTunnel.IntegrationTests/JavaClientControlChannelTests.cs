using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Hosting;

namespace ShuaiTunnel.IntegrationTests;

/// <summary>
/// Spin up the C# server on a random TCP port + ephemeral SQLite, then drive the actual
/// Java tunnel-client jar against it. The HMAC handshake, framing, and idle/heartbeat all
/// run end-to-end through real Java code on the client side and real .NET code on the
/// server — the strongest protocol-parity assertion we can make at this phase.
/// </summary>
public sealed class JavaClientControlChannelTests : IAsyncLifetime
{
    private static readonly string RepoRoot = LocateRepoRoot();
    private static readonly string ClientJar = Path.Combine(RepoRoot,
        "tunnel-client", "target", "tunnel-client-0.0.1-SNAPSHOT-exec.jar");
    private static readonly string Java21Home =
        "/Users/shaoshuai/Library/Java/JavaVirtualMachines/temurin-21.0.10/Contents/Home";

    private TestServerFixture? _server;
    private string? _clientWorkDir;
    private Process? _clientProcess;

    public async Task InitializeAsync()
    {
        // Skip-mark: if the client jar isn't built we don't fail the suite — print and bail.
        // CI is expected to run `mvn -pl tunnel-client -am package -DskipTests` before the
        // .NET tests so this branch only triggers in local dev where someone forgot.
        if (!File.Exists(ClientJar))
        {
            throw new SkipException(
                $"client jar missing at {ClientJar}; run `mvn -pl tunnel-client -am package -DskipTests`");
        }

        _server = await TestServerFixture.StartAsync();

        _clientWorkDir = Directory.CreateTempSubdirectory("tunnel-client-it-").FullName;
        var configPath = Path.Combine(_clientWorkDir, "tunnelClientConfig.json");
        File.WriteAllText(configPath, JsonSerializer.Serialize(new
        {
            clientName = DatabaseInitializer.DemoClientName,
            password = DatabaseInitializer.DemoClientPassword,
            httpTunnelConfigList = Array.Empty<object>(),
            remoteAddress = "127.0.0.1",
            remotePort = _server.ControlPort,
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
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task JavaClient_LoginsSuccessfullyAndStaysConnectedAcrossHeartbeats()
    {
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

    private Process StartClient()
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Java21Home, "bin", "java"),
            WorkingDirectory = _clientWorkDir!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.Environment["JAVA_HOME"] = Java21Home;
        psi.ArgumentList.Add("-Dlogging.level.com.theshuai=info");
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
            var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
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
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var row = await db.ConnectionRecords
            .AsNoTracking()
            .OrderByDescending(r => r.Id)
            .FirstOrDefaultAsync();
        return row is null ? null
            : new ConnectionRecordView(row.Id, row.ClientName, row.Success,
                row.DisconnectedAt, row.DisconnectReason);
    }

    private static string LocateRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir, "pom.xml")) && Directory.Exists(Path.Combine(dir, "tunnel-client")))
            {
                return dir;
            }
            dir = Path.GetDirectoryName(dir);
        }
        throw new InvalidOperationException("could not locate repo root from " + AppContext.BaseDirectory);
    }

    private sealed record ConnectionRecordView(long Id, string ClientName, bool Success,
        DateTimeOffset? DisconnectedAt, string? DisconnectReason);
}

/// <summary>
/// Minimal "skip this fact" exception. xUnit v2 reports the test as Skipped when this is
/// thrown — handier than annotating with a Trait + filter at the runner level.
/// </summary>
internal sealed class SkipException : Exception
{
    public SkipException(string reason) : base(reason) { }
}
