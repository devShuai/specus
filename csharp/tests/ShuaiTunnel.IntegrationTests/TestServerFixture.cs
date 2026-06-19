using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data;

namespace ShuaiTunnel.IntegrationTests;

/// <summary>
/// Boots the C# server in-process for an integration test. Hands out:
/// <list type="bullet">
/// <item><see cref="ControlPort"/> — the kernel-assigned control TCP port (we ask for 0).</item>
/// <item><see cref="Services"/> — the DI root so tests can read the live <see cref="TunnelDbContext"/>.</item>
/// </list>
///
/// <para>The fixture wires Kestrel to a random http port too (0), so multiple parallel test
/// runs don't fight over <c>:8088</c>. The HTTP surface is just the <c>/health</c> endpoint
/// at this phase — tests don't depend on it yet.</para>
/// </summary>
internal sealed class TestServerFixture : WebApplicationFactory<Program>, IAsyncDisposable
{
    private string? _dbPath;

    public int ControlPort { get; private set; }

    public IServiceProvider HostServices => Server.Services;

    public static async Task<TestServerFixture> StartAsync()
    {
        var fixture = new TestServerFixture();
        // Starts the host eagerly so ControlChannelListener has bound by the time we read its port.
        _ = fixture.Server;
        var listener = fixture.Server.Services.GetRequiredService<ControlChannelListener>();
        // Spin briefly until the listener has its port; StartAsync runs synchronously inside
        // ControlChannelListener so this is usually one iteration.
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (listener.BoundPort < 0 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }
        fixture.ControlPort = listener.BoundPort;
        if (fixture.ControlPort <= 0)
        {
            throw new InvalidOperationException("control listener never bound");
        }
        return fixture;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Each test run gets its own SQLite file under TempPath so seeded state and rows from a
        // previous run don't leak into this one.
        _dbPath = Path.Combine(Path.GetTempPath(), $"shuai-tunnel-it-{Guid.NewGuid():N}.db");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Listen on an ephemeral TCP control port so we can run in parallel.
                ["Tunnel:Netty:Port"] = "0",
                ["ConnectionStrings:Tunnel"] = $"Data Source={_dbPath}",
                // HTTP surface unused at this phase, but we still bind to ephemeral so we don't
                // collide with anything. WebApplicationFactory uses an in-memory test server by
                // default, so this is mostly defense-in-depth.
                ["Kestrel:Endpoints:Http:Url"] = "http://127.0.0.1:0",
            });
        });
    }

    public new async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dbPath is not null && File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { /* best effort — file lock may persist briefly */ }
        }
    }
}
