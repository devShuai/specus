using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Nat;

namespace Specus.IntegrationTests;

/// <summary>
/// Boots the C# server in-process for an integration test. Hands out:
/// <list type="bullet">
/// <item><see cref="ControlPort"/> — the kernel-assigned control TCP port (we ask for 0).</item>
/// <item><see cref="HostServices"/> — the DI root so tests can read the live <see cref="SpecusDbContext"/>
/// and pull <see cref="TrafficUsageService"/>.</item>
/// </list>
///
/// <para>The fixture wires Kestrel to a random http port too (0), so multiple parallel test
/// runs don't fight over <c>:8088</c>. The HTTP surface is just the <c>/health</c> endpoint
/// at this phase — tests don't depend on it yet.</para>
/// </summary>
/// <summary>Stamps a loopback remote address on every TestServer request.</summary>
internal sealed class LoopbackPeerStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            context.Connection.RemoteIpAddress ??= System.Net.IPAddress.Loopback;
            await nextMiddleware().ConfigureAwait(false);
        });
        next(app);
    };
}

internal sealed class TestServerFixture : WebApplicationFactory<Program>, IAsyncDisposable
{
    static TestServerFixture()
    {
        // Initialize SQLite's process-wide prune timer without a HostingListener context.
        if (ExecutionContext.IsFlowSuppressed()) PrimeSqlite();
        else { using (ExecutionContext.SuppressFlow()) PrimeSqlite(); }
    }

    private static void PrimeSqlite()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
    }

    private readonly IReadOnlyDictionary<string, string?> _configurationOverrides;
    private readonly Action<IServiceCollection>? _configureServices;
    private string? _dbPath;

    public int ControlPort { get; private set; }

    public IServiceProvider HostServices => Server.Services;

    private TestServerFixture(IReadOnlyDictionary<string, string?>? configurationOverrides = null,
        Action<IServiceCollection>? configureServices = null)
    {
        _configurationOverrides = configurationOverrides ?? new Dictionary<string, string?>();
        _configureServices = configureServices;
    }

    public static async Task<TestServerFixture> StartAsync(
        IReadOnlyDictionary<string, string?>? configurationOverrides = null,
        Action<IServiceCollection>? configureServices = null)
    {
        var fixture = new TestServerFixture(configurationOverrides, configureServices);
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

    /// <summary>
    /// Inserts a <see cref="SpecusMapping"/> row tied to the seeded Demo client. Tests use this
    /// to make the Java client's REGISTER succeed — the client registers whatever is in its
    /// <c>specusConfigList</c>, and the server binds a listener on that port, pointing at the
    /// given <paramref name="specusAddress"/>:<paramref name="specusPort"/>.
    /// </summary>
    public async Task<long> SeedSpecusMappingAsync(int listenPort, string specusAddress, int specusPort,
        CancellationToken cancellationToken = default)
    {
        await using var scope = HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();

        var demoAccount = await db.ClientAccounts.AsNoTracking()
            .FirstAsync(c => c.ClientName == DatabaseInitializer.DemoClientName, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        var existing = await db.SpecusMappings.AsNoTracking()
            .FirstOrDefaultAsync(m => m.ListenPort == listenPort, cancellationToken);
        if (existing is not null)
        {
            db.SpecusMappings.Remove(existing);
        }
        var mapping = new SpecusMapping
        {
            Id = Specus.Server.Authentication.ClientIdGenerator.NewId(),
            ClientId = demoAccount.Id,
            ClientName = demoAccount.ClientName,
            ListenPort = listenPort,
            TargetAddress = specusAddress,
            TargetPort = specusPort,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.SpecusMappings.Add(mapping);
        await db.SaveChangesAsync(cancellationToken);
        return mapping.Id;
    }

    /// <summary>
    /// Force-flushes the traffic counter buckets so a test can observe upload/download bytes
    /// without waiting for the 5-second background flush.
    /// </summary>
    public async Task FlushTrafficAsync(CancellationToken cancellationToken = default)
    {
        var service = HostServices.GetRequiredService<TrafficUsageService>();
        await service.FlushAsync(cancellationToken);
    }

    /// <summary>Read current upload/download byte totals for a client name.</summary>
    public async Task<(long Upload, long Download)> ReadTrafficTotalsAsync(string clientName,
        CancellationToken cancellationToken = default)
    {
        await using var scope = HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var rows = await db.TrafficUsages.AsNoTracking()
            .Where(t => t.ClientName == clientName)
            .ToListAsync(cancellationToken);
        return (rows.Sum(r => r.UploadBytes), rows.Sum(r => r.DownloadBytes));
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Each test run gets its own SQLite file under TempPath so seeded state and rows from a
        // previous run don't leak into this one.
        _dbPath = Path.Combine(Path.GetTempPath(), $"specus-it-{Guid.NewGuid():N}.db");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Integration tests rely on the demo client/credential seed and on the weak built-in
                // password; both are only permitted outside prod.
                ["Specus:Env"] = "test",
                // TestServer has no real connection peer. Stamp a loopback peer (below) and trust
                // it so these tests keep exercising the forwarded-header path a real deployment
                // gets from its reverse proxy.
                ["Specus:TrustedProxies"] = "127.0.0.1/32",
                // Listen on an ephemeral TCP control port so we can run in parallel.
                ["Specus:Netty:Port"] = "0",
                ["Specus:Auth:PasswordLoginEnabled"] = "true",
                ["Specus:Auth:Password"] = "admin",
                ["Specus:Auth:JwtSecret"] = "integration-test-secret",
                ["Specus:Http:MaxRequestBodySize"] = "64",
                ["Specus:Database:Provider"] = "sqlite",
                ["ConnectionStrings:Specus"] = $"Data Source={_dbPath}",
                ["Specus:Elasticsearch:Uris"] = "",
                ["Specus:Elasticsearch:Username"] = "",
                ["Specus:Elasticsearch:Password"] = "",
                ["Specus:Elasticsearch:ApiKey"] = "",
                // HTTP surface unused at this phase, but we still bind to ephemeral so we don't
                // collide with anything. WebApplicationFactory uses an in-memory test server by
                // default, so this is mostly defense-in-depth.
                ["Kestrel:Endpoints:Http:Url"] = "http://127.0.0.1:0",
            });
            if (_configurationOverrides.Count > 0)
            {
                config.AddInMemoryCollection(_configurationOverrides);
            }
        });

        builder.ConfigureLogging(logging => logging.ClearProviders());

        // Give every in-memory request a loopback peer so ClientAddressResolver sees a trusted
        // proxy and honours the X-Real-IP / X-Forwarded-For headers the tests send.
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IStartupFilter, LoopbackPeerStartupFilter>();
            // A short-lived in-memory host owns its handler cache and scopes. Do not leave
            // two-minute factory expiry timers retaining disposed hosts between test cases.
            // Pooling and real handlers remain enabled; timed handler rotation belongs to
            // production process configuration, which this fixture does not change.
            services.ConfigureAll<HttpClientFactoryOptions>(options => options.HandlerLifetime = Timeout.InfiniteTimeSpan);
            services.AddSingleton<IHttpMessageHandlerBuilderFilter, FixtureHttpHandlers>();
        });

        if (_configureServices is not null)
        {
            builder.ConfigureTestServices(_configureServices);
        }
    }

    public new async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        if (_dbPath is not null)
        {
            // This fixture owns this unique database. Its pool's prune timer captures
            // the startup ExecutionContext and otherwise retains the disposed host.
            // Never clear all pools: other fixtures may still be using theirs.
            using var connection = new SqliteConnection($"Data Source={_dbPath}");
            SqliteConnection.ClearPool(connection);
            try { File.Delete(_dbPath); } catch { /* best effort — file lock may persist briefly */ }
        }
    }
}

// Keep this alongside the fixture: mandatory native-provider projects link this file.
// Preserve real named handlers and their scopes, disposing them with the test host.
internal sealed class FixtureHttpHandlers : IHttpMessageHandlerBuilderFilter, IDisposable, IAsyncDisposable
{
    private readonly IServiceProvider _root;
    private readonly object _gate = new();
    private readonly List<HttpMessageHandlerBuilder> _builders = [];
    private bool _disposed;

    public FixtureHttpHandlers(IServiceProvider root) => _root = root;

    public Action<HttpMessageHandlerBuilder> Configure(Action<HttpMessageHandlerBuilder> next) => builder =>
    {
        next(builder);
        if (!ReferenceEquals(builder.Services, _root) && builder.Services is not IServiceScope)
            throw new InvalidOperationException("The fixture requires the default DI handler scope.");
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _builders.Add(builder);
        }
    };

    public void Dispose() => DisposeCoreAsync(asyncScopes: false).GetAwaiter().GetResult();
    public ValueTask DisposeAsync() => DisposeCoreAsync(asyncScopes: true);

    private async ValueTask DisposeCoreAsync(bool asyncScopes)
    {
        HttpMessageHandlerBuilder[] entries;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            entries = _builders.ToArray();
            _builders.Clear();
        }
        List<Exception> failures = [];
        foreach (var entry in entries)
        {
            try
            {
                // Select after every builder filter has finished, including logging wrappers.
                (entry.AdditionalHandlers.FirstOrDefault() ?? entry.PrimaryHandler).Dispose();
            }
            catch (Exception error) { failures.Add(error); }
            try
            {
                if (!ReferenceEquals(entry.Services, _root) && entry.Services is IServiceScope scope)
                {
                    if (asyncScopes && scope is IAsyncDisposable asynchronous)
                        await asynchronous.DisposeAsync().ConfigureAwait(false);
                    else scope.Dispose();
                }
            }
            catch (Exception error) { failures.Add(error); }
        }
        if (failures.Count != 0) throw new AggregateException("Fixture HTTP resources failed to dispose.", failures);
    }
}
