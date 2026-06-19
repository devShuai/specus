using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Hosting;

/// <summary>
/// Mirrors Java's <c>DatabaseInitializer</c>: applies pending migrations on boot and (optionally)
/// inserts a <c>Demo client</c> account so dev / E2E tests have a working credential without
/// extra setup.
///
/// <para>The seed runs only when (a) the option is enabled and (b) no row matches by name.
/// Production deployments turn <c>Tunnel:Database:SeedDemoClient</c> off explicitly.</para>
/// </summary>
public sealed class DatabaseInitializer
{
    public const string DemoClientName = "Demo client";
    public const string DemoClientPassword = "test1234";

    private readonly IServiceProvider _services;
    private readonly IOptions<DatabaseOptions> _options;
    private readonly ILogger<DatabaseInitializer> _logger;

    public DatabaseInitializer(IServiceProvider services, IOptions<DatabaseOptions> options,
        ILogger<DatabaseInitializer> logger)
    {
        _services = services;
        _options = options;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);

        if (!_options.Value.SeedDemoClient)
        {
            return;
        }
        var existing = await db.ClientAccounts
            .AsNoTracking()
            .FirstOrDefaultAsync(a => a.ClientName == DemoClientName, cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        db.ClientAccounts.Add(new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            ClientName = DemoClientName,
            PasswordHash = PasswordHasher.Hash(DemoClientPassword),
            Enabled = true,
            ConnectionRateLimitPerMinute = 30,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("seeded {ClientName}", DemoClientName);
    }
}
