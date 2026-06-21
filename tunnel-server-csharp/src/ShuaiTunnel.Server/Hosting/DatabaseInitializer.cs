using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Hosting;

/// <summary>
/// Database bootstrapper for both process startup and the management UI's idempotent
/// "initialize database" action. It mirrors Java's <c>DatabaseInitializer</c> while using
/// EF Core migrations as the schema authority.
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

    public async Task<DatabaseInitializeResult> InitializeAsync(CancellationToken cancellationToken)
    {
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);

        if (_options.Value.SeedDemoClient)
        {
            await SeedDemoClientAsync(db, cancellationToken).ConfigureAwait(false);
        }

        var clients = await db.ClientAccounts.LongCountAsync(cancellationToken).ConfigureAwait(false);
        return new DatabaseInitializeResult(
            Initialized: true,
            Orm: "entity-framework-core",
            Dialect: DatabaseDialect(db.Database.ProviderName),
            Clients: clients);
    }

    private async Task SeedDemoClientAsync(TunnelDbContext db, CancellationToken cancellationToken)
    {
        var exists = await db.ClientAccounts
            .AsNoTracking()
            .AnyAsync(a => a.ClientName == DemoClientName, cancellationToken)
            .ConfigureAwait(false);
        if (exists)
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

    private static string DatabaseDialect(string? providerName)
    {
        if (providerName is null)
        {
            return "unknown";
        }

        if (providerName.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            return "sqlite";
        }

        if (providerName.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            return "postgresql";
        }

        if (providerName.Contains("MySql", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("MySQL", StringComparison.OrdinalIgnoreCase))
        {
            return "mysql";
        }

        return providerName;
    }
}

public sealed record DatabaseInitializeResult(bool Initialized, string Orm, string Dialect, long Clients);
