using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Upgrading to tenant-scoped login names (protocol/spec/management-accounts.md section 3), the
/// counterpart of Java's <c>ManagementUserSchemaMigratorTests</c>. SQLite databases are built at the
/// schema of the previous release and upgraded for real; PostgreSQL and MySQL are checked offline on
/// the SQL their migration generates, as <see cref="MultiProviderModelTests"/> does for the model.
/// </summary>
public sealed class ManagementLoginNameMigrationTests
{
    private const string PreviousMigration = "AddProductMetrics";
    private const string LoginNamesMigration = "AddManagementLoginNames";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static TheoryData<string> Providers => new() { "sqlite", "postgres", "mysql" };

    [Fact]
    public async Task UpgradedDatabaseBackfillsLoginNamesAndExistingAccountsStillSignIn()
    {
        var path = await CreatePreviousReleaseDatabaseAsync(
            new LegacyAccount("LegacyAdmin", "default", "Admin", "legacy-admin-password"),
            new LegacyAccount("Élise", "default", "User", "elise-password"),
            new LegacyAccount("bob", "tenant-b", "User", "bob-password"),
            // Same name, different case, different tenants: allowed by the upgrade.
            new LegacyAccount("Carol", "tenant-a", "User", "carol-a-password"),
            new LegacyAccount("carol", "tenant-b", "User", "carol-b-password"));
        try
        {
            // A client recorded under the old username (the client table is unchanged by the upgrade).
            await using (var db = CreateContext($"Data Source={path}"))
            {
                var at = DateTimeOffset.Parse("2026-07-31T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
                db.ClientAccounts.Add(new ClientAccount
                {
                    Id = 424242,
                    TenantId = "default",
                    OwnerUsername = "LegacyAdmin",
                    ClientName = "legacy-admin-client",
                    PasswordHash = PasswordHasher.HashToken("unused"),
                    Enabled = true,
                    ConnectionRateLimitPerMinute = 30,
                    CreatedAt = at,
                    UpdatedAt = at,
                });
                await db.SaveChangesAsync();
            }

            await using (var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
                         {
                             ["ConnectionStrings:Specus"] = $"Data Source={path}",
                         }))
            {
                var tokens = server.HostServices.GetRequiredService<LocalTokenService>();
                using var client = server.CreateClient();

                // Old accounts sign in exactly as before: the login name is the old username.
                var admin = await LoginAsync(client, "legacyadmin", "legacy-admin-password", null);
                AssertToken(tokens, admin, "LegacyAdmin", "default", "ADMIN");
                AssertToken(tokens, await LoginAsync(client, "élise", "elise-password", null),
                    "Élise", "default", "USER");
                AssertToken(tokens, await LoginAsync(client, "ÉLISE", "elise-password", "default"),
                    "Élise", "default", "USER");
                // An old account outside the default tenant still signs in without a tenant ...
                AssertToken(tokens, await LoginAsync(client, "bob", "bob-password", null), "bob", "tenant-b", "USER");
                AssertToken(tokens, await LoginAsync(client, "BOB", "bob-password", "tenant-b"),
                    "bob", "tenant-b", "USER");
                // ... unless the name is ambiguous across tenants, which then needs the tenant.
                using (var ambiguous = await client.PostAsJsonAsync("/auth/login",
                           new { username = "carol", password = "carol-b-password" }))
                {
                    Assert.Equal(HttpStatusCode.Unauthorized, ambiguous.StatusCode);
                }
                AssertToken(tokens, await LoginAsync(client, "carol", "carol-a-password", "tenant-a"),
                    "Carol", "tenant-a", "USER");
                AssertToken(tokens, await LoginAsync(client, "carol", "carol-b-password", "tenant-b"),
                    "carol", "tenant-b", "USER");

                // Data recorded under the old username still belongs to the account.
                using var adminClient = server.CreateClient();
                adminClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin);
                using var clients = JsonDocument.Parse(await adminClient.GetStringAsync("/api/admin/clients"));
                Assert.Contains(clients.RootElement.EnumerateArray(),
                    item => item.GetProperty("clientName").GetString() == "legacy-admin-client");
                var me = await adminClient.GetFromJsonAsync<JsonElement>("/api/admin/me", JsonOptions);
                Assert.Equal("LegacyAdmin", me.GetProperty("username").GetString());
            }

            var rows = await ReadLoginNamesAsync(path);
            // Account keys are unchanged; login names are the old usernames; the canonical form is
            // lower-cased beyond ASCII too (SQLite's own LOWER() would have left the É).
            Assert.Equal(new[]
            {
                ("Carol", "tenant-a", "Carol", "carol"),
                ("LegacyAdmin", "default", "LegacyAdmin", "legacyadmin"),
                ("bob", "tenant-b", "bob", "bob"),
                ("carol", "tenant-b", "carol", "carol"),
                ("Élise", "default", "Élise", "élise"),
            }, rows);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task DuplicateLoginNameWithinATenantFailsTheMigrationBeforeAnythingIsWritten()
    {
        var path = await CreatePreviousReleaseDatabaseAsync(
            new LegacyAccount("Alice", "tenant-a", "User", "alice-password"),
            new LegacyAccount("alice", "tenant-a", "User", "alice-password"),
            new LegacyAccount("dave", "default", "User", "dave-password"));
        try
        {
            // The start refuses before EF applies the migration ...
            var startup = await Assert.ThrowsAsync<InvalidOperationException>(() => InitializeAsync(path));
            Assert.Contains("duplicate management login name", startup.Message, StringComparison.Ordinal);
            Assert.Contains("tenant-a", startup.Message, StringComparison.Ordinal);
            await AssertStillPreviousReleaseAsync(path);

            // ... and the migration on its own fails at the unique index and rolls back.
            await using (var db = CreateContext($"Data Source={path}"))
            {
                var failure = await Assert.ThrowsAnyAsync<Exception>(() => db.Database.MigrateAsync());
                Assert.Contains("UNIQUE", failure.Message, StringComparison.OrdinalIgnoreCase);
            }
            await AssertStillPreviousReleaseAsync(path);
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task PreMigrationCheckLeavesANewDatabaseToEfCore()
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-login-names-{Guid.NewGuid():N}.db");
        try
        {
            await InitializeAsync(path);

            // Had the check opened the missing file first, EF would have found an existing database
            // and skipped its creation, which is what switches a new SQLite file to WAL.
            await using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
            await connection.OpenAsync();
            Assert.Equal("wal", await ScalarAsync(connection, "PRAGMA journal_mode"));
            Assert.Equal(1L, await ScalarAsync(connection,
                "SELECT COUNT(*) FROM __EFMigrationsHistory WHERE MigrationId LIKE '%_AddManagementLoginNames'"));
        }
        finally
        {
            DeleteDatabase(path);
        }
    }

    [Fact]
    public async Task StartupStepBackfillsEnforcesUniquenessAndIsRepeatable()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateContext(connection);
        await db.Database.MigrateAsync();
        // Rows written by something that does not know the new columns.
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO specus_management_user (username, tenant_id, password_hash, role, enabled, created_at, updated_at)
            VALUES ('Frank', 'tenant-a', 'x', 'User', 1, 'now', 'now');
            INSERT INTO specus_management_user (username, login_name, tenant_id, password_hash, role, enabled, created_at, updated_at)
            VALUES ('3b8f8f5e-1f0e-4a52-9a7e-3f1f6c1d2a10', '  Grace ', 'tenant-a', 'x', 'User', 1, 'now', 'now');
            """);

        await DatabaseInitializer.EnsureManagementLoginNamesAsync(db, CancellationToken.None);
        await DatabaseInitializer.EnsureManagementLoginNamesAsync(db, CancellationToken.None);

        var rows = await ReadLoginNamesAsync(connection);
        Assert.Equal(new[]
        {
            ("3b8f8f5e-1f0e-4a52-9a7e-3f1f6c1d2a10", "tenant-a", "Grace", "grace"),
            ("Frank", "tenant-a", "Frank", "frank"),
        }, rows);

        // The index enforces uniqueness within a tenant, not across tenants.
        await Assert.ThrowsAnyAsync<SqliteException>(() => db.Database.ExecuteSqlRawAsync("""
            INSERT INTO specus_management_user (username, login_name, login_name_normalized, tenant_id, password_hash, role, enabled, created_at, updated_at)
            VALUES ('frank-2', 'FRANK', 'frank', 'tenant-a', 'x', 'User', 1, 'now', 'now');
            """));
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO specus_management_user (username, login_name, login_name_normalized, tenant_id, password_hash, role, enabled, created_at, updated_at)
            VALUES ('frank-b', 'FRANK', 'frank', 'tenant-b', 'x', 'User', 1, 'now', 'now');
            """);
        await DatabaseInitializer.EnsureManagementLoginNamesAsync(db, CancellationToken.None);

        // Without the index a duplicate gets in; the start then refuses before writing anything.
        await db.Database.ExecuteSqlRawAsync("""
            DROP INDEX uq_management_user_tenant_login_name;
            INSERT INTO specus_management_user (username, tenant_id, password_hash, role, enabled, created_at, updated_at)
            VALUES ('fRANK', 'tenant-a', 'x', 'User', 1, 'now', 'now');
            """);
        var duplicate = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DatabaseInitializer.EnsureManagementLoginNamesAsync(db, CancellationToken.None));
        Assert.Equal("duplicate management login name in tenant 'tenant-a'", duplicate.Message);
        Assert.Null(await ScalarAsync(connection,
            "SELECT login_name FROM specus_management_user WHERE username = 'fRANK'"));
        await db.Database.ExecuteSqlRawAsync("DELETE FROM specus_management_user WHERE username = 'fRANK'");
        await DatabaseInitializer.EnsureManagementLoginNamesAsync(db, CancellationToken.None);
    }

    [Theory]
    [InlineData("CREATE INDEX uq_management_user_tenant_login_name ON specus_management_user (tenant_id, login_name_normalized)")]
    [InlineData("CREATE UNIQUE INDEX uq_management_user_tenant_login_name ON specus_management_user (login_name_normalized, tenant_id)")]
    [InlineData("CREATE UNIQUE INDEX uq_management_user_tenant_login_name ON specus_management_user (login_name_normalized)")]
    public async Task StartupStepRejectsAnIndexOfTheRightNameButTheWrongDefinition(string definition)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateContext(connection);
        await db.Database.MigrateAsync();
        await db.Database.ExecuteSqlRawAsync("DROP INDEX uq_management_user_tenant_login_name");
        await db.Database.ExecuteSqlRawAsync(definition);

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            DatabaseInitializer.EnsureManagementLoginNamesAsync(db, CancellationToken.None));
        Assert.Equal("index uq_management_user_tenant_login_name must be unique on (tenant_id, login_name_normalized)",
            failure.Message);
    }

    [Theory]
    [MemberData(nameof(Providers))]
    public void MigrationAddsColumnsBackfillsThenCreatesTheTenantUniqueIndex(string provider)
    {
        using var context = CreateOfflineContext(provider);
        var script = context.GetService<IMigrator>().GenerateScript(PreviousMigration, LoginNamesMigration);
        var plain = script.Replace("\"", string.Empty, StringComparison.Ordinal)
            .Replace("`", string.Empty, StringComparison.Ordinal);

        var addLoginName = plain.IndexOf("ADD login_name ", StringComparison.Ordinal);
        var addNormalized = plain.IndexOf("ADD login_name_normalized ", StringComparison.Ordinal);
        var backfill = plain.IndexOf(
            "SET login_name = COALESCE(NULLIF(TRIM(login_name), ''), username),", StringComparison.Ordinal);
        // Terminated, so a generated script stays runnable.
        var normalize = plain.IndexOf(
            "login_name_normalized = LOWER(TRIM(COALESCE(NULLIF(TRIM(login_name), ''), username)));",
            StringComparison.Ordinal);
        var index = plain.IndexOf(
            "CREATE UNIQUE INDEX uq_management_user_tenant_login_name ON specus_management_user (tenant_id, login_name_normalized)",
            StringComparison.Ordinal);
        Assert.True(addLoginName >= 0 && addNormalized >= 0, script);
        Assert.True(backfill > Math.Max(addLoginName, addNormalized), script);
        Assert.True(normalize > backfill, script);
        Assert.True(index > normalize, script);
        Assert.Contains(provider == "sqlite" ? "TEXT" : provider == "postgres" ? "character varying(80)" : "varchar(80)",
            script, StringComparison.Ordinal);

        var model = context.Model.FindEntityType(typeof(ManagementUser))!;
        var unique = Assert.Single(model.GetIndexes(), item => item.GetDatabaseName() == "uq_management_user_tenant_login_name");
        Assert.True(unique.IsUnique);
        Assert.Equal(new[] { "tenant_id", "login_name_normalized" },
            unique.Properties.Select(property => property.GetColumnName()));
    }

    private sealed record LegacyAccount(string Username, string TenantId, string Role, string Password);

    /// <summary>A SQLite file at the schema of the release before login names, holding these accounts.</summary>
    private static async Task<string> CreatePreviousReleaseDatabaseAsync(params LegacyAccount[] accounts)
    {
        var path = Path.Combine(Path.GetTempPath(), $"specus-login-names-{Guid.NewGuid():N}.db");
        await using (var db = CreateContext($"Data Source={path}"))
        {
            await db.GetService<IMigrator>().MigrateAsync(PreviousMigration);
            foreach (var account in accounts)
            {
                await db.Database.ExecuteSqlRawAsync("""
                    INSERT INTO specus_management_user (username, tenant_id, password_hash, role, enabled, created_at, updated_at)
                    VALUES ({0}, {1}, {2}, {3}, 1, '2026-07-31T00:00:00.0000000+00:00', '2026-07-31T00:00:00.0000000+00:00')
                    """, account.Username, account.TenantId, PasswordHasher.Hash(account.Password), account.Role);
            }
        }
        await AssertStillPreviousReleaseAsync(path);
        return path;
    }

    private static async Task AssertStillPreviousReleaseAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        await connection.OpenAsync();
        await using var columns = connection.CreateCommand();
        columns.CommandText = "SELECT COUNT(*) FROM pragma_table_info('specus_management_user') WHERE name LIKE 'login_name%'";
        Assert.Equal(0L, Convert.ToInt64(await columns.ExecuteScalarAsync()));
        await using var history = connection.CreateCommand();
        history.CommandText = "SELECT COUNT(*) FROM __EFMigrationsHistory WHERE MigrationId LIKE '%_AddManagementLoginNames'";
        Assert.Equal(0L, Convert.ToInt64(await history.ExecuteScalarAsync()));
    }

    /// <summary>The startup path Program.cs runs, against this file.</summary>
    private static async Task InitializeAsync(string path)
    {
        var services = new ServiceCollection();
        services.AddDbContext<SpecusDbContext>(options => options.UseSqlite($"Data Source={path}"));
        await using var provider = services.BuildServiceProvider();
        var initializer = new DatabaseInitializer(provider,
            Options.Create(new DatabaseOptions { SeedDemoClient = false }),
            Options.Create(new ClientAuthOptions()),
            Options.Create(new SpecusOptions { Env = "test" }),
            NullLogger<DatabaseInitializer>.Instance);
        await initializer.InitializeAsync(CancellationToken.None);
    }

    private static async Task<(string, string, string, string)[]> ReadLoginNamesAsync(string path)
    {
        await using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        await connection.OpenAsync();
        return await ReadLoginNamesAsync(connection);
    }

    private static async Task<(string, string, string, string)[]> ReadLoginNamesAsync(SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT username, tenant_id, login_name, login_name_normalized
            FROM specus_management_user ORDER BY username
            """;
        var rows = new List<(string, string, string, string)>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            rows.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }
        return rows.ToArray();
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        var value = await command.ExecuteScalarAsync();
        return value is DBNull ? null : value;
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password,
        string? tenantId)
    {
        using var response = await client.PostAsJsonAsync("/auth/login", tenantId is null
            ? new { username, password, tenantId = (string?)null }
            : new { username, password, tenantId = (string?)tenantId });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(JsonOptions);
        return body.GetProperty("accessToken").GetString()!;
    }

    private static void AssertToken(LocalTokenService tokens, string token, string subject, string tenantId,
        string role)
    {
        var principal = tokens.Validate(token);
        Assert.NotNull(principal);
        Assert.Equal(subject, principal!.Identity!.Name);
        Assert.Equal(tenantId, principal.FindFirst("tenant_id")!.Value);
        Assert.Equal(role, principal.FindFirst("role")!.Value);
    }

    private static void DeleteDatabase(string path)
    {
        SqliteConnection.ClearAllPools();
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best effort: a pooled handle may outlive the test briefly.
        }
    }

    private static SpecusDbContext CreateContext(string connectionString) =>
        new(new DbContextOptionsBuilder<SpecusDbContext>().UseSqlite(connectionString).Options);

    private static SpecusDbContext CreateContext(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<SpecusDbContext>().UseSqlite(connection).Options);

    private static SpecusDbContext CreateOfflineContext(string provider)
    {
        // Throwaway connection strings: generating a migration script never connects.
        var builder = new DbContextOptionsBuilder<SpecusDbContext>();
        switch (provider)
        {
            case "sqlite":
                builder.UseSqlite("Data Source=:memory:", o => o.MigrationsAssembly("Specus.Server.Data"));
                break;
            case "postgres":
                builder.UseNpgsql("Host=localhost;Database=specus;Username=postgres;Password=postgres",
                    o => o.MigrationsAssembly("Specus.Server.Data.Postgres"));
                break;
            case "mysql":
                builder.UseMySQL("server=localhost;database=specus;user=root;password=root",
                    o => o.MigrationsAssembly("Specus.Server.Data.MySql"));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(provider), provider, "unknown provider");
        }
        return new SpecusDbContext(builder.Options);
    }
}
