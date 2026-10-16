using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

public sealed class PostgresBootstrapTests
{
    [Fact]
    public async Task NativeTargetDeletionCannotOrphanACommittedOwnershipTransfer()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await OwnerTransferWriterProof.VerifyNativeTargetDeletionOrderingAsync(server);
    }

    [Fact]
    public async Task NativeSignedHttpStartupUsesCurrentOwnerAndCanonicalIdentityMaterial()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        var gate = new ClientStartupProviderProof.StartupGate(false);
        await using var server = await StartStartupAsync(database, gate);
        await ClientStartupProviderProof.VerifyTransferBeforeStartupAsync(server, gate);
    }

    [Fact]
    public async Task NativeStartupCredentialLockMakesTransferRefreshItsCompletePreview()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        var gate = new ClientStartupProviderProof.StartupGate(true);
        await using var server = await StartStartupAsync(database, gate);
        await ClientStartupProviderProof.VerifyStartupBeforeTransferAsync(server, gate);
    }

    private static Task<TestServerFixture> StartStartupAsync(OwnedDatabase database, ClientStartupProviderProof.StartupGate gate) =>
        TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Database:Provider"] = "postgres", ["ConnectionStrings:Specus"] = database.ConnectionString,
            ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true",
            ["Specus:PeerMesh:StunTurnPort"] = "0", ["Specus:PeerMesh:NatProbeAlternatePort"] = "0",
        }, services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(gate)));

    [Fact]
    public async Task NativeOwnerTransferTargetStatusHasAnObservedDatabaseCommitOrder()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await OwnerTransferWriterProof.VerifyNativeTargetOrderingAsync(server);
    }

    [Fact]
    public async Task NativeOwnerTransferWriterCommitsCanonicalGroupAndAuditWithoutRevokingAccessMaterial()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await OwnerTransferWriterProof.VerifyAsync(server);
    }

    [Fact]
    public async Task NativeControlDisconnectCannotOverwriteANewerPhysicalChannel()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await ControlDisconnectProviderProof.VerifyAsync(server);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeBootstrapRestartAndDownloadCataloguePreserveUnicode(bool missingDatabase)
    {
        await using var database = await OwnedDatabase.CreateAsync(create: !missingDatabase);
        long trafficId;
        string before;
        await using (var server = await StartAsync(database))
        {
            using var client = server.CreateClient();
            using var health = await client.GetAsync("/health");
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
            await using var scope = server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal("Npgsql.EntityFrameworkCore.PostgreSQL", db.Database.ProviderName);
            Assert.False(db.Database.HasPendingModelChanges());
            var download = Link(9001);
            download.IsLatest = true;
            download.LatestSlot = "csharp/windows/x64";
            db.ClientDownloadLinks.Add(download);
            var traffic = MaximumTraffic();
            db.HttpTrafficExchanges.Add(traffic);
            await db.SaveChangesAsync();
            trafficId = traffic.Id;
            before = JsonSerializer.Serialize(traffic);
            Assert.Equal(before, JsonSerializer.Serialize(await db.HttpTrafficExchanges.AsNoTracking().SingleAsync(row => row.Id == trafficId)));
            using var catalogue = await client.GetFromJsonAsync<JsonDocument>("/api/public/client-downloads");
            Assert.Equal(9001, Assert.Single(catalogue!.RootElement.EnumerateArray()).GetProperty("id").GetInt64());
        }
        await using (var restarted = await StartAsync(database))
        {
            await using var scope = restarted.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(before, JsonSerializer.Serialize(await db.HttpTrafficExchanges.AsNoTracking().SingleAsync(row => row.Id == trafficId)));
            Assert.Equal("下载😀", (await db.ClientDownloadLinks.SingleAsync(row => row.Id == 9001)).DisplayName);
            var initializer = restarted.HostServices.GetRequiredService<DatabaseInitializer>();
            Assert.True((await initializer.InitializeAsync(CancellationToken.None)).Initialized);
        }
    }

    [Fact]
    public async Task ActualMigratedQuotedKeyRejectsOriginalSqlAndCompatibilityUsesIt()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.Database.MigrateAsync();
        var failure = await Assert.ThrowsAsync<PostgresException>(() => db.Database.ExecuteSqlRawAsync("SELECT MAX(id) FROM client_download_link"));
        Assert.Equal(PostgresErrorCodes.UndefinedColumn, failure.SqlState);
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        db.ClientDownloadLinks.Add(Link(5001));
        await db.SaveChangesAsync();
        Assert.Equal(5001, (await db.ClientDownloadLinks.AsNoTracking().SingleAsync()).Id);
    }

    [Fact]
    public async Task EmptyCompatibilityTableMatchesEfKeyAndBooleanTypes()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        db.ClientDownloadLinks.Add(Link(5002));
        await db.SaveChangesAsync();
        Assert.Equal(JsonSerializer.Serialize(Link(5002)), JsonSerializer.Serialize(await db.ClientDownloadLinks.AsNoTracking().SingleAsync()));
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        Assert.Equal(1, await db.ClientDownloadLinks.CountAsync());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task LegacyLowercaseSmallintTableUpgradesWithoutLosingKeysIndexesOrRows(int enabledDefault)
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await LegacyTableAsync(db, smallint: true);
        if (enabledDefault == 0)
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE client_download_link ALTER COLUMN enabled SET DEFAULT 0");
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO client_download_link (id, implementation, platform, arch, display_name, download_url, display_order, enabled, created_at, updated_at)
            VALUES (1,'csharp','windows','x64','下载😀','https://example.invalid/one',0,1,'2026-10-14T00:00:00.0000000+00:00','2026-10-14T00:00:00.0000000+00:00'),
                   (2,'csharp','windows','x64','第二个🌍','https://example.invalid/two',1,0,'2026-10-14T00:00:00.0000000+00:00','2026-10-14T00:00:00.0000000+00:00');
            CREATE INDEX legacy_download_id_lookup ON client_download_link(id);
            """);
        string indexBefore = await ScalarAsync(db, "SELECT indexrelid::text FROM pg_index WHERE indexrelid='legacy_download_id_lookup'::regclass");
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        var rows = await db.ClientDownloadLinks.AsNoTracking().OrderBy(row => row.Id).ToListAsync();
        Assert.Equal(new long[] { 1, 2 }, rows.Select(row => row.Id));
        Assert.Equal(new[] { true, false }, rows.Select(row => row.Enabled));
        Assert.Equal(new[] { "下载😀", "第二个🌍" }, rows.Select(row => row.DisplayName));
        Assert.Equal(indexBefore, await ScalarAsync(db, "SELECT indexrelid::text FROM pg_index WHERE indexrelid='legacy_download_id_lookup'::regclass"));
        Assert.Equal("Id", await ScalarAsync(db, "SELECT a.attname FROM pg_constraint c JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey) WHERE c.conrelid='client_download_link'::regclass AND c.contype='p'"));
        Assert.Equal(enabledDefault == 1 ? "true" : "false", await ScalarAsync(db, "SELECT pg_get_expr(d.adbin,d.adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE a.attrelid='client_download_link'::regclass AND a.attname='enabled'"));
        string before = JsonSerializer.Serialize(rows);
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        Assert.Equal(before, JsonSerializer.Serialize(await db.ClientDownloadLinks.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
    }

    [Fact]
    public async Task NativeStartupRepairsLegacyLayoutWithValidMigrationHistory()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        string before;
        await using (var db = database.Context())
        {
            await db.Database.MigrateAsync();
            var link = Link(777);
            link.IsLatest = true;
            link.LatestSlot = "csharp/windows/x64";
            db.ClientDownloadLinks.Add(link);
            await db.SaveChangesAsync();
            before = JsonSerializer.Serialize(link);
            await db.Database.ExecuteSqlRawAsync("""
                ALTER TABLE client_download_link RENAME COLUMN "Id" TO id;
                ALTER TABLE client_download_link ALTER COLUMN enabled DROP DEFAULT;
                ALTER TABLE client_download_link ALTER COLUMN enabled TYPE SMALLINT USING (CASE WHEN enabled THEN 1 ELSE 0 END);
                ALTER TABLE client_download_link ALTER COLUMN enabled SET DEFAULT 1;
                """);
        }
        await using (var server = await StartAsync(database))
        {
            using var client = server.CreateClient();
            using var health = await client.GetAsync("/health");
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
            await using var scope = server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(before, JsonSerializer.Serialize(await db.ClientDownloadLinks.AsNoTracking().SingleAsync()));
        }
        await using (var restarted = await StartAsync(database))
        {
            await using var scope = restarted.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(before, JsonSerializer.Serialize(await db.ClientDownloadLinks.AsNoTracking().SingleAsync()));
        }
    }

    [Fact]
    public async Task LatestRepairKeepsHighestEnabledIdForEachTargetAndIsIdempotent()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.Database.MigrateAsync();
        var links = Enumerable.Range(1, 6).Select(number => Link(number)).ToArray();
        foreach (var link in links) { link.IsLatest = true; link.LatestSlot = null; }
        links[2].Enabled = false;
        links[3].Implementation = links[4].Implementation = "go";
        links[3].Platform = links[4].Platform = "linux";
        links[3].Arch = links[4].Arch = "arm64";
        links[5].Arch = "arm64";
        db.ClientDownloadLinks.AddRange(links);
        await db.SaveChangesAsync();
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        db.ChangeTracker.Clear();
        var rows = await db.ClientDownloadLinks.AsNoTracking().OrderBy(row => row.Id).ToListAsync();
        Assert.Equal(6, rows.Count);
        Assert.Equal(new long[] { 2, 5, 6 }, rows.Where(row => row.IsLatest).Select(row => row.Id));
        Assert.Equal(new[] { "csharp/windows/x64", "go/linux/arm64", "csharp/windows/arm64" }, rows.Where(row => row.IsLatest).Select(row => row.LatestSlot));
        Assert.All(rows.Where(row => !row.IsLatest), row => Assert.Null(row.LatestSlot));
        Assert.Equal(links.Select(row => (row.Id, row.DownloadUrl, row.Version, row.Enabled)), rows.Select(row => (row.Id, row.DownloadUrl, row.Version, row.Enabled)));
        string before = JsonSerializer.Serialize(rows);
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        Assert.Equal(before, JsonSerializer.Serialize(await db.ClientDownloadLinks.AsNoTracking().OrderBy(row => row.Id).ToListAsync()));
    }

    [Fact]
    public async Task MetadataFromAnotherSchemaCannotHideMissingColumnsOrIndexes()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await LegacyTableAsync(db, smallint: false);
        await db.Database.ExecuteSqlRawAsync("CREATE SCHEMA decoy; CREATE TABLE decoy.client_download_link (LIKE public.client_download_link INCLUDING ALL)");
        var decoyConnection = new NpgsqlConnectionStringBuilder(database.ConnectionString) { SearchPath = "decoy" };
        await using var decoy = database.Context(decoyConnection.ConnectionString);
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(decoy, CancellationToken.None);
        decoy.ClientDownloadLinks.Add(Link(99));
        await decoy.SaveChangesAsync();
        string decoyBefore = JsonSerializer.Serialize(await decoy.ClientDownloadLinks.AsNoTracking().ToListAsync());
        await DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None);
        db.ClientDownloadLinks.Add(Link(100));
        await db.SaveChangesAsync();
        Assert.Equal(100, (await db.ClientDownloadLinks.AsNoTracking().SingleAsync()).Id);
        Assert.Equal("2", await ScalarAsync(db, "SELECT count(*)::text FROM pg_index WHERE indrelid='client_download_link'::regclass AND indisunique AND NOT indisprimary"));
        Assert.Equal(decoyBefore, JsonSerializer.Serialize(await decoy.ClientDownloadLinks.AsNoTracking().ToListAsync()));
    }

    [Theory]
    [InlineData("keys")]
    [InlineData("value")]
    [InlineData("default")]
    public async Task AmbiguousKeysAndInvalidLegacyBooleansFailWithoutPartialRepair(string conflict)
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await LegacyTableAsync(db, smallint: true);
        if (conflict == "keys")
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE client_download_link ADD COLUMN \"Id\" BIGINT");
        if (conflict == "default")
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE client_download_link ALTER COLUMN enabled SET DEFAULT 2");
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO client_download_link (id,implementation,platform,arch,display_name,download_url,display_order,enabled,created_at,updated_at)
            VALUES (1,'go','linux','x64','keep','https://example.invalid/keep',0,2,'now','now')
            """);
        if (conflict != "value")
            await db.Database.ExecuteSqlRawAsync("UPDATE client_download_link SET enabled=1");
        string before = await ScalarAsync(db, "SELECT row_to_json(d)::text FROM client_download_link d");
        var failure = await Assert.ThrowsAsync<PostgresException>(() => DatabaseInitializer.EnsureClientDownloadLinkTableAsync(db, CancellationToken.None));
        Assert.Equal(PostgresErrorCodes.RaiseException, failure.SqlState);
        Assert.Equal(before, await ScalarAsync(db, "SELECT row_to_json(d)::text FROM client_download_link d"));
        Assert.Equal("smallint", await ScalarAsync(db, "SELECT format_type(atttypid,atttypmod) FROM pg_attribute WHERE attrelid='client_download_link'::regclass AND attname='enabled'"));
        Assert.Equal("id", await ScalarAsync(db, "SELECT attname FROM pg_attribute WHERE attrelid='client_download_link'::regclass AND attname='id'"));
        Assert.Equal(conflict == "default" ? "2" : "1", await ScalarAsync(db, "SELECT pg_get_expr(d.adbin,d.adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE a.attrelid='client_download_link'::regclass AND a.attname='enabled'"));
    }

    private static Task<TestServerFixture> StartAsync(OwnedDatabase database) => TestServerFixture.StartAsync(new Dictionary<string, string?>
    {
        ["Specus:Database:Provider"] = "postgres",
        ["ConnectionStrings:Specus"] = database.ConnectionString,
        ["Specus:Database:SeedDemoClient"] = "false",
    });

    private static Task LegacyTableAsync(SpecusDbContext db, bool smallint)
    {
        string boolean = smallint ? "SMALLINT NOT NULL DEFAULT 1" : "BOOLEAN NOT NULL DEFAULT TRUE";
        // Both alternatives are closed compile-time SQL type definitions, never user input.
        string sql = $"""
            CREATE TABLE client_download_link (
              id BIGINT PRIMARY KEY, implementation VARCHAR(32) NOT NULL, platform VARCHAR(32) NOT NULL,
              arch VARCHAR(32) NOT NULL, display_name VARCHAR(120) NOT NULL, download_url VARCHAR(1024) NOT NULL,
              description VARCHAR(512), display_order INTEGER NOT NULL DEFAULT 0, enabled {boolean},
              created_at VARCHAR(40) NOT NULL, updated_at VARCHAR(40) NOT NULL
            )
            """;
        return db.Database.ExecuteSqlRawAsync(sql);
    }

    private static ClientDownloadLink Link(long id) => new()
    {
        Id = id, Implementation = "csharp", Platform = "windows", Arch = "x64", DisplayName = "下载😀",
        DownloadUrl = $"https://example.invalid/download/{id}", Description = "完整目录🌍", Version = $"1.0.{id}", Enabled = true,
        CreatedAt = DateTimeOffset.Parse("2026-10-14T00:00:00.0000000+00:00", System.Globalization.CultureInfo.InvariantCulture),
        UpdatedAt = DateTimeOffset.Parse("2026-10-14T00:00:00.0000000+00:00", System.Globalization.CultureInfo.InvariantCulture),
    };

    private static HttpTrafficExchange MaximumTraffic() => new()
    {
        TenantId = new string('租', 80), ClientId = 1001, ClientName = new string('端', 120), Route = new string('r', 128),
        ResourceName = new string('资', 255), RelativePath = new string('路', 1024), RawQuery = new string('查', 2048),
        RequestHeaders = new string('请', 8192), ResponseHeaders = new string('回', 8192),
        RequestPreviewHex = new string('A', 4096), ResponsePreviewHex = new string('F', 4096),
        RequestPreviewText = string.Concat(Enumerable.Repeat("请求😀", 4096)), ResponsePreviewText = string.Concat(Enumerable.Repeat("响应🌍", 4096)),
        RequestBodyData = Enumerable.Range(0, 131072).Select(number => (byte)number).ToArray(),
        ResponseBodyData = Enumerable.Range(0, 131072).Select(number => (byte)(255 - number)).ToArray(), CapturedAt = DateTimeOffset.UtcNow,
    };

    private static async Task<string> ScalarAsync(SpecusDbContext db, string sql)
    {
        await db.Database.OpenConnectionAsync();
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        return Convert.ToString(await command.ExecuteScalarAsync())!;
    }

    private sealed class OwnedDatabase(string adminConnection, string name, string connectionString) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public SpecusDbContext Context(string? connection = null) => new(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseNpgsql(connection ?? ConnectionString, postgres => postgres.MigrationsAssembly("Specus.Server.Data.Postgres")).Options);

        public static async Task<OwnedDatabase> CreateAsync(bool create = true)
        {
            var configured = Environment.GetEnvironmentVariable("SPECUS_TEST_POSTGRES_CONNECTION");
            Assert.False(string.IsNullOrWhiteSpace(configured), "SPECUS_TEST_POSTGRES_CONNECTION must identify an owned loopback PostgreSQL instance; these tests never skip.");
            var settings = new NpgsqlConnectionStringBuilder(configured!) { Database = "postgres", Pooling = false, SearchPath = "public" };
            Assert.Contains(settings.Host, new[] { "127.0.0.1", "localhost" });
            await using var connection = new NpgsqlConnection(settings.ConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            if (Environment.GetEnvironmentVariable("SPECUS_TEST_POSTGRES_EXPECTED_DATA_DIR") is { Length: > 0 } expected)
            {
                command.CommandText = "SHOW data_directory";
                string actual = Convert.ToString(await command.ExecuteScalarAsync())!;
                Assert.Equal(Path.GetFullPath(expected).TrimEnd('/', '\\'), Path.GetFullPath(actual).TrimEnd('/', '\\'), ignoreCase: OperatingSystem.IsWindows());
            }
            string name = "specus_281_" + Guid.NewGuid().ToString("N");
            if (create)
            {
                command.CommandText = $"CREATE DATABASE \"{name}\" ENCODING 'UTF8' TEMPLATE template0";
                await command.ExecuteNonQueryAsync();
            }
            string admin = settings.ConnectionString;
            settings.Database = name;
            return new OwnedDatabase(admin, name, settings.ConnectionString);
        }

        public async ValueTask DisposeAsync()
        {
            if (!Regex.IsMatch(name, "^specus_281_[0-9a-f]{32}$", RegexOptions.CultureInvariant)) throw new InvalidOperationException("Refuse to drop an unowned database.");
            await using var connection = new NpgsqlConnection(adminConnection);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS \"{name}\"";
            await command.ExecuteNonQueryAsync();
        }
    }
}
