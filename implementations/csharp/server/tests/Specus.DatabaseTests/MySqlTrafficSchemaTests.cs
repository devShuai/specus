using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using MySql.Data.MySqlClient;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

public sealed class MySqlTrafficSchemaTests
{
    [Fact]
    public async Task NativePeerManagementWritesRecheckTransferredOwnersAndDeletedParents()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await PeerManagementProviderProof.VerifyAsync(server);
    }

    [Fact]
    public async Task NativeConfigurationMutationsRecheckTransferredOwnersAndDeletedParents()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await ClientConfigurationProviderProof.VerifyAsync(server);
    }

    [Fact]
    public async Task NativeManagementMutationsRevalidateActorsAndUseOneAccountLockOrder()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await ManagementUserActorProviderProof.VerifyAsync(server);
    }

    [Fact]
    public async Task NativeManagementPasswordHashesUpgradeWithoutTruncationOrUnsafeDowngrade()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await OwnerTransferWriterProof.VerifyPasswordHashUpgradeAsync(db);
    }

    [Fact]
    public async Task NativeResourceMutationsRecheckOwnersAndOriginalActorsAfterDatabaseWaits()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var server = await StartAsync(database);
        await OwnerTransferWriterProof.VerifyNativeResourceWriteOrderingAsync(server);
    }

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
            ["Specus:Database:Provider"] = "mysql", ["ConnectionStrings:Specus"] = database.ConnectionString,
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

    private const string Previous = "20261013031423_BindManagementWebSocketAccount";
    private const string Repair = "20261014023000_WidenHttpTrafficText";
    private static readonly string[] WideColumns = ["request_headers", "response_headers", "request_preview_hex", "response_preview_hex"];

    [Fact]
    public async Task FullProductionBootstrapAndRestartPreserveMaximumTrafficData()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        long id;
        string before;
        await using (var server = await StartAsync(database))
        {
            using var client = server.CreateClient();
            using var health = await client.GetAsync("/health");
            Assert.Equal(HttpStatusCode.OK, health.StatusCode);
            await using var scope = server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await AssertPhysicalSchemaAsync(db, "utf8mb4");
            Assert.Contains(Repair, await db.Database.GetAppliedMigrationsAsync());
            (id, before) = await InsertAndReadMaximumAsync(db);
        }
        await using (var restarted = await StartAsync(database))
        {
            await using var scope = restarted.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(before, await ReadAsync(db, id));
            Assert.False(db.Database.HasPendingModelChanges());
            await AssertPhysicalSchemaAsync(db, "utf8mb4");
        }
    }

    [Fact]
    public async Task EnsureCreatedUsesTheSameSafeFullModel()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        Assert.True(await db.Database.EnsureCreatedAsync());
        await AssertPhysicalSchemaAsync(db, "utf8mb4");
        await InsertAndReadMaximumAsync(db);
    }

    [Fact]
    public async Task ExistingUtf8mb4HistoryAndDataUpgradeWithoutNarrowingOrCharsetChanges()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.GetService<IMigrator>().MigrateAsync(Previous);
        // A valid legacy workaround kept headers off-row but bounded the hex columns.
        // The impossible four-VARCHAR utf8mb4 definition is the separate negative below.
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange MODIFY request_preview_hex VARCHAR(4096) NULL, MODIFY response_preview_hex VARCHAR(4096) NULL");
        var (id, before) = await InsertAndReadMaximumAsync(db);
        var indexes = await IndexesAsync(db);
        await db.Database.MigrateAsync();
        Assert.Equal(before, await ReadAsync(db, id));
        Assert.Equal(indexes, await IndexesAsync(db));
        await AssertPhysicalSchemaAsync(db, "utf8mb4");
        await db.Database.MigrateAsync();
        Assert.Equal(before, await ReadAsync(db, id));
    }

    [Fact]
    public async Task ValidLegacyLatin1VarcharsUpgradeWithoutLosingDataOrChangingCharset()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.GetService<IMigrator>().MigrateAsync(Previous);
        // Fixture only: latin1 supports the original layout. The repair must not change
        // either table's character set to evade utf8mb4 row limits.
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange CONVERT TO CHARACTER SET latin1 COLLATE latin1_swedish_ci");
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange MODIFY request_headers VARCHAR(8192) NULL, MODIFY response_headers VARCHAR(8192) NULL, MODIFY request_preview_hex VARCHAR(4096) NULL, MODIFY response_preview_hex VARCHAR(4096) NULL");
        var record = new HttpTrafficExchange { ClientId = 1001, ClientName = "legacy", Route = "legacy", RequestHeaders = new string('é', 8192), ResponseHeaders = new string('à', 8192), RequestPreviewHex = new string('A', 4096), ResponsePreviewHex = new string('F', 4096), CapturedAt = DateTimeOffset.UtcNow };
        db.HttpTrafficExchanges.Add(record);
        await db.SaveChangesAsync();
        var before = await ReadAsync(db, record.Id);
        await db.Database.MigrateAsync();
        Assert.Equal(before, await ReadAsync(db, record.Id));
        await AssertPhysicalSchemaAsync(db, "latin1");
    }

    [Fact]
    public async Task ExplicitColumnCharacterSetAndCollationSurviveTheUpgrade()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.GetService<IMigrator>().MigrateAsync(Previous);
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange CONVERT TO CHARACTER SET latin1 COLLATE latin1_swedish_ci");
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange MODIFY request_headers LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL");
        var record = new HttpTrafficExchange { ClientId = 1001, ClientName = "mixed", Route = "mixed", RequestHeaders = new string('请', 8192), CapturedAt = DateTimeOffset.UtcNow };
        db.HttpTrafficExchanges.Add(record);
        await db.SaveChangesAsync();
        var before = await ReadAsync(db, record.Id);
        await db.Database.MigrateAsync();
        Assert.Equal(before, await ReadAsync(db, record.Id));
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = "SELECT COLLATION_NAME FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='specus_http_traffic_exchange' AND column_name='request_headers'";
            Assert.Equal("utf8mb4_bin", Convert.ToString(await command.ExecuteScalarAsync()));
        }
        finally { await db.Database.CloseConnectionAsync(); }
    }

    [Fact]
    public async Task OriginalFourVarcharDefinitionFailsOnRealStrictUtf8mb4()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        // Restore ONLY the four original physical types in the historical CREATE operation.
        // This is the definition captured in #276, not an artificially larger row.
        var migrations = db.GetService<IMigrationsAssembly>();
        var type = migrations.Migrations["20260624185209_AddManagementAndTrafficDetailSchema"];
        var migration = migrations.CreateMigration(type, db.Database.ProviderName!);
        var create = migration.UpOperations.OfType<Microsoft.EntityFrameworkCore.Migrations.Operations.CreateTableOperation>().Single(op => op.Name == "specus_http_traffic_exchange");
        foreach (var column in create.Columns.Where(c => WideColumns.Contains(c.Name)))
            column.ColumnType = column.Name.EndsWith("headers", StringComparison.Ordinal) ? "varchar(8192)" : "varchar(4096)";
        var sql = db.GetService<IMigrationsSqlGenerator>().Generate([create]).Single().CommandText;
        Assert.Contains("varchar(8192)", sql);
        var failure = await Assert.ThrowsAsync<MySqlException>(() => db.Database.ExecuteSqlRawAsync(sql));
        Assert.Equal(1118, failure.Number);
        Assert.Contains("65535", failure.Message);
    }

    [Fact]
    public async Task UnsafeDowngradeIsRefusedBeforeChangingDataOrHistory()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.Database.MigrateAsync();
        var (id, before) = await InsertAndReadMaximumAsync(db);
        var history = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        await Assert.ThrowsAsync<NotSupportedException>(() => db.GetService<IMigrator>().MigrateAsync(Previous));
        Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal(before, await ReadAsync(db, id));
    }

    private static Task<TestServerFixture> StartAsync(OwnedDatabase database) => TestServerFixture.StartAsync(new Dictionary<string, string?>
    {
        ["Specus:Database:Provider"] = "mysql",
        ["ConnectionStrings:Specus"] = database.ConnectionString,
        ["Specus:Database:SeedDemoClient"] = "false",
    });

    private static async Task<(long Id, string Json)> InsertAndReadMaximumAsync(SpecusDbContext db)
    {
        var record = new HttpTrafficExchange
        {
            TenantId = new string('租', 80),
            ClientId = 1001,
            ClientName = new string('端', 120),
            Route = new string('r', 128),
            ResourceName = new string('资', 255),
            Method = new string('M', 16),
            RelativePath = new string('路', 1024),
            RawQuery = new string('查', 2048),
            Error = new string('错', 2048),
            RemoteAddress = new string('a', 255),
            RequestContentType = new string('a', 255),
            ResponseContentType = new string('b', 255),
            ResponseBodyType = "TEXT",
            RequestHeaders = new string('请', 8192),
            ResponseHeaders = new string('回', 8192),
            RequestPreviewHex = new string('A', 4096),
            ResponsePreviewHex = new string('F', 4096),
            RequestPreviewText = string.Concat(Enumerable.Repeat("请求😀", 4096)),
            ResponsePreviewText = string.Concat(Enumerable.Repeat("响应🌍", 4096)),
            RequestBodyData = Enumerable.Range(0, 131072).Select(n => (byte)n).ToArray(),
            ResponseBodyData = Enumerable.Range(0, 131072).Select(n => (byte)(255 - n)).ToArray(),
            CapturedAt = DateTimeOffset.UtcNow,
        };
        db.HttpTrafficExchanges.Add(record);
        await db.SaveChangesAsync();
        var expected = JsonSerializer.Serialize(record);
        Assert.Equal(expected, await ReadAsync(db, record.Id));
        return (record.Id, expected);
    }

    private static async Task<string> ReadAsync(SpecusDbContext db, long id) => JsonSerializer.Serialize(await db.HttpTrafficExchanges.AsNoTracking().SingleAsync(r => r.Id == id));

    private static async Task AssertPhysicalSchemaAsync(SpecusDbContext db, string charset)
    {
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = "SELECT @@SESSION.sql_mode";
            Assert.Contains("STRICT_TRANS_TABLES", Convert.ToString(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT COLUMN_NAME,DATA_TYPE,CHARACTER_SET_NAME FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='specus_http_traffic_exchange' AND column_name IN ('request_headers','response_headers','request_preview_hex','response_preview_hex') ORDER BY column_name";
            await using var reader = await command.ExecuteReaderAsync();
            var count = 0;
            while (await reader.ReadAsync()) { Assert.Equal("longtext", reader.GetString(1)); Assert.Equal(charset, reader.GetString(2)); count++; }
            Assert.Equal(4, count);
        }
        finally { await db.Database.CloseConnectionAsync(); }
    }

    private static async Task<string> IndexesAsync(SpecusDbContext db)
    {
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = "SELECT INDEX_NAME,COLUMN_NAME,SEQ_IN_INDEX FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='specus_http_traffic_exchange' ORDER BY INDEX_NAME,SEQ_IN_INDEX";
            await using var reader = await command.ExecuteReaderAsync();
            List<string> rows = [];
            while (await reader.ReadAsync()) rows.Add($"{reader.GetString(0)}:{reader.GetString(1)}:{reader.GetInt32(2)}");
            return string.Join("|", rows);
        }
        finally { await db.Database.CloseConnectionAsync(); }
    }

    private sealed class OwnedDatabase(string adminConnection, string name, string connectionString) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;
        public SpecusDbContext Context() => new(new DbContextOptionsBuilder<SpecusDbContext>().UseMySQL(ConnectionString, o => o.MigrationsAssembly("Specus.Server.Data.MySql")).Options);

        public static async Task<OwnedDatabase> CreateAsync()
        {
            var configured = Environment.GetEnvironmentVariable("SPECUS_TEST_MYSQL_CONNECTION");
            Assert.False(string.IsNullOrWhiteSpace(configured), "SPECUS_TEST_MYSQL_CONNECTION must point to an owned loopback test instance; these tests do not skip without MySQL.");
            var settings = new MySqlConnectionStringBuilder(configured!) { Database = "mysql", Pooling = false };
            Assert.Contains(settings.Server, new[] { "127.0.0.1", "localhost" });
            await using var connection = new MySqlConnection(settings.ConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            if (Environment.GetEnvironmentVariable("SPECUS_TEST_MYSQL_EXPECTED_DATA_DIR") is { Length: > 0 } expected)
            {
                command.CommandText = "SELECT @@datadir";
                var actual = Convert.ToString(await command.ExecuteScalarAsync())!;
                Assert.Equal(Path.GetFullPath(expected).TrimEnd('/', '\\'), Path.GetFullPath(actual).TrimEnd('/', '\\'), ignoreCase: OperatingSystem.IsWindows());
            }
            var name = "specus_276_" + Guid.NewGuid().ToString("N");
            command.CommandText = $"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci";
            await command.ExecuteNonQueryAsync();
            var admin = settings.ConnectionString;
            settings.Database = name;
            return new OwnedDatabase(admin, name, settings.ConnectionString);
        }

        public async ValueTask DisposeAsync()
        {
            if (!Regex.IsMatch(name, "^specus_276_[0-9a-f]{32}$", RegexOptions.CultureInvariant)) throw new InvalidOperationException("Refuse to drop an unowned database name");
            await using var connection = new MySqlConnection(adminConnection);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE `{name}`";
            await command.ExecuteNonQueryAsync();
        }
    }
}
