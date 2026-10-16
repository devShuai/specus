using System.Diagnostics;
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
using Specus.Server.Data.MySql;

namespace Specus.IntegrationTests;

public sealed class MariaDbCompatibilityTests
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
            ["Specus:Database:Provider"] = "mariadb", ["ConnectionStrings:Specus"] = database.ConnectionString,
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

    [Fact]
    public async Task OriginalDriverFailureAndBootstrapOnlyMetadataAdaptationAreReal()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        // Some MariaDB builds automatically mask NULL IDs for Connector/NET. Expose
        // the real underlying metadata on ONLY these test connections, without
        // mocking reader results or relying on an OS-specific handshake heuristic.
        var testHook = typeof(UnmaskedMariaDbMetadataInterceptor);
        var original = new MySqlConnectionStringBuilder(database.ConnectionString)
        {
            CommandInterceptors = $"{testHook.FullName}, {testHook.Assembly.GetName().Name}",
        };
        await using (var raw = new MySqlConnection(original.ConnectionString))
            await Assert.ThrowsAsync<InvalidCastException>(() => raw.OpenAsync());

        await using var connection = new MySqlConnection(MySqlDatabaseCompatibility.PrepareConnectionString(original.ConnectionString));
        await connection.OpenAsync();
        Assert.True(await NullCollationsAsync(connection) > 0, "Ordinary SHOW COLLATION must retain MariaDB's NULL mappings after Open.");
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT @@character_set_client,@@character_set_connection,@@character_set_results";
        await using (var reader = await command.ExecuteReaderAsync())
        {
            Assert.True(await reader.ReadAsync());
            for (int column = 0; column < 2; column++) Assert.Equal("utf8mb4", reader.GetString(column));
            // Oracle's driver deliberately sets character_set_results=NULL so each
            // result retains its actual column charset (Driver.ExecuteCharacterSetCommands).
            Assert.True(reader.IsDBNull(2));
        }
        command.CommandText = "SELECT GET_LOCK('__EFMigrationsLock',-1)";
        Assert.IsType<DBNull>(await command.ExecuteScalarAsync());
        command.CommandText = "SHOW WARNINGS";
        await using var warnings = await command.ExecuteReaderAsync();
        bool unsupportedTimeout = false;
        while (await warnings.ReadAsync()) unsupportedTimeout |= warnings.GetInt32(1) == 1411;
        Assert.True(unsupportedTimeout, "The original negative lock timeout must not be misreported as an acquisition.");
    }

    [Fact]
    public async Task SyncAndPooledReopensPreserveOrdinaryQueriesAndUnicode()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        var settings = new MySqlConnectionStringBuilder(database.ConnectionString) { Pooling = true, MaximumPoolSize = 1 };
        using var connection = new MySqlConnection(settings.ConnectionString);
        try
        {
            int? expectedNulls = null;
            for (int iteration = 0; iteration < 5; iteration++)
            {
                if (iteration % 2 == 0) connection.Open(); else await connection.OpenAsync();
                // Real user SQL after Open: the production hook must not re-mask
                // or filter subsequent ordinary metadata queries on either OS.
                using (var unmask = connection.CreateCommand())
                {
                    unmask.CommandText = "SET SESSION old_mode=''";
                    unmask.ExecuteNonQuery();
                }
                int nulls = await NullCollationsAsync(connection);
                Assert.True(nulls > 0);
                expectedNulls ??= nulls;
                Assert.Equal(expectedNulls.Value, nulls);
                using var command = connection.CreateCommand();
                command.CommandText = "SELECT @unicode";
                command.Parameters.AddWithValue("@unicode", "请求😀响应🌍");
                Assert.Equal("请求😀响应🌍", Convert.ToString(command.ExecuteScalar()));
                connection.Close();
            }
        }
        finally
        {
            connection.Close();
            // Never clear unrelated application/test pools.
            MySqlConnection.ClearPool(connection);
        }
    }

    [Fact]
    public async Task FullProductionBootstrapAndRestartPreserveMaximumUnicodeTraffic()
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
            Assert.Contains(Repair, await db.Database.GetAppliedMigrationsAsync());
            (id, before) = await InsertMaximumAsync(db);
        }
        await using (var restarted = await StartAsync(database))
        {
            await using var scope = restarted.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(before, await ReadAsync(db, id));
            Assert.False(db.Database.HasPendingModelChanges());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProductionStartupCreatesAMissingDatabaseAndPreservesUnicode(bool quotedName)
    {
        await using var database = await OwnedDatabase.CreateAsync(create: false, quotedName: quotedName);
        string serverCharset = await database.ServerCharsetAsync();
        await using var server = await StartAsync(database);
        using var client = server.CreateClient();
        using var health = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Contains(Repair, await db.Database.GetAppliedMigrationsAsync());
        await InsertMaximumAsync(db);
        Assert.Equal(serverCharset, await database.ServerCharsetAsync());
    }

    [Fact]
    public async Task EnsureCreatedPreservesTheFullSharedModel()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        Assert.True(await db.Database.EnsureCreatedAsync());
        await InsertMaximumAsync(db);
        Assert.False(db.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task ExistingUtf8HistoryUpgradesIdempotentlyWithoutLosingMaximumData()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.GetService<IMigrator>().MigrateAsync(Previous);
        // A valid legacy workaround, not the impossible original four-wide-VARCHAR schema.
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange MODIFY request_preview_hex VARCHAR(4096) NULL, MODIFY response_preview_hex VARCHAR(4096) NULL");
        var (id, before) = await InsertMaximumAsync(db);
        await db.Database.MigrateAsync();
        Assert.Contains(Repair, await db.Database.GetAppliedMigrationsAsync());
        Assert.Equal(before, await ReadAsync(db, id));
        await db.Database.MigrateAsync();
        Assert.Equal(before, await ReadAsync(db, id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyLatin1AndExplicitMixedColumnCharsetsSurviveUpgrade(bool mixed)
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.GetService<IMigrator>().MigrateAsync(Previous);
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange CONVERT TO CHARACTER SET latin1 COLLATE latin1_swedish_ci");
        await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange MODIFY request_headers VARCHAR(8192) NULL, MODIFY response_headers VARCHAR(8192) NULL, MODIFY request_preview_hex VARCHAR(4096) NULL, MODIFY response_preview_hex VARCHAR(4096) NULL");
        if (mixed)
            await db.Database.ExecuteSqlRawAsync("ALTER TABLE specus_http_traffic_exchange MODIFY request_headers LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL");
        var record = new HttpTrafficExchange
        {
            ClientId = 1001, ClientName = "legacy", Route = "legacy", CapturedAt = DateTimeOffset.UtcNow,
            RequestHeaders = new string(mixed ? '请' : 'é', 8192), ResponseHeaders = new string('à', 8192),
            RequestPreviewHex = new string('A', 4096), ResponsePreviewHex = new string('F', 4096),
        };
        db.HttpTrafficExchanges.Add(record);
        await db.SaveChangesAsync();
        string before = JsonSerializer.Serialize(record);
        await db.Database.MigrateAsync();
        Assert.Equal(before, await ReadAsync(db, record.Id));
        await db.Database.OpenConnectionAsync();
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT COLLATION_NAME FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='specus_http_traffic_exchange' AND column_name='request_headers'";
        Assert.Equal(mixed ? "utf8mb4_bin" : "latin1_swedish_ci", Convert.ToString(await command.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task RealTransactionsCommitAndRollbackWithoutUnicodeLoss()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var db = database.Context();
        await db.Database.MigrateAsync();
        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            await InsertMaximumAsync(db);
            await transaction.RollbackAsync();
        }
        db.ChangeTracker.Clear();
        Assert.Empty(await db.HttpTrafficExchanges.ToListAsync());
        long id;
        string before;
        await using (var transaction = await db.Database.BeginTransactionAsync())
        {
            (id, before) = await InsertMaximumAsync(db);
            await transaction.CommitAsync();
        }
        await using var other = database.Context();
        Assert.Equal(before, await ReadAsync(other, id));
    }

    [Fact]
    public async Task OccupiedMigrationLockFailsClosedAndCancelsWithoutReleasingForeignOwner()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        await using var owner = new MySqlConnection(database.ConnectionString);
        await owner.OpenAsync();
        await using var command = owner.CreateCommand();
        command.CommandText = "SELECT GET_LOCK('__EFMigrationsLock',0)";
        Assert.Equal(1, Convert.ToInt64(await command.ExecuteScalarAsync()));
        try
        {
            foreach (bool async in new[] { false, true })
            {
                await using var contender = database.Context();
                await contender.Database.OpenConnectionAsync();
                contender.Database.SetCommandTimeout(1);
                var repository = contender.GetService<IHistoryRepository>();
                var started = Stopwatch.GetTimestamp();
                if (async)
                    await Assert.ThrowsAsync<TimeoutException>(async () => { await using var illegal = await repository.AcquireDatabaseLockAsync(); });
                else
                    Assert.Throws<TimeoutException>(() => { using var illegal = repository.AcquireDatabaseLock(); });
                Assert.InRange(Stopwatch.GetElapsedTime(started), TimeSpan.FromMilliseconds(900), TimeSpan.FromSeconds(10));
            }
            await using (var contender = database.Context())
            {
                await contender.Database.OpenConnectionAsync();
                contender.Database.SetCommandTimeout(0);
                using var cancellation = new CancellationTokenSource();
                var pending = contender.GetService<IHistoryRepository>().AcquireDatabaseLockAsync(cancellation.Token);
                await Task.Delay(200);
                Assert.False(pending.IsCompleted, "An occupied real lock cannot be reported acquired.");
                cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => { await using var illegal = await pending.WaitAsync(TimeSpan.FromSeconds(10)); });
            }
            command.CommandText = "SELECT IS_USED_LOCK('__EFMigrationsLock')=CONNECTION_ID()";
            Assert.Equal(1, Convert.ToInt64(await command.ExecuteScalarAsync()));
            command.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()";
            Assert.Equal(0, Convert.ToInt64(await command.ExecuteScalarAsync()));
        }
        finally
        {
            command.CommandText = "SELECT RELEASE_LOCK('__EFMigrationsLock')";
            Assert.Equal(1, Convert.ToInt64(await command.ExecuteScalarAsync()));
        }
        await using (var acquired = database.Context())
        {
            await acquired.Database.OpenConnectionAsync();
            await using var held = await acquired.GetService<IHistoryRepository>().AcquireDatabaseLockAsync();
            command.CommandText = "SELECT IS_FREE_LOCK('__EFMigrationsLock')";
            Assert.Equal(0, Convert.ToInt64(await command.ExecuteScalarAsync()));
        }
        command.CommandText = "SELECT IS_FREE_LOCK('__EFMigrationsLock')";
        Assert.Equal(1, Convert.ToInt64(await command.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task SynchronousMigrationAcquiresAndReleasesTheActualLock()
    {
        await using var database = await OwnedDatabase.CreateAsync();
        using (var db = database.Context())
        {
            db.Database.Migrate();
            Assert.Contains(Repair, db.Database.GetAppliedMigrations());
            Assert.False(db.Database.HasPendingModelChanges());
            await InsertMaximumAsync(db);
        }
        await using var observer = new MySqlConnection(database.ConnectionString);
        await observer.OpenAsync();
        await using var command = observer.CreateCommand();
        command.CommandText = "SELECT IS_FREE_LOCK('__EFMigrationsLock')";
        Assert.Equal(1, Convert.ToInt64(await command.ExecuteScalarAsync()));
    }

    private static Task<TestServerFixture> StartAsync(OwnedDatabase database) => TestServerFixture.StartAsync(new Dictionary<string, string?>
    {
        ["Specus:Database:Provider"] = "mariadb",
        ["ConnectionStrings:Specus"] = database.ConnectionString,
        ["Specus:Database:SeedDemoClient"] = "false",
    });

    private static async Task<int> NullCollationsAsync(MySqlConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SHOW COLLATION";
        await using var reader = await command.ExecuteReaderAsync();
        int nulls = 0;
        while (await reader.ReadAsync())
            if (reader.IsDBNull(reader.GetOrdinal("Id")) || reader.IsDBNull(reader.GetOrdinal("Charset"))) nulls++;
        return nulls;
    }

    private static async Task<(long Id, string Json)> InsertMaximumAsync(SpecusDbContext db)
    {
        var record = new HttpTrafficExchange
        {
            TenantId = new string('租', 80), ClientId = 1001, ClientName = new string('端', 120), Route = new string('r', 128),
            ResourceName = new string('资', 255), Method = new string('M', 16), RelativePath = new string('路', 1024),
            RawQuery = new string('查', 2048), Error = new string('错', 2048), RemoteAddress = new string('a', 255),
            RequestContentType = new string('a', 255), ResponseContentType = new string('b', 255), ResponseBodyType = "TEXT",
            RequestHeaders = new string('请', 8192), ResponseHeaders = new string('回', 8192),
            RequestPreviewHex = new string('A', 4096), ResponsePreviewHex = new string('F', 4096),
            RequestPreviewText = string.Concat(Enumerable.Repeat("请求😀", 4096)), ResponsePreviewText = string.Concat(Enumerable.Repeat("响应🌍", 4096)),
            RequestBodyData = Enumerable.Range(0, 131072).Select(n => (byte)n).ToArray(),
            ResponseBodyData = Enumerable.Range(0, 131072).Select(n => (byte)(255 - n)).ToArray(), CapturedAt = DateTimeOffset.UtcNow,
        };
        db.HttpTrafficExchanges.Add(record);
        await db.SaveChangesAsync();
        string before = JsonSerializer.Serialize(record);
        Assert.Equal(before, await ReadAsync(db, record.Id));
        return (record.Id, before);
    }

    private static async Task<string> ReadAsync(SpecusDbContext db, long id) => JsonSerializer.Serialize(await db.HttpTrafficExchanges.AsNoTracking().SingleAsync(row => row.Id == id));

    private sealed class OwnedDatabase(string adminConnection, string name, string connectionString) : IAsyncDisposable
    {
        public string ConnectionString { get; } = connectionString;

        public async Task<string> ServerCharsetAsync()
        {
            await using var connection = new MySqlConnection(adminConnection);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT @@character_set_server";
            return Convert.ToString(await command.ExecuteScalarAsync())!;
        }

        public SpecusDbContext Context()
        {
            var options = new DbContextOptionsBuilder<SpecusDbContext>();
            MySqlDatabaseCompatibility.Configure(options, ConnectionString);
            return new SpecusDbContext(options.Options);
        }

        public static async Task<OwnedDatabase> CreateAsync(bool create = true, bool quotedName = false)
        {
            var configured = Environment.GetEnvironmentVariable("SPECUS_TEST_MARIADB_CONNECTION");
            Assert.False(string.IsNullOrWhiteSpace(configured), "SPECUS_TEST_MARIADB_CONNECTION must point to an owned loopback test MariaDB; these tests never skip.");
            var settings = new MySqlConnectionStringBuilder(configured!) { Database = "mysql", Pooling = false };
            Assert.Contains(settings.Server, new[] { "127.0.0.1", "localhost" });
            string admin = MySqlDatabaseCompatibility.PrepareConnectionString(settings.ConnectionString);
            await using var connection = new MySqlConnection(admin);
            await connection.OpenAsync();
            Assert.Contains("MariaDB", connection.ServerVersion, StringComparison.OrdinalIgnoreCase);
            await using var command = connection.CreateCommand();
            if (Environment.GetEnvironmentVariable("SPECUS_TEST_MARIADB_EXPECTED_DATA_DIR") is { Length: > 0 } expected)
            {
                command.CommandText = "SELECT @@datadir";
                var actual = Convert.ToString(await command.ExecuteScalarAsync())!;
                Assert.Equal(Path.GetFullPath(expected).TrimEnd('/', '\\'), Path.GetFullPath(actual).TrimEnd('/', '\\'), ignoreCase: OperatingSystem.IsWindows());
            }
            string name = "specus_277_" + Guid.NewGuid().ToString("N") + (quotedName ? "`quoted" : "");
            if (create)
            {
                command.CommandText = $"CREATE DATABASE `{name.Replace("`", "``", StringComparison.Ordinal)}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
                await command.ExecuteNonQueryAsync();
            }
            else
            {
                command.CommandText = "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=@name";
                command.Parameters.AddWithValue("@name", name);
                Assert.Equal(0, Convert.ToInt64(await command.ExecuteScalarAsync()));
            }
            settings.Database = name;
            return new OwnedDatabase(admin, name, MySqlDatabaseCompatibility.PrepareConnectionString(settings.ConnectionString));
        }

        public async ValueTask DisposeAsync()
        {
            if (!Regex.IsMatch(name, "^specus_277_[0-9a-f]{32}(?:`quoted)?$", RegexOptions.CultureInvariant)) throw new InvalidOperationException("Refuse to drop an unowned database.");
            await using var connection = new MySqlConnection(adminConnection);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"DROP DATABASE IF EXISTS `{name.Replace("`", "``", StringComparison.Ordinal)}`";
            await command.ExecuteNonQueryAsync();
        }
    }
}
