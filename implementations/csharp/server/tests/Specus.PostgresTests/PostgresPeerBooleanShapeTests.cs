using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

public sealed partial class PostgresBootstrapTests
{
    private static readonly (string Table, string Column)[] PeerFlags =
    [
        ("peer_mesh_acl", "allowed"), ("peer_mesh_device", "enabled"),
        ("peer_mesh_service_sharing", "enabled"), ("peer_mesh_service_sharing", "mdns_import_enabled"),
        ("peer_mesh_shared_service", "enabled"),
    ];

    [Fact]
    public async Task NativePeerBootstrapNormalizesAndValidatesBooleanShape()
    {
        foreach (var defaultValue in new[] { 0, 1 })
        {
            await using var database = await OwnedDatabase.CreateAsync();
            await using var db = database.Context();
            await SeedPeerFlagsAsync(db);
            var originalData = await PeerFlagDataAsync(db);
            var originalIndexes = await PeerFlagIndexesAsync(db);
            await MakeLegacyPeerFlagsAsync(db, defaultValue);
            Assert.Contains("smallint", await PeerFlagShapeAsync(db));
            await DatabaseInitializer.EnsurePeerMeshTablesAsync(db, CancellationToken.None);
            using var shape = JsonDocument.Parse(await PeerFlagShapeAsync(db));
            Assert.Equal(5, shape.RootElement.GetArrayLength());
            foreach (var column in shape.RootElement.EnumerateArray())
            {
                Assert.Equal("boolean", column.GetProperty("type").GetString());
                Assert.Equal(defaultValue == 0 ? "false" : "true", column.GetProperty("default").GetString());
                Assert.True(column.GetProperty("notNull").GetBoolean());
            }
            Assert.Equal(originalData, await PeerFlagDataAsync(db));
            Assert.Equal(originalIndexes, await PeerFlagIndexesAsync(db));
            var once = await SnapshotPeerFlagsAsync(db);
            await DatabaseInitializer.EnsurePeerMeshTablesAsync(db, CancellationToken.None);
            Assert.Equal(once, await SnapshotPeerFlagsAsync(db));
            db.ChangeTracker.Clear();
            var sharing = await db.PeerMeshServiceSharings.SingleAsync();
            Assert.False(sharing.Enabled); Assert.True(sharing.MdnsImportEnabled);
            sharing.Enabled = true; sharing.MdnsImportEnabled = false;
            await db.SaveChangesAsync();
            var stored = await db.PeerMeshServiceSharings.AsNoTracking().SingleAsync();
            Assert.True(stored.Enabled); Assert.False(stored.MdnsImportEnabled);
        }
        foreach (var invalid in new[] { "value", "null", "default", "type" })
        {
            await using var database = await OwnedDatabase.CreateAsync();
            await using var db = database.Context();
            await SeedPeerFlagsAsync(db);
            await MakeLegacyPeerFlagsAsync(db, 0);
            // The last validated table is corrupt: even earlier valid columns must remain
            // untouched when validation refuses the whole conversion.
            var sql = invalid switch
            {
                "value" => "UPDATE peer_mesh_shared_service SET enabled=2",
                "null" => "ALTER TABLE peer_mesh_shared_service ALTER COLUMN enabled DROP NOT NULL; UPDATE peer_mesh_shared_service SET enabled=NULL",
                "default" => "ALTER TABLE peer_mesh_shared_service ALTER COLUMN enabled SET DEFAULT 2",
                _ => "ALTER TABLE peer_mesh_shared_service ALTER COLUMN enabled DROP DEFAULT; ALTER TABLE peer_mesh_shared_service ALTER COLUMN enabled TYPE INTEGER USING enabled::INTEGER",
            };
            await db.Database.ExecuteSqlRawAsync(sql);
            var before = await SnapshotPeerFlagsAsync(db);
            var error = await Assert.ThrowsAsync<PostgresException>(() => DatabaseInitializer.EnsurePeerMeshTablesAsync(db, CancellationToken.None));
            Assert.Equal(PostgresErrorCodes.RaiseException, error.SqlState);
            Assert.Equal(before, await SnapshotPeerFlagsAsync(db));
        }
    }

    private static async Task SeedPeerFlagsAsync(SpecusDbContext db)
    {
        await db.Database.MigrateAsync();
        // Missing mdns_import_enabled is added by the compatibility initializer, not by
        // the historical EF migration. The actual resulting shape must match the model.
        await DatabaseInitializer.EnsurePeerMeshTablesAsync(db, CancellationToken.None);
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 6801, TenantId = "peer-flags", OwnerUsername = "alice", ClientId = 6001, ClientName = "flag-source", Enabled = true, VirtualIp = "10.66.0.3", Cidr = "10.66.0.0/16", PublicKey = "fixture-public-key" });
        db.PeerMeshAcls.Add(new PeerMeshAcl { Id = 6802, TenantId = "peer-flags", OwnerUsername = "alice", SourceClientId = 6001, SourceClientName = "flag-source", TargetClientId = 6002, TargetClientName = "flag-target", Allowed = false, Direction = "BOTH" });
        db.PeerMeshServiceSharings.Add(new PeerMeshServiceSharing { TenantId = "peer-flags", Enabled = false, MdnsImportEnabled = true, UpdatedBy = "fixture", UpdatedAt = DateTimeOffset.UtcNow });
        db.PeerMeshSharedServices.Add(new PeerMeshSharedService { Id = 6803, TenantId = "peer-flags", ClientId = 6001, ClientName = "flag-source", ServiceId = "flag-service", Name = "flag-service", Enabled = true, TargetHost = "127.0.0.1", TargetPort = 8080, PublishedPort = 18080 });
        await db.SaveChangesAsync();
        using var shape = JsonDocument.Parse(await PeerFlagShapeAsync(db));
        Assert.All(shape.RootElement.EnumerateArray(), column => Assert.Equal("boolean", column.GetProperty("type").GetString()));
    }

    private static async Task MakeLegacyPeerFlagsAsync(SpecusDbContext db, int defaultValue)
    {
        if (defaultValue is not (0 or 1)) throw new ArgumentOutOfRangeException(nameof(defaultValue));
        var quoting = db.GetService<ISqlGenerationHelper>();
        foreach (var (table, column) in PeerFlags)
        {
            // Identifiers come only from the closed fixture list and are provider-quoted;
            // PostgreSQL DDL cannot bind identifiers/default syntax as value parameters.
            var target = quoting.DelimitIdentifier(table); var field = quoting.DelimitIdentifier(column);
            var ddl = $"ALTER TABLE {target} ALTER COLUMN {field} DROP DEFAULT; ALTER TABLE {target} ALTER COLUMN {field} TYPE SMALLINT USING (CASE WHEN {field} THEN 1 ELSE 0 END)::SMALLINT; ALTER TABLE {target} ALTER COLUMN {field} SET DEFAULT {defaultValue}";
            await db.Database.ExecuteSqlRawAsync(ddl);
        }
    }

    private static Task<string> PeerFlagShapeAsync(SpecusDbContext db) => ScalarAsync(db, """
        SELECT jsonb_agg(jsonb_build_object('table', c.relname, 'column', a.attname,
          'type', pg_catalog.format_type(a.atttypid,a.atttypmod),
          'default', pg_catalog.pg_get_expr(d.adbin,d.adrelid), 'notNull', a.attnotnull)
          ORDER BY c.relname,a.attname)::TEXT
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
        LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attnum>0 AND NOT a.attisdropped AND (a.attrelid,a.attname) IN (
          ('peer_mesh_acl'::regclass,'allowed'), ('peer_mesh_device'::regclass,'enabled'),
          ('peer_mesh_service_sharing'::regclass,'enabled'), ('peer_mesh_service_sharing'::regclass,'mdns_import_enabled'),
          ('peer_mesh_shared_service'::regclass,'enabled'))
        """);

    private static Task<string> PeerFlagDataAsync(SpecusDbContext db) => ScalarAsync(db, """
        SELECT jsonb_build_object(
          'device',(SELECT to_jsonb(t) FROM peer_mesh_device t WHERE tenant_id='peer-flags'),
          'acl',(SELECT to_jsonb(t) FROM peer_mesh_acl t WHERE tenant_id='peer-flags'),
          'sharing',(SELECT to_jsonb(t) FROM peer_mesh_service_sharing t WHERE tenant_id='peer-flags'),
          'service',(SELECT to_jsonb(t) FROM peer_mesh_shared_service t WHERE tenant_id='peer-flags'))::TEXT
        """);

    private static Task<string> PeerFlagIndexesAsync(SpecusDbContext db) => ScalarAsync(db, """
        SELECT COALESCE(jsonb_agg(jsonb_build_array(tablename,indexname,indexdef) ORDER BY tablename,indexname),'[]'::jsonb)::TEXT
        FROM pg_catalog.pg_indexes WHERE schemaname=current_schema()
          AND tablename IN ('peer_mesh_acl','peer_mesh_device','peer_mesh_service_sharing','peer_mesh_shared_service')
        """);

    private static async Task<(string Shape, string Data, string Indexes, string History)> SnapshotPeerFlagsAsync(SpecusDbContext db) =>
        (await PeerFlagShapeAsync(db), await PeerFlagDataAsync(db), await PeerFlagIndexesAsync(db), string.Join(',', await db.Database.GetAppliedMigrationsAsync()));
}
