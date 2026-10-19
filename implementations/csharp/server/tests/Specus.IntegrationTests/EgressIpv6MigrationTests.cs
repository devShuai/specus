using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

public sealed class EgressIpv6MigrationTests
{
    [Fact]
    public async Task LegacySessionDefaultsFalseAndRollbackRetainsDeclarationsAndHistory()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(connection).Options);
        const string previous = "20261013031414_BindManagementWebSocketAccount";
        await db.GetService<IMigrator>().MigrateAsync(previous);
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO specus_client_session
            (Id, tenant_id, credential_id, identity_id, client_id, client_name, token_hash, status,
             machine_fingerprint, os_user, message_send_capable, message_receive_capable,
             message_attachments_capable, message_media_preview_capable, message_max_attachment_bytes,
             peer_service_discovery_version, client_egress_version, client_egress_domain_targets,
             http_login_at, expires_at)
            VALUES (901, 'ipv6-upgrade', 1, 1, 1, 'legacy', 'ipv6-legacy-token', 'NETTY_ONLINE',
             'fixture-machine', 'fixture-user', 0, 0, 0, 0, 0, 0, 1, 0,
             '2026-10-18T00:00:00Z', '2026-10-19T00:00:00Z')
            """);
        await db.Database.MigrateAsync();
        var legacy = await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 901);
        Assert.False(legacy.ClientEgressIpv6Targets);
        Assert.Equal("ipv6-legacy-token", legacy.TokenHash);
        db.ClientSessions.Add(new ClientSession
        {
            Id = 902, TenantId = "ipv6-upgrade", CredentialId = 1, IdentityId = 1, ClientId = 1,
            ClientName = "current", TokenHash = "ipv6-current-token", Status = "NETTY_ONLINE",
            MachineFingerprint = "fixture-machine", OsUser = "fixture-user",
            ClientEgressVersion = 1, ClientEgressIpv6Targets = true,
            HttpLoginAt = DateTimeOffset.Parse("2026-10-18T00:01:00Z"),
            ExpiresAt = DateTimeOffset.Parse("2026-10-19T00:00:00Z"),
        });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var history = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        await Assert.ThrowsAsync<NotSupportedException>(() => db.GetService<IMigrator>().MigrateAsync(previous));
        Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync());
        Assert.False((await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 901)).ClientEgressIpv6Targets);
        Assert.True((await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 902)).ClientEgressIpv6Targets);
        // A refused downgrade must not strand EF's SQLite migration lock. Bound this
        // new recovery assertion so a retained lock is a failure, not an endless test.
        using var recoveryDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await db.Database.MigrateAsync(recoveryDeadline.Token);
        Assert.False(db.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task LegacySessionPacketsDefaultFalseAndRollbackRetainsDeclarationsAndHistory()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
            .UseSqlite(connection).Options);
        const string previous = "20261017202442_PersistClientEgressIpv6Targets";
        await db.GetService<IMigrator>().MigrateAsync(previous);
        // A pre-column row that declared IPv6 targets must not be read as declaring IPv6 packets.
        await db.Database.ExecuteSqlRawAsync("""
            INSERT INTO specus_client_session
            (Id, tenant_id, credential_id, identity_id, client_id, client_name, token_hash, status,
             machine_fingerprint, os_user, message_send_capable, message_receive_capable,
             message_attachments_capable, message_media_preview_capable, message_max_attachment_bytes,
             peer_service_discovery_version, client_egress_version, client_egress_domain_targets,
             client_egress_ipv6_targets, http_login_at, expires_at)
            VALUES (911, 'ipv6-packet-upgrade', 1, 1, 1, 'legacy', 'ipv6-packet-legacy-token', 'NETTY_ONLINE',
             'fixture-machine', 'fixture-user', 0, 0, 0, 0, 0, 0, 1, 0, 1,
             '2026-10-18T00:00:00Z', '2026-10-19T00:00:00Z')
            """);
        await db.Database.MigrateAsync();
        var legacy = await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 911);
        Assert.False(legacy.ClientEgressIpv6Packets);
        Assert.True(legacy.ClientEgressIpv6Targets);
        Assert.Equal("ipv6-packet-legacy-token", legacy.TokenHash);
        db.ClientSessions.Add(new ClientSession
        {
            Id = 912, TenantId = "ipv6-packet-upgrade", CredentialId = 1, IdentityId = 1, ClientId = 1,
            ClientName = "current", TokenHash = "ipv6-packet-current-token", Status = "NETTY_ONLINE",
            MachineFingerprint = "fixture-machine", OsUser = "fixture-user",
            ClientEgressVersion = 1, ClientEgressIpv6Packets = true,
            HttpLoginAt = DateTimeOffset.Parse("2026-10-18T00:01:00Z"),
            ExpiresAt = DateTimeOffset.Parse("2026-10-19T00:00:00Z"),
        });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var current = await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 912);
        Assert.True(current.ClientEgressIpv6Packets);
        Assert.False(current.ClientEgressIpv6Targets);
        var history = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        await Assert.ThrowsAsync<NotSupportedException>(() => db.GetService<IMigrator>().MigrateAsync(previous));
        Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync());
        Assert.False((await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 911)).ClientEgressIpv6Packets);
        Assert.True((await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == 912)).ClientEgressIpv6Packets);
        using var recoveryDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await db.Database.MigrateAsync(recoveryDeadline.Token);
        Assert.False(db.Database.HasPendingModelChanges());
    }
}
