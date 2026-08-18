using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Nat;

namespace Specus.IntegrationTests;

public sealed class Issue10TenantIsolationTests
{
    [Fact]
    public void RemotePortCountersRemainTenantScopedWhileAdmissionIsGlobal()
    {
        var options = Options.Create(new NettyServerOptions { MaxExternalConnections = 2 });
        var manager = new RemotePortServerManager(
            options, NullLoggerFactory.Instance, NullLogger<RemotePortServerManager>.Instance);

        Assert.True(manager.TryAcquireExternalConnection("tenant-a"));
        Assert.True(manager.TryAcquireExternalConnection("tenant-b"));
        Assert.False(manager.TryAcquireExternalConnection("tenant-a"));

        Assert.Equal(2, manager.ActiveExternalConnections);
        Assert.Equal(1, manager.ActiveExternalConnectionsForTenant("tenant-a"));
        Assert.Equal(1, manager.ActiveExternalConnectionsForTenant("tenant-b"));
        Assert.Equal(1, manager.RejectedExternalConnections);
        Assert.Equal(1, manager.RejectedExternalConnectionsForTenant("tenant-a"));
        Assert.Equal(0, manager.RejectedExternalConnectionsForTenant("tenant-b"));

        manager.ReleaseExternalConnection("tenant-a");
        Assert.True(manager.TryAcquireExternalConnection("tenant-a"));
        manager.ReleaseExternalConnection("tenant-a");
        manager.ReleaseExternalConnection("tenant-b");

        Assert.Equal(0, manager.ActiveExternalConnections);
        Assert.Equal(0, manager.ActiveExternalConnectionsForTenant("tenant-a"));
        Assert.Equal(0, manager.ActiveExternalConnectionsForTenant("tenant-b"));
    }

    [Fact]
    public async Task OverviewAndConnectionListUseStrictTenantAndRoleVisibility()
    {
        await using var server = await TestServerFixture.StartAsync();
        var manager = server.HostServices.GetRequiredService<RemotePortServerManager>();
        Assert.True(manager.TryAcquireExternalConnection("tenant-a"));
        Assert.True(manager.TryAcquireExternalConnection("tenant-b"));
        manager.RecordRejectedExternalConnection("tenant-a");
        manager.RecordRejectedExternalConnection("tenant-b");

        var now = DateTimeOffset.UtcNow;
        var aliceId = ClientIdGenerator.NewId();
        var bobId = ClientIdGenerator.NewId();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.ClientAccounts.AddRange(
                Account(aliceId, "tenant-a", "alice", "alice-client", now),
                Account(bobId, "tenant-b", "bob", "bob-client", now));
            db.ConnectionRecords.AddRange(
                Record("tenant-a", aliceId, "alice-client", true, now),
                Record("tenant-a", aliceId, "alice-client", false, now.AddSeconds(1)),
                Record("tenant-a", null, "unknown-a", false, now.AddSeconds(2)),
                Record("tenant-b", bobId, "bob-client", true, now.AddSeconds(3)),
                Record("tenant-b", null, "unknown-b", false, now.AddSeconds(4)),
                Record("default", null, "legacy-default", false, now.AddSeconds(5)));
            await db.SaveChangesAsync();
        }

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var query = scope.ServiceProvider.GetRequiredService<ManagementQueryService>();
            var adminA = new ManagementContext("tenant-a", "admin-a", ManagementRole.Admin, false);
            var overviewA = await query.GetOverviewAsync(adminA, CancellationToken.None);
            var connectionsA = await query.ListConnectionsAsync(
                adminA, null, null, null, null, 0, 100, CancellationToken.None);

            Assert.Equal(1, overviewA.SuccessfulConnections);
            Assert.Equal(2, overviewA.FailedConnections);
            Assert.Equal(1, overviewA.ExternalConnections);
            Assert.Equal(1, overviewA.RejectedExternalConnections);
            Assert.Equal(3, connectionsA.Total);
            Assert.Contains(connectionsA.Items, row => row.ClientId is null && row.ClientName == "unknown-a");
            Assert.DoesNotContain(connectionsA.Items, row => row.ClientName is "unknown-b" or "legacy-default");

            var alice = new ManagementContext("tenant-a", "alice", ManagementRole.User, false);
            var userOverview = await query.GetOverviewAsync(alice, CancellationToken.None);
            var userConnections = await query.ListConnectionsAsync(
                alice, null, null, null, null, 0, 100, CancellationToken.None);

            Assert.Equal(1, userOverview.SuccessfulConnections);
            Assert.Equal(1, userOverview.FailedConnections);
            Assert.Equal(0, userOverview.ExternalConnections);
            Assert.Equal(0, userOverview.RejectedExternalConnections);
            Assert.Equal(2, userConnections.Total);
            Assert.All(userConnections.Items, row => Assert.Equal(aliceId, row.ClientId));

            var adminB = new ManagementContext("tenant-b", "admin-b", ManagementRole.Admin, false);
            var overviewB = await query.GetOverviewAsync(adminB, CancellationToken.None);
            var connectionsB = await query.ListConnectionsAsync(
                adminB, null, null, null, null, 0, 100, CancellationToken.None);
            Assert.Equal(1, overviewB.SuccessfulConnections);
            Assert.Equal(1, overviewB.FailedConnections);
            Assert.Equal(2, connectionsB.Total);
            Assert.Equal(new[] { "unknown-b", "bob-client" },
                connectionsB.Items.Select(row => row.ClientName));
        }

        manager.ReleaseExternalConnection("tenant-a");
        manager.ReleaseExternalConnection("tenant-b");
    }

    [Fact]
    public async Task WrongTokenUsesPersistedSessionTenantForClientlessFailureAudit()
    {
        await using var server = await TestServerFixture.StartAsync();
        var sessionId = ClientIdGenerator.NewId();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.ClientSessions.Add(new ClientSession
            {
                Id = sessionId,
                TenantId = "tenant-audit",
                CredentialId = ClientIdGenerator.NewId(),
                IdentityId = ClientIdGenerator.NewId(),
                ClientId = ClientIdGenerator.NewId(),
                ClientName = "known-session",
                TokenHash = new string('0', 64),
                Status = ClientAccountService.StatusHttpAuthenticated,
                MachineFingerprint = "machine",
                OsUser = "user",
                HttpLoginAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            });
            await db.SaveChangesAsync();
        }

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var auth = scope.ServiceProvider.GetRequiredService<ClientAccountService>();
            var result = await auth.AuthenticateAsync(new LoginRequestPacket
            {
                ClientSessionId = sessionId,
                AccessToken = "wrong-token",
                ClientName = "claimed-client",
            }, "wrong-token-channel", "127.0.0.1:50000", CancellationToken.None);

            Assert.False(result.Success);
            Assert.Null(result.Account);
            Assert.Equal("tenant-audit", result.AuditTenantId);

            var unknown = await auth.AuthenticateAsync(new LoginRequestPacket
            {
                ClientSessionId = ClientIdGenerator.NewId(),
                AccessToken = "wrong-token",
                ClientName = "unknown-session",
            }, "unknown-session-channel", "127.0.0.1:50001", CancellationToken.None);
            Assert.False(unknown.Success);
            Assert.Null(unknown.Account);
            Assert.Equal("default", unknown.AuditTenantId);

            var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
            var recordId = await records.RecordConnectionAsync(result, "claimed-client",
                "wrong-token-channel", "127.0.0.1:50000", CancellationToken.None);
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var row = await db.ConnectionRecords.AsNoTracking().SingleAsync(item => item.Id == recordId);
            Assert.Equal("tenant-audit", row.TenantId);
            Assert.Null(row.ClientId);
            Assert.False(row.Success);
        }

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var query = scope.ServiceProvider.GetRequiredService<ManagementQueryService>();
            var admin = new ManagementContext("tenant-audit", "admin", ManagementRole.Admin, false);
            var page = await query.ListConnectionsAsync(
                admin, null, false, null, null, 0, 100, CancellationToken.None);
            Assert.Contains(page.Items,
                row => row.ClientId is null && row.ChannelId == "wrong-token-channel");
        }
    }

    private static ClientAccount Account(long id, string tenantId, string owner, string clientName,
        DateTimeOffset now) => new()
    {
        Id = id,
        TenantId = tenantId,
        OwnerUsername = owner,
        ClientName = clientName,
        PasswordHash = "unused",
        Enabled = true,
        ConnectionRateLimitPerMinute = 30,
        CreatedAt = now,
        UpdatedAt = now,
    };

    private static ConnectionRecord Record(string tenantId, long? clientId, string clientName,
        bool success, DateTimeOffset now) => new()
    {
        TenantId = tenantId,
        ClientId = clientId,
        ClientName = clientName,
        ChannelId = Guid.NewGuid().ToString("N"),
        ConnectedAt = now,
        DisconnectedAt = now,
        Success = success,
        FailureReason = success ? null : "failure",
        DisconnectReason = success
            ? DisconnectReason.ClientClosed.ToWireString()
            : DisconnectReason.LoginFailure.ToWireString(),
    };
}
