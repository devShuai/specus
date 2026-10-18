using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class PeerManagementOwnershipTests
{
    [Theory]
    [InlineData("device")]
    [InlineData("acl-upsert")]
    public async Task FormerOwnerCannotWritePeerConfigurationAfterTransferWithTrackedRows(string operation)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var alice = await ManagementResourceOwnershipTests.ContextAsync(server, services, "alice", "alice-password");
        var admin = await OwnerTransferWriterProof.ActorAsync(server, services);
        await TransferAsync(server, admin);
        Assert.Equal("alice", db.ChangeTracker.Entries<ClientAccount>().Single(e => e.Entity.Id == 1001).Entity.OwnerUsername);
        Assert.Equal("alice", db.ChangeTracker.Entries<PeerMeshDevice>().Single().Entity.OwnerUsername);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => MutateAsync(services.GetRequiredService<PeerMeshService>(), alice, operation));
        Assert.Equal("bob", (await db.PeerMeshDevices.AsNoTracking().SingleAsync()).OwnerUsername);
        Assert.True((await db.PeerMeshDevices.AsNoTracking().SingleAsync()).Enabled);
        Assert.True((await db.PeerMeshAcls.AsNoTracking().SingleAsync()).Allowed);
    }

    [Theory]
    [InlineData("device")]
    [InlineData("acl-upsert")]
    [InlineData("acl-delete")]
    public async Task PeerWritesCannotFlushUnrelatedPendingChanges(string operation)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, services, "alice", "alice-password");
        db.ClientCredentials.Add(new ClientCredential { Id = 4501, TenantId = "default", OwnerUsername = "unrelated", ApiKey = "unrelated-peer-pending", SecretHash = "fixture-private" });
        await Assert.ThrowsAsync<InvalidOperationException>(() => MutateAsync(services.GetRequiredService<PeerMeshService>(), actor, operation));
        Assert.False(await db.ClientCredentials.AsNoTracking().AnyAsync(c => c.Id == 4501));
        Assert.True((await db.PeerMeshDevices.AsNoTracking().SingleAsync()).Enabled);
        Assert.True((await db.PeerMeshAcls.AsNoTracking().SingleAsync()).Allowed);
    }

    [Theory]
    [InlineData("device", false)]
    [InlineData("acl-upsert", false)]
    [InlineData("acl-delete", false)]
    [InlineData("device", true)]
    [InlineData("acl-upsert", true)]
    [InlineData("acl-delete", true)]
    public async Task OriginalActorIsRecheckedInsteadOfFollowingDisabledOrReusedLogin(string operation, bool replace)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var original = await ManagementResourceOwnershipTests.ContextAsync(server, services, "alice", "alice-password");
        await using (var other = server.HostServices.CreateAsyncScope())
        {
            var changed = other.ServiceProvider.GetRequiredService<SpecusDbContext>();
            if (replace)
            {
                await changed.Database.ExecuteSqlRawAsync("DELETE FROM specus_management_user WHERE username='peer-alice-key'");
                changed.ManagementUsers.Add(new ManagementUser { Username = "replacement-peer-alice", LoginName = "alice", TenantId = "default", Enabled = true });
                await changed.SaveChangesAsync();
            }
            else await changed.Database.ExecuteSqlRawAsync("UPDATE specus_management_user SET enabled=0 WHERE username='peer-alice-key'");
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => MutateAsync(services.GetRequiredService<PeerMeshService>(), original, operation));
        Assert.True((await db.PeerMeshDevices.AsNoTracking().SingleAsync()).Enabled);
        Assert.True((await db.PeerMeshAcls.AsNoTracking().SingleAsync()).Allowed);
    }

    [Fact]
    public async Task TransferPreservesIndependentAclManagementOwner()
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var admin = await OwnerTransferWriterProof.ActorAsync(server, services);
        await TransferAsync(server, admin);
        var bob = await ManagementResourceOwnershipTests.ContextAsync(server, services, "bob", "bob-password");
        var peer = services.GetRequiredService<PeerMeshService>();
        await Assert.ThrowsAsync<ArgumentException>(() => peer.DeleteAclAsync(bob, 4801, CancellationToken.None));
        Assert.Equal("alice", (await db.PeerMeshAcls.AsNoTracking().SingleAsync()).OwnerUsername);
        var alice = await ManagementResourceOwnershipTests.ContextAsync(server, services, "alice", "alice-password");
        await peer.DeleteAclAsync(alice, 4801, CancellationToken.None);
        Assert.Empty(await db.PeerMeshAcls.AsNoTracking().ToListAsync());
        Assert.Equal("bob", (await db.PeerMeshDevices.AsNoTracking().SingleAsync()).OwnerUsername);
    }

    private static Task<TestServerFixture> StartAsync() => TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });

    internal static async Task SeedAsync(SpecusDbContext db)
    {
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        db.ManagementUsers.Add(new ManagementUser { Username = "peer-alice-key", LoginName = "alice", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("alice-password") });
        (await db.ManagementUsers.SingleAsync(u => u.Username == "bob-key")).PasswordHash = PasswordHasher.Hash("bob-password");
        (await db.ClientAccounts.SingleAsync(c => c.Id == 1002)).OwnerUsername = "alice";
        db.PeerMeshAcls.Add(new PeerMeshAcl { Id = 4801, TenantId = "default", OwnerUsername = "alice", SourceClientId = 1001, SourceClientName = "laptop", TargetClientId = 1002, TargetClientName = "offline", Allowed = true, Direction = PeerMeshService.DirectionBoth });
        await db.SaveChangesAsync();
    }

    private static async Task TransferAsync(TestServerFixture server, OwnerTransferActor admin)
    {
        await using var transfer = server.HostServices.CreateAsyncScope();
        var services = transfer.ServiceProvider;
        var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(admin.Context, "501", CancellationToken.None);
        Assert.True((await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(admin, PathScope.CredentialGroup, "501",
            OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None)).Response.Changed);
    }

    private static async Task MutateAsync(PeerMeshService service, ManagementContext actor, string operation)
    {
        switch (operation)
        {
            case "device": await service.UpdateDeviceAsync(actor, 1001, new PeerMeshDeviceMutation(false), CancellationToken.None); break;
            case "acl-upsert": await service.CreateAclAsync(actor, new PeerMeshAclMutation(1001, 1002, false, PeerMeshService.DirectionBoth), CancellationToken.None); break;
            case "acl-delete": await service.DeleteAclAsync(actor, 4801, CancellationToken.None); break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }
}
