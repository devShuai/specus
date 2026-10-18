using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class ClientConfigurationOwnershipTests
{
    [Theory]
    [InlineData("tcp-create")]
    [InlineData("tcp-update")]
    [InlineData("tcp-delete")]
    [InlineData("http-create")]
    [InlineData("http-update")]
    [InlineData("http-delete")]
    public async Task FormerOwnerCannotChangeConfigurationAfterTransferUsingTrackedParents(string operation)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        db.ManagementUsers.Add(new ManagementUser { Username = "config-alice", LoginName = "alice", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("alice-password") });
        SeedConfiguration(db);
        await db.SaveChangesAsync();
        var alice = await ManagementResourceOwnershipTests.ContextAsync(server, scope.ServiceProvider, "alice", "alice-password");
        var admin = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        await using (var transfer = server.HostServices.CreateAsyncScope())
        {
            var services = transfer.ServiceProvider;
            var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(admin.Context, "501", CancellationToken.None);
            Assert.True((await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(admin, PathScope.CredentialGroup, "501",
                OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None)).Response.Changed);
        }
        Assert.Equal("alice", db.ChangeTracker.Entries<ClientAccount>().Single(e => e.Entity.Id == 1001).Entity.OwnerUsername);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => MutateAsync(scope.ServiceProvider.GetRequiredService<ManagementMutationService>(), alice, operation));
        Assert.Equal("bob", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001)).OwnerUsername);
        Assert.Equal(1, await db.SpecusMappings.CountAsync()); Assert.Equal(1, await db.HttpRouteMappings.CountAsync());
        Assert.Equal(80, (await db.SpecusMappings.AsNoTracking().SingleAsync()).TargetPort);
        Assert.Equal("http://127.0.0.1:8000", (await db.HttpRouteMappings.AsNoTracking().SingleAsync()).TargetBaseUrl);
    }

    [Theory]
    [InlineData("tcp-create")]
    [InlineData("tcp-update")]
    [InlineData("tcp-delete")]
    [InlineData("http-create")]
    [InlineData("http-update")]
    [InlineData("http-delete")]
    public async Task ConfigurationMutationsCannotFlushUnrelatedPendingChanges(string operation)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default"); SeedConfiguration(db); await db.SaveChangesAsync();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        db.ClientCredentials.Add(new ClientCredential { Id = 4501, TenantId = "default", OwnerUsername = "unrelated", ApiKey = "unrelated-config-pending", SecretHash = "fixture-private" });
        await Assert.ThrowsAsync<InvalidOperationException>(() => MutateAsync(scope.ServiceProvider.GetRequiredService<ManagementMutationService>(), actor.Context, operation));
        Assert.False(await db.ClientCredentials.AsNoTracking().AnyAsync(c => c.Id == 4501));
        Assert.Equal(1, await db.SpecusMappings.CountAsync()); Assert.Equal(1, await db.HttpRouteMappings.CountAsync());
    }

    internal static void SeedConfiguration(SpecusDbContext db)
    {
        db.SpecusMappings.Add(new SpecusMapping { Id = 4201, TenantId = "default", ClientId = 1001, ClientName = "laptop", ListenPort = 24861, TargetAddress = "127.0.0.1", TargetPort = 80, Enabled = false });
        db.HttpRouteMappings.Add(new HttpRouteMapping { Id = 4301, TenantId = "default", ClientId = 1001, ClientName = "laptop", Route = "existing", TargetBaseUrl = "http://127.0.0.1:8000", Enabled = false });
    }

    private static async Task MutateAsync(ManagementMutationService service, ManagementContext context, string operation)
    {
        switch (operation)
        {
            case "tcp-create": await service.CreateSpecusAsync(context, 1001, new SpecusMappingMutation(24862, "127.0.0.1", 81, false, false), CancellationToken.None); break;
            case "tcp-update": await service.UpdateSpecusAsync(context, 4201, new SpecusMappingMutation(24861, "127.0.0.1", 81, false, false), CancellationToken.None); break;
            case "tcp-delete": await service.DeleteSpecusAsync(context, 4201, CancellationToken.None); break;
            case "http-create": await service.CreateHttpRouteAsync(context, 1001, new HttpRouteMutation("new-route", "http://127.0.0.1:8001", false, false, false, false, null, null), CancellationToken.None); break;
            case "http-update": await service.UpdateHttpRouteAsync(context, 4301, new HttpRouteMutation("existing", "http://127.0.0.1:8001", false, false, false, false, null, null), CancellationToken.None); break;
            case "http-delete": await service.DeleteHttpRouteAsync(context, 4301, CancellationToken.None); break;
        }
    }
}
