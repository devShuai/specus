using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ClientNameBoundaryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedCommitRollsBackEveryCurrentReferenceAndIdentityDeletion(bool delete)
    {
        var fault = new CommitFault();
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true", ["Specus:PeerMesh:StunTurnPort"] = "0", ["Specus:PeerMesh:NatProbeAlternatePort"] = "0" },
            services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(fault)));
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await ClientNameReferenceTests.SeedAsync(db);
        var names = await ClientNameReferenceTests.NamesAsync(db);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        fault.Armed = true;
        var service = services.GetRequiredService<ManagementMutationService>();
        await Assert.ThrowsAsync<InvalidOperationException>(() => delete
            ? service.DeleteClientAsync(actor.Context, 1001, CancellationToken.None)
            : service.UpdateClientAsync(actor.Context, 1001, new ClientMutation("rolled-back-name", null, null), CancellationToken.None));
        Assert.True(fault.Triggered);
        Assert.Equal("laptop", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001)).ClientName);
        Assert.Equal(names.OrderBy(p => p.Key), (await ClientNameReferenceTests.NamesAsync(db)).OrderBy(p => p.Key));
        Assert.Equal(2, await db.ClientIdentities.CountAsync());
        Assert.Equal(1, await db.ClientSessions.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RenameAndDeleteNeverChangeAnIdentityInACaseVariantForeignTenant(bool delete)
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await ClientNameReferenceTests.SeedAsync(db);
        db.ClientIdentities.Add(new ClientIdentity { Id = 703, TenantId = "DEFAULT", ClientId = 1001, CredentialId = 501,
            ClientName = "foreign-name", MachineFingerprint = "foreign-machine", OsUser = "foreign-user" });
        await db.SaveChangesAsync();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        var service = services.GetRequiredService<ManagementMutationService>();
        if (delete) await service.DeleteClientAsync(actor.Context, 1001, CancellationToken.None);
        else await service.UpdateClientAsync(actor.Context, 1001, new ClientMutation("canonical-name", null, null), CancellationToken.None);
        var foreign = await db.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 703);
        Assert.Equal("DEFAULT", foreign.TenantId); Assert.Equal("foreign-name", foreign.ClientName);
        Assert.Equal(1001, foreign.ClientId); Assert.Equal(501, foreign.CredentialId);
    }

    [Fact]
    public async Task RenameRepairsLegacyNullTenantConfigurationWithoutRelabellingForeignRows()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await ClientNameReferenceTests.SeedAsync(db);
        (await db.SpecusMappings.SingleAsync()).TenantId = null;
        (await db.HttpRouteMappings.SingleAsync()).TenantId = null;
        db.TrafficUsages.Add(new TrafficUsage { Id = 5103, ClientId = 1001, ClientName = "foreign-name", TenantId = "DEFAULT", UsageDate = "2026-10-02" });
        await db.SaveChangesAsync();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        await services.GetRequiredService<ManagementMutationService>().UpdateClientAsync(actor.Context, 1001,
            new ClientMutation("canonical-name", null, null), CancellationToken.None);
        Assert.Equal("canonical-name", (await db.SpecusMappings.AsNoTracking().SingleAsync()).ClientName);
        Assert.Equal("canonical-name", (await db.HttpRouteMappings.AsNoTracking().SingleAsync()).ClientName);
        Assert.Equal("foreign-name", (await db.TrafficUsages.AsNoTracking().SingleAsync(u => u.Id == 5103)).ClientName);
    }

    [Fact]
    public async Task DuplicateNameFailureDoesNotPartiallyRenameReferences()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await ClientNameReferenceTests.SeedAsync(db);
        var names = await ClientNameReferenceTests.NamesAsync(db);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        await Assert.ThrowsAsync<ArgumentException>(() => services.GetRequiredService<ManagementMutationService>()
            .UpdateClientAsync(actor.Context, 1001, new ClientMutation("offline", null, null), CancellationToken.None));
        Assert.Equal(names.OrderBy(p => p.Key), (await ClientNameReferenceTests.NamesAsync(db)).OrderBy(p => p.Key));
    }

    private sealed class CommitFault : DbTransactionInterceptor
    {
        internal bool Armed { get; set; }
        internal bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
            InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Armed) { Triggered = true; throw new InvalidOperationException("owned client reference commit fixture failure"); }
            return ValueTask.FromResult(result);
        }
    }
}
