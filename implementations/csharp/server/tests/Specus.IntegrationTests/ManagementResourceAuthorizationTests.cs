using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ManagementResourceAuthorizationTests
{
    [Theory]
    [InlineData("disabled")]
    [InlineData("tenant")]
    [InlineData("renamed")]
    [InlineData("deleted")]
    public async Task ResourceCreationRevalidatesTheOriginalAccountAfterAuthentication(string change)
    {
        await using var server = await TestServerFixture.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var user = new ManagementUser { Username = "actor-key", LoginName = "actor", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("actor-password") };
        db.ManagementUsers.Add(user); await db.SaveChangesAsync();
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, scope.ServiceProvider, "actor", "actor-password");
        if (change == "disabled") user.Enabled = false;
        else if (change == "tenant") user.TenantId = "foreign";
        else if (change == "renamed") user.LoginName = "renamed";
        else db.ManagementUsers.Remove(user);
        await db.SaveChangesAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => scope.ServiceProvider.GetRequiredService<ManagementMutationService>()
            .CreateCredentialAsync(actor, new CredentialMutation("denied-current-actor", "fixture-private", true, 3), CancellationToken.None));
        Assert.False(await db.ClientCredentials.AsNoTracking().AnyAsync(c => c.ApiKey == "denied-current-actor"));
    }

    [Fact]
    public async Task DemotedAdministratorCannotUseTheOldRoleToModifyAnotherOwnersClient()
    {
        await using var server = await TestServerFixture.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var user = new ManagementUser { Username = "actor-key", LoginName = "actor", TenantId = "default", Role = ManagementRole.Admin, Enabled = true, PasswordHash = PasswordHasher.Hash("actor-password") };
        db.ManagementUsers.Add(user);
        db.ClientAccounts.Add(new ClientAccount { Id = 9841, TenantId = "default", OwnerUsername = "bob", ClientName = "another-owners-device", PasswordHash = "retained", Enabled = true });
        await db.SaveChangesAsync();
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, scope.ServiceProvider, "actor", "actor-password");
        Assert.True(actor.IsAdmin);
        user.Role = ManagementRole.User; await db.SaveChangesAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => scope.ServiceProvider.GetRequiredService<ManagementMutationService>()
            .UpdateClientAsync(actor, 9841, new ClientMutation(null, false, null), CancellationToken.None));
        Assert.True((await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 9841)).Enabled);
    }

    [Theory]
    [InlineData("client-create")]
    [InlineData("client-update")]
    [InlineData("client-delete")]
    [InlineData("credential-create")]
    [InlineData("credential-update")]
    [InlineData("credential-delete")]
    public async Task ResourceMutationCannotFlushUnrelatedPendingChanges(string operation)
    {
        await using var server = await TestServerFixture.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        db.ClientCredentials.Add(new ClientCredential { Id = 9842, TenantId = "default", OwnerUsername = "unrelated", ApiKey = "unrelated-pending", SecretHash = "retained" });
        var mutation = scope.ServiceProvider.GetRequiredService<ManagementMutationService>();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            switch (operation)
            {
                case "client-create": await mutation.CreateClientAsync(actor.Context, new ClientMutation("new-device", true, 30), CancellationToken.None); break;
                case "client-update": await mutation.UpdateClientAsync(actor.Context, 9841, new ClientMutation(null, false, null), CancellationToken.None); break;
                case "client-delete": await mutation.DeleteClientAsync(actor.Context, 9841, CancellationToken.None); break;
                case "credential-create": await mutation.CreateCredentialAsync(actor.Context, new CredentialMutation("new-api", "fixture", true, 3), CancellationToken.None); break;
                case "credential-update": await mutation.UpdateCredentialAsync(actor.Context, 9841, new CredentialMutation(null, null, false, 3), CancellationToken.None); break;
                case "credential-delete": await mutation.DeleteCredentialAsync(actor.Context, 9841, CancellationToken.None); break;
            }
        });
        Assert.False(await db.ClientCredentials.AsNoTracking().AnyAsync(c => c.Id == 9842));
    }
}
