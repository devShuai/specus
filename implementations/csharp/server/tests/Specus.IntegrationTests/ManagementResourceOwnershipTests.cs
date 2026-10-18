using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class ManagementResourceOwnershipTests
{
    [Theory]
    [InlineData("client-update")]
    [InlineData("client-delete")]
    [InlineData("credential-update")]
    [InlineData("credential-delete")]
    public async Task FormerOwnerCannotMutateTransferredResourcesThroughTrackedSnapshots(string operation)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        db.ManagementUsers.Add(new ManagementUser { Username = "alice-key", LoginName = "alice", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("alice-password") });
        await db.SaveChangesAsync();
        var alice = await ContextAsync(server, scope.ServiceProvider, "alice", "alice-password");
        var admin = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
        await using (var transferScope = server.HostServices.CreateAsyncScope())
        {
            var services = transferScope.ServiceProvider;
            var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(admin.Context, "501", CancellationToken.None);
            Assert.True((await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(admin, PathScope.CredentialGroup, "501",
                OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None)).Response.Changed);
        }
        // Seeded objects remain tracked as Alice, but the committed database owner is Bob.
        Assert.Equal("alice", db.ChangeTracker.Entries<ClientAccount>().Single(e => e.Entity.Id == 1001).Entity.OwnerUsername);
        var mutation = scope.ServiceProvider.GetRequiredService<ManagementMutationService>();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
        {
            switch (operation)
            {
                case "client-update": await mutation.UpdateClientAsync(alice, 1001, new ClientMutation(null, false, null), CancellationToken.None); break;
                case "client-delete": await mutation.DeleteClientAsync(alice, 1001, CancellationToken.None); break;
                case "credential-update": await mutation.UpdateCredentialAsync(alice, 501, new CredentialMutation(null, null, true, 19), CancellationToken.None); break;
                case "credential-delete": await mutation.DeleteCredentialAsync(alice, 501, CancellationToken.None); break;
            }
        });
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001);
        var credential = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        Assert.Equal("bob", account.OwnerUsername); Assert.True(account.Enabled);
        Assert.Equal("bob", credential.OwnerUsername); Assert.False(credential.Enabled);
        Assert.Equal("retained-api", credential.ApiKey); Assert.Equal("retained-secret", credential.SecretHash);
        Assert.Equal(1, await db.ClientOwnerTransferAudits.CountAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ResolvedOriginalAccountCannotCreateResourcesAfterSameNameReplacement(bool credential)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ManagementUsers.Add(new ManagementUser { Username = "original-alice", LoginName = "alice", TenantId = "default", Enabled = true, PasswordHash = PasswordHasher.Hash("alice-password") });
        await db.SaveChangesAsync();
        var original = await ContextAsync(server, scope.ServiceProvider, "alice", "alice-password");
        await using (var other = server.HostServices.CreateAsyncScope())
        {
            var changed = other.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await changed.Database.ExecuteSqlRawAsync("DELETE FROM specus_management_user WHERE username='original-alice'");
            changed.ManagementUsers.Add(new ManagementUser { Username = "replacement-alice", LoginName = "alice", TenantId = "default", Enabled = true });
            await changed.SaveChangesAsync();
        }
        var mutation = scope.ServiceProvider.GetRequiredService<ManagementMutationService>();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
        {
            if (credential) await mutation.CreateCredentialAsync(original, new CredentialMutation("new-api", "new-secret", true, 3), CancellationToken.None);
            else await mutation.CreateClientAsync(original, new ClientMutation("new-device", true, 30), CancellationToken.None);
        });
        Assert.Empty(await db.ClientAccounts.AsNoTracking().ToListAsync());
        Assert.Empty(await db.ClientCredentials.AsNoTracking().ToListAsync());
    }

    internal static async Task<ManagementContext> ContextAsync(TestServerFixture server, IServiceProvider services, string username, string password)
    {
        using var http = server.CreateClient();
        using var response = await http.PostAsJsonAsync("/auth/login", new AdminLoginRequest(username, password, TenantId: "default"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString();
        var principal = await services.GetRequiredService<AdminBearerTokenValidator>().ValidateAsync(token);
        Assert.NotNull(principal);
        return ManagementContext.From(new DefaultHttpContext { User = principal }, services.GetRequiredService<IOptions<AuthOptions>>().Value);
    }
}
