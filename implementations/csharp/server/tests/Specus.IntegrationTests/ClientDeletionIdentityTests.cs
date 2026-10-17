using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ClientDeletionIdentityTests
{
    [Fact]
    public async Task CompleteDeletionRemovesOnlyCurrentIdentityAndPreservesHistoryAndCredential()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await ClientNameReferenceTests.SeedAsync(db);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        await services.GetRequiredService<ManagementMutationService>().DeleteClientAsync(actor.Context, 1001, CancellationToken.None);
        Assert.False(await db.ClientAccounts.AsNoTracking().AnyAsync(c => c.Id == 1001));
        Assert.False(await db.ClientIdentities.AsNoTracking().AnyAsync(i => i.ClientId == 1001));
        Assert.True(await db.ClientIdentities.AsNoTracking().AnyAsync(i => i.Id == 702 && i.ClientId == 1002));
        Assert.Equal("retained-secret", (await db.ClientCredentials.AsNoTracking().SingleAsync()).SecretHash);
        Assert.Equal("laptop", (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901)).ClientName);
        Assert.Equal("laptop", (await db.ConnectionRecords.AsNoTracking().SingleAsync()).ClientName);
        Assert.Equal("laptop", (await db.HttpTrafficExchanges.AsNoTracking().SingleAsync()).ClientName);
    }

    [Fact]
    public async Task ValidCredentialRegistersANewIdAfterDeletionButOldTokenCannotAuthenticateIt()
    {
        await using var server = await ClientNameReferenceTests.StartAsync();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await ClientNameReferenceTests.SeedAsync(db); await ClientNameReferenceTests.EnableCredentialAsync(db);
        }
        using var http = server.CreateClient();
        using var beforeResponse = await http.PostAsJsonAsync("/api/client/auth/login", ClientNameReferenceTests.Request());
        Assert.Equal(HttpStatusCode.OK, beforeResponse.StatusCode);
        var before = await beforeResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(); Assert.NotNull(before);
        await using (var deletion = server.HostServices.CreateAsyncScope())
        {
            var actor = await OwnerTransferWriterProof.ActorAsync(server, deletion.ServiceProvider);
            await deletion.ServiceProvider.GetRequiredService<ManagementMutationService>().DeleteClientAsync(actor.Context, before.ClientId, CancellationToken.None);
        }
        using var afterResponse = await http.PostAsJsonAsync("/api/client/auth/login", ClientNameReferenceTests.Request());
        Assert.Equal(HttpStatusCode.OK, afterResponse.StatusCode);
        var after = await afterResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(); Assert.NotNull(after);
        Assert.NotEqual(before.ClientId, after.ClientId);
        await using var verify = server.HostServices.CreateAsyncScope();
        var dbAfter = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.False(await dbAfter.ClientAccounts.AsNoTracking().AnyAsync(c => c.Id == before.ClientId));
        var identity = await dbAfter.ClientIdentities.AsNoTracking().SingleAsync(i => i.MachineFingerprint == "retained-machine1");
        Assert.Equal(after.ClientId, identity.ClientId); Assert.NotEqual(701, identity.Id);
        var oldToken = await verify.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(
            new LoginRequestPacket { ClientSessionId = before.ClientSessionId, AccessToken = before.AccessToken, ClientName = after.ClientName },
            "deleted-client-token", "127.0.0.1", CancellationToken.None);
        Assert.False(oldToken.Success);
        Assert.True(await dbAfter.ClientSessions.AsNoTracking().AnyAsync(s => s.Id == before.ClientSessionId && s.ClientId == before.ClientId));
    }
}
