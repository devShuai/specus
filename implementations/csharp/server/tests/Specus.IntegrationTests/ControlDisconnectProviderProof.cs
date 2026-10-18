using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

// Shared by the mandatory real-provider projects, not a generated-SQL/model-only assertion.
internal static class ControlDisconnectProviderProof
{
    public static async Task VerifyAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var store = scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>();
        var auth = store.Create(new ClientCredential { Id = 9101, TenantId = "generation-proof" },
            new ClientIdentity { Id = 9102 },
            new ClientAccount { Id = 9103, ClientName = "generation-proof" }, TimeSpan.FromHours(1),
            new ClientEnvironmentInfo { MachineFingerprint = "proof-machine", OsUser = "proof-user" });
        store.MarkOnline(auth, "new-channel", "127.0.0.1");
        db.ClientSessions.Add(new ClientSession
        {
            Id = auth.Id, TenantId = auth.TenantId, CredentialId = auth.CredentialId,
            IdentityId = auth.IdentityId, ClientId = auth.ClientId, ClientName = auth.ClientName,
            TokenHash = auth.TokenHash, Status = ClientAccountService.StatusNettyOnline,
            MachineFingerprint = auth.MachineFingerprint, OsUser = auth.OsUser,
            HttpLoginAt = DateTimeOffset.UtcNow, ExpiresAt = auth.ExpiresAt, ChannelId = "new-channel",
        });
        await db.SaveChangesAsync();
        var service = scope.ServiceProvider.GetRequiredService<ClientAccountService>();
        Assert.False(await service.MarkNettyDisconnectedAsync(auth.Id, "old-channel", CancellationToken.None));
        var online = await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == auth.Id);
        Assert.Equal(ClientAccountService.StatusNettyOnline, online.Status);
        Assert.Equal("new-channel", online.ChannelId);
        Assert.Null(online.DisconnectedAt);
        Assert.Equal(ClientAuthSessionStatus.NettyOnline, auth.Status);

        Assert.True(await service.MarkNettyDisconnectedAsync(auth.Id, "new-channel", CancellationToken.None));
        var offline = await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == auth.Id);
        Assert.Equal(ClientAccountService.StatusDisconnected, offline.Status);
        Assert.NotNull(offline.DisconnectedAt);
        Assert.Equal(ClientAuthSessionStatus.Disconnected, auth.Status);
        Assert.False(await service.MarkNettyDisconnectedAsync(auth.Id, "new-channel", CancellationToken.None));
        Assert.Equal(offline.DisconnectedAt,
            (await db.ClientSessions.AsNoTracking().SingleAsync(row => row.Id == auth.Id)).DisconnectedAt);
    }
}
