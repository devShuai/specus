using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ManagementUserWriteCoordinationTests
{
    private static readonly ManagementContext Admin = new("default", "admin", ManagementRole.Admin, true);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnrelatedPendingChangesCannotBeFlushedByAnAccountMutation(bool delete)
    {
        await using var server = await TestServerFixture.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ManagementUsers.Add(new ManagementUser { Username = "target-key", LoginName = "target", TenantId = "default", Enabled = true });
        await db.SaveChangesAsync();
        db.ClientCredentials.Add(new ClientCredential { Id = 9741, TenantId = "default", OwnerUsername = "target", ApiKey = "unrelated-pending-api", SecretHash = "unrelated-pending-secret" });
        var service = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            if (delete) await service.DeleteUserAsync(Admin, "target", CancellationToken.None);
            else await service.UpdateUserAsync(Admin, "target", new UserMutation(null, null, null, false), CancellationToken.None);
        });
        Assert.False(await db.ClientCredentials.AsNoTracking().AnyAsync(c => c.Id == 9741));
        Assert.True((await db.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "target-key")).Enabled);
    }

    [Fact]
    public async Task CurrentEnabledStateOverridesAnUnchangedTrackedSnapshotBeforeRevokingTickets()
    {
        await using var server = await TestServerFixture.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ManagementUsers.Add(new ManagementUser { Username = "target-key", LoginName = "target", TenantId = "default", Enabled = false });
        db.WebSocketTickets.Add(new WebSocketTicket { TokenHash = "current-state-ticket", Scope = "connections", Username = "target", TenantId = "default", CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddHours(1) });
        await db.SaveChangesAsync();
        var stale = await db.ManagementUsers.SingleAsync(u => u.Username == "target-key");
        await using (var other = server.HostServices.CreateAsyncScope())
            await other.ServiceProvider.GetRequiredService<SpecusDbContext>().Database.ExecuteSqlRawAsync("UPDATE specus_management_user SET enabled=1 WHERE username='target-key'");
        Assert.False(stale.Enabled);
        var result = await scope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(Admin, "target",
            new UserMutation(null, null, null, false), CancellationToken.None);
        Assert.False(result.Enabled);
        Assert.False((await db.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "target-key")).Enabled);
        Assert.False(await db.WebSocketTickets.AsNoTracking().AnyAsync(t => t.TokenHash == "current-state-ticket"));
    }
}
