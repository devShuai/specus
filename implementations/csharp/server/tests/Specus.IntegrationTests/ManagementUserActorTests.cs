using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ManagementUserActorTests
{
    [Theory]
    [InlineData("create", "disabled")]
    [InlineData("update", "disabled")]
    [InlineData("delete", "disabled")]
    [InlineData("create", "demoted")]
    [InlineData("update", "demoted")]
    [InlineData("delete", "demoted")]
    [InlineData("create", "replaced")]
    [InlineData("update", "replaced")]
    [InlineData("delete", "replaced")]
    public async Task AccountMutationCannotBorrowAnOutdatedAdministratorIdentity(string operation, string change)
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false" });
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        db.ManagementUsers.AddRange(
            new ManagementUser { Username = "operator-key", LoginName = "operator", TenantId = "default", Role = ManagementRole.Admin, Enabled = true, PasswordHash = PasswordHasher.Hash("operator-password") },
            new ManagementUser { Username = "target-key", LoginName = "target", TenantId = "default", Enabled = true });
        await db.SaveChangesAsync();
        var original = await ManagementResourceOwnershipTests.ContextAsync(server, scope.ServiceProvider, "operator", "operator-password");
        Assert.True(original.IsAdmin);
        await using (var other = server.HostServices.CreateAsyncScope())
        {
            var changed = other.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var actor = await changed.ManagementUsers.SingleAsync(u => u.Username == "operator-key");
            if (change == "disabled") actor.Enabled = false;
            else if (change == "demoted") actor.Role = ManagementRole.User;
            else
            {
                changed.ManagementUsers.Remove(actor);
                await changed.SaveChangesAsync();
                changed.ManagementUsers.Add(new ManagementUser { Username = "replacement-operator", LoginName = "operator", TenantId = "default", Role = ManagementRole.Admin, Enabled = true });
            }
            await changed.SaveChangesAsync();
        }
        var service = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
        {
            if (operation == "create") await service.CreateUserAsync(original, new UserMutation("new-account", "new-password", "USER", true), CancellationToken.None);
            else if (operation == "update") await service.UpdateUserAsync(original, "target", new UserMutation(null, null, null, false), CancellationToken.None);
            else await service.DeleteUserAsync(original, "target", CancellationToken.None);
        });
        Assert.True((await db.ManagementUsers.AsNoTracking().SingleAsync(u => u.Username == "target-key")).Enabled);
        Assert.False(await db.ManagementUsers.AsNoTracking().AnyAsync(u => u.LoginName == "new-account"));
    }
}
