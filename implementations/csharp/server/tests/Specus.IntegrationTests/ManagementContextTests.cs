using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ManagementContextTests
{
    [Fact]
    public void TenantAndOwnerVisibilityIsCaseSensitiveLikeJavaRepositories()
    {
        var context = new ManagementContext("tenant-a", "Alice", ManagementRole.User, false);
        var exact = new ClientAccount { TenantId = "tenant-a", OwnerUsername = "Alice" };
        var ownerCaseMismatch = new ClientAccount { TenantId = "tenant-a", OwnerUsername = "alice" };
        var tenantCaseMismatch = new ClientAccount { TenantId = "TENANT-A", OwnerUsername = "Alice" };

        Assert.True(context.CanAccess(exact));
        Assert.False(context.CanAccess(ownerCaseMismatch));
        Assert.False(context.CanAccess(tenantCaseMismatch));
        Assert.False(ManagementContext.SameTenant("tenant-a", "TENANT-A"));
    }
}
