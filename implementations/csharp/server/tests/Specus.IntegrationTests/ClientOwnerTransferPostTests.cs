using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class ClientOwnerTransferPostTests
{
    [Fact]
    public async Task PublicSingleTransferCommitsCanonicalOwnerAndAudit()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        using var http = server.CreateClient();
        using var login = await http.PostAsJsonAsync("/auth/login", new AdminLoginRequest("admin", "admin", TenantId: "tenant-a"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        var preview = await http.GetFromJsonAsync<ClientOwnerTransferPreview>("/api/admin/clients/1001/owner-transfer");
        Assert.NotNull(preview?.Revision);
        using var response = await http.PostAsJsonAsync("/api/admin/clients/1001/owner-transfer", new { scope = "single", targetUsername = "BoB", expectedRevision = preview.Revision });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("bob", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001)).OwnerUsername);
        Assert.Single(await db.ClientOwnerTransferAudits.AsNoTracking().ToListAsync());
    }
}
