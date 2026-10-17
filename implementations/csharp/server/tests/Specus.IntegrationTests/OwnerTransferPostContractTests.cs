using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

public sealed class OwnerTransferPostContractTests
{
    [Fact]
    public async Task PublicGroupTransferAndPerConsumerReceiptsUseTheRealHttpContract()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await OwnerTransferPostProviderProof.VerifyAsync(server);
    }

    internal static async Task<HttpClient> AdminAsync(TestServerFixture server)
    {
        var http = server.CreateClient();
        using var response = await http.PostAsJsonAsync("/auth/login", new AdminLoginRequest("admin", "admin", TenantId: "tenant-a"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        return http;
    }

    [Theory]
    [InlineData("legacy", "clients/1001", "single", 1)]
    [InlineData("unique", "clients/1001", "single", 1)]
    [InlineData("shared", "client-credentials/501", "credential-group", 2)]
    [InlineData("empty", "client-credentials/501", "credential-group", 0)]
    public async Task PublicScopeShapesKeepAccessAndNoOpDoesNotRepeatAudit(string shape, string resource, string scopeName, int count)
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, shape);
        using var http = await AdminAsync(server);
        var path = "/api/admin/" + resource + "/owner-transfer";
        var preview = (await http.GetFromJsonAsync<ClientOwnerTransferPreview>(path))!;
        using var response = await http.PostAsJsonAsync(path, new { scope = scopeName, targetUsername = "BoB", expectedRevision = preview.Revision });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<OwnerTransferWriteResult>();
        Assert.NotNull(result); Assert.True(result.Changed); Assert.True(result.AccessRetained);
        Assert.Equal("bob", result.TargetUsername); Assert.Equal(count, result.AffectedClientIds.Count);
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
        foreach (var client in await db.ClientAccounts.AsNoTracking().ToListAsync()) Assert.Equal("retained-password", client.PasswordHash);
        var credential = await db.ClientCredentials.AsNoTracking().SingleAsync();
        Assert.Equal("retained-secret", credential.SecretHash); Assert.False(credential.Enabled);
        preview = (await http.GetFromJsonAsync<ClientOwnerTransferPreview>(path))!;
        using var noop = await http.PostAsJsonAsync(path, new { scope = scopeName, targetUsername = "bob", expectedRevision = preview.Revision });
        Assert.Equal(HttpStatusCode.OK, noop.StatusCode);
        Assert.False((await noop.Content.ReadFromJsonAsync<OwnerTransferWriteResult>())!.Changed);
        Assert.Single(await db.ClientOwnerTransferAudits.AsNoTracking().ToListAsync());
    }

    [Theory]
    [InlineData("shared", "clients/1001", "{\"scope\":\"single\"}", 409, "CREDENTIAL_SHARED")]
    [InlineData("orphan", "client-credentials/501", "{\"scope\":\"credential-group\"}", 409, "INCONSISTENT_CREDENTIAL_GROUP")]
    [InlineData("unique", "clients/999", "{\"scope\":\"credential-group\"}", 404, "RESOURCE_NOT_FOUND")]
    [InlineData("unique", "clients/999", "[]", 400, "INVALID_TRANSFER_REQUEST")]
    [InlineData("unique", "clients/999", "{} {}", 400, "INVALID_TRANSFER_REQUEST")]
    [InlineData("unique", "clients/invalid", "{", 400, "INVALID_TRANSFER_REQUEST")]
    [InlineData("foreign-client", "clients/1002", "{}", 404, "RESOURCE_NOT_FOUND")]
    [InlineData("shared", "clients/1001", "{\"scope\":\"single\",\"targetUsername\":null}", 400, "INVALID_TRANSFER_REQUEST")]
    [InlineData("unique", "clients/1001", "{\"scope\":\"single\",\"targetUsername\":\"missing-target\",\"expectedRevision\":\"old\"}", 409, "TRANSFER_PREVIEW_CHANGED")]
    public async Task PublicErrorsKeepContractPrecedenceAndWriteNothing(string shape, string resource, string json, int status, string code)
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, shape);
        var before = await ClientOwnerTransferWriterTests.RowsAsync(db);
        using var http = await AdminAsync(server);
        using var response = await http.PostAsync("/api/admin/" + resource + "/owner-transfer", new StringContent(json, Encoding.UTF8, "application/json"));
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(code, (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        Assert.Equal(before, await ClientOwnerTransferWriterTests.RowsAsync(db));
    }

    [Fact]
    public async Task AuditFaultRollsBackAndRenameInvalidatesTheOriginalPublicPreview()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        using var http = await AdminAsync(server);
        const string path = "/api/admin/clients/1001/owner-transfer";
        var preview = (await http.GetFromJsonAsync<ClientOwnerTransferPreview>(path))!;
        var request = new { scope = "single", targetUsername = "bob", expectedRevision = preview.Revision };
        await db.Database.ExecuteSqlRawAsync("CREATE TRIGGER reject_public_audit BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'injected audit fault'); END");
        using var failed = await http.PostAsJsonAsync(path, request);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.DoesNotContain("injected", await failed.Content.ReadAsStringAsync());
        Assert.Equal("alice", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001)).OwnerUsername);
        Assert.Empty(await db.ClientOwnerTransferAudits.AsNoTracking().ToListAsync());
        await db.Database.ExecuteSqlRawAsync("DROP TRIGGER reject_public_audit");
        await db.ClientAccounts.Where(c => c.Id == 1001).ExecuteUpdateAsync(setters => setters.SetProperty(c => c.ClientName, "renamed-after-preview"));
        using var stale = await http.PostAsJsonAsync(path, request);
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal("TRANSFER_PREVIEW_CHANGED", (await stale.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
    }

    [Fact]
    public async Task PublicWritesAuthenticateBeforeReadingAndRejectOversizedBodies()
    {
        await using var server = await ClientOwnerTransferWriterTests.StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await ClientOwnerTransferWriterTests.SeedAsync(db, "unique");
        db.ManagementUsers.Add(new Specus.Server.Data.Entities.ManagementUser { Username = "post-reader-key", LoginName = "reader", TenantId = "tenant-a", Enabled = true,
            PasswordHash = Specus.Server.Authentication.PasswordHasher.Hash("reader-test-password") });
        await db.SaveChangesAsync();
        using var http = server.CreateClient();
        using var anonymous = await http.PostAsync("/api/admin/clients/invalid/owner-transfer", new StringContent("{"));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        using var login = await http.PostAsJsonAsync("/auth/login", new AdminLoginRequest("reader", "reader-test-password", TenantId: "tenant-a"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString());
        using var forbidden = await http.PostAsync("/api/admin/clients/invalid/owner-transfer", new StringContent("{"));
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        using var admin = await AdminAsync(server);
        using var oversized = await admin.PostAsync("/api/admin/clients/1001/owner-transfer", new StringContent("{\"scope\":\"" + new string('x', 65536) + "\"}"));
        Assert.Equal(HttpStatusCode.BadRequest, oversized.StatusCode);
        Assert.Equal("INVALID_TRANSFER_REQUEST", (await oversized.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        Assert.Empty(await db.ClientOwnerTransferAudits.AsNoTracking().ToListAsync());
    }
}
