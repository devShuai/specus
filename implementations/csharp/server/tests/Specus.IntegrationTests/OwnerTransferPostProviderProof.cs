using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

// Real public HTTP/bearer + transaction/audit + each consumer's SQL receipt in every
// native database. Independent consumers are not claimed as separate OS processes.
internal static class OwnerTransferPostProviderProof
{
    internal static async Task VerifyAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var auth = scope.ServiceProvider.GetRequiredService<IOptions<AuthOptions>>().Value;
        await OwnerTransferWriterProof.SeedAsync(db, ManagementContext.NormalizeTenant(auth.TenantId));
        var credentialBefore = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        var foreignTenant = ManagementContext.NormalizeTenant(auth.TenantId).ToUpperInvariant();
        Assert.NotEqual(ManagementContext.NormalizeTenant(auth.TenantId), foreignTenant);
        // Case-folding SQL collations must not let an event for one tenant close
        // another tenant's session, even if it references an affected client ID.
        db.PeerMeshSessions.Add(new Specus.Server.Data.Entities.PeerMeshSession { Id = 89501, TenantId = foreignTenant,
            SourceClientId = 1001, TargetClientId = 1002, SourceClientName = "foreign-source", TargetClientName = "foreign-target",
            Status = Specus.Server.PeerMesh.PeerMeshService.StatusActive, ExpiresAt = DateTimeOffset.UtcNow.AddHours(1) });
        await db.SaveChangesAsync();
        var sessionBefore = JsonSerializer.Serialize(await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct = timeout.Token;
        using var http = server.CreateClient();
        using var login = await http.PostAsJsonAsync("/auth/login", new AdminLoginRequest(auth.Username, auth.Password, TenantId: auth.TenantId), ct);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("accessToken").GetString());
        using var conflict = await http.PostAsJsonAsync("/api/admin/clients/1001/owner-transfer", new { scope = "single" }, ct);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal("CREDENTIAL_SHARED", (await conflict.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("code").GetString());
        const string path = "/api/admin/client-credentials/501/owner-transfer";
        var preview = (await http.GetFromJsonAsync<ClientOwnerTransferPreview>(path, ct))!;
        using var response = await http.PostAsJsonAsync(path, new { scope = "credential-group", targetUsername = "BoB", expectedRevision = preview.Revision }, ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = (await response.Content.ReadFromJsonAsync<JsonElement>(ct));
        Assert.Equal("bob", result.GetProperty("targetUsername").GetString());
        Assert.True(result.GetProperty("accessRetained").GetBoolean());
        Assert.Equal(2, result.GetProperty("affectedClientIds").GetArrayLength());
        Assert.Single(await db.ClientOwnerTransferAudits.AsNoTracking().ToListAsync(ct));
        using var first = new OwnerTransferNotifications(server.HostServices.GetRequiredService<IServiceScopeFactory>(), NullLogger<OwnerTransferNotifications>.Instance);
        using var second = new OwnerTransferNotifications(server.HostServices.GetRequiredService<IServiceScopeFactory>(), NullLogger<OwnerTransferNotifications>.Instance);
        Assert.Equal(1, await first.DrainAsync(ct)); Assert.Equal(1, await second.DrainAsync(ct));
        Assert.Equal(1, await db.ClientOwnerTransferReceipts.CountAsync(r => r.NodeId == first.NodeId, ct));
        Assert.Equal(1, await db.ClientOwnerTransferReceipts.CountAsync(r => r.NodeId == second.NodeId, ct));
        Assert.Equal(Specus.Server.PeerMesh.PeerMeshService.StatusActive,
            (await db.PeerMeshSessions.AsNoTracking().SingleAsync(s => s.Id == 89501, ct)).Status);
        var after = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501, ct);
        Assert.Equal("bob", after.OwnerUsername); Assert.Equal(credentialBefore.ApiKey, after.ApiKey);
        Assert.Equal(credentialBefore.SecretHash, after.SecretHash); Assert.Equal(credentialBefore.Enabled, after.Enabled);
        Assert.Equal(sessionBefore, JsonSerializer.Serialize(await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901, ct)));
        Assert.False(db.Database.HasPendingModelChanges());
    }
}
