using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Authentication;

namespace Specus.IntegrationTests;

public sealed class ClientNameReferenceTests
{
    [Theory]
    [InlineData("identity")]
    [InlineData("device")]
    [InlineData("tcp")]
    [InlineData("http")]
    [InlineData("acl-source")]
    [InlineData("acl-target")]
    [InlineData("service")]
    [InlineData("egress")]
    [InlineData("traffic")]
    [InlineData("resource")]
    public async Task OrdinaryRenameUpdatesTheCurrentOperationalReference(string kind)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        await services.GetRequiredService<ManagementMutationService>().UpdateClientAsync(actor.Context, 1001,
            new ClientMutation("canonical-name", null, null), CancellationToken.None);
        Assert.Equal("canonical-name", (await NamesAsync(db))[kind]);
    }

    [Fact]
    public async Task RenamePreservesHistoricalNamesAndImmutableBindings()
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var identityBefore = await db.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701);
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        await services.GetRequiredService<ManagementMutationService>().UpdateClientAsync(actor.Context, 1001,
            new ClientMutation("canonical-name", null, null), CancellationToken.None);
        Assert.Equal("laptop", (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == 901)).ClientName);
        Assert.Equal("laptop", (await db.ConnectionRecords.AsNoTracking().SingleAsync()).ClientName);
        Assert.Equal("laptop", (await db.PeerMeshSessions.AsNoTracking().SingleAsync()).SourceClientName);
        Assert.Equal("laptop", (await db.HttpTrafficExchanges.AsNoTracking().SingleAsync()).ClientName);
        var identity = await db.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701);
        Assert.Equal(identityBefore.CredentialId, identity.CredentialId); Assert.Equal(identityBefore.ClientId, identity.ClientId);
        Assert.Equal(identityBefore.MachineFingerprint, identity.MachineFingerprint); Assert.Equal(identityBefore.OsUser, identity.OsUser);
        Assert.Equal(identityBefore.FirstSeenAt, identity.FirstSeenAt); Assert.Equal(identityBefore.LastSeenAt, identity.LastSeenAt);
        var peer = await db.PeerMeshDevices.AsNoTracking().SingleAsync();
        Assert.Equal("10.66.0.3", peer.VirtualIp); Assert.Equal("retained-public-key", peer.PublicKey); Assert.True(peer.Enabled);
        Assert.Equal("alice", peer.OwnerUsername);
        Assert.Equal(13, (await db.TrafficUsages.AsNoTracking().SingleAsync()).UploadBytes);
        Assert.Equal(29, (await db.ResourceTrafficUsages.AsNoTracking().SingleAsync()).DownloadBytes);
        Assert.Equal("retained-secret", (await db.ClientCredentials.AsNoTracking().SingleAsync()).SecretHash);
    }

    [Fact]
    public async Task SignedHttpLoginUsesCurrentAccountIdDespiteLegacyStaleIdentityName()
    {
        await using var server = await StartAsync();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await SeedAsync(db);
            await EnableCredentialAsync(db);
            (await db.ClientAccounts.SingleAsync(c => c.Id == 1001)).ClientName = "canonical-name";
            await db.SaveChangesAsync();
        }
        using var http = server.CreateClient();
        using var response = await http.PostAsJsonAsync("/api/client/auth/login", Request());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>();
        Assert.NotNull(login); Assert.Equal(1001, login.ClientId); Assert.Equal("canonical-name", login.ClientName);
        await using var verify = server.HostServices.CreateAsyncScope();
        var current = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal("canonical-name", (await current.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701)).ClientName);
        Assert.Equal("canonical-name", (await current.PeerMeshDevices.AsNoTracking().SingleAsync()).ClientName);
        Assert.Equal(2, await current.ClientAccounts.CountAsync());
    }

    [Fact]
    public async Task OrdinaryRenameAllowsTheSameDeviceToAuthenticateAgainWithoutChangingItsId()
    {
        await using var server = await StartAsync();
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await SeedAsync(db); await EnableCredentialAsync(db);
        }
        using var http = server.CreateClient();
        using var firstResponse = await http.PostAsJsonAsync("/api/client/auth/login", Request());
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var first = await firstResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(); Assert.NotNull(first);
        await using (var rename = server.HostServices.CreateAsyncScope())
        {
            var actor = await OwnerTransferWriterProof.ActorAsync(server, rename.ServiceProvider);
            await rename.ServiceProvider.GetRequiredService<ManagementMutationService>().UpdateClientAsync(actor.Context, first.ClientId,
                new ClientMutation("canonical-name", null, null), CancellationToken.None);
        }
        using var secondResponse = await http.PostAsJsonAsync("/api/client/auth/login", Request());
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        var second = await secondResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(); Assert.NotNull(second);
        Assert.Equal(first.ClientId, second.ClientId); Assert.Equal("canonical-name", second.ClientName);
        Assert.NotEqual(first.ClientSessionId, second.ClientSessionId);
    }

    internal static Task<TestServerFixture> StartAsync() => TestServerFixture.StartAsync(new Dictionary<string, string?>
    { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true", ["Specus:PeerMesh:StunTurnPort"] = "0", ["Specus:PeerMesh:NatProbeAlternatePort"] = "0" });

    internal static async Task SeedAsync(SpecusDbContext db)
    {
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        ClientConfigurationOwnershipTests.SeedConfiguration(db);
        db.PeerMeshAcls.AddRange(
            new PeerMeshAcl { Id = 4801, TenantId = "default", OwnerUsername = "alice", SourceClientId = 1001, SourceClientName = "laptop", TargetClientId = 1002, TargetClientName = "offline", Allowed = true },
            new PeerMeshAcl { Id = 4802, TenantId = "default", OwnerUsername = "carol", SourceClientId = 1002, SourceClientName = "offline", TargetClientId = 1001, TargetClientName = "laptop", Allowed = true });
        db.PeerMeshSharedServices.Add(new PeerMeshSharedService { Id = 4901, TenantId = "default", ClientId = 1001, ClientName = "laptop", ServiceId = "name-service", Name = "name-service", TargetPort = 8080, PublishedPort = 18080 });
        db.PeerMeshEgressPolicies.Add(new PeerMeshEgressPolicy { Id = 4951, TenantId = "default", EgressClientId = 1001, EgressClientName = "laptop", OwnerUsername = "policy-manager" });
        db.TrafficUsages.Add(new TrafficUsage { Id = 5101, TenantId = "default", ClientId = 1001, ClientName = "laptop", UsageDate = "2026-10-01", UploadBytes = 13, DownloadBytes = 29 });
        db.ResourceTrafficUsages.Add(new ResourceTrafficUsage { Id = 5102, TenantId = "default", ClientId = 1001, ClientName = "laptop", ResourceType = "TCP", ResourceKey = "24861", ResourceName = "fixture", UsageDate = "2026-10-01", UploadBytes = 13, DownloadBytes = 29 });
        db.ConnectionRecords.Add(new ConnectionRecord { Id = 5201, TenantId = "default", ClientId = 1001, ClientName = "laptop", ChannelId = "historical", ConnectedAt = DateTimeOffset.UtcNow.AddDays(-1), Success = true });
        db.PeerMeshSessions.Add(new PeerMeshSession { Id = 5202, TenantId = "default", SourceClientId = 1001, SourceClientName = "laptop", TargetClientId = 1002, TargetClientName = "offline", Status = "CLOSED", PathType = "RELAY", ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1) });
        db.HttpTrafficExchanges.Add(new HttpTrafficExchange { Id = 5203, TenantId = "default", ClientId = 1001, ClientName = "laptop", Route = "existing", CapturedAt = DateTimeOffset.UtcNow.AddDays(-1) });
        await db.SaveChangesAsync();
    }

    internal static async Task EnableCredentialAsync(SpecusDbContext db)
    {
        var credential = await db.ClientCredentials.SingleAsync();
        credential.Enabled = true; credential.SecretHash = ClientStartupOwnershipTests.Hash("name-fixture-secret"); credential.MaxOnlineInstances = 7;
        // SeedAsync retains row 901 for history/transfer checks. A live-auth fixture must
        // not simultaneously claim that this same machine already has an online control
        // session on another server; strict SQL quota admission correctly rejects that.
        var historical = await db.ClientSessions.SingleAsync(s => s.Id == 901);
        historical.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        await db.SaveChangesAsync();
    }

    internal static ClientAuthLoginRequest Request() => ClientStartupOwnershipTests.Signed("retained-api", "name-fixture-secret", Guid.NewGuid().ToString("N"), "retained-machine1", "retained-user");

    internal static async Task<Dictionary<string, string>> NamesAsync(SpecusDbContext db) => new()
    {
        ["identity"] = (await db.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701)).ClientName,
        ["device"] = (await db.PeerMeshDevices.AsNoTracking().SingleAsync()).ClientName,
        ["tcp"] = (await db.SpecusMappings.AsNoTracking().SingleAsync()).ClientName,
        ["http"] = (await db.HttpRouteMappings.AsNoTracking().SingleAsync()).ClientName,
        ["acl-source"] = (await db.PeerMeshAcls.AsNoTracking().SingleAsync(a => a.Id == 4801)).SourceClientName,
        ["acl-target"] = (await db.PeerMeshAcls.AsNoTracking().SingleAsync(a => a.Id == 4802)).TargetClientName,
        ["service"] = (await db.PeerMeshSharedServices.AsNoTracking().SingleAsync()).ClientName,
        ["egress"] = (await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).EgressClientName,
        ["traffic"] = (await db.TrafficUsages.AsNoTracking().SingleAsync()).ClientName,
        ["resource"] = (await db.ResourceTrafficUsages.AsNoTracking().SingleAsync()).ClientName,
    };
}
