using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;

namespace Specus.IntegrationTests;

public sealed class PeerDefinitionOwnershipTests
{
    public static IEnumerable<object[]> Operations() => new[] { "sharing", "service-create", "service-update", "service-delete", "egress-switch", "egress-upsert", "egress-delete", "import-tcp" }.Select(operation => new object[] { operation });
    public static IEnumerable<object[]> RevokedActors() => Operations().SelectMany(operation => new[] { "disabled", "demoted", "replaced" }.Select(change => new object[] { operation[0], change }));

    [Theory]
    [MemberData(nameof(RevokedActors))]
    public async Task DefinitionWritesRevalidateOriginalAdministrativeActor(string operation, string change)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var original = await ManagementResourceOwnershipTests.ContextAsync(server, services, "definition-operator", "operator-password");
        await using (var other = server.HostServices.CreateAsyncScope())
        {
            var changed = other.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var user = await changed.ManagementUsers.SingleAsync(u => u.Username == "definition-operator-key");
            if (change == "disabled") user.Enabled = false;
            else if (change == "demoted") user.Role = ManagementRole.User;
            else
            {
                changed.ManagementUsers.Remove(user);
                await changed.SaveChangesAsync();
                changed.ManagementUsers.Add(new ManagementUser { Username = "replacement-definition-operator", LoginName = "definition-operator", TenantId = "default", Enabled = true, Role = ManagementRole.Admin });
            }
            await changed.SaveChangesAsync();
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => ChangeAsync(services.GetRequiredService<PeerMeshService>(), original, operation));
        await AssertUnchangedAsync(db);
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task DefinitionWritesNeverFlushUnrelatedPendingChanges(string operation)
    {
        await using var server = await StartAsync();
        await using var scope = server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db);
        var actor = await ManagementResourceOwnershipTests.ContextAsync(server, services, "definition-operator", "operator-password");
        db.ClientCredentials.Add(new ClientCredential { Id = 4501, TenantId = "default", OwnerUsername = "unrelated", ApiKey = "unrelated-definition-pending", SecretHash = "fixture-private" });
        await Assert.ThrowsAsync<InvalidOperationException>(() => ChangeAsync(services.GetRequiredService<PeerMeshService>(), actor, operation));
        Assert.False(await db.ClientCredentials.AsNoTracking().AnyAsync(c => c.Id == 4501));
        await AssertUnchangedAsync(db);
    }

    internal static Task<TestServerFixture> StartAsync() => TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true" });

    internal static async Task SeedAsync(SpecusDbContext db)
    {
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        db.ManagementUsers.Add(new ManagementUser { Username = "definition-operator-key", LoginName = "definition-operator", TenantId = "default", Role = ManagementRole.Admin, Enabled = true, PasswordHash = PasswordHasher.Hash("operator-password") });
        db.PeerMeshServiceSharings.Add(new PeerMeshServiceSharing { TenantId = "default", Enabled = true, MdnsImportEnabled = true, UpdatedBy = "initial", UpdatedAt = DateTimeOffset.UtcNow });
        db.PeerMeshEgressSwitches.Add(new PeerMeshEgressSwitch { TenantId = "default", Enabled = true, UpdatedBy = "initial", UpdatedAt = DateTimeOffset.UtcNow });
        db.PeerMeshSharedServices.Add(new PeerMeshSharedService { Id = 4901, TenantId = "default", ClientId = 1001, ClientName = "laptop", ServiceId = "existing-service", Name = "existing", Application = "http", Transport = "tcp", TargetHost = "127.0.0.1", TargetPort = 8080, PublishedPort = 18080, Path = "/", Enabled = false });
        db.PeerMeshEgressPolicies.Add(new PeerMeshEgressPolicy { Id = 4951, TenantId = "default", EgressClientId = 1001, EgressClientName = "laptop", OwnerUsername = "policy-manager", Enabled = false });
        db.SpecusMappings.Add(new SpecusMapping { Id = 4201, TenantId = "default", ClientId = 1001, ClientName = "laptop", ListenPort = 24861, TargetAddress = "127.0.0.1", TargetPort = 8082, Enabled = false });
        await db.SaveChangesAsync();
    }

    private static async Task AssertUnchangedAsync(SpecusDbContext db)
    {
        Assert.True((await db.PeerMeshServiceSharings.AsNoTracking().SingleAsync()).Enabled);
        Assert.True((await db.PeerMeshEgressSwitches.AsNoTracking().SingleAsync()).Enabled);
        Assert.Single(await db.PeerMeshSharedServices.AsNoTracking().ToListAsync());
        Assert.Equal(8080, (await db.PeerMeshSharedServices.AsNoTracking().SingleAsync()).TargetPort);
        Assert.False((await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).Enabled);
        Assert.Equal("policy-manager", (await db.PeerMeshEgressPolicies.AsNoTracking().SingleAsync()).OwnerUsername);
    }

    internal static PeerMeshServiceMutation NewService(long clientId = 1001) => new(clientId, "new-service-01", "new", "", "tcp", "http", "127.0.0.1", 8081, 18081, "/", false, "OWNER");

    internal static async Task ChangeAsync(PeerMeshService peer, ManagementContext actor, string operation)
    {
        switch (operation)
        {
            case "sharing": await peer.SetSharingAsync(actor, false, CancellationToken.None); break;
            case "service-create": await peer.CreateSharedServiceAsync(actor, NewService(), CancellationToken.None); break;
            case "service-update": await peer.UpdateSharedServiceAsync(actor, 4901, new PeerMeshServiceMutation(null, null, null, null, null, null, null, 8081, null, null, null, null), CancellationToken.None); break;
            case "service-delete": await peer.DeleteSharedServiceAsync(actor, 4901, CancellationToken.None); break;
            case "egress-switch": await peer.SetEgressSwitchAsync(actor, false, CancellationToken.None); break;
            case "egress-upsert": await peer.UpsertEgressPolicyAsync(actor, new PeerEgressPolicyMutation(EgressClientId: 1001, Enabled: true), CancellationToken.None); break;
            case "egress-delete": await peer.DeleteEgressPolicyAsync(actor, 4951, CancellationToken.None); break;
            case "import-tcp": await peer.ImportCandidatesAsync(actor, 1001, CancellationToken.None); break;
            default: throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }
}
