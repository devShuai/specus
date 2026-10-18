using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using Specus.Server.WebSockets;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class ClientOwnerTransferWriterTests
{
    [Fact]
    public async Task PortableTicketRevocationPreservesOtherScopesTenantsAndUsers()
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedTicketsAsync(db, "tenant-a");
        await ManagementAccessRevocations.RevokeTicketsAsync(db, "tenant-a", "bob", CancellationToken.None);
        await OwnerTransferWriterProof.AssertRetainedTicketsAsync(db);
    }

    [Fact]
    public async Task RealDatabaseBearerBindsTheImmutableActorKeyAndAuditsItsCanonicalLogin()
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var admin = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, "unique");
        await services.ServiceProvider.GetRequiredService<ManagementUserService>().CreateUserAsync(admin.Context,
            new UserMutation("Operator", "operator-proof-password", "ADMIN", true), CancellationToken.None);
        using var client = server.CreateClient();
        using var login = await client.PostAsJsonAsync("/auth/login", new AdminLoginRequest("Operator", "operator-proof-password", TenantId: "tenant-a"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var token = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString();
        var principal = await services.ServiceProvider.GetRequiredService<AdminBearerTokenValidator>().ValidateAsync(token);
        Assert.NotNull(principal);
        var actor = OwnerTransferActor.From(new DefaultHttpContext { User = principal }, services.ServiceProvider.GetRequiredService<IOptions<AuthOptions>>().Value);
        var account = await db.ManagementUsers.AsNoTracking().SingleAsync(u => u.LoginName == "Operator");
        Assert.Equal(account.Username, actor.AccountKey); Assert.NotEqual(actor.Context.Username, actor.AccountKey);
        var preview = await PreviewAsync(services.ServiceProvider, actor, PathScope.Single, 1001);
        await services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, PathScope.Single,
            "1001", Body(PathScope.Single, "bob", preview.Revision!), CancellationToken.None);
        Assert.Equal("Operator", (await db.ClientOwnerTransferAudits.AsNoTracking().SingleAsync()).Actor);
    }

    [Fact]
    public async Task RealBearerGroupWriteKeepsAccessMaterialAndNoOpDoesNotRepeatAudit()
    {
        await using var server = await StartAsync();
        await OwnerTransferWriterProof.VerifyAsync(server);
    }

    [Theory]
    [InlineData("legacy", "single", 1001, false, 1)]
    [InlineData("unique", "single", 1001, true, 1)]
    [InlineData("empty", "credential-group", 501, true, 0)]
    [InlineData("duplicate-identities", "single", 1001, true, 1)]
    public async Task RangeShapesFollowTheActualSqlRelationships(string shape, string scopeName, long id, bool credential, int count)
    {
        var scope = scopeName == "single" ? PathScope.Single : PathScope.CredentialGroup;
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, shape);
        var before = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        var preview = await PreviewAsync(services.ServiceProvider, actor, scope, id);
        var result = await services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>()
            .CommitAsync(actor, scope, id.ToString(), Body(scope, "BoB", preview.Revision!), CancellationToken.None);
        Assert.True(result.Response.Changed);
        Assert.Equal(count, result.Response.AffectedClientIds.Count);
        Assert.Equal(credential ? 501L : (long?)null, result.Response.CredentialId);
        Assert.Equal("bob", result.Response.TargetUsername);
        var after = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        Assert.Equal(credential ? "bob" : before.OwnerUsername, after.OwnerUsername);
        Assert.Equal(before.SecretHash, after.SecretHash);
        Assert.Equal(before.Enabled, after.Enabled);
    }

    [Theory]
    [InlineData("shared", "single", 1001, "{}", 400, "INVALID_TRANSFER_REQUEST")]
    [InlineData("shared", "single", 1001, "{\"scope\":\"single\"}", 409, "CREDENTIAL_SHARED")]
    [InlineData("orphan", "credential-group", 501, "{\"scope\":\"credential-group\"}", 409, "INCONSISTENT_CREDENTIAL_GROUP")]
    [InlineData("multiple-credentials", "single", 1001, "{\"scope\":\"single\"}", 409, "INCONSISTENT_CREDENTIAL_GROUP")]
    [InlineData("foreign-client", "single", 1002, "{}", 404, "RESOURCE_NOT_FOUND")]
    [InlineData("unique", "single", 999, "{}", 404, "RESOURCE_NOT_FOUND")]
    public async Task ValidationErrorsHaveFixedPrecedenceAndNoWrites(string shape, string scopeName, long id, string json, int status, string code)
    {
        var scope = scopeName == "single" ? PathScope.Single : PathScope.CredentialGroup;
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, shape);
        var before = await RowsAsync(db);
        var error = await Assert.ThrowsAsync<ClientOwnerTransferException>(() => services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>()
            .CommitAsync(actor, scope, id.ToString(), JsonSerializer.Deserialize<JsonElement>(json), CancellationToken.None));
        Assert.Equal(status, error.Status); Assert.Equal(code, error.Code);
        Assert.Equal(before, await RowsAsync(db));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("disabled")]
    [InlineData("other-tenant")]
    public async Task InvalidTargetsDoNotExposeOrMutateOtherTenants(string target)
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, "unique");
        db.ManagementUsers.Add(new ManagementUser { Username = "foreign-key", LoginName = "other-tenant", TenantId = "tenant-b", Enabled = true });
        db.ManagementUsers.Add(new ManagementUser { Username = "disabled-key", LoginName = "disabled", TenantId = "tenant-a", Enabled = false });
        await db.SaveChangesAsync();
        var before = await RowsAsync(db);
        var preview = await PreviewAsync(services.ServiceProvider, actor, PathScope.Single, 1001);
        var error = await Assert.ThrowsAsync<ClientOwnerTransferException>(() => services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>()
            .CommitAsync(actor, PathScope.Single, "1001", Body(PathScope.Single, target, preview.Revision!), CancellationToken.None));
        Assert.Equal(400, error.Status); Assert.Equal("INVALID_TARGET_OWNER", error.Code);
        Assert.Equal(before, await RowsAsync(db));
    }

    [Theory]
    [InlineData("peer-write")]
    [InlineData("audit-write")]
    [InlineData("audit-disappeared")]
    public async Task FinalWriteAndAuditFailuresRollBackEveryOwnershipRow(string fault)
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, "shared");
        var preview = await PreviewAsync(services.ServiceProvider, actor, PathScope.CredentialGroup, 501);
        var before = await RowsAsync(db);
        var trigger = fault switch
        {
            "peer-write" => "CREATE TRIGGER owner_fault BEFORE UPDATE ON peer_mesh_device BEGIN SELECT RAISE(ABORT,'owned fixture peer failure'); END",
            "audit-write" => "CREATE TRIGGER owner_fault BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'owned fixture audit failure'); END",
            _ => "CREATE TRIGGER owner_fault AFTER INSERT ON client_owner_transfer_audit BEGIN DELETE FROM client_owner_transfer_audit WHERE id=NEW.id; END",
        };
        await db.Database.ExecuteSqlRawAsync(trigger);
        await Assert.ThrowsAnyAsync<Exception>(() => services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>()
            .CommitAsync(actor, PathScope.CredentialGroup, "501", Body(PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None));
        Assert.Equal(before, await RowsAsync(db));
    }

    [Fact]
    public async Task StaleRevisionCannotOverwriteTheNewOwnerAndBuiltinTargetUsesConfiguredCanonicalName()
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, "unique");
        var writer = services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>();
        var original = await PreviewAsync(services.ServiceProvider, actor, PathScope.Single, 1001);
        await writer.CommitAsync(actor, PathScope.Single, "1001", Body(PathScope.Single, "bob", original.Revision!), CancellationToken.None);
        var error = await Assert.ThrowsAsync<ClientOwnerTransferException>(() => writer.CommitAsync(actor, PathScope.Single, "1001",
            Body(PathScope.Single, "AdMiN", original.Revision!), CancellationToken.None));
        Assert.Equal("TRANSFER_PREVIEW_CHANGED", error.Code);
        var fresh = await PreviewAsync(services.ServiceProvider, actor, PathScope.Single, 1001);
        var result = await writer.CommitAsync(actor, PathScope.Single, "1001", Body(PathScope.Single, " AdMiN ", fresh.Revision!), CancellationToken.None);
        Assert.Equal("admin", result.Response.TargetUsername);
        Assert.Equal(2, await db.ClientOwnerTransferAudits.CountAsync());
    }

    [Theory]
    [InlineData("demoted")]
    [InlineData("disabled")]
    [InlineData("replaced")]
    [InlineData("oidc-rebound")]
    public async Task ResolvedActorCannotFollowMutableRolesOrReusedLoginNames(string mutation)
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await SeedAsync(db, "unique");
        var user = new ManagementUser { Username = "original-key", LoginName = "operator", TenantId = "tenant-a", Enabled = true, Role = ManagementRole.Admin };
        if (mutation == "oidc-rebound")
        {
            user.OidcIssuer = "https://old-issuer.example"; user.OidcSubject = "old-subject";
            user.OidcIdentityKey = OidcKey(user.OidcIssuer, user.OidcSubject);
        }
        db.ManagementUsers.Add(user); await db.SaveChangesAsync();
        var actor = new OwnerTransferActor(new ManagementContext("tenant-a", "operator", ManagementRole.Admin, false), user.Username);
        if (mutation == "demoted") user.Role = ManagementRole.User;
        else if (mutation == "disabled") user.Enabled = false;
        else if (mutation == "oidc-rebound")
        {
            actor = actor with { ExternalIssuer = "https://old-issuer.example", ExternalSubject = "old-subject" };
            var resolved = await services.ServiceProvider.GetRequiredService<ManagementUserService>().ResolveBoundOidcUserAsync(
                actor.ExternalIssuer, actor.ExternalSubject, CancellationToken.None);
            Assert.NotNull(resolved); Assert.Equal(user.Username, resolved.AccountKey);
            var valid = await PreviewAsync(services.ServiceProvider, actor, PathScope.Single, 1001);
            Assert.True((await services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor,
                PathScope.Single, "1001", Body(PathScope.Single, "bob", valid.Revision!), CancellationToken.None)).Response.Changed);
            user.OidcIssuer = "https://new-issuer.example"; user.OidcSubject = "new-subject";
            user.OidcIdentityKey = OidcKey(user.OidcIssuer, user.OidcSubject);
        }
        else
        {
            db.ManagementUsers.Remove(user); await db.SaveChangesAsync();
            db.ManagementUsers.Add(new ManagementUser { Username = "replacement-key", LoginName = "operator", TenantId = "tenant-a", Enabled = true, Role = ManagementRole.Admin });
        }
        await db.SaveChangesAsync();
        var before = await RowsAsync(db);
        var preview = await services.ServiceProvider.GetRequiredService<ClientOwnerTransferService>().PreviewClientAsync(
            new ManagementContext("tenant-a", "admin", ManagementRole.Admin, true), "1001", CancellationToken.None);
        var failure = await Record.ExceptionAsync(() => services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>()
            .CommitAsync(actor, PathScope.Single, "1001", Body(PathScope.Single, mutation == "oidc-rebound" ? "admin" : "bob", preview.Revision!), CancellationToken.None));
        if (mutation == "demoted") Assert.Equal("FORBIDDEN", Assert.IsType<ClientOwnerTransferException>(failure).Code);
        else Assert.IsType<UnauthorizedAccessException>(failure);
        Assert.Equal(before, await RowsAsync(db));
    }

    [Fact]
    public async Task WriterDoesNotFlushUnrelatedTrackedObjects()
    {
        await using var server = await StartAsync();
        await using var services = server.HostServices.CreateAsyncScope();
        var db = services.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var actor = await OwnerTransferWriterProof.ActorAsync(server, services.ServiceProvider);
        await SeedAsync(db, "shared");
        var unrelated = new ClientAccount { Id = 9999, TenantId = "tenant-b", ClientName = "must-not-flush", PasswordHash = "test" };
        db.ClientAccounts.Add(unrelated);
        var preview = await PreviewAsync(services.ServiceProvider, actor, PathScope.CredentialGroup, 501);
        await services.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, PathScope.CredentialGroup,
            "501", Body(PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None);
        Assert.False(await db.ClientAccounts.AsNoTracking().AnyAsync(c => c.Id == unrelated.Id));
        Assert.Equal(EntityState.Added, db.Entry(unrelated).State);
    }

    internal static Task<TestServerFixture> StartAsync() => TestServerFixture.StartAsync(new Dictionary<string, string?>
    { ["Specus:Auth:TenantId"] = "tenant-a", ["Specus:Database:SeedDemoClient"] = "false" });
    private static string OidcKey(string issuer, string subject) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(issuer + "\0" + subject)));
    internal static JsonElement Body(PathScope scope, string target, string revision) => JsonSerializer.SerializeToElement(new { scope = scope.WireName(), targetUsername = target, expectedRevision = revision });
    internal static Task<ClientOwnerTransferPreview> PreviewAsync(IServiceProvider services, OwnerTransferActor actor, PathScope scope, long id) =>
        scope == PathScope.Single ? services.GetRequiredService<ClientOwnerTransferService>().PreviewClientAsync(actor.Context, id.ToString(), CancellationToken.None)
            : services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, id.ToString(), CancellationToken.None);

    internal static async Task SeedAsync(SpecusDbContext db, string shape)
    {
        var input = ClientOwnerTransferPlanTests.ReadSnapshot(ClientOwnerTransferPlanTests.Input(new System.Text.Json.Nodes.JsonObject { ["snapshot"] = shape }));
        var now = DateTimeOffset.UtcNow.AddDays(-1);
        db.ClientAccounts.AddRange(input.Clients.Select(c => new ClientAccount { Id = c.Id, TenantId = c.TenantId, ClientName = c.ClientName!, OwnerUsername = c.OwnerUsername, Enabled = c.Enabled, PasswordHash = "retained-password", CreatedAt = now, UpdatedAt = now }));
        db.ClientCredentials.AddRange(input.Credentials.Select(c => new ClientCredential { Id = c.Id, TenantId = c.TenantId, OwnerUsername = c.OwnerUsername, Enabled = c.Enabled, ApiKey = $"retained-key-{c.Id}", SecretHash = "retained-secret", CreatedAt = now, UpdatedAt = now }));
        db.ClientIdentities.AddRange(input.Identities.Select(i => new ClientIdentity { Id = i.Id, TenantId = i.TenantId, CredentialId = i.CredentialId, ClientId = i.ClientId, ClientName = $"identity-{i.ClientId}", MachineFingerprint = $"retained-machine-{i.Id}", OsUser = "retained-user", FirstSeenAt = now, LastSeenAt = now }));
        db.PeerMeshDevices.AddRange(input.Peers.Select(p => new PeerMeshDevice { Id = p.Id, TenantId = p.TenantId, ClientId = p.ClientId, ClientName = p.ClientName!, OwnerUsername = p.OwnerUsername!, Enabled = p.Enabled, VirtualIp = $"10.66.0.{p.Id % 240 + 2}", Cidr = "10.66.0.0/16", PublicKey = "retained-public-key", CreatedAt = now, UpdatedAt = now }));
        db.ManagementUsers.Add(new ManagementUser { Username = "bob-key", LoginName = "bob", TenantId = "tenant-a", Enabled = true });
        await db.SaveChangesAsync();
    }

    internal static async Task<string> RowsAsync(SpecusDbContext db) => JsonSerializer.Serialize(new
    {
        clients = await db.ClientAccounts.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
        credentials = await db.ClientCredentials.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
        identities = await db.ClientIdentities.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
        peers = await db.PeerMeshDevices.AsNoTracking().OrderBy(p => p.Id).ToListAsync(),
        audits = await db.ClientOwnerTransferAudits.AsNoTracking().OrderBy(a => a.Id).ToListAsync(),
    });
}
