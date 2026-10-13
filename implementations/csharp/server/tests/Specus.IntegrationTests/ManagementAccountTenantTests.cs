using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Tenant-scoped management login names (protocol/spec/management-accounts.md): the counterparts of
/// Java's <c>ManagementUserServiceTests</c> and <c>ManagementUserServiceIntegrationTests</c> cases the
/// contract lists in section 12, driven through the HTTP API.
/// </summary>
public sealed class ManagementAccountTenantTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task TenantsCanCreateTheSameLoginNameWithoutEnumeration()
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAccountAsync(server, "admin-a", "tenant-a", ManagementRole.Admin, "admin-a-password");
        await SeedAccountAsync(server, "admin-b", "tenant-b", ManagementRole.Admin, "admin-b-password");
        using var adminA = await LoggedInClientAsync(server, "admin-a", "admin-a-password", "tenant-a");
        using var adminB = await LoggedInClientAsync(server, "admin-b", "admin-b-password", "tenant-b");

        var createdA = await CreateUserAsync(adminA, "Shared", "shared-password-a");
        var createdB = await CreateUserAsync(adminB, "Shared", "shared-password-b");

        // The other tenant's account of the same name is no conflict: both are created, not 409.
        Assert.Equal(HttpStatusCode.Created, createdA.StatusCode);
        Assert.Equal(HttpStatusCode.Created, createdB.StatusCode);
        var viewA = await createdA.Content.ReadFromJsonAsync<UserBody>(JsonOptions);
        var viewB = await createdB.Content.ReadFromJsonAsync<UserBody>(JsonOptions);
        Assert.Equal(("Shared", "tenant-a"), (viewA!.Username, viewA.TenantId));
        Assert.Equal(("Shared", "tenant-b"), (viewB!.Username, viewB.TenantId));

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var rows = await db.ManagementUsers.AsNoTracking()
                .Where(user => user.LoginNameNormalized == "shared")
                .OrderBy(user => user.TenantId)
                .ToListAsync();
            Assert.Equal(new[] { "tenant-a", "tenant-b" }, rows.Select(row => row.TenantId));
            Assert.All(rows, row =>
            {
                // The account key is an opaque UUID, not the login name.
                Assert.NotEqual("Shared", row.Username);
                Assert.True(Guid.TryParseExact(row.Username, "D", out _));
                Assert.Equal(row.Username.ToLowerInvariant(), row.Username);
                Assert.Equal("Shared", row.LoginName);
            });
        }

        // Each tenant's list shows its own account of that name only.
        var listA = await adminA.GetFromJsonAsync<List<UserBody>>("/api/admin/users", JsonOptions);
        var listB = await adminB.GetFromJsonAsync<List<UserBody>>("/api/admin/users", JsonOptions);
        Assert.Equal("tenant-a", Assert.Single(listA!, view => view.Username == "Shared").TenantId);
        Assert.Equal("tenant-b", Assert.Single(listB!, view => view.Username == "Shared").TenantId);
        Assert.DoesNotContain(listA!, view => view.Username == "admin-b");
        Assert.DoesNotContain(listB!, view => view.Username == "admin-a");

        // A conflict within the tenant keeps .NET's status, ignoring case.
        using var conflict = await CreateUserAsync(adminA, "shared", "another-password");
        Assert.Equal(HttpStatusCode.BadRequest, conflict.StatusCode);
    }

    [Fact]
    public async Task CreatesSameLoginNameInDifferentTenantWithoutGlobalLookup()
    {
        await using var server = await TestServerFixture.StartAsync();
        // An account that predates login names: its key is its name, and it lives in tenant-b.
        await SeedAccountAsync(server, "bob", "tenant-b", ManagementRole.User, "legacy-bob-password");

        await using var scope = server.HostServices.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
        var tenantAAdmin = new ManagementContext("tenant-a", "admin-a", ManagementRole.Admin, BuiltInAdmin: false);
        var created = await users.CreateUserAsync(tenantAAdmin,
            new UserMutation("Bob", "secret-password", "USER", true), CancellationToken.None);

        Assert.Equal("Bob", created.Username);
        Assert.Equal("tenant-a", created.TenantId);
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var row = await db.ManagementUsers.AsNoTracking()
            .SingleAsync(user => user.TenantId == "tenant-a" && user.LoginNameNormalized == "bob");
        Assert.Matches("^[0-9a-f-]{36}$", row.Username);
        Assert.Equal("Bob", row.LoginName);
        // The tenant-b account is untouched and still the only one with the key "bob".
        Assert.Equal("tenant-b", (await db.ManagementUsers.AsNoTracking().SingleAsync(user => user.Username == "bob"))
            .TenantId);

        // Mutations look in the acting tenant only: tenant-a cannot reach tenant-b's bob, and a
        // missing name answers the same as a foreign one.
        var tenantBOnly = new ManagementContext("tenant-c", "admin-c", ManagementRole.Admin, BuiltInAdmin: false);
        var update = await Assert.ThrowsAsync<ArgumentException>(() => users.UpdateUserAsync(tenantBOnly, "bob",
            new UserMutation("bob", null, "ADMIN", false), CancellationToken.None));
        Assert.Equal("用户不存在: bob", update.Message);
        var delete = await Assert.ThrowsAsync<ArgumentException>(() =>
            users.DeleteUserAsync(tenantBOnly, "bob", CancellationToken.None));
        Assert.Equal("用户不存在: bob", delete.Message);
        var legacyBob = await db.ManagementUsers.AsNoTracking().SingleAsync(user => user.Username == "bob");
        Assert.Equal(ManagementRole.User, legacyBob.Role);
        Assert.True(legacyBob.Enabled);
    }

    [Fact]
    public async Task TenantQualifiedLoginAndRefreshResolveOnlyTheMatchingTenant()
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAccountAsync(server, "admin-a", "tenant-a", ManagementRole.Admin, "admin-a-password");
        await SeedAccountAsync(server, "admin-b", "tenant-b", ManagementRole.Admin, "admin-b-password");
        using var adminA = await LoggedInClientAsync(server, "admin-a", "admin-a-password", "tenant-a");
        using var adminB = await LoggedInClientAsync(server, "admin-b", "admin-b-password", "tenant-b");
        Assert.Equal(HttpStatusCode.Created, (await CreateUserAsync(adminA, "alice", "alice-a-password")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await CreateUserAsync(adminB, "alice", "alice-b-password")).StatusCode);
        var tokens = server.HostServices.GetRequiredService<LocalTokenService>();

        // Each alice signs in to her own tenant and gets a token of it.
        using var anonymous = server.CreateClient();
        var tokenA = await LoginAsync(anonymous, "alice", "alice-a-password", "tenant-a");
        var tokenB = await LoginAsync(anonymous, "ALICE", "alice-b-password", " tenant-b ");
        AssertToken(tokens, tokenA, "alice", "tenant-a", "USER");
        AssertToken(tokens, tokenB, "alice", "tenant-b", "USER");

        // A wrong tenant, or none (alice is neither in the default tenant nor an account that
        // predates login names), fails exactly like a wrong password.
        await AssertLoginFailsAsync(anonymous, "alice", "alice-a-password", "tenant-b");
        await AssertLoginFailsAsync(anonymous, "alice", "alice-a-password", null);
        await AssertLoginFailsAsync(anonymous, "alice", "alice-a-password", "default");
        await AssertLoginFailsAsync(anonymous, "alice", "alice-a-password", new string('t', 81));
        await AssertLoginFailsAsync(anonymous, "alice", "wrong-password", "tenant-a");

        using var aliceA = Bearer(server, tokenA);
        using var aliceB = Bearer(server, tokenB);
        var meA = await aliceA.GetFromJsonAsync<UserBody>("/api/admin/me", JsonOptions);
        var meB = await aliceB.GetFromJsonAsync<UserBody>("/api/admin/me", JsonOptions);
        Assert.Equal(("alice", "tenant-a"), (meA!.Username, meA.TenantId));
        Assert.Equal(("alice", "tenant-b"), (meB!.Username, meB.TenantId));

        // Refresh stays in the token's tenant.
        AssertToken(tokens, await RefreshAsync(aliceA), "alice", "tenant-a", "USER");
        AssertToken(tokens, await RefreshAsync(aliceB), "alice", "tenant-b", "USER");

        // One alice's token never sees the other's data.
        using (var created = await aliceA.PostAsJsonAsync("/api/admin/clients", new
               {
                   clientName = "alice-a-client",
                   enabled = true,
                   connectionRateLimitPerMinute = 12,
               }))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }
        Assert.Contains("alice-a-client", await ClientNamesAsync(aliceA));
        Assert.DoesNotContain("alice-a-client", await ClientNamesAsync(aliceB));
        Assert.DoesNotContain("alice-a-client", await ClientNamesAsync(adminB));
        Assert.Contains("alice-a-client", await ClientNamesAsync(adminA));

        // Tenant-b's administrator changes tenant-b's alice only.
        using (var disable = await adminB.PutAsJsonAsync("/api/admin/users/alice", new { enabled = false }))
        {
            Assert.Equal(HttpStatusCode.OK, disable.StatusCode);
        }
        Assert.Equal(HttpStatusCode.Unauthorized, (await aliceB.GetAsync("/api/admin/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await aliceA.GetAsync("/api/admin/me")).StatusCode);
        await LoginAsync(anonymous, "alice", "alice-a-password", "tenant-a");
        await AssertLoginFailsAsync(anonymous, "alice", "alice-b-password", "tenant-b");

        // A tenant-a token for a name that only exists in tenant-b resolves to no one.
        using var forged = Bearer(server, tokens.IssueToken("admin-b", "tenant-a", ManagementRole.Admin));
        Assert.Equal(HttpStatusCode.Unauthorized, (await forged.GetAsync("/api/admin/users")).StatusCode);

        // Deleting tenant-b's alice leaves tenant-a's alice in place.
        Assert.Equal(HttpStatusCode.NoContent, (await adminB.DeleteAsync("/api/admin/users/alice")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await aliceA.GetAsync("/api/admin/me")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await adminB.DeleteAsync("/api/admin/users/alice")).StatusCode);
    }

    [Fact]
    public async Task BareLegacyLoginFailsClosedWhenCaseInsensitiveAccountKeyIsAmbiguous()
    {
        await using var server = await TestServerFixture.StartAsync();
        // Accounts that predate login names: their keys are their names. "Alice" and "alice" could
        // only coexist in different tenants.
        await SeedAccountAsync(server, "Alice", "tenant-a", ManagementRole.User, "secret-password");
        await SeedAccountAsync(server, "alice", "tenant-b", ManagementRole.User, "secret-password");
        await SeedAccountAsync(server, "carol", "tenant-c", ManagementRole.User, "carol-password");
        using var client = server.CreateClient();
        var tokens = server.HostServices.GetRequiredService<LocalTokenService>();

        await AssertLoginFailsAsync(client, "alice", "secret-password", null);
        await AssertLoginFailsAsync(client, "ALICE", "secret-password", null);
        AssertToken(tokens, await LoginAsync(client, "alice", "secret-password", "tenant-a"),
            "Alice", "tenant-a", "USER");
        AssertToken(tokens, await LoginAsync(client, "alice", "secret-password", "tenant-b"),
            "alice", "tenant-b", "USER");

        // A single legacy account keeps signing in without a tenant, as before the upgrade.
        AssertToken(tokens, await LoginAsync(client, "Carol", "carol-password", null), "carol", "tenant-c", "USER");
    }

    [Fact]
    public async Task DefaultTenantLoginNameWinsAndBuiltInAdminBelongsToTheDefaultTenant()
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAccountAsync(server, "admin-b", "tenant-b", ManagementRole.Admin, "admin-b-password");
        using var adminB = await LoggedInClientAsync(server, "admin-b", "admin-b-password", "tenant-b");
        using var admin = await LoggedInClientAsync(server, "admin", "admin", null);
        Assert.Equal(HttpStatusCode.Created, (await CreateUserAsync(admin, "dave", "dave-default")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await CreateUserAsync(adminB, "dave", "dave-b")).StatusCode);
        var tokens = server.HostServices.GetRequiredService<LocalTokenService>();
        using var client = server.CreateClient();

        // Without a tenant the default tenant's dave answers; tenant-b's needs its tenant.
        AssertToken(tokens, await LoginAsync(client, "dave", "dave-default", null), "dave", "default", "USER");
        await AssertLoginFailsAsync(client, "dave", "dave-b", null);
        AssertToken(tokens, await LoginAsync(client, "dave", "dave-b", "tenant-b"), "dave", "tenant-b", "USER");

        // The built-in administrator is matched without a tenant or with the default one only.
        AssertToken(tokens, await LoginAsync(client, "admin", "admin", "default"), "admin", "default", "ADMIN");
        await AssertLoginFailsAsync(client, "admin", "admin", "tenant-b");
        // No tenant can create an account under the built-in administrator's name.
        Assert.Equal(HttpStatusCode.BadRequest, (await CreateUserAsync(adminB, "Admin", "x-password")).StatusCode);
        // A built-in-admin token claiming another tenant is not the built-in administrator.
        using var forged = Bearer(server, tokens.IssueToken("admin", "tenant-b", ManagementRole.Admin));
        Assert.Equal(HttpStatusCode.Unauthorized, (await forged.GetAsync("/api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task OidcProvisioningUsesTheDefaultTenantOnlyAndIgnoresOtherTenants()
    {
        await using var server = await TestServerFixture.StartAsync();
        // Same name in another tenant: neither bound nor in the way.
        await SeedAccountAsync(server, "erin", "tenant-b", ManagementRole.Admin, "erin-b-password");

        await using var scope = server.HostServices.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
        var provisioned = await users.ResolveOrProvisionOidcUserAsync("https://issuer.example", "erin-subject",
            "Erin", CancellationToken.None);

        Assert.NotNull(provisioned);
        Assert.Equal(("Erin", "default", ManagementRole.User), (provisioned!.Username, provisioned.TenantId,
            provisioned.Role));
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var rows = await db.ManagementUsers.AsNoTracking().Where(user => user.LoginNameNormalized == "erin")
            .OrderBy(user => user.TenantId).ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.True(Guid.TryParseExact(rows[0].Username, "D", out _));
        Assert.Equal("default", rows[0].TenantId);
        Assert.Equal(("erin", "tenant-b"), (rows[1].Username, rows[1].TenantId));
        Assert.Null(rows[1].OidcIdentityKey);

        // The bound identity answers from now on, whatever its tenant.
        var again = await users.ResolveOrProvisionOidcUserAsync("https://issuer.example", "erin-subject",
            "someone-else", CancellationToken.None);
        Assert.Equal(("Erin", "default"), (again!.Username, again.TenantId));
    }

    [Fact]
    public async Task HttpShareReReadsAnActorByTenantAndCanonicalLoginName()
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAccountAsync(server, "frank", "tenant-a", ManagementRole.User, "frank-a-password");
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var created = await seed.ServiceProvider.GetRequiredService<ManagementUserService>().CreateUserAsync(
                new ManagementContext("tenant-b", "admin-b", ManagementRole.Admin, BuiltInAdmin: false),
                new UserMutation("Frank", "frank-b-password", "ADMIN", Enabled: false), CancellationToken.None);
            Assert.Equal("tenant-b", created.TenantId);
        }

        await using var scope = server.HostServices.CreateAsyncScope();
        var shares = scope.ServiceProvider.GetRequiredService<HttpShareService>();
        var frankA = await shares.LoadPrincipalAsync("tenant-a", "FRANK", CancellationToken.None);
        Assert.Equal(new HttpShareService.SharePrincipal("frank", "tenant-a", false), frankA);
        // tenant-b's Frank is disabled; tenant-a's enabled frank does not stand in for him.
        Assert.Null(await shares.LoadPrincipalAsync("tenant-b", "frank", CancellationToken.None));
        Assert.Null(await shares.LoadPrincipalAsync("tenant-c", "frank", CancellationToken.None));
        // The built-in administrator is an actor of the default tenant only.
        Assert.Equal(new HttpShareService.SharePrincipal("admin", "default", true),
            await shares.LoadPrincipalAsync("default", "admin", CancellationToken.None));
        Assert.Null(await shares.LoadPrincipalAsync("tenant-a", "admin", CancellationToken.None));
    }

    private static async Task SeedAccountAsync(TestServerFixture server, string username, string tenantId,
        ManagementRole role, string password)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        // The account key is the name, like every account created before login names existed.
        db.ManagementUsers.Add(new ManagementUser
        {
            Username = username,
            TenantId = tenantId,
            PasswordHash = PasswordHasher.Hash(password),
            Role = role,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    private static Task<HttpResponseMessage> CreateUserAsync(HttpClient admin, string username, string password) =>
        admin.PostAsJsonAsync("/api/admin/users", new { username, password, role = "USER", enabled = true });

    private static async Task<HttpClient> LoggedInClientAsync(TestServerFixture server, string username,
        string password, string? tenantId)
    {
        using var anonymous = server.CreateClient();
        return Bearer(server, await LoginAsync(anonymous, username, password, tenantId));
    }

    private static HttpClient Bearer(TestServerFixture server, string token)
    {
        var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password,
        string? tenantId)
    {
        using var response = await client.PostAsJsonAsync("/auth/login", LoginBody(username, password, tenantId));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions);
        return body!.AccessToken;
    }

    private static async Task AssertLoginFailsAsync(HttpClient client, string username, string password,
        string? tenantId)
    {
        using var response = await client.PostAsJsonAsync("/auth/login", LoginBody(username, password, tenantId));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("""{"error":"用户名或密码错误"}""", await response.Content.ReadAsStringAsync());
    }

    // Without a tenant the field is left out, as the management page sends it.
    private static object LoginBody(string username, string password, string? tenantId) => tenantId is null
        ? new { username, password }
        : new { username, password, tenantId };

    private static async Task<string> RefreshAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/auth/refresh", content: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions))!.AccessToken;
    }

    private static void AssertToken(LocalTokenService tokens, string token, string subject, string tenantId,
        string role)
    {
        var principal = tokens.Validate(token);
        Assert.NotNull(principal);
        Assert.Equal(subject, principal!.Identity!.Name);
        Assert.Equal(tenantId, principal.FindFirst("tenant_id")!.Value);
        Assert.Equal(role, principal.FindFirst("role")!.Value);
    }

    private static async Task<List<string>> ClientNamesAsync(HttpClient client)
    {
        using var document = JsonDocument.Parse(await client.GetStringAsync("/api/admin/clients"));
        return document.RootElement.EnumerateArray()
            .Select(item => item.GetProperty("clientName").GetString()!)
            .ToList();
    }

    private sealed record TokenBody(string AccessToken, string TokenType, long ExpiresIn);

    private sealed record UserBody(string Username, string TenantId, string Role, bool Admin, bool BuiltIn,
        bool Enabled);
}
