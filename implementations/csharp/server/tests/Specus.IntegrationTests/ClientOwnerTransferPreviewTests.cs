using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.IntegrationTests.ClientOwnerTransferPlanTests;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class ClientOwnerTransferPreviewTests
{
    public static IEnumerable<object[]> GetCases() => SharedCases().Where(data =>
    {
        var scenario = JsonNode.Parse((string)data[1])!.AsObject();
        // Do not disable the real unique (tenant, client) constraint to inject duplicate Peer rows.
        // The pure plan separately covers that corrupt snapshot.
        return !scenario.ContainsKey("request") && scenario["snapshot"]!.GetValue<string>() != "duplicate-peer";
    });

    [Theory]
    [MemberData(nameof(GetCases))]
    public async Task SharedGetVectorsThroughActualAuthenticatedRoutes(string name, string scenarioJson)
    {
        Assert.NotEmpty(name);
        var scenario = JsonNode.Parse(scenarioJson)!.AsObject();
        var input = ReadSnapshot(Input(scenario));
        await using var server = await StartAsync();
        await SeedAsync(server, input);
        var before = await RowsAsync(server);
        using var client = await LoginAsync(server, "admin", "admin");
        using var response = await client.GetAsync(Route(scenario["scope"]!.GetValue<string>(), scenario["id"]!.GetValue<long>().ToString(System.Globalization.CultureInfo.InvariantCulture)));
        Assert.True(response.Headers.CacheControl?.NoStore);
        var json = await response.Content.ReadAsStringAsync();
        if (scenario["error"] is { } expected)
        {
            Assert.Equal(expected["status"]!.GetValue<int>(), (int)response.StatusCode);
            var body = JsonNode.Parse(json)!;
            Assert.Equal(expected["code"]!.GetValue<string>(), body["code"]!.GetValue<string>());
            Assert.Equal(body["code"]!.GetValue<string>(), body["error"]!.GetValue<string>());
            Assert.DoesNotContain("secret-other", json);
        }
        else
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertPreview(JsonSerializer.Deserialize<ClientOwnerTransferPreview>(json, JsonOptions)!, scenario, input);
            // Null fields must be present on the wire, not omitted or substituted with zero.
            var body = JsonNode.Parse(json)!.AsObject();
            foreach (var field in new[] { "clientId", "credentialId", "credentialOwnerUsername", "credentialEnabled", "conflictCode", "revision" }) Assert.True(body.ContainsKey(field), field);
        }
        foreach (var sensitive in new[] { "sensitive-", "secretHash", "passwordHash", "machineFingerprint", "privateKey" }) Assert.DoesNotContain(sensitive, json);
        Assert.Equal(before, await RowsAsync(server));
    }

    [Fact]
    public async Task CurrentAccountRoleAndEnabledStateAreRecheckedAfterRealTokenAuthentication()
    {
        await using var server = await StartAsync();
        await SeedAsync(server, ReadSnapshot(Vector()["base"]!));
        using var anonymous = server.CreateClient();
        using var denied = await anonymous.GetAsync(Route("single", "1001"));
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        await using (var scope = server.HostServices.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ManagementUserService>().CreateUserAsync(Admin,
                new UserMutation("preview-admin", "preview-test-password", "ADMIN", true), CancellationToken.None);
        using var user = await LoginAsync(server, "preview-admin", "preview-test-password");
        using (var allowed = await user.GetAsync(Route("single", "1001"))) Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        await using (var scope = server.HostServices.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(Admin, "preview-admin",
                new UserMutation(null, null, "USER", null), CancellationToken.None);
        foreach (var id in new[] { "1001", "999", "not-a-number", "0", "9007199254740992" })
        {
            using var response = await user.GetAsync(Route("single", id));
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("FORBIDDEN", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        }
        await using (var scope = server.HostServices.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ManagementUserService>().UpdateUserAsync(Admin, "preview-admin",
                new UserMutation(null, null, "ADMIN", false), CancellationToken.None);
        using var disabled = await user.GetAsync(Route("single", "1001"));
        Assert.Equal(HttpStatusCode.Unauthorized, disabled.StatusCode);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("1.0")]
    [InlineData("1e3")]
    [InlineData("9223372036854775808")]
    [InlineData("abc")]
    [InlineData("１２３")]
    public async Task InvalidIdsHaveStableErrors(string id)
    {
        await using var server = await StartAsync();
        using var client = await LoginAsync(server, "admin", "admin");
        using var response = await client.GetAsync(Route("single", Uri.EscapeDataString(id)));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("INVALID_TRANSFER_REQUEST", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Fact]
    public async Task ForeignAndAbsentPathResourcesAreIndistinguishable()
    {
        var scenario = new JsonObject { ["snapshot"] = "foreign-client" };
        await using var server = await StartAsync();
        await SeedAsync(server, ReadSnapshot(Input(scenario)));
        using var client = await LoginAsync(server, "admin", "admin");
        string? first = null;
        foreach (var id in new[] { "1002", "999" })
        {
            using var response = await client.GetAsync(Route("single", id));
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("secret-other", body);
            first ??= body;
            Assert.Equal(first, body);
        }
    }

    [Fact]
    public async Task SqlSnapshotIncludesReverseAndForeignEdgesForSinglePath()
    {
        foreach (var snapshotName in new[] { "multiple-credentials", "foreign-identity" })
        {
            await using var server = await StartAsync();
            await SeedAsync(server, ReadSnapshot(Input(new JsonObject { ["snapshot"] = snapshotName })));
            using var client = await LoginAsync(server, "admin", "admin");
            using var response = await client.GetAsync(Route("single", "1001"));
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal("INCONSISTENT_CREDENTIAL_GROUP", (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());
        }
    }

    [Fact]
    public async Task HeartbeatsDoNotInvalidateButRenameDoesAndFreshScopeAgrees()
    {
        await using var server = await StartAsync();
        await SeedAsync(server, ReadSnapshot(Vector()["base"]!));
        using var client = await LoginAsync(server, "admin", "admin");
        var revision = (await client.GetFromJsonAsync<ClientOwnerTransferPreview>(Route("credential-group", "501")))!.Revision;
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var identity = await db.ClientIdentities.SingleAsync(i => i.Id == 701);
            identity.LastSeenAt = DateTimeOffset.UtcNow.AddDays(1);
            identity.Hostname = "updated-hostname";
            var peer = await db.PeerMeshDevices.SingleAsync(p => p.Id == 801);
            peer.LastSeenAt = DateTimeOffset.UtcNow.AddDays(1);
            peer.LastEndpoint = "192.0.2.1:5000";
            peer.UpdatedAt = DateTimeOffset.UtcNow.AddDays(1);
            await db.SaveChangesAsync();
        }
        Assert.Equal(revision, (await client.GetFromJsonAsync<ClientOwnerTransferPreview>(Route("credential-group", "501")))!.Revision);
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            // New scoped service/connection can reproduce the revision; not a multi-instance writer proof.
            var service = scope.ServiceProvider.GetRequiredService<ClientOwnerTransferService>();
            Assert.Equal(revision, (await service.PreviewCredentialAsync(Admin, "501", CancellationToken.None)).Revision);
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ClientAccounts.SingleAsync(c => c.Id == 1002);
            account.ClientName = "renamed";
            await db.SaveChangesAsync();
        }
        Assert.NotEqual(revision, (await client.GetFromJsonAsync<ClientOwnerTransferPreview>(Route("credential-group", "501")))!.Revision);
    }

    [Fact]
    public async Task ActualSqlGroupDoesNotTruncateOrExceedParameterLimits()
    {
        var clients = Enumerable.Range(0, 1050).Select(n => new ClientRow(1001 + n, "tenant-a", $"device-{n}", "alice", n % 2 == 0)).ToArray();
        var edges = Enumerable.Range(0, 1050).Select(n => new IdentityRow(10001 + n, "tenant-a", 501, 1001 + n)).ToArray();
        await using var server = await StartAsync();
        await SeedAsync(server, new Snapshot(clients, [new CredentialRow(501, "tenant-a", "alice", false)], edges, []));
        using var client = await LoginAsync(server, "admin", "admin");
        var preview = await client.GetFromJsonAsync<ClientOwnerTransferPreview>(Route("credential-group", "501"));
        Assert.Equal(1050, preview!.AffectedClientCount);
        Assert.Equal(Enumerable.Range(1001, 1050).Select(n => (long)n), preview.AffectedClients.Select(c => c.Id));
        Assert.False(preview.CredentialEnabled);
        Assert.NotNull(preview.Revision);
    }

    private static Task<TestServerFixture> StartAsync() => TestServerFixture.StartAsync(new Dictionary<string, string?> { ["Specus:Auth:TenantId"] = "tenant-a" });
    private static string Route(string scope, string id) => $"/api/admin/{(scope == "single" ? "clients" : "client-credentials")}/{id}/owner-transfer";

    private static async Task<HttpClient> LoginAsync(TestServerFixture server, string username, string password)
    {
        var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/login", new AdminLoginRequest(username, password, TenantId: "tenant-a"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("accessToken").GetString());
        return client;
    }

    private static async Task SeedAsync(TestServerFixture server, Snapshot input)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.Parse("2026-10-14T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        db.ClientAccounts.AddRange(input.Clients.Select(c => new ClientAccount { Id = c.Id, TenantId = c.TenantId, ClientName = c.ClientName!, OwnerUsername = c.OwnerUsername, Enabled = c.Enabled, PasswordHash = "sensitive-password-hash", CreatedAt = now, UpdatedAt = now }));
        db.ClientCredentials.AddRange(input.Credentials.Select(c => new ClientCredential { Id = c.Id, TenantId = c.TenantId, OwnerUsername = c.OwnerUsername, Enabled = c.Enabled, ApiKey = $"sensitive-api-key-{c.Id}", SecretHash = "sensitive-secret-hash", CreatedAt = now, UpdatedAt = now }));
        db.ClientIdentities.AddRange(input.Identities.Select(i => new ClientIdentity { Id = i.Id, TenantId = i.TenantId, CredentialId = i.CredentialId, ClientId = i.ClientId, ClientName = $"identity-{i.ClientId}", MachineFingerprint = $"sensitive-fingerprint-{i.Id}", OsUser = "sensitive-os-user", FirstSeenAt = now, LastSeenAt = now }));
        db.PeerMeshDevices.AddRange(input.Peers.Select(p => new PeerMeshDevice { Id = p.Id, TenantId = p.TenantId, ClientId = p.ClientId, ClientName = p.ClientName!, OwnerUsername = p.OwnerUsername!, Enabled = p.Enabled, VirtualIp = $"10.66.0.{p.Id % 240 + 2}", Cidr = "10.66.0.0/16", PublicKey = "sensitive-public-key", CreatedAt = now, UpdatedAt = now }));
        await db.SaveChangesAsync();
    }

    private static async Task<string> RowsAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        return JsonSerializer.Serialize(new
        {
            clients = await db.ClientAccounts.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
            credentials = await db.ClientCredentials.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
            identities = await db.ClientIdentities.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
            peers = await db.PeerMeshDevices.AsNoTracking().OrderBy(c => c.Id).ToListAsync(),
        });
    }
}
