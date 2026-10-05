using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// The egress management API over HTTP: the shared destination-rule vector replayed through the
/// real endpoint, and the status codes protocol/spec/peer-egress.md fixes for it. The service-level
/// behaviour is covered in <see cref="PeerEgressServiceTests"/>; what is tested here is what a
/// client of the API actually receives.
/// </summary>
public sealed class PeerEgressManagementApiTests : IAsyncLifetime
{
    private const string PoliciesPath = "/api/admin/peer-mesh/egress/policies";
    private const string SwitchPath = "/api/admin/peer-mesh/egress/switch";

    private TestServerFixture? _server;

    public async Task InitializeAsync() => _server = await TestServerFixture.StartAsync();

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact]
    public async Task EveryAcceptedVectorCaseIsStoredAsTheVectorSays()
    {
        var egressId = await AddClientAsync("vector-accept-egress");
        using var client = AdminClient();

        foreach (var vectorCase in PeerEgressManagementVector.Cases("accept"))
        {
            var name = vectorCase.GetProperty("name").GetString();
            using var response = await PostPolicyAsync(client, egressId, vectorCase.GetProperty("destinationRules"));
            Assert.True(response.StatusCode == HttpStatusCode.OK,
                $"{name}: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.True(PeerEgressManagementVector.Compact(vectorCase.GetProperty("stored"))
                    == PeerEgressManagementVector.Compact(body.RootElement.GetProperty("destinationRules")),
                $"{name}: returned {body.RootElement.GetProperty("destinationRules").GetRawText()}");
        }
    }

    /// <summary>
    /// A refused case is refused whole: 400 with the usual error body, and no policy appears for
    /// the device, not even one carrying the other, valid fields of the request.
    /// </summary>
    [Fact]
    public async Task EveryRefusedVectorCaseIsABadRequestThatSavesNothing()
    {
        var egressId = await AddClientAsync("vector-reject-egress");
        using var client = AdminClient();

        foreach (var vectorCase in PeerEgressManagementVector.Cases("reject"))
        {
            var name = vectorCase.GetProperty("name").GetString();
            using var response = await PostPolicyAsync(client, egressId, vectorCase.GetProperty("destinationRules"));
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{name}: {response.StatusCode}");
            await AssertErrorBodyAsync(response);
        }

        using var list = await client.GetAsync(PoliciesPath);
        list.EnsureSuccessStatusCode();
        using var policies = JsonDocument.Parse(await list.Content.ReadAsStringAsync());
        Assert.DoesNotContain(policies.RootElement.EnumerateArray(),
            policy => policy.GetProperty("egressClientId").GetInt64() == egressId);
    }

    /// <summary>
    /// The domain-policy vector's accepted cases, posted as raw JSON: each answers with exactly the
    /// vector's <c>stored</c> rules, in the compact form the 4096-byte limit is measured on.
    /// </summary>
    [Fact]
    public async Task EveryAcceptedDomainPolicyCaseIsStoredAsTheVectorSays()
    {
        var egressId = await AddClientAsync("domain-vector-accept-egress");
        using var client = AdminClient();

        foreach (var vectorCase in PeerEgressDomainPolicyVector.Cases("accept"))
        {
            var name = vectorCase.GetProperty("name").GetString();
            using var response = await PostDomainPolicyAsync(client, egressId, vectorCase.GetProperty("domainRules"));
            Assert.True(response.StatusCode == HttpStatusCode.OK,
                $"{name}: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.True(PeerEgressManagementVector.Compact(vectorCase.GetProperty("stored"))
                    == PeerEgressManagementVector.Compact(body.RootElement.GetProperty("domainRules")),
                $"{name}: returned {body.RootElement.GetProperty("domainRules").GetRawText()}");
        }
    }

    /// <summary>
    /// The domain-policy vector's refused cases: each is a 400 with the usual error body, and no
    /// policy appears for the device.
    /// </summary>
    [Fact]
    public async Task EveryRefusedDomainPolicyCaseIsABadRequestThatSavesNothing()
    {
        var egressId = await AddClientAsync("domain-vector-reject-egress");
        using var client = AdminClient();

        foreach (var vectorCase in PeerEgressDomainPolicyVector.Cases("reject"))
        {
            var name = vectorCase.GetProperty("name").GetString();
            using var response = await PostDomainPolicyAsync(client, egressId, vectorCase.GetProperty("domainRules"));
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{name}: {response.StatusCode}");
            await AssertErrorBodyAsync(response);
        }

        using var list = await client.GetAsync(PoliciesPath);
        list.EnsureSuccessStatusCode();
        using var policies = JsonDocument.Parse(await list.Content.ReadAsStringAsync());
        Assert.DoesNotContain(policies.RootElement.EnumerateArray(),
            policy => policy.GetProperty("egressClientId").GetInt64() == egressId);
    }

    /// <summary>
    /// A switch request without <c>enabled</c> used to be read as "off". It is refused instead, and
    /// the stored switch is left as it was.
    /// </summary>
    [Fact]
    public async Task SwitchWithoutEnabledIsABadRequestAndChangesNothing()
    {
        // Set directly: the test deployment runs with Peer Mesh off, so the API cannot turn it on.
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.PeerMeshEgressSwitches.Add(new PeerMeshEgressSwitch
            {
                TenantId = "default",
                Enabled = true,
                UpdatedBy = "admin",
                UpdatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }
        using var client = AdminClient();

        using var response = await client.PutAsync(SwitchPath, Json("{}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertErrorBodyAsync(response);
        using var status = await client.GetAsync(SwitchPath);
        status.EnsureSuccessStatusCode();
        using var view = JsonDocument.Parse(await status.Content.ReadAsStringAsync());
        Assert.True(view.RootElement.GetProperty("configuredEnabled").GetBoolean());
    }

    [Fact]
    public async Task EnablingWhileTheDeploymentHasPeerMeshOffIsABadRequest()
    {
        using var client = AdminClient();

        using var enable = await client.PutAsync(SwitchPath, Json("{\"enabled\":true}"));
        Assert.Equal(HttpStatusCode.BadRequest, enable.StatusCode);
        await AssertErrorBodyAsync(enable);

        // Switching off stays possible, so an operator can always withdraw egress.
        using var disable = await client.PutAsync(SwitchPath, Json("{\"enabled\":false}"));
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);
    }

    [Fact]
    public async Task AnUnparseableBodyIsABadRequest()
    {
        using var client = AdminClient();

        using var response = await client.PostAsync(PoliciesPath, Json("{\"egressClientId\":"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task MutationsByANonAdminAreForbidden()
    {
        var egressId = await AddClientAsync("forbidden-egress");
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.ManagementUsers.Add(new ManagementUser
            {
                Username = "egress-viewer",
                TenantId = "default",
                PasswordHash = "unused",
                Role = ManagementRole.User,
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }
        using var client = _server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            _server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken("egress-viewer", "default", ManagementRole.User));

        using var upsert = await client.PostAsync(PoliciesPath,
            Json($"{{\"egressClientId\":{egressId},\"enabled\":true}}"));
        Assert.Equal(HttpStatusCode.Forbidden, upsert.StatusCode);
        await AssertErrorBodyAsync(upsert);

        // Authorisation comes before validation: a body the admin would get a 400 for is still a
        // 403 here, so a non-admin learns nothing about what the API would accept.
        using var toggle = await client.PutAsync(SwitchPath, Json("{}"));
        Assert.Equal(HttpStatusCode.Forbidden, toggle.StatusCode);
        await AssertErrorBodyAsync(toggle);

        using var delete = await client.DeleteAsync($"{PoliciesPath}/1");
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        await AssertErrorBodyAsync(delete);
    }

    [Fact]
    public async Task AnUnknownPolicyOrEgressDeviceIsNotFound()
    {
        using var client = AdminClient();

        using var delete = await client.DeleteAsync($"{PoliciesPath}/424242");
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        await AssertErrorBodyAsync(delete);

        using var upsert = await client.PostAsync(PoliciesPath,
            Json("{\"egressClientId\":424242,\"enabled\":true}"));
        Assert.Equal(HttpStatusCode.NotFound, upsert.StatusCode);
        await AssertErrorBodyAsync(upsert);
    }

    private HttpClient AdminClient()
    {
        var client = _server!.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            _server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken("admin", "default", ManagementRole.Admin));
        return client;
    }

    private async Task<long> AddClientAsync(string clientName)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        var account = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = "default",
            OwnerUsername = "admin",
            ClientName = clientName,
            PasswordHash = "unused",
            Enabled = true,
            ConnectionRateLimitPerMinute = 30,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.ClientAccounts.Add(account);
        await db.SaveChangesAsync();
        return account.Id;
    }

    /// <summary>
    /// Posts the vector's rules as raw JSON, so fields the vector leaves out stay absent instead of
    /// being filled in by a serializer on the way.
    /// </summary>
    private static Task<HttpResponseMessage> PostPolicyAsync(HttpClient client, long egressId,
        JsonElement destinationRules) =>
        client.PostAsync(PoliciesPath, Json(
            $"{{\"egressClientId\":{egressId},\"enabled\":true,\"scope\":\"PUBLIC\","
            + $"\"destinationRules\":{destinationRules.GetRawText()}}}"));

    private static Task<HttpResponseMessage> PostDomainPolicyAsync(HttpClient client, long egressId,
        JsonElement domainRules) =>
        client.PostAsync(PoliciesPath, Json(
            $"{{\"egressClientId\":{egressId},\"enabled\":true,\"scope\":\"PUBLIC\","
            + $"\"domainRules\":{domainRules.GetRawText()}}}"));

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static async Task AssertErrorBodyAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("error").GetString()));
    }
}

/// <summary>
/// protocol/test-vectors/peer-egress-management-v1.json, shared with the other servers.
/// </summary>
internal static class PeerEgressManagementVector
{
    private static readonly Lazy<JsonElement> Root = new(() =>
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindVector()));
        return document.RootElement.Clone();
    });

    /// <summary>The cases of one kind, <c>accept</c> or <c>reject</c>.</summary>
    public static IEnumerable<JsonElement> Cases(string kind) => Root.Value.GetProperty(kind).EnumerateArray();

    public static JsonElement Case(string kind, string name) =>
        Cases(kind).Single(item => item.GetProperty("name").GetString() == name);

    public static TheoryData<string> Names(string kind)
    {
        var names = new TheoryData<string>();
        foreach (var item in Cases(kind))
        {
            names.Add(item.GetProperty("name").GetString()!);
        }
        return names;
    }

    /// <summary>
    /// Compact JSON, the form the reference measures the 4096-byte limit on, so comparing it also
    /// pins that the server measures the same bytes.
    /// </summary>
    public static string Compact(JsonElement element) => JsonSerializer.Serialize(element);

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "peer-egress-management-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate peer-egress-management-v1.json");
    }
}

/// <summary>
/// protocol/test-vectors/peer-egress-domain-policy-v1.json, shared with the other servers. Only its
/// <c>management</c> half concerns a server.
/// </summary>
internal static class PeerEgressDomainPolicyVector
{
    private static readonly Lazy<JsonElement> Root = new(() =>
    {
        using var document = JsonDocument.Parse(File.ReadAllText(FindVector()));
        return document.RootElement.Clone();
    });

    public static JsonElement Limits => Root.Value.GetProperty("limits");

    /// <summary>The management cases of one kind, <c>accept</c> or <c>reject</c>.</summary>
    public static IEnumerable<JsonElement> Cases(string kind) =>
        Root.Value.GetProperty("management").GetProperty(kind).EnumerateArray();

    public static JsonElement Case(string kind, string name) =>
        Cases(kind).Single(item => item.GetProperty("name").GetString() == name);

    public static TheoryData<string> Names(string kind)
    {
        var names = new TheoryData<string>();
        foreach (var item in Cases(kind))
        {
            names.Add(item.GetProperty("name").GetString()!);
        }
        return names;
    }

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "peer-egress-domain-policy-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate peer-egress-domain-policy-v1.json");
    }
}
