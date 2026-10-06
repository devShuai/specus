using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
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
/// The workbench API over HTTP beyond the shared vector (which <see cref="ServiceWorkbenchVectorTests"/>
/// replays): the session requirement, the cache header on every answer, ids validated as text,
/// identity isolation for administrators too, and the cascades through the real delete endpoints.
/// </summary>
public sealed class ServiceWorkbenchApiTests : IAsyncLifetime
{
    private const string Tenant = "default";
    private const string Workbench = "/api/admin/workbench";

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
    public async Task EveryAnswerNeedsASessionAndIsNeverCached()
    {
        using var anonymous = _server!.CreateClient();
        foreach (var (method, path) in new[]
                 {
                     (HttpMethod.Get, Workbench),
                     (HttpMethod.Put, Workbench + "/favorites/http-route/1"),
                     (HttpMethod.Post, Workbench + "/recents/http-route/1"),
                     (HttpMethod.Delete, Workbench + "/recents"),
                 })
        {
            using var response = await anonymous.SendAsync(new HttpRequestMessage(method, path));
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            AssertNoStore(response);
        }

        using var admin = Client(AdminToken());
        using var read = await admin.GetAsync(Workbench);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        AssertNoStore(read);
        using (var document = await JsonAsync(read))
        {
            Assert.Equal(1, document.RootElement.GetProperty("schemaVersion").GetInt32());
            var limits = document.RootElement.GetProperty("limits");
            Assert.Equal(50, limits.GetProperty("maxFavorites").GetInt32());
            Assert.Equal(20, limits.GetProperty("maxRecents").GetInt32());
            Assert.Equal(30, limits.GetProperty("recentRetentionDays").GetInt32());
            Assert.Equal(0, document.RootElement.GetProperty("favorites").GetArrayLength());
            Assert.Equal(0, document.RootElement.GetProperty("recents").GetArrayLength());
        }

        using var invalid = await admin.PutAsync(Workbench + "/favorites/http-route/042", content: null);
        await AssertRefusedAsync(invalid, HttpStatusCode.BadRequest, WorkbenchCodes.RequestInvalid);

        using var missing = await admin.PostAsync(Workbench + "/recents/http-route/123456789", content: null);
        await AssertRefusedAsync(missing, HttpStatusCode.NotFound, WorkbenchCodes.TargetNotFound);
    }

    /// <summary>
    /// The id is checked as the raw path text: nothing a number parser would forgive (a leading zero,
    /// a sign, a fraction, an exponent, whitespace, a value past 2^53-1) gets through, on growth and
    /// removal alike, and the kind must be one of the three names exactly.
    /// </summary>
    [Fact]
    public async Task KindAndIdAreValidatedAsText()
    {
        using var admin = Client(AdminToken());
        string[] ids = ["042", "0", "00", "+1", "-1", "1.0", "1e3", "%201", "1%20", "0x10",
            "9007199254740992", "99999999999999999999", "１"];
        foreach (var id in ids)
        {
            foreach (var (method, list) in new[]
                     {
                         (HttpMethod.Put, "favorites"), (HttpMethod.Delete, "favorites"),
                         (HttpMethod.Post, "recents"), (HttpMethod.Delete, "recents"),
                     })
            {
                using var response = await admin.SendAsync(
                    new HttpRequestMessage(method, $"{Workbench}/{list}/http-route/{id}"));
                await AssertRefusedAsync(response, HttpStatusCode.BadRequest, WorkbenchCodes.RequestInvalid,
                    $"{method} {list} {id}");
            }
        }
        foreach (var kind in new[] { "HTTP-ROUTE", "Http-Route", "route", "tcp_mapping", "peer-services" })
        {
            using var response = await admin.PutAsync($"{Workbench}/favorites/{kind}/1", content: null);
            await AssertRefusedAsync(response, HttpStatusCode.BadRequest, WorkbenchCodes.RequestInvalid, kind);
        }
        Assert.Empty(await RowsAsync());
    }

    /// <summary>
    /// An administrator sees and clears only their own lists. Nothing in the path, query or body can
    /// name another identity: the query is ignored, the body is never read.
    /// </summary>
    [Fact]
    public async Task ListsBelongToTheCallerAdministratorsIncluded()
    {
        await CreateUserAsync("carol");
        var objects = await AddClientWithServicesAsync("carol-client", "carol", 7_001);
        using var carol = Client(UserToken("carol"));
        using var admin = Client(AdminToken());

        (await carol.PutAsync($"{Workbench}/favorites/http-route/{objects.Route}", content: null)).EnsureSuccessStatusCode();
        (await carol.PostAsync($"{Workbench}/recents/tcp-mapping/{objects.Mapping}", content: null)).EnsureSuccessStatusCode();

        using (var adminView = await JsonAsync(await admin.GetAsync($"{Workbench}?username=carol&tenantId={Tenant}")))
        {
            Assert.Equal(0, adminView.RootElement.GetProperty("favorites").GetArrayLength());
            Assert.Equal(0, adminView.RootElement.GetProperty("recents").GetArrayLength());
        }

        // The body names carol and another kind; it is not read, so the admin favourites the route.
        using var withBody = new HttpRequestMessage(HttpMethod.Put,
            $"{Workbench}/favorites/http-route/{objects.Route}")
        {
            Content = new StringContent("""{"tenantId":"other","username":"carol","kind":"tcp-mapping","id":1}""",
                Encoding.UTF8, "application/json"),
        };
        using (var added = await JsonAsync(await admin.SendAsync(withBody)))
        {
            var favorite = Assert.Single(added.RootElement.GetProperty("favorites").EnumerateArray());
            Assert.Equal("http-route", favorite.GetProperty("kind").GetString());
            Assert.Equal(objects.Route, favorite.GetProperty("id").GetInt64());
        }

        foreach (var list in new[] { "favorites", "recents" })
        {
            using var clear = new HttpRequestMessage(HttpMethod.Delete, $"{Workbench}/{list}?username=carol")
            {
                Content = new StringContent("""{"username":"carol"}""", Encoding.UTF8, "application/json"),
            };
            using var cleared = await admin.SendAsync(clear);
            Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);
            AssertNoStore(cleared);
        }

        using (var carolView = await JsonAsync(await carol.GetAsync(Workbench)))
        {
            var favorite = Assert.Single(carolView.RootElement.GetProperty("favorites").EnumerateArray());
            Assert.Equal(objects.Route, favorite.GetProperty("id").GetInt64());
            var recent = Assert.Single(carolView.RootElement.GetProperty("recents").EnumerateArray());
            Assert.Equal("tcp-mapping", recent.GetProperty("kind").GetString());
            Assert.Equal(objects.Mapping, recent.GetProperty("id").GetInt64());
        }
        var expected = new[]
        {
            ("default", "carol", "favorite", "http-route", objects.Route),
            ("default", "carol", "recent", "tcp-mapping", objects.Mapping),
        };
        Assert.Equal(expected,
            (await RowsAsync()).Select(row => (row.TenantId, row.Username, row.List, row.Kind, row.ObjectId)));
    }

    [Fact]
    public async Task DeletingARouteMappingOrPeerServiceRemovesEveryonesReferences()
    {
        await CreateUserAsync("carol");
        var deleted = await AddClientWithServicesAsync("carol-client", "carol", 7_101);
        var kept = await AddClientWithServicesAsync("carol-other", "carol", 7_201);
        using var carol = Client(UserToken("carol"));
        using var admin = Client(AdminToken());
        foreach (var client in new[] { carol, admin })
        {
            await ReferenceAllAsync(client, deleted);
            await ReferenceAllAsync(client, kept);
        }
        Assert.Equal(24, (await RowsAsync()).Count);

        Assert.Equal(HttpStatusCode.NoContent,
            (await admin.DeleteAsync($"/api/admin/http-routes/{deleted.Route}")).StatusCode);
        Assert.DoesNotContain(await RowsAsync(), row => row.Kind == "http-route" && row.ObjectId == deleted.Route);
        Assert.Equal(20, (await RowsAsync()).Count);

        Assert.Equal(HttpStatusCode.NoContent,
            (await admin.DeleteAsync($"/api/admin/specus-mappings/{deleted.Mapping}")).StatusCode);
        Assert.DoesNotContain(await RowsAsync(), row => row.Kind == "tcp-mapping" && row.ObjectId == deleted.Mapping);
        Assert.Equal(16, (await RowsAsync()).Count);

        Assert.Equal(HttpStatusCode.OK,
            (await admin.DeleteAsync($"/api/admin/peer-mesh/services/{deleted.Service}")).StatusCode);
        Assert.DoesNotContain(await RowsAsync(), row => row.Kind == "peer-service" && row.ObjectId == deleted.Service);

        // Only the other client's references are left, for both identities.
        var rows = await RowsAsync();
        Assert.Equal(12, rows.Count);
        Assert.All(rows, row => Assert.Contains(row.ObjectId, new[] { kept.Route, kept.Mapping, kept.Service }));
    }

    [Fact]
    public async Task DeletingAClientRemovesReferencesToEachOfItsServices()
    {
        await CreateUserAsync("carol");
        var deleted = await AddClientWithServicesAsync("carol-client", "carol", 7_301);
        var kept = await AddClientWithServicesAsync("carol-other", "carol", 7_401);
        using var carol = Client(UserToken("carol"));
        using var admin = Client(AdminToken());
        foreach (var client in new[] { carol, admin })
        {
            await ReferenceAllAsync(client, deleted);
            await ReferenceAllAsync(client, kept);
        }

        Assert.Equal(HttpStatusCode.NoContent,
            (await admin.DeleteAsync($"/api/admin/clients/{deleted.ClientId}")).StatusCode);

        var rows = await RowsAsync();
        Assert.Equal(12, rows.Count);
        Assert.All(rows, row => Assert.Contains(row.ObjectId, new[] { kept.Route, kept.Mapping, kept.Service }));
        using var carolView = await JsonAsync(await carol.GetAsync(Workbench));
        Assert.Equal(3, carolView.RootElement.GetProperty("favorites").GetArrayLength());
        Assert.Equal(3, carolView.RootElement.GetProperty("recents").GetArrayLength());
    }

    [Fact]
    public async Task DeletingAnAccountRemovesItsListsAndDisablingDoesNot()
    {
        await CreateUserAsync("carol");
        var objects = await AddClientWithServicesAsync("carol-client", "carol", 7_501);
        using var carol = Client(UserToken("carol"));
        using var admin = Client(AdminToken());
        await ReferenceAllAsync(carol, objects);
        await ReferenceAllAsync(admin, objects);

        Assert.Equal(HttpStatusCode.OK,
            (await admin.PutAsJsonAsync("/api/admin/users/carol", new { enabled = false })).StatusCode);
        using (var refused = await carol.GetAsync(Workbench))
        {
            Assert.False(refused.IsSuccessStatusCode);
            AssertNoStore(refused);
        }
        Assert.Equal(12, (await RowsAsync()).Count);
        Assert.Equal(HttpStatusCode.OK,
            (await admin.PutAsJsonAsync("/api/admin/users/carol", new { enabled = true })).StatusCode);
        using (var restored = await JsonAsync(await carol.GetAsync(Workbench)))
        {
            Assert.Equal(3, restored.RootElement.GetProperty("favorites").GetArrayLength());
        }

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync("/api/admin/users/carol")).StatusCode);
        var rows = await RowsAsync();
        Assert.Equal(6, rows.Count);
        Assert.All(rows, row => Assert.Equal("admin", row.Username));
        using (var stale = await carol.PostAsync($"{Workbench}/recents/http-route/{objects.Route}", content: null))
        {
            Assert.False(stale.IsSuccessStatusCode);
        }
        Assert.Equal(6, (await RowsAsync()).Count);

        await CreateUserAsync("carol");
        using var fresh = await JsonAsync(await carol.GetAsync(Workbench));
        Assert.Equal(0, fresh.RootElement.GetProperty("favorites").GetArrayLength());
        Assert.Equal(0, fresh.RootElement.GetProperty("recents").GetArrayLength());
    }

    /// <summary>
    /// The limiter keeps at most 10 000 keys: a new identity is admitted by evicting entries whose
    /// TAT has passed, and refused with Retry-After 1 while every entry is still live.
    /// </summary>
    [Fact]
    public void RateLimiterKeyTableIsBounded()
    {
        var limiter = new WorkbenchRateLimiter();
        for (var i = 0; i < WorkbenchRateLimiter.MaxKeys; i++)
        {
            Assert.True(limiter.TryAcquire("t", $"user-{i}", 0, out _));
        }
        Assert.False(limiter.TryAcquire("t", "newcomer", 999, out var retryAfter));
        Assert.Equal(1, retryAfter);
        Assert.True(limiter.TryAcquire("t", "user-1", 999, out _));
        Assert.True(limiter.TryAcquire("t", "newcomer", 1_000, out _));

        limiter.Reset();
        for (var i = 0; i < WorkbenchRateLimiter.Burst; i++)
        {
            Assert.True(limiter.TryAcquire("t", "burst", 0, out _));
        }
        Assert.False(limiter.TryAcquire("t", "burst", 0, out retryAfter));
        Assert.Equal(1, retryAfter);
        // Another identity has a key of its own.
        Assert.True(limiter.TryAcquire("t", "another", 0, out _));
    }

    private sealed record ClientServices(long ClientId, long Route, long Mapping, long Service);

    private async Task ReferenceAllAsync(HttpClient client, ClientServices objects)
    {
        foreach (var (kind, id) in new[]
                 {
                     ("http-route", objects.Route), ("tcp-mapping", objects.Mapping), ("peer-service", objects.Service),
                 })
        {
            using var favorite = await client.PutAsync($"{Workbench}/favorites/{kind}/{id}", content: null);
            Assert.Equal(HttpStatusCode.OK, favorite.StatusCode);
            using var visit = await client.PostAsync($"{Workbench}/recents/{kind}/{id}", content: null);
            Assert.Equal(HttpStatusCode.OK, visit.StatusCode);
        }
    }

    private async Task CreateUserAsync(string username)
    {
        using var admin = Client(AdminToken());
        using var response = await admin.PostAsJsonAsync("/api/admin/users", new
        {
            username,
            password = username + "-password",
            role = "USER",
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    /// <summary>A client of <paramref name="owner"/> carrying one route, one mapping and one Peer service.</summary>
    private async Task<ClientServices> AddClientWithServicesAsync(string clientName, string owner, long firstId)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        var client = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = Tenant,
            OwnerUsername = owner,
            ClientName = clientName,
            PasswordHash = new string('0', 64),
            Enabled = true,
            ConnectionRateLimitPerMinute = 30,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.ClientAccounts.Add(client);
        db.HttpRouteMappings.Add(new HttpRouteMapping
        {
            Id = firstId,
            TenantId = Tenant,
            ClientId = client.Id,
            ClientName = clientName,
            Route = "workbench",
            TargetBaseUrl = "http://127.0.0.1:8080",
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        db.SpecusMappings.Add(new SpecusMapping
        {
            Id = firstId + 1,
            TenantId = Tenant,
            ClientId = client.Id,
            ClientName = clientName,
            ListenPort = (int)(30_000 + firstId % 10_000),
            TargetAddress = "127.0.0.1",
            TargetPort = 22,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        db.PeerMeshSharedServices.Add(new PeerMeshSharedService
        {
            Id = firstId + 2,
            TenantId = Tenant,
            ClientId = client.Id,
            ClientName = clientName,
            ServiceId = $"workbench-{firstId}",
            Name = "workbench",
            Transport = "tcp",
            Application = "tcp",
            TargetHost = "127.0.0.1",
            TargetPort = 22,
            PublishedPort = (int)(40_000 + firstId % 10_000),
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        return new ClientServices(client.Id, firstId, firstId + 1, firstId + 2);
    }

    private async Task<List<ManagementWorkbenchItem>> RowsAsync()
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var rows = await db.ManagementWorkbenchItems.AsNoTracking().ToListAsync();
        return rows.OrderBy(row => row.Username, StringComparer.Ordinal)
            .ThenBy(row => row.List, StringComparer.Ordinal)
            .ThenBy(row => WorkbenchKinds.Order(row.Kind))
            .ThenBy(row => row.ObjectId)
            .ToList();
    }

    private string AdminToken() =>
        _server!.HostServices.GetRequiredService<LocalTokenService>().IssueToken("admin", Tenant, ManagementRole.Admin);

    private string UserToken(string username) =>
        _server!.HostServices.GetRequiredService<LocalTokenService>().IssueToken(username, Tenant, ManagementRole.User);

    private HttpClient Client(string token)
    {
        var client = _server!.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<JsonDocument> JsonAsync(HttpResponseMessage response)
    {
        using (response)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertNoStore(response);
            return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        }
    }

    private static async Task AssertRefusedAsync(HttpResponseMessage response, HttpStatusCode status, string code,
        string? label = null)
    {
        Assert.True(status == response.StatusCode, $"{label}: expected {status}, got {response.StatusCode}");
        AssertNoStore(response);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(code, body.RootElement.GetProperty("code").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("error").GetString()));
    }

    private static void AssertNoStore(HttpResponseMessage response)
    {
        var cacheControl = response.Headers.CacheControl;
        Assert.NotNull(cacheControl);
        Assert.True(cacheControl!.NoStore && cacheControl.Private,
            $"Cache-Control was '{cacheControl}' on {(int)response.StatusCode}");
    }
}
