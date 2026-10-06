using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays protocol/test-vectors/service-workbench-v1.json through the real HTTP pipeline: every
/// scenario on a fresh server and SQLite store, every API step as a request through routing, the
/// shared admin authentication layer and the workbench handlers, with the workbench clock at
/// baseTime + atMs. Events go through the existing paths: deletions through the route, mapping and
/// Peer service delete services (which carry the cascades), account changes through
/// <see cref="ManagementUserService"/>, ownership changes and new objects through fixtures, the
/// store outage by renaming the table away and back, and the sweep through the service method the
/// hosted sweep calls. After each scenario the whole table must equal rowsAfter.
///
/// <para>Management usernames are globally unique on this server, so the vector's two
/// <c>alice</c> accounts (tenants t1 and t2) cannot both exist. Identities of t1 keep their names;
/// any other tenant's names get a <c>-tenant</c> suffix (<c>alice-t2</c>). The mapping is applied to
/// accounts, tokens, object owners and injected rows, and reversed when rows are compared.</para>
/// </summary>
public sealed class ServiceWorkbenchVectorTests
{
    private const string Table = "management_workbench_item";
    private const string OfflineTable = "management_workbench_item_offline";

    public static TheoryData<string> ScenarioNames()
    {
        var names = new TheoryData<string>();
        foreach (var name in ScenarioNameList())
        {
            names.Add(name);
        }
        return names;
    }

    private static List<string> ScenarioNameList()
    {
        using var vector = LoadVector();
        return vector.RootElement.GetProperty("scenarios").EnumerateArray()
            .Select(scenario => scenario.GetProperty("name").GetString()!)
            .ToList();
    }

    /// <summary>
    /// The theory below covers the whole vector: one case per scenario, no scenario twice, and
    /// every scenario carries steps and its final rows.
    /// </summary>
    [Fact]
    public void EveryScenarioOfTheVectorIsReplayed()
    {
        using var vector = LoadVector();
        var scenarios = vector.RootElement.GetProperty("scenarios").EnumerateArray().ToList();
        var names = ScenarioNameList();
        Assert.Equal(names.Count, ScenarioNames().Count);
        Assert.Equal(scenarios.Count, names.Count);
        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(15, scenarios.Count);
        Assert.Equal(150, scenarios.Sum(scenario => scenario.GetProperty("steps").GetArrayLength()));
        Assert.All(scenarios, scenario => Assert.True(scenario.TryGetProperty("rowsAfter", out _)));
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task ScenarioMatchesTheSharedVector(string name)
    {
        using var vector = LoadVector();
        var baseTime = DateTimeOffset.Parse(vector.RootElement.GetProperty("baseTime").GetString()!,
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        var scenario = vector.RootElement.GetProperty("scenarios").EnumerateArray()
            .Single(item => item.GetProperty("name").GetString() == name);

        await using var run = await ScenarioRun.StartAsync(baseTime);
        await run.SeedAsync(scenario);

        var steps = scenario.GetProperty("steps").EnumerateArray().ToList();
        var replayed = 0;
        foreach (var (step, index) in steps.Select((step, index) => (step, index)))
        {
            var label = $"{name} step {index}";
            run.SetClock(step.GetProperty("atMs").GetInt64());
            if (step.TryGetProperty("event", out var eventName))
            {
                await run.ApplyEventAsync(eventName.GetString()!, step, label);
            }
            else
            {
                await run.CallAsync(step, label);
            }
            replayed++;
        }
        Assert.Equal(steps.Count, replayed);

        var expectedRows = scenario.GetProperty("rowsAfter").EnumerateArray()
            .Select(row => new VectorRow(
                row.GetProperty("tenantId").GetString()!,
                row.GetProperty("username").GetString()!,
                row.GetProperty("list").GetString()!,
                row.GetProperty("kind").GetString()!,
                row.GetProperty("id").GetInt64(),
                row.GetProperty("atMs").GetInt64()))
            .OrderBy(row => row, VectorRow.Order)
            .ToList();
        var actualRows = await run.ReadRowsAsync();
        Assert.True(expectedRows.SequenceEqual(actualRows),
            $"{name}: rows after the scenario\nexpected: {string.Join("; ", expectedRows)}\n"
            + $"actual:   {string.Join("; ", actualRows)}");
    }

    internal static JsonDocument LoadVector() => JsonDocument.Parse(File.ReadAllText(FindVector()));

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "service-workbench-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate service-workbench-v1.json");
    }

    /// <summary>A workbench row in the vector's terms (vector tenant and username).</summary>
    private sealed record VectorRow(string TenantId, string Username, string List, string Kind, long Id, long AtMs)
    {
        public static readonly IComparer<VectorRow> Order = Comparer<VectorRow>.Create((left, right) =>
        {
            var byTenant = string.CompareOrdinal(left.TenantId, right.TenantId);
            if (byTenant != 0) return byTenant;
            var byUser = string.CompareOrdinal(left.Username, right.Username);
            if (byUser != 0) return byUser;
            var byList = string.CompareOrdinal(left.List, right.List);
            if (byList != 0) return byList;
            var byKind = WorkbenchKinds.Order(left.Kind).CompareTo(WorkbenchKinds.Order(right.Kind));
            return byKind != 0 ? byKind : left.Id.CompareTo(right.Id);
        });
    }

    /// <summary>One scenario's server, clock, accounts and objects.</summary>
    private sealed class ScenarioRun : IAsyncDisposable
    {
        private readonly TestServerFixture _server;
        private readonly SettableTimeProvider _time;
        private readonly DateTimeOffset _baseTime;
        private readonly HttpClient _http;
        private readonly Dictionary<(string Tenant, string Username), string> _tokens = new();
        private readonly Dictionary<(string Tenant, string Username), (string Tenant, string Username)> _vectorIdentity =
            new();
        private readonly Dictionary<(string Kind, long Id), string> _objectTenants = new();
        private readonly Dictionary<(string Tenant, string Owner), ClientAccount> _clients = new();
        private int _nextPort = 21_000;

        private ScenarioRun(TestServerFixture server, SettableTimeProvider time, DateTimeOffset baseTime)
        {
            _server = server;
            _time = time;
            _baseTime = baseTime;
            _http = server.CreateClient();
        }

        public static async Task<ScenarioRun> StartAsync(DateTimeOffset baseTime)
        {
            var time = new SettableTimeProvider(baseTime);
            var server = await TestServerFixture.StartAsync(configureServices: services =>
            {
                services.AddSingleton(new WorkbenchClock(time));
                // The sweep runs only when the vector says so.
                foreach (var hosted in services
                             .Where(descriptor => descriptor.ServiceType == typeof(IHostedService)
                                 && descriptor.ImplementationType == typeof(WorkbenchRetentionSweepService))
                             .ToList())
                {
                    services.Remove(hosted);
                }
            });
            server.HostServices.GetRequiredService<WorkbenchRateLimiter>().Reset();
            return new ScenarioRun(server, time, baseTime);
        }

        public void SetClock(long atMs) => _time.Set(_baseTime.AddMilliseconds(atMs));

        public async Task SeedAsync(JsonElement scenario)
        {
            await using var scope = _server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            foreach (var user in scenario.GetProperty("users").EnumerateArray())
            {
                var (tenant, username) = Identity(user);
                db.ManagementUsers.Add(new ManagementUser
                {
                    Username = username,
                    TenantId = tenant,
                    PasswordHash = new string('0', 64),
                    Role = user.GetProperty("admin").GetBoolean() ? ManagementRole.Admin : ManagementRole.User,
                    Enabled = true,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                IssueToken(tenant, username);
            }
            await db.SaveChangesAsync();

            foreach (var item in scenario.GetProperty("objects").EnumerateArray())
            {
                await AddObjectAsync(db, item.GetProperty("kind").GetString()!, item.GetProperty("id").GetInt64(),
                    item.GetProperty("tenantId").GetString()!, item.GetProperty("ownerUsername").GetString()!);
            }

            foreach (var row in scenario.GetProperty("rows").EnumerateArray())
            {
                var (tenant, username) = Identity(row);
                db.ManagementWorkbenchItems.Add(new ManagementWorkbenchItem
                {
                    TenantId = tenant,
                    Username = username,
                    List = row.GetProperty("list").GetString()!,
                    Kind = row.GetProperty("kind").GetString()!,
                    ObjectId = row.GetProperty("id").GetInt64(),
                    AtMs = _baseTime.ToUnixTimeMilliseconds() + row.GetProperty("atMs").GetInt64(),
                });
            }
            await db.SaveChangesAsync();
        }

        public async Task CallAsync(JsonElement step, string label)
        {
            var method = new HttpMethod(step.GetProperty("method").GetString()!);
            var path = step.GetProperty("path").GetString()!;
            using var request = new HttpRequestMessage(method, path);
            var asUser = step.GetProperty("as");
            if (asUser.ValueKind != JsonValueKind.Null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _tokens[Identity(asUser)]);
            }
            var expect = step.GetProperty("expect");

            if (expect.TryGetProperty("sessionRejected", out var rejected) && rejected.GetBoolean())
            {
                var before = await ReadRowsAsync();
                using var refused = await _http.SendAsync(request);
                Assert.False(refused.IsSuccessStatusCode, $"{label}: {(int)refused.StatusCode} for a deleted account");
                Assert.True(before.SequenceEqual(await ReadRowsAsync()), $"{label}: a refused session wrote rows");
                return;
            }

            using var response = await _http.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();
            var status = expect.GetProperty("httpStatus").GetInt32();
            Assert.True(status == (int)response.StatusCode, $"{label}: expected {status}, got {(int)response.StatusCode} {body}");
            if (expect.TryGetProperty("retryAfterSeconds", out var retryAfter))
            {
                Assert.Equal(retryAfter.GetInt32().ToString(CultureInfo.InvariantCulture),
                    response.Headers.TryGetValues("Retry-After", out var values) ? values.Single() : null);
            }
            if (!expect.TryGetProperty("body", out var expectedBody))
            {
                return;
            }
            using var actual = JsonDocument.Parse(body);
            if (status == 200)
            {
                AssertJsonEqual(expectedBody, actual.RootElement, $"{label}: body");
            }
            else
            {
                Assert.Equal(expectedBody.GetProperty("code").GetString(),
                    actual.RootElement.GetProperty("code").GetString());
            }
        }

        public async Task ApplyEventAsync(string name, JsonElement step, string label)
        {
            await using var scope = _server.HostServices.CreateAsyncScope();
            var services = scope.ServiceProvider;
            var db = services.GetRequiredService<SpecusDbContext>();
            switch (name)
            {
                case "delete-object":
                {
                    var kind = step.GetProperty("kind").GetString()!;
                    var id = step.GetProperty("id").GetInt64();
                    var admin = TenantAdmin(_objectTenants[(kind, id)]);
                    switch (kind)
                    {
                        case WorkbenchKinds.HttpRoute:
                            await services.GetRequiredService<ManagementMutationService>()
                                .DeleteHttpRouteAsync(admin, id, CancellationToken.None);
                            break;
                        case WorkbenchKinds.TcpMapping:
                            await services.GetRequiredService<ManagementMutationService>()
                                .DeleteSpecusAsync(admin, id, CancellationToken.None);
                            break;
                        default:
                            await services.GetRequiredService<PeerMeshService>()
                                .DeleteSharedServiceAsync(admin, id, CancellationToken.None);
                            break;
                    }
                    _objectTenants.Remove((kind, id));
                    break;
                }
                case "create-object":
                    await AddObjectAsync(db, step.GetProperty("kind").GetString()!, step.GetProperty("id").GetInt64(),
                        step.GetProperty("tenantId").GetString()!, step.GetProperty("ownerUsername").GetString()!);
                    break;
                case "change-owner":
                    await ChangeOwnerAsync(db, step.GetProperty("kind").GetString()!, step.GetProperty("id").GetInt64(),
                        step.GetProperty("ownerUsername").GetString()!);
                    break;
                case "set-admin":
                {
                    var (tenant, username) = Identity(step);
                    await services.GetRequiredService<ManagementUserService>().UpdateUserAsync(TenantAdmin(tenant),
                        username, new UserMutation(null, null, step.GetProperty("admin").GetBoolean() ? "ADMIN" : "USER",
                            null), CancellationToken.None);
                    break;
                }
                case "delete-user":
                {
                    var (tenant, username) = Identity(step);
                    // The token issued before the deletion is kept: later steps replay it.
                    await services.GetRequiredService<ManagementUserService>().DeleteUserAsync(TenantAdmin(tenant),
                        username, CancellationToken.None);
                    break;
                }
                case "create-user":
                {
                    var (tenant, username) = Identity(step);
                    var admin = step.TryGetProperty("admin", out var flag) && flag.GetBoolean();
                    await services.GetRequiredService<ManagementUserService>().CreateUserAsync(TenantAdmin(tenant),
                        new UserMutation(username, "vector-password", admin ? "ADMIN" : "USER", true),
                        CancellationToken.None);
                    IssueToken(tenant, username);
                    break;
                }
                case "store-down":
                    await db.Database.ExecuteSqlRawAsync($"ALTER TABLE {Table} RENAME TO {OfflineTable}");
                    break;
                case "store-up":
                    await db.Database.ExecuteSqlRawAsync($"ALTER TABLE {OfflineTable} RENAME TO {Table}");
                    break;
                case "sweep":
                    await services.GetRequiredService<WorkbenchService>().SweepExpiredRecentsAsync(CancellationToken.None);
                    break;
                default:
                    Assert.Fail($"{label}: unknown event {name}");
                    break;
            }
        }

        public async Task<List<VectorRow>> ReadRowsAsync()
        {
            await using var scope = _server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var rows = await db.ManagementWorkbenchItems.AsNoTracking().ToListAsync();
            return rows
                .Select(row =>
                {
                    var (tenant, username) = _vectorIdentity.TryGetValue((row.TenantId, row.Username), out var mapped)
                        ? mapped
                        : (row.TenantId, row.Username);
                    return new VectorRow(tenant, username, row.List, row.Kind, row.ObjectId,
                        row.AtMs - _baseTime.ToUnixTimeMilliseconds());
                })
                .OrderBy(row => row, VectorRow.Order)
                .ToList();
        }

        /// <summary>The account standing for a vector identity; see the class remarks.</summary>
        private (string Tenant, string Username) Identity(JsonElement element) =>
            Map(element.GetProperty("tenantId").GetString()!, element.GetProperty("username").GetString()!);

        private (string Tenant, string Username) Map(string tenant, string username)
        {
            var mapped = (tenant, tenant == "t1" ? username : $"{username}-{tenant}");
            _vectorIdentity[mapped] = (tenant, username);
            return mapped;
        }

        private void IssueToken(string tenant, string username)
        {
            var tokens = _server.HostServices.GetRequiredService<LocalTokenService>();
            _tokens[(tenant, username)] = tokens.IssueToken(username, tenant, ManagementRole.User);
        }

        /// <summary>
        /// The tenant administrator account management and object deletion act as. The services
        /// take the context the admin layer would have resolved; the vector's own identities are not
        /// used, so none of them gains rows or rights from it.
        /// </summary>
        private static ManagementContext TenantAdmin(string tenant) =>
            new(tenant, "vector-fixture-admin", ManagementRole.Admin, BuiltInAdmin: false);

        private async Task<ClientAccount> ClientOfAsync(SpecusDbContext db, string tenant, string owner)
        {
            if (_clients.TryGetValue((tenant, owner), out var existing))
            {
                return existing;
            }
            var now = DateTimeOffset.UtcNow;
            var account = new ClientAccount
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = tenant,
                OwnerUsername = owner,
                ClientName = $"workbench-{tenant}-{owner}",
                PasswordHash = new string('0', 64),
                Enabled = true,
                ConnectionRateLimitPerMinute = 30,
                CreatedAt = now,
                UpdatedAt = now,
            };
            db.ClientAccounts.Add(account);
            await db.SaveChangesAsync();
            _clients[(tenant, owner)] = account;
            return account;
        }

        /// <summary>Inserts an object with the vector's exact id on a client of (tenant, owner).</summary>
        private async Task AddObjectAsync(SpecusDbContext db, string kind, long id, string vectorTenant,
            string vectorOwner)
        {
            var (tenant, owner) = Map(vectorTenant, vectorOwner);
            var client = await ClientOfAsync(db, tenant, owner);
            var now = DateTimeOffset.UtcNow;
            switch (kind)
            {
                case WorkbenchKinds.HttpRoute:
                    db.HttpRouteMappings.Add(new HttpRouteMapping
                    {
                        Id = id,
                        TenantId = tenant,
                        ClientId = client.Id,
                        ClientName = client.ClientName,
                        Route = $"wb{id}",
                        TargetBaseUrl = "http://127.0.0.1:8080",
                        Enabled = true,
                        CreatedAt = now,
                        UpdatedAt = now,
                    });
                    break;
                case WorkbenchKinds.TcpMapping:
                    db.SpecusMappings.Add(new SpecusMapping
                    {
                        Id = id,
                        TenantId = tenant,
                        ClientId = client.Id,
                        ClientName = client.ClientName,
                        ListenPort = _nextPort++,
                        TargetAddress = "127.0.0.1",
                        TargetPort = 22,
                        Enabled = true,
                        CreatedAt = now,
                        UpdatedAt = now,
                    });
                    break;
                case WorkbenchKinds.PeerService:
                    db.PeerMeshSharedServices.Add(new PeerMeshSharedService
                    {
                        Id = id,
                        TenantId = tenant,
                        ClientId = client.Id,
                        ClientName = client.ClientName,
                        ServiceId = $"workbench-service-{id}",
                        Name = $"service {id}",
                        Transport = "tcp",
                        Application = "tcp",
                        TargetHost = "127.0.0.1",
                        TargetPort = 22,
                        PublishedPort = _nextPort++,
                        Enabled = true,
                        CreatedAt = now,
                        UpdatedAt = now,
                    });
                    break;
                default:
                    Assert.Fail($"unknown kind {kind}");
                    break;
            }
            await db.SaveChangesAsync();
            _objectTenants[(kind, id)] = tenant;
        }

        /// <summary>Moves the object to a client of the new owner in the same tenant.</summary>
        private async Task ChangeOwnerAsync(SpecusDbContext db, string kind, long id, string vectorOwner)
        {
            // Tenants keep their vector names; only usernames are mapped.
            var tenant = _objectTenants[(kind, id)];
            var client = await ClientOfAsync(db, tenant, Map(tenant, vectorOwner).Username);
            switch (kind)
            {
                case WorkbenchKinds.HttpRoute:
                    await db.HttpRouteMappings.Where(row => row.Id == id).ExecuteUpdateAsync(setters => setters
                        .SetProperty(row => row.ClientId, client.Id)
                        .SetProperty(row => row.ClientName, client.ClientName));
                    break;
                case WorkbenchKinds.TcpMapping:
                    await db.SpecusMappings.Where(row => row.Id == id).ExecuteUpdateAsync(setters => setters
                        .SetProperty(row => row.ClientId, client.Id)
                        .SetProperty(row => row.ClientName, client.ClientName));
                    break;
                default:
                    await db.PeerMeshSharedServices.Where(row => row.Id == id).ExecuteUpdateAsync(setters => setters
                        .SetProperty(row => row.ClientId, client.Id)
                        .SetProperty(row => row.ClientName, client.ClientName));
                    break;
            }
        }

        public async ValueTask DisposeAsync()
        {
            _http.Dispose();
            await _server.DisposeAsync();
        }
    }

    /// <summary>
    /// Structural equality with the vector's body: same property names, arrays in the same order,
    /// scalars equal -- except addedAt / visitedAt, which are compared as instants.
    /// </summary>
    private static void AssertJsonEqual(JsonElement expected, JsonElement actual, string path)
    {
        Assert.True(expected.ValueKind == actual.ValueKind, $"{path}: {expected.ValueKind} vs {actual.ValueKind} ({actual})");
        switch (expected.ValueKind)
        {
            case JsonValueKind.Object:
            {
                var expectedNames = expected.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal);
                var actualNames = actual.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal);
                Assert.True(expectedNames.SequenceEqual(actualNames), $"{path}: properties differ in {actual}");
                foreach (var property in expected.EnumerateObject())
                {
                    var actualValue = actual.GetProperty(property.Name);
                    if (property.Name is "addedAt" or "visitedAt")
                    {
                        Assert.True(Instant(property.Value) == Instant(actualValue),
                            $"{path}.{property.Name}: expected {property.Value}, got {actualValue}");
                    }
                    else
                    {
                        AssertJsonEqual(property.Value, actualValue, $"{path}.{property.Name}");
                    }
                }
                break;
            }
            case JsonValueKind.Array:
            {
                var expectedItems = expected.EnumerateArray().ToList();
                var actualItems = actual.EnumerateArray().ToList();
                Assert.True(expectedItems.Count == actualItems.Count,
                    $"{path}: {expectedItems.Count} items expected, got {actualItems.Count}: {actual}");
                for (var i = 0; i < expectedItems.Count; i++)
                {
                    AssertJsonEqual(expectedItems[i], actualItems[i], $"{path}[{i}]");
                }
                break;
            }
            case JsonValueKind.Number:
                Assert.True(expected.GetDecimal() == actual.GetDecimal(), $"{path}: expected {expected}, got {actual}");
                break;
            default:
                Assert.True(expected.GetRawText() == actual.GetRawText(), $"{path}: expected {expected}, got {actual}");
                break;
        }
    }

    private static DateTimeOffset Instant(JsonElement value) =>
        DateTimeOffset.Parse(value.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    private sealed class SettableTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private long _epochMs = start.ToUnixTimeMilliseconds();

        public void Set(DateTimeOffset value) => Interlocked.Exchange(ref _epochMs, value.ToUnixTimeMilliseconds());

        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _epochMs));
    }
}
