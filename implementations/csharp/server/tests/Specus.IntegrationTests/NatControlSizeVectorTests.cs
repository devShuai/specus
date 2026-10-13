using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Nat;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays protocol/test-vectors/nat-control-size-v1.json: the size of a client's NAT_CONTROL with
/// its name counted at the longest a rename allows, and the management API refusing, with 400, a
/// mapping or route change that would take it past the 1 MiB MESSAGE body, while accepting one that
/// takes it to exactly 1 MiB and any change that leaves the entry disabled.
/// </summary>
public sealed class NatControlSizeVectorTests : IAsyncLifetime
{
    private const string Tenant = "default";
    private const string TargetPrefix = "http://127.0.0.1:8080/";

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
    public async Task SizingMatchesTheVector()
    {
        using var vector = LoadVector();
        var root = vector.RootElement;
        Assert.Equal(NatControlService.MessageBodyLimit, root.GetProperty("messageBodyLimitBytes").GetInt32());
        Assert.Equal(NatControlService.ClientNameReserveCharacters,
            root.GetProperty("clientNameReserve").GetProperty("maxCharacters").GetInt32());
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
        foreach (var sizing in root.GetProperty("sizing").EnumerateArray())
        {
            var jsonBytes = sizing.GetProperty("jsonBytesWithEmptyClientName").GetInt32();
            var route = new HttpRouteMapping { Id = 1, Route = "sized", TargetBaseUrl = TargetPrefix, Enabled = true };
            var shortest = JsonBytes(natControl, [], [route]);
            Assert.True(jsonBytes >= shortest, $"J={jsonBytes} is shorter than the {shortest} of one route");
            route.TargetBaseUrl += new string('a', jsonBytes - shortest);
            Assert.Equal(jsonBytes, JsonBytes(natControl, [], [route]));

            var body = natControl.ReservedBodyBytes([], [route]);
            Assert.Equal(sizing.GetProperty("bodyBytes").GetInt32(), body);
            Assert.Equal(sizing.GetProperty("fits").GetBoolean(), body <= NatControlService.MessageBodyLimit);
        }
    }

    /// <summary>
    /// Whatever a rename makes the client's name, its NAT_CONTROL as sent is never larger than the
    /// body the size check counted for it.
    /// </summary>
    [Fact]
    public async Task TheReserveCoversEveryNameARenameAllows()
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
        SpecusMapping[] mappings =
            [new SpecusMapping { Id = 1, ListenPort = 42_001, TargetAddress = "127.0.0.1", TargetPort = 22, Enabled = true }];
        HttpRouteMapping[] routes =
            [new HttpRouteMapping { Id = 2, Route = "web", TargetBaseUrl = TargetPrefix + "?a=1&b=<2>", Enabled = true }];
        var reserved = natControl.ReservedBodyBytes(mappings, routes);
        // 120 UTF-16 code units each: the longest name every server's rename accepts.
        string[] names =
        [
            new('\u0001', 120), new('"', 120), new('中', 120), string.Concat(Enumerable.Repeat("😀", 60)),
            new('\u2028', 120), new('a', 120),
        ];
        foreach (var name in names)
        {
            var body = CompactBinarySerializer.Serialize(new MessageResponsePacket
            {
                ClientName = name,
                MessageType = MessageType.NatControl,
                Message = natControl.MessageJson(name, mappings, routes),
            });
            Assert.True(body.Length <= reserved, $"name {name[..2]}: {body.Length} bytes, {reserved} reserved");
        }
    }

    [Fact]
    public async Task ManagementStepsMatchTheVector()
    {
        using var vector = LoadVector();
        var root = vector.RootElement;
        var limit = root.GetProperty("messageBodyLimitBytes").GetInt32();
        var maxJson = root.GetProperty("maxJsonBytesWithEmptyClientName").GetInt32();
        var errorContains = root.GetProperty("errorContains").GetString()!;
        var management = root.GetProperty("management");

        var clientId = await CreateClientAsync("nat-control-size");
        await FillAsync(clientId, maxJson - management.GetProperty("fillRemainingJsonBytes").GetInt32());

        using var admin = _server!.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            _server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken("admin", Tenant, ManagementRole.Admin));
        var routes = new Dictionary<string, long>();
        var mappings = new Dictionary<string, long>();
        var nextPort = 42_000;
        var index = 0;
        foreach (var step in management.GetProperty("steps").EnumerateArray())
        {
            var op = step.GetProperty("op").GetString()!;
            var routeName = step.TryGetProperty("route", out var r) ? r.GetString()! : null;
            var mappingName = step.TryGetProperty("mapping", out var m) ? m.GetString()! : null;
            var label = $"step {index++} {op} {routeName}{mappingName}";
            bool? enabled = step.TryGetProperty("enabled", out var e) ? e.GetBoolean() : null;
            var exact = step.TryGetProperty("targetBaseUrl", out var t) && t.GetString() == "exact";
            var before = await StoredAsync(clientId);

            HttpResponseMessage response;
            switch (op)
            {
                case "createRoute":
                    var target = exact ? await ExactTargetAsync(clientId, routeName!, maxJson) : t.GetString()!;
                    response = await admin.PostAsJsonAsync($"/api/admin/clients/{clientId}/http-routes",
                        new { route = routeName, targetBaseUrl = target, enabled });
                    break;
                case "createMapping":
                    response = await admin.PostAsJsonAsync($"/api/admin/clients/{clientId}/specus-mappings",
                        new { listenPort = ++nextPort, targetAddress = "127.0.0.1", targetPort = 8080, enabled });
                    break;
                case "updateRoute":
                {
                    var route = await RouteAsync(routes[routeName!]);
                    var grow = step.TryGetProperty("growTargetBaseUrlBy", out var g) ? g.GetInt32() : 0;
                    var detail = step.TryGetProperty("detailCaptureEnabled", out var d)
                        ? d.GetBoolean()
                        : route.DetailCaptureEnabled;
                    response = await admin.PutAsJsonAsync($"/api/admin/http-routes/{route.Id}", new
                    {
                        route = route.Route,
                        targetBaseUrl = route.TargetBaseUrl + new string('g', grow),
                        enabled = enabled ?? route.Enabled,
                        detailCaptureEnabled = detail,
                    });
                    break;
                }
                case "updateMapping":
                {
                    var mapping = await MappingAsync(mappings[mappingName!]);
                    response = await admin.PutAsJsonAsync($"/api/admin/specus-mappings/{mapping.Id}", new
                    {
                        listenPort = mapping.ListenPort,
                        targetAddress = mapping.TargetAddress,
                        targetPort = mapping.TargetPort,
                        enabled = enabled ?? mapping.Enabled,
                    });
                    break;
                }
                case "deleteRoute":
                    response = await admin.DeleteAsync($"/api/admin/http-routes/{routes[routeName!]}");
                    break;
                default:
                    throw new InvalidOperationException($"{label}: unknown op");
            }

            using (response)
            {
                var body = await response.Content.ReadAsStringAsync();
                Assert.True(step.GetProperty("expect").GetInt32() == (int)response.StatusCode,
                    $"{label}: {(int)response.StatusCode} {body}");
                if (response.StatusCode == HttpStatusCode.BadRequest)
                {
                    using var answer = JsonDocument.Parse(body);
                    Assert.Contains(errorContains, answer.RootElement.GetProperty("error").GetString());
                    Assert.True(before == await StoredAsync(clientId), $"{label}: the refused change was stored");
                }
                else if (op is "createRoute" or "createMapping")
                {
                    using var created = JsonDocument.Parse(body);
                    (routeName is not null ? routes : mappings)[routeName ?? mappingName!] =
                        created.RootElement.GetProperty("id").GetInt64();
                }
            }

            // Whatever was accepted still reaches the client: its NAT_CONTROL fits with the room for any name.
            await using var scope = _server.HostServices.CreateAsyncScope();
            var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
            var (enabledMappings, enabledRoutes) = await EnabledAsync(scope, clientId);
            Assert.True(natControl.ReservedBodyBytes(enabledMappings, enabledRoutes) <= limit,
                $"{label}: the accepted configuration no longer fits");
            if (exact)
            {
                Assert.Equal(maxJson, JsonBytes(natControl, enabledMappings, enabledRoutes));
            }
        }
    }

    private static int JsonBytes(NatControlService natControl, IReadOnlyList<SpecusMapping> mappings,
        IReadOnlyList<HttpRouteMapping> routes) =>
        Encoding.UTF8.GetByteCount(natControl.MessageJson("", mappings, routes));

    private async Task<long> CreateClientAsync(string clientName)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        var client = new ClientAccount
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = Tenant,
            OwnerUsername = "admin",
            ClientName = clientName,
            PasswordHash = new string('0', 64),
            Enabled = true,
            ConnectionRateLimitPerMinute = 30,
            CreatedAt = now,
            UpdatedAt = now,
        };
        db.ClientAccounts.Add(client);
        await db.SaveChangesAsync();
        return client.Id;
    }

    /// <summary>
    /// Writes enabled routes straight to the database until the client's NAT_CONTROL JSON, with an
    /// empty name, is exactly <paramref name="target"/> bytes.
    /// </summary>
    private async Task FillAsync(long clientId, int target)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
        var now = DateTimeOffset.UtcNow;
        HttpRouteMapping Filler(int index, int pad) => new()
        {
            Id = 700_000 + index,
            TenantId = Tenant,
            ClientId = clientId,
            ClientName = "nat-control-size",
            Route = $"fill-{index:000}",
            TargetBaseUrl = TargetPrefix + new string('f', pad),
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        const int padding = 32 * 1024;
        var routes = new List<HttpRouteMapping>();
        while (JsonBytes(natControl, [], [.. routes, Filler(routes.Count, padding)]) + 100 <= target)
        {
            routes.Add(Filler(routes.Count, padding));
        }
        var last = Filler(routes.Count, 0);
        last.TargetBaseUrl += new string('f', target - JsonBytes(natControl, [], [.. routes, last]));
        routes.Add(last);
        Assert.Equal(target, JsonBytes(natControl, [], routes));
        db.HttpRouteMappings.AddRange(routes);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// The target that brings the NAT_CONTROL JSON to exactly <paramref name="maxJson"/> bytes once a
    /// route named <paramref name="route"/> joins the client's enabled configuration.
    /// </summary>
    private async Task<string> ExactTargetAsync(long clientId, string route, int maxJson)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
        var (mappings, routes) = await EnabledAsync(scope, clientId);
        var probe = new HttpRouteMapping { Route = route, TargetBaseUrl = TargetPrefix, Enabled = true };
        var missing = maxJson - JsonBytes(natControl, mappings, [.. routes, probe]);
        Assert.True(missing >= 0, $"no room left for route {route}");
        return TargetPrefix + new string('e', missing);
    }

    private static async Task<(List<SpecusMapping> Mappings, List<HttpRouteMapping> Routes)> EnabledAsync(
        AsyncServiceScope scope, long clientId)
    {
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var mappings = await db.SpecusMappings.AsNoTracking().Where(x => x.ClientId == clientId && x.Enabled)
            .OrderBy(x => x.Id).ToListAsync();
        var routes = await db.HttpRouteMappings.AsNoTracking().Where(x => x.ClientId == clientId && x.Enabled)
            .OrderBy(x => x.Id).ToListAsync();
        return (mappings, routes);
    }

    /// <summary>Every mapping and route of the client, enabled or not, to compare across a refusal.</summary>
    private async Task<string> StoredAsync(long clientId)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var mappings = await db.SpecusMappings.AsNoTracking().Where(x => x.ClientId == clientId)
            .OrderBy(x => x.Id)
            .Select(x => new { x.Id, x.ListenPort, x.TargetAddress, x.TargetPort, x.Enabled, x.UpdatedAt })
            .ToListAsync();
        var routes = await db.HttpRouteMappings.AsNoTracking().Where(x => x.ClientId == clientId)
            .OrderBy(x => x.Id)
            .Select(x => new { x.Id, x.Route, x.TargetBaseUrl, x.Enabled, x.DetailCaptureEnabled, x.UpdatedAt })
            .ToListAsync();
        return JsonSerializer.Serialize(new { mappings, routes });
    }

    private async Task<HttpRouteMapping> RouteAsync(long id)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().HttpRouteMappings.AsNoTracking()
            .SingleAsync(x => x.Id == id);
    }

    private async Task<SpecusMapping> MappingAsync(long id)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().SpecusMappings.AsNoTracking()
            .SingleAsync(x => x.Id == id);
    }

    private static JsonDocument LoadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "nat-control-size-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
        }
        throw new FileNotFoundException("cannot locate nat-control-size-v1.json");
    }
}
