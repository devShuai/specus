using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.HttpRoute;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Http;
using Specus.Server.Nat;
using Specus.Server.Networking;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

/// <summary>
/// <c>POST /api/admin/http-routes/{routeId}/connectivity-check</c> through the real server: who may
/// see a route, how bad requests are refused, and a probe that really travels the NAT data
/// connection, so an RST <c>failure</c> reaches the check while the public path keeps its fixed 502.
/// </summary>
public sealed class ConnectivityCheckEndpointTests : IAsyncLifetime
{
    private const string NoStore = "private, no-store";
    private const string NotFoundBody = """{"code":"CHECK_TARGET_NOT_FOUND"}""";
    private const string InvalidBody = """{"code":"CHECK_REQUEST_INVALID"}""";
    private static readonly string ClientName = DatabaseInitializer.DemoClientName;

    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact]
    public async Task UnauthenticatedAndInvalidRequestsAreRefusedBeforeTheRouteIsRead()
    {
        using var anonymous = _server!.CreateClient();
        using var unauthenticated = await anonymous.PostAsync(CheckPath("1"), Json("{}"));
        Assert.Equal(HttpStatusCode.Unauthorized, unauthenticated.StatusCode);
        Assert.Equal(NoStore, ConnectivityCheckVectorTests.RawCacheControl(unauthenticated));

        using var admin = await AuthenticatedClientAsync();
        string[] invalid =
        [
            "[]", "null", "42", "\"/\"", "{\"path\":7}", "{\"path\":null}", "{\"path\":\"/a\",\"extra\":1}",
            "{\"Path\":\"/a\"}", "{\"path\":\"/a\",\"path\":\"/b\"}", "{\"path\":\"/a\"", "{} {}",
            "{\"path\":\"\"}", "{\"path\":\"a\"}", "{\"path\":\"//host/x\"}", "{\"path\":\"/a?b=1\"}",
            "{\"path\":\"/a#b\"}", "{\"path\":\"/a b\"}", "{\"path\":\"/a\\\\b\"}", "{\"path\":\"/%zz\"}",
            "{\"path\":\"/%2\"}", "{\"path\":\"/a/../b\"}", "{\"path\":\"/./a\"}", "{\"path\":\"/a/%2e%2E\"}",
            "{\"path\":\"/a/%2E\"}", "{\"path\":\"/caf\\u00e9\"}", "{\"path\":\"/" + new string('a', 256) + "\"}",
            "{\"path\":\"/a\"" + new string(' ', 4096) + "}",
        ];
        foreach (var body in invalid)
        {
            foreach (var routeId in new[] { "999999", "abc" })
            {
                using var response = await admin.PostAsync(CheckPath(routeId), Json(body));
                Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{body} -> {response.StatusCode}");
                Assert.Equal(InvalidBody, await response.Content.ReadAsStringAsync());
                Assert.Equal(NoStore, ConnectivityCheckVectorTests.RawCacheControl(response));
            }
        }

        // Valid bodies reach the lookup: the route does not exist.
        string[] valid =
        [
            "", "  \r\n\t", "{}", "{\"path\":\"/\"}", "{\"path\":\"/healthz\"}", "{\"path\":\"/a//b/\"}",
            "{\"path\":\"/%E4%BD%A0/x.y/..z/%2e%2e%2e\"}",
            "{\"path\":\"/-._~!$&'()*+,;=:@\"}", "{\"path\":\"/" + new string('a', 255) + "\"}",
        ];
        foreach (var body in valid)
        {
            using var response = await admin.PostAsync(CheckPath("999999"), Json(body));
            Assert.True(response.StatusCode == HttpStatusCode.NotFound, $"{body} -> {response.StatusCode}");
            Assert.Equal(NotFoundBody, await response.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task RoutesTheCallerMayNotManageAllAnswerTheSameNotFound()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var adminRoute = await CreateRouteAsync(admin, demo.Id, "admin-only");

        var createUser = await admin.PostAsJsonAsync("/api/admin/users", new
        {
            username = "alice",
            password = "alice-password",
            role = "USER",
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, createUser.StatusCode);
        using var alice = await AuthenticatedClientAsync("alice", "alice-password");

        long otherTenantRoute;
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            var account = new ClientAccount
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = "tenant-b",
                OwnerUsername = "admin",
                ClientName = "tenant-b-client",
                PasswordHash = "unused",
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            };
            otherTenantRoute = ClientIdGenerator.NewId();
            db.ClientAccounts.Add(account);
            db.HttpRouteMappings.Add(new HttpRouteMapping
            {
                Id = otherTenantRoute,
                TenantId = "tenant-b",
                ClientId = account.Id,
                ClientName = account.ClientName,
                Route = "elsewhere",
                TargetBaseUrl = "http://127.0.0.1:8080",
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }

        var attempts = new List<(HttpClient Client, string RouteId)>
        {
            (admin, "987654321"),
            (admin, "abc"),
            (admin, "0"),
            (admin, "-5"),
            (admin, otherTenantRoute.ToString()),
            (alice, adminRoute.ToString()),
        };
        foreach (var (client, routeId) in attempts)
        {
            using var response = await client.PostAsync(CheckPath(routeId), Json("{}"));
            Assert.True(response.StatusCode == HttpStatusCode.NotFound, $"{routeId} -> {response.StatusCode}");
            Assert.Equal(NotFoundBody, await response.Content.ReadAsStringAsync());
            Assert.Equal(NoStore, ConnectivityCheckVectorTests.RawCacheControl(response));
            Assert.False(response.Headers.Contains("Retry-After"));
        }
    }

    [Fact]
    public async Task VisibleRouteOfAnOfflineClientReportsDeviceOffline()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var routeId = await CreateRouteAsync(admin, demo.Id, "offline-check");

        using var response = await admin.PostAsync(CheckPath(routeId.ToString()), Json("""{"path":"/healthz"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(NoStore, ConnectivityCheckVectorTests.RawCacheControl(response));
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!.AsObject();
        Assert.Equal(
            ["schemaVersion", "kind", "routeId", "checkedAt", "outcome", "stoppedAt", "code", "totalMs",
                "requests", "stages"],
            body.Select(pair => pair.Key));
        Assert.Equal(1, body["schemaVersion"]!.GetValue<int>());
        Assert.Equal("http-route", body["kind"]!.GetValue<string>());
        Assert.Equal(routeId, body["routeId"]!.GetValue<long>());
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", body["checkedAt"]!.GetValue<string>());
        Assert.Equal("failed", body["outcome"]!.GetValue<string>());
        Assert.Equal("device-online", body["stoppedAt"]!.GetValue<string>());
        Assert.Equal("DEVICE_OFFLINE", body["code"]!.GetValue<string>());
        Assert.Equal(0, body["totalMs"]!.GetValue<long>());
        Assert.Empty(body["requests"]!.AsArray());
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            [
              {"stage":"configured","result":"passed","code":"CONFIGURED","atMs":0},
              {"stage":"device-online","result":"failed","code":"DEVICE_OFFLINE","atMs":0},
              {"stage":"target-reachable","result":"skipped"},
              {"stage":"access-succeeded","result":"skipped"}
            ]
            """), body["stages"]), body["stages"]!.ToJsonString());

        // The route key allows one check per 10 s, whoever asks.
        using var again = await admin.PostAsync(CheckPath(routeId.ToString()), Json(""));
        Assert.Equal(HttpStatusCode.TooManyRequests, again.StatusCode);
        Assert.Equal("10", again.Headers.GetValues("Retry-After").Single());
        Assert.Equal(NoStore, ConnectivityCheckVectorTests.RawCacheControl(again));
        Assert.Equal("""{"code":"CHECK_RATE_LIMITED"}""", await again.Content.ReadAsStringAsync());

        // An owner who is not an admin checks a route of their own client.
        var createUser = await admin.PostAsJsonAsync("/api/admin/users", new
        {
            username = "bob",
            password = "bob-password",
            role = "USER",
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, createUser.StatusCode);
        using var bob = await AuthenticatedClientAsync("bob", "bob-password");
        var createClient = await bob.PostAsJsonAsync("/api/admin/clients", new
        {
            clientName = "bob-client",
            enabled = true,
            connectionRateLimitPerMinute = 12,
        });
        Assert.Equal(HttpStatusCode.Created, createClient.StatusCode);
        var bobClientId = (await createClient.Content.ReadFromJsonAsync<JsonObject>())!["client"]!["id"]!
            .GetValue<long>();
        var bobRoute = await CreateRouteAsync(bob, bobClientId, "bob-route");
        using var owned = await bob.PostAsync(CheckPath(bobRoute.ToString()), Json(""));
        Assert.Equal(HttpStatusCode.OK, owned.StatusCode);
        Assert.Equal("DEVICE_OFFLINE",
            JsonNode.Parse(await owned.Content.ReadAsStringAsync())!["code"]!.GetValue<string>());
    }

    /// <summary>
    /// A capable device resets the probe with metadata.failure: the check reports the classified
    /// stage and never the reason, while a public request reset the same way gets the fixed 502.
    /// </summary>
    [Fact]
    public async Task ResetFailureReachesTheCheckWhileThePublicPathKeepsItsFixedBadGateway()
    {
        const string reason = "dial tcp 10.20.30.40:8080: connect: connection refused (http://10.20.30.40/x?token=s3cret)";
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var routeId = await CreateRouteAsync(admin, demo.Id, "refused");
        await using var device = await BindDeviceAsync(HttpRouteFailure.CapabilityVersion);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var checkTask = admin.PostAsync(CheckPath(routeId.ToString()), Json("""{"path":"/healthz"}"""), timeout.Token);
        var open = await device.Writer.ReadAsync(p => p.NatMessageType == NatMessageType.Open, timeout.Token);
        ConnectivityCheckVectorTests.AssertProbeMetadata(open.MetaData!, "HEAD", "refused", "/healthz");
        var fin = await device.Writer.ReadAsync(p => p.StreamId == open.StreamId, timeout.Token);
        Assert.Equal(NatMessageType.Fin, fin.NatMessageType);
        Assert.Null(fin.MetaData);
        await device.Writer.InjectAsync(Reset(open.StreamId, reason, HttpRouteFailure.ConnectRefused));

        using var check = await checkTask;
        var checkText = await check.Content.ReadAsStringAsync(timeout.Token);
        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        var body = JsonNode.Parse(checkText)!.AsObject();
        Assert.Equal("failed", body["outcome"]!.GetValue<string>());
        Assert.Equal("target-reachable", body["stoppedAt"]!.GetValue<string>());
        Assert.Equal("TARGET_CONNECT_REFUSED", body["code"]!.GetValue<string>());
        Assert.Equal(["HEAD"], body["requests"]!.AsArray().Select(m => m!.GetValue<string>()));
        Assert.Equal("passed", body["stages"]![1]!["result"]!.GetValue<string>());
        Assert.False(body.ContainsKey("statusClass"));
        foreach (var leaked in new[] { "10.20.30.40", "s3cret", "refused (", "/healthz" })
        {
            Assert.DoesNotContain(leaked, checkText, StringComparison.Ordinal);
        }

        // The public ingress, reset the same way, answers the generic 502 and nothing else.
        using var publicClient = _server!.CreateClient();
        var publicTask = publicClient.GetAsync($"/http/{Uri.EscapeDataString(ClientName)}/refused/x", timeout.Token);
        var publicOpen = await device.Writer.ReadAsync(
            p => p.NatMessageType == NatMessageType.Open && Equals(p.MetaData?["method"], "GET"), timeout.Token);
        await device.Writer.InjectAsync(Reset(publicOpen.StreamId, reason, HttpRouteFailure.ConnectRefused));
        using var publicResponse = await publicTask;
        var publicText = await publicResponse.Content.ReadAsStringAsync(timeout.Token);
        Assert.Equal(HttpStatusCode.BadGateway, publicResponse.StatusCode);
        Assert.Equal(DirectHttpEndpoints.StreamResetBody, publicText);
        Assert.DoesNotContain(HttpRouteFailure.ConnectRefused, publicText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task HeadRefusedByMethodFallsBackToOneGetAndResetsEachAnsweredStream()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var routeId = await CreateRouteAsync(admin, demo.Id, "fallback");
        await using var device = await BindDeviceAsync(HttpRouteFailure.CapabilityVersion);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var checkTask = admin.PostAsync(CheckPath(routeId.ToString()), Json(""), timeout.Token);
        var head = await device.Writer.ReadAsync(p => p.NatMessageType == NatMessageType.Open, timeout.Token);
        ConnectivityCheckVectorTests.AssertProbeMetadata(head.MetaData!, "HEAD", "fallback", "/");
        await device.Writer.ReadAsync(p => p.StreamId == head.StreamId && p.NatMessageType == NatMessageType.Fin,
            timeout.Token);
        await device.Writer.InjectAsync(ResponseHead(head.StreamId, 405));

        // The head ends the exchange: the server resets the stream it will not read.
        var headReset = await device.Writer.ReadAsync(p => p.StreamId == head.StreamId, timeout.Token);
        Assert.Equal(NatMessageType.Rst, headReset.NatMessageType);
        Assert.Equal(1U, headReset.Value);
        // DATA that was already in flight is dropped without credit.
        await device.Writer.InjectAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = head.StreamId,
            Data = Encoding.UTF8.GetBytes("ignored"),
        });

        var get = await device.Writer.ReadAsync(p => p.NatMessageType == NatMessageType.Open, timeout.Token);
        ConnectivityCheckVectorTests.AssertProbeMetadata(get.MetaData!, "GET", "fallback", "/");
        await device.Writer.InjectAsync(ResponseHead(get.StreamId, 204));
        // A body relayed right behind the head, more frames than any event queue holds: dropped,
        // not a protocol violation that would close the device's data connection.
        for (var i = 0; i < 64; i++)
        {
            await device.Writer.InjectAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Data,
                StreamId = get.StreamId,
                Data = new byte[1024],
            });
        }

        using var check = await checkTask;
        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        var text = await check.Content.ReadAsStringAsync(timeout.Token);
        var body = JsonNode.Parse(text)!.AsObject();
        // Response headers, Location included, never reach the result.
        Assert.DoesNotContain("10.0.0.9", text, StringComparison.Ordinal);
        Assert.DoesNotContain("upstream-banner", text, StringComparison.Ordinal);
        Assert.Equal("succeeded", body["outcome"]!.GetValue<string>());
        Assert.Null(body["stoppedAt"]);
        Assert.True(body.ContainsKey("stoppedAt"));
        Assert.Equal("ACCESS_OK", body["code"]!.GetValue<string>());
        Assert.Equal(["HEAD", "GET"], body["requests"]!.AsArray().Select(m => m!.GetValue<string>()));
        Assert.Equal("2xx", body["statusClass"]!.GetValue<string>());
        Assert.DoesNotContain(device.Writer.Snapshot(), p => p.NatMessageType == NatMessageType.WindowUpdate);
        Assert.Null(device.DataDisconnectReason);
    }

    /// <summary>
    /// The device answers each probe before the server has even finished writing its OPEN: the
    /// response head, and for the GET more body frames than an event queue holds, all land while
    /// the stream is still being opened. The probe drops that body from the start, so the check
    /// succeeds and the data connection is never closed as a protocol violation.
    /// </summary>
    [Fact]
    public async Task ProbeAnsweredBeforeItsOpenReturnsDropsTheBodyAndKeepsTheDataConnection()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var routeId = await CreateRouteAsync(admin, demo.Id, "eager");
        await using var device = await BindDeviceAsync(HttpRouteFailure.CapabilityVersion);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        device.Writer.AnswerOpen = async open =>
        {
            if (Equals(open.MetaData?["method"], "HEAD"))
            {
                await device.Writer.InjectAsync(ResponseHead(open.StreamId, 405));
                return;
            }
            await device.Writer.InjectAsync(ResponseHead(open.StreamId, 200));
            for (var i = 0; i < 64; i++)
            {
                await device.Writer.InjectAsync(new NatMessagePacket
                {
                    NatMessageType = NatMessageType.Data,
                    StreamId = open.StreamId,
                    Data = new byte[1024],
                });
            }
        };

        using var check = await admin.PostAsync(CheckPath(routeId.ToString()), Json(""), timeout.Token);
        Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        var body = JsonNode.Parse(await check.Content.ReadAsStringAsync(timeout.Token))!.AsObject();
        Assert.Equal("succeeded", body["outcome"]!.GetValue<string>());
        Assert.Equal("ACCESS_OK", body["code"]!.GetValue<string>());
        Assert.Equal(["HEAD", "GET"], body["requests"]!.AsArray().Select(m => m!.GetValue<string>()));
        Assert.Equal("2xx", body["statusClass"]!.GetValue<string>());
        Assert.DoesNotContain(device.Writer.Snapshot(), p => p.NatMessageType == NatMessageType.WindowUpdate);
        Assert.Null(device.DataDisconnectReason);
    }

    [Fact]
    public async Task LostDataConnectionAndLegacySessionsAreNeverReportedAsClassified()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var legacyRoute = await CreateRouteAsync(admin, demo.Id, "legacy");
        var lostRoute = await CreateRouteAsync(admin, demo.Id, "lost");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        // A session that did not announce the capability: its failure value is not trusted.
        await using (var legacy = await BindDeviceAsync(0))
        {
            var checkTask = admin.PostAsync(CheckPath(legacyRoute.ToString()), Json(""), timeout.Token);
            var open = await legacy.Writer.ReadAsync(p => p.NatMessageType == NatMessageType.Open, timeout.Token);
            await legacy.Writer.InjectAsync(Reset(open.StreamId, "connection refused",
                HttpRouteFailure.ConnectRefused));
            using var check = await checkTask;
            var body = JsonNode.Parse(await check.Content.ReadAsStringAsync(timeout.Token))!;
            Assert.Equal("unverified", body["outcome"]!.GetValue<string>());
            Assert.Equal("TARGET_UNVERIFIED", body["code"]!.GetValue<string>());
        }

        // The data connection goes away before the device answers.
        await using (var lost = await BindDeviceAsync(HttpRouteFailure.CapabilityVersion))
        {
            var checkTask = admin.PostAsync(CheckPath(lostRoute.ToString()), Json(""), timeout.Token);
            await lost.Writer.ReadAsync(p => p.NatMessageType == NatMessageType.Open, timeout.Token);
            await lost.CloseDataConnectionAsync();
            using var check = await checkTask;
            var body = JsonNode.Parse(await check.Content.ReadAsStringAsync(timeout.Token))!;
            Assert.Equal("failed", body["outcome"]!.GetValue<string>());
            Assert.Equal("device-online", body["stoppedAt"]!.GetValue<string>());
            Assert.Equal("DEVICE_LINK_LOST", body["code"]!.GetValue<string>());
            Assert.Equal(["HEAD"], body["requests"]!.AsArray().Select(m => m!.GetValue<string>()));
        }

        // Control session present, data connection gone: the data channel is down.
        await using (var half = await BindDeviceAsync(HttpRouteFailure.CapabilityVersion))
        {
            await half.CloseDataConnectionAsync();
            var dataDown = await CreateRouteAsync(admin, demo.Id, "data-down");
            using var check = await admin.PostAsync(CheckPath(dataDown.ToString()), Json(""), timeout.Token);
            var body = JsonNode.Parse(await check.Content.ReadAsStringAsync(timeout.Token))!;
            Assert.Equal("DEVICE_DATA_CHANNEL_DOWN", body["code"]!.GetValue<string>());
            Assert.Empty(body["requests"]!.AsArray());
        }
    }

    private static string CheckPath(string routeId) => $"/api/admin/http-routes/{routeId}/connectivity-check";

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private static NatMessagePacket Reset(uint streamId, string reason, string failure) => new()
    {
        NatMessageType = NatMessageType.Rst,
        StreamId = streamId,
        Value = 26,
        MetaData = new Dictionary<string, object?>
        {
            ["reason"] = reason,
            [HttpRouteFailure.MetadataKey] = failure,
        },
    };

    private static NatMessagePacket ResponseHead(uint streamId, int status) => new()
    {
        NatMessageType = NatMessageType.Open,
        StreamId = streamId,
        MetaData = new Dictionary<string, object?>
        {
            ["source"] = "http",
            ["phase"] = "response",
            ["statusCode"] = status,
            ["headers"] = new List<string> { "Server:upstream-banner", "Location:http://10.0.0.9/" },
            ["trailerNames"] = new List<string>(),
        },
    };

    private async Task<HttpClient> AuthenticatedClientAsync(string username = "admin", string password = "admin")
    {
        var client = _server!.CreateClient();
        var login = await client.PostAsJsonAsync("/auth/login", new { username, password });
        login.EnsureSuccessStatusCode();
        var token = (await login.Content.ReadFromJsonAsync<JsonObject>())!["accessToken"]!.GetValue<string>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<(long Id, string ClientName)> ReadDemoClientAsync(HttpClient client)
    {
        var clients = await client.GetFromJsonAsync<JsonArray>("/api/admin/clients");
        var demo = clients!.Single(c => c!["clientName"]!.GetValue<string>() == ClientName)!;
        return (demo["id"]!.GetValue<long>(), ClientName);
    }

    private static async Task<long> CreateRouteAsync(HttpClient client, long clientId, string route)
    {
        var create = await client.PostAsJsonAsync($"/api/admin/clients/{clientId}/http-routes", new
        {
            route,
            targetBaseUrl = "http://127.0.0.1:18080/base",
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        return (await create.Content.ReadFromJsonAsync<JsonObject>())!["id"]!.GetValue<long>();
    }

    /// <summary>
    /// Logs the Demo client in the way the control channel does: a control connection and its data
    /// connection, both of one in-memory session that announced <paramref name="capability"/>.
    /// </summary>
    private async Task<BoundDevice> BindDeviceAsync(int capability)
    {
        var services = _server!.HostServices;
        ClientAuthSession session;
        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ClientAccounts.AsNoTracking().SingleAsync(a => a.ClientName == ClientName);
            var credential = await db.ClientCredentials.AsNoTracking()
                .SingleAsync(c => c.ApiKey == DatabaseInitializer.DemoCredentialApiKey);
            var identity = new ClientIdentity
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = credential.TenantId,
                CredentialId = credential.Id,
                ClientId = account.Id,
                ClientName = account.ClientName,
                MachineFingerprint = "connectivity-machine",
                OsUser = "connectivity",
                Hostname = "connectivity-host",
            };
            session = services.GetRequiredService<ClientAuthSessionStore>().Create(credential, identity, account,
                TimeSpan.FromHours(1), new ClientEnvironmentInfo
                {
                    MachineFingerprint = "connectivity-machine",
                    OsUser = "connectivity",
                    Hostname = "connectivity-host",
                    ClientHttpRouteCapabilities = new ClientHttpRouteCapabilities { Version = capability },
                });
        }
        Assert.Equal(capability, session.HttpRouteCapabilityVersion);
        return BoundDevice.Bind(services, session.Id);
    }

    private sealed class BoundDevice : IAsyncDisposable
    {
        private readonly NatServerHandler _nat;
        private readonly SessionRegistry _registry;
        private readonly CancellationTokenSource _lifetime = new();
        private readonly SpecusConnectionContext _control;
        private readonly SpecusConnectionContext _data;
        private bool _dataClosed;

        private BoundDevice(NatServerHandler nat, SessionRegistry registry, long sessionId)
        {
            _nat = nat;
            _registry = registry;
            Writer = new CapturingNatWriter(nat);
            _control = Context("connectivity-control", new DiscardingWriter(), sessionId, ConnectionRole.Control);
            _data = Context("connectivity-data", Writer, sessionId, ConnectionRole.Data);
            Writer.Context = _data;
        }

        public CapturingNatWriter Writer { get; }

        /// <summary>Set when the server decided to drop the data connection, e.g. on a protocol violation.</summary>
        public DisconnectReason? DataDisconnectReason => _data.ReadDisconnectReason();

        public static BoundDevice Bind(IServiceProvider services, long sessionId)
        {
            var device = new BoundDevice(services.GetRequiredService<NatServerHandler>(),
                services.GetRequiredService<SessionRegistry>(), sessionId);
            device._registry.Replace(ClientName, device._control);
            device._registry.ReplaceData(ClientName, device._data);
            device._nat.Attach(device._data);
            return device;
        }

        /// <summary>The data connection closes the way a dropped socket does: unbound, then disposed.</summary>
        public async Task CloseDataConnectionAsync()
        {
            _dataClosed = true;
            _registry.Unbind(ClientName, _data);
            await _nat.OnConnectionClosedAsync(_data);
        }

        public async ValueTask DisposeAsync()
        {
            _registry.Unbind(ClientName, _control);
            if (!_dataClosed)
            {
                await CloseDataConnectionAsync();
            }
            _lifetime.Cancel();
            _lifetime.Dispose();
        }

        private SpecusConnectionContext Context(string channelId, IFrameWriter writer, long sessionId, string role)
        {
            var context = new SpecusConnectionContext(channelId, "127.0.0.1:12345", writer, _lifetime.Token,
                () => { }, new ReadGate(_lifetime.Token), new WriteBackpressureGate(64 * 1024, 1024 * 1024));
            context.OnLoginSuccess(ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), sessionId, role);
            return context;
        }
    }

    private sealed class DiscardingWriter : IFrameWriter
    {
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default) =>
            ValueTask.CompletedTask;
    }

    /// <summary>Records what the server writes to the device and feeds the device's frames back.</summary>
    private sealed class CapturingNatWriter(NatServerHandler nat) : IFrameWriter
    {
        private readonly Channel<NatMessagePacket> _packets = Channel.CreateUnbounded<NatMessagePacket>();
        private readonly List<NatMessagePacket> _snapshot = [];

        public SpecusConnectionContext Context { get; set; } = null!;

        /// <summary>
        /// When set, plays the device answering an OPEN before the server's write of it returns,
        /// the order a loaded server can see the frames in.
        /// </summary>
        public Func<NatMessagePacket, Task>? AnswerOpen { get; set; }

        public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            if (packet is NatMessagePacket natPacket)
            {
                var captured = new NatMessagePacket
                {
                    NatMessageType = natPacket.NatMessageType,
                    Flags = natPacket.Flags,
                    StreamId = natPacket.StreamId,
                    Value = natPacket.Value,
                    MetaData = natPacket.MetaData is null ? null : new Dictionary<string, object?>(natPacket.MetaData),
                    Data = natPacket.Data?.ToArray(),
                };
                lock (_snapshot)
                {
                    _snapshot.Add(captured);
                }
                _packets.Writer.TryWrite(captured);
                if (captured.NatMessageType == NatMessageType.Open && AnswerOpen is { } answer)
                {
                    await answer(captured);
                }
            }
        }

        public Task InjectAsync(NatMessagePacket packet) => nat.HandleAsync(Context, packet);

        public async Task<NatMessagePacket> ReadAsync(Func<NatMessagePacket, bool> predicate,
            CancellationToken cancellationToken)
        {
            await foreach (var packet in _packets.Reader.ReadAllAsync(cancellationToken))
            {
                if (predicate(packet))
                {
                    return packet;
                }
            }
            throw new EndOfStreamException("NAT packet capture completed");
        }

        public IReadOnlyList<NatMessagePacket> Snapshot()
        {
            lock (_snapshot)
            {
                return _snapshot.ToArray();
            }
        }
    }
}
