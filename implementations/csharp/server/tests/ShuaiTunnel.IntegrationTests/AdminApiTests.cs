using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Http;
using ShuaiTunnel.Server.Networking;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.IntegrationTests;

public sealed class AdminApiTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Traffic:CaptureDetailEnabled"] = "true",
        });
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact]
    public async Task AdminEndpointsRejectMissingBearerToken()
    {
        using var client = _server!.CreateClient();

        var response = await client.GetAsync("/api/admin/overview");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task LoginRejectsBadCredentials()
    {
        using var client = _server!.CreateClient();

        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "wrong",
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task LoginTokenCanReadOverviewAndClients()
    {
        using var client = _server!.CreateClient();
        var token = await LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

        var overview = await client.GetFromJsonAsync<OverviewBody>("/api/admin/overview", JsonOptions);
        Assert.NotNull(overview);
        Assert.True(overview!.Clients >= 1);
        Assert.True(overview.SuccessfulConnections >= 0);

        var clients = await client.GetFromJsonAsync<List<ClientBody>>("/api/admin/clients", JsonOptions);
        Assert.NotNull(clients);
        var demo = Assert.Single(clients!, clientBody => clientBody.ClientName == "Demo client");
        Assert.True(demo.Enabled);
        Assert.False(demo.Online);
        Assert.True(demo.ConnectionRateLimitPerMinute > 0);
    }

    [Fact]
    public async Task RefreshIssuesANewLocalToken()
    {
        using var client = _server!.CreateClient();
        var token = await LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

        var response = await client.PostAsync("/auth/refresh", content: null);

        response.EnsureSuccessStatusCode();
        var refreshed = await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions);
        Assert.NotNull(refreshed);
        Assert.Equal("Bearer", refreshed!.TokenType);
        Assert.False(string.IsNullOrWhiteSpace(refreshed.AccessToken));
    }

    [Fact]
    public async Task ClientCrudAndCredentialCrudMatchJavaApi()
    {
        using var client = await AuthenticatedClientAsync();

        var create = await client.PostAsJsonAsync("/api/admin/clients", new
        {
            clientName = "Phase4 CRUD",
            enabled = true,
            connectionRateLimitPerMinute = 12,
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var created = await create.Content.ReadFromJsonAsync<ClientResultBody>(JsonOptions);
        Assert.NotNull(created);
        Assert.Equal("Phase4 CRUD", created!.Client.ClientName);
        Assert.Equal("admin", created.Client.OwnerUsername);

        var update = await client.PutAsJsonAsync($"/api/admin/clients/{created.Client.Id}", new
        {
            clientName = "Phase4 CRUD renamed",
            enabled = false,
            connectionRateLimitPerMinute = 0,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<ClientResultBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal("Phase4 CRUD renamed", updated!.Client.ClientName);
        Assert.False(updated.Client.Enabled);

        var delete = await client.DeleteAsync($"/api/admin/clients/{created.Client.Id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        var createCredential = await client.PostAsJsonAsync("/api/admin/client-credentials", new
        {
            apiKey = "ck_phase4",
            secret = "new-secret",
            enabled = true,
            maxOnlineInstances = 3,
        });
        Assert.Equal(HttpStatusCode.Created, createCredential.StatusCode);
        var credential = await createCredential.Content.ReadFromJsonAsync<CredentialBody>(JsonOptions);
        Assert.NotNull(credential);
        Assert.Equal("ck_phase4", credential!.Credential.ApiKey);
        Assert.Equal("new-secret", credential.Secret);
        Assert.Equal(3, credential.Credential.MaxOnlineInstances);

        var credentials = await client.GetFromJsonAsync<List<CredentialViewBody>>(
            "/api/admin/client-credentials", JsonOptions);
        Assert.Contains(credentials!, row => row.ApiKey == "ck_phase4");

        var updateCredential = await client.PutAsJsonAsync(
            $"/api/admin/client-credentials/{credential.Credential.Id}", new
            {
                enabled = false,
                maxOnlineInstances = 4,
            });
        updateCredential.EnsureSuccessStatusCode();
        var updatedCredential = await updateCredential.Content.ReadFromJsonAsync<CredentialBody>(JsonOptions);
        Assert.NotNull(updatedCredential);
        Assert.False(updatedCredential!.Credential.Enabled);
        Assert.Equal(4, updatedCredential.Credential.MaxOnlineInstances);
        Assert.Null(updatedCredential.Secret);

        var deleteCredential = await client.DeleteAsync(
            $"/api/admin/client-credentials/{credential.Credential.Id}");
        Assert.Equal(HttpStatusCode.NoContent, deleteCredential.StatusCode);
    }

    [Fact]
    public async Task ClientDownloadLinksAdminCrudAndPublicListMatchJavaApi()
    {
        using var admin = await AuthenticatedClientAsync();

        var createDisabled = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "java",
            platform = "any",
            arch = "any",
            displayName = "Java exec jar",
            downloadUrl = "https://example.com/shuai-tunnel.jar",
            description = "cross platform",
            displayOrder = 20,
            enabled = false,
        });
        Assert.Equal(HttpStatusCode.Created, createDisabled.StatusCode);
        var disabled = await createDisabled.Content.ReadFromJsonAsync<ClientDownloadLinkBody>(JsonOptions);
        Assert.NotNull(disabled);
        Assert.False(disabled!.Enabled);

        var createEnabled = await admin.PostAsJsonAsync("/api/admin/client-downloads", new
        {
            implementation = "go",
            platform = "linux",
            arch = "x64",
            displayName = "Linux x64",
            downloadUrl = "https://example.com/shuai-tunnel-linux-amd64",
            displayOrder = 10,
        });
        Assert.Equal(HttpStatusCode.Created, createEnabled.StatusCode);
        var enabled = await createEnabled.Content.ReadFromJsonAsync<ClientDownloadLinkBody>(JsonOptions);
        Assert.NotNull(enabled);
        Assert.True(enabled!.Enabled);

        using var anonymous = _server!.CreateClient();
        var publicLinks = await anonymous.GetFromJsonAsync<List<ClientDownloadLinkBody>>(
            "/api/public/client-downloads", JsonOptions);
        Assert.NotNull(publicLinks);
        var publicLink = Assert.Single(publicLinks!);
        Assert.Equal(enabled.Id, publicLink.Id);
        Assert.Equal("go", publicLink.Implementation);

        var update = await admin.PutAsJsonAsync($"/api/admin/client-downloads/{enabled.Id}", new
        {
            implementation = "csharp",
            platform = "windows",
            arch = "x64",
            displayName = "Windows x64",
            downloadUrl = "https://example.com/shuai-tunnel-win-x64.zip",
            enabled = true,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<ClientDownloadLinkBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal("csharp", updated!.Implementation);
        Assert.Equal(10, updated.DisplayOrder);

        var adminLinks = await admin.GetFromJsonAsync<List<ClientDownloadLinkBody>>(
            "/api/admin/client-downloads", JsonOptions);
        Assert.NotNull(adminLinks);
        Assert.Collection(adminLinks!,
            first => Assert.Equal(updated.Id, first.Id),
            second => Assert.Equal(disabled.Id, second.Id));

        var createUser = await admin.PostAsJsonAsync("/api/admin/users", new
        {
            username = "download-user",
            password = "download-user-password",
            role = "USER",
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, createUser.StatusCode);
        using var user = _server!.CreateClient();
        var userToken = await LoginAsync(user, "download-user", "download-user-password");
        user.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", userToken.AccessToken);

        var forbidden = await user.GetAsync("/api/admin/client-downloads");
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        var delete = await admin.DeleteAsync($"/api/admin/client-downloads/{disabled.Id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
    }

    [Fact]
    public async Task ManagementUsersAndOwnerScopeMatchJavaApi()
    {
        using var admin = await AuthenticatedClientAsync();

        var createUser = await admin.PostAsJsonAsync("/api/admin/users", new
        {
            username = "alice",
            password = "alice-password",
            role = "USER",
            enabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, createUser.StatusCode);

        using var alice = _server!.CreateClient();
        var aliceToken = await LoginAsync(alice, "alice", "alice-password");
        alice.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", aliceToken.AccessToken);

        var me = await alice.GetFromJsonAsync<ManagementUserBody>("/api/admin/me", JsonOptions);
        Assert.NotNull(me);
        Assert.Equal("alice", me!.Username);
        Assert.Equal("USER", me.Role);
        Assert.False(me.Admin);

        var listUsers = await alice.GetAsync("/api/admin/users");
        Assert.Equal(HttpStatusCode.Forbidden, listUsers.StatusCode);

        var initialize = await alice.PostAsync("/api/admin/database/initialize", content: null);
        Assert.Equal(HttpStatusCode.Forbidden, initialize.StatusCode);

        var createAliceClient = await alice.PostAsJsonAsync("/api/admin/clients", new
        {
            clientName = "alice-client",
            enabled = true,
            connectionRateLimitPerMinute = 12,
        });
        Assert.Equal(HttpStatusCode.Created, createAliceClient.StatusCode);
        var aliceClient = await createAliceClient.Content.ReadFromJsonAsync<ClientResultBody>(JsonOptions);
        Assert.NotNull(aliceClient);

        var createAdminClient = await admin.PostAsJsonAsync("/api/admin/clients", new
        {
            clientName = "admin-client",
            enabled = true,
            connectionRateLimitPerMinute = 12,
        });
        Assert.Equal(HttpStatusCode.Created, createAdminClient.StatusCode);
        var adminClient = await createAdminClient.Content.ReadFromJsonAsync<ClientResultBody>(JsonOptions);
        Assert.NotNull(adminClient);

        var aliceClients = await alice.GetFromJsonAsync<List<ClientBody>>("/api/admin/clients", JsonOptions);
        var onlyClient = Assert.Single(aliceClients!);
        Assert.Equal("alice-client", onlyClient.ClientName);

        var deleteAdminClient = await alice.DeleteAsync($"/api/admin/clients/{adminClient!.Client.Id}");
        Assert.Equal(HttpStatusCode.Forbidden, deleteAdminClient.StatusCode);

        var createAliceCredential = await alice.PostAsJsonAsync("/api/admin/client-credentials", new
        {
            apiKey = "ck_alice",
            secret = "alice-secret",
            enabled = true,
            maxOnlineInstances = 2,
        });
        Assert.Equal(HttpStatusCode.Created, createAliceCredential.StatusCode);

        var createAdminCredential = await admin.PostAsJsonAsync("/api/admin/client-credentials", new
        {
            apiKey = "ck_admin",
            secret = "admin-secret",
            enabled = true,
            maxOnlineInstances = 2,
        });
        Assert.Equal(HttpStatusCode.Created, createAdminCredential.StatusCode);

        var aliceCredentials = await alice.GetFromJsonAsync<List<CredentialViewBody>>(
            "/api/admin/client-credentials", JsonOptions);
        var onlyCredential = Assert.Single(aliceCredentials!);
        Assert.Equal("ck_alice", onlyCredential.ApiKey);

        var createBlockedTunnel = await alice.PostAsJsonAsync(
            $"/api/admin/clients/{adminClient.Client.Id}/tunnels", new
            {
                listenPort = 46101,
                targetAddress = "127.0.0.1",
                targetPort = 8080,
                enabled = true,
            });
        Assert.Equal(HttpStatusCode.Forbidden, createBlockedTunnel.StatusCode);

        var createOwnTunnel = await alice.PostAsJsonAsync(
            $"/api/admin/clients/{aliceClient!.Client.Id}/tunnels", new
            {
                listenPort = 46102,
                targetAddress = "127.0.0.1",
                targetPort = 8080,
                enabled = true,
            });
        Assert.Equal(HttpStatusCode.Created, createOwnTunnel.StatusCode);
    }

    [Fact]
    public async Task TunnelCrudAndOfflineNatPushBehaveLikeJavaApi()
    {
        using var client = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(client);

        var create = await client.PostAsJsonAsync($"/api/admin/clients/{demo.Id}/tunnels", new
        {
            listenPort = 45123,
            targetAddress = "127.0.0.1",
            targetPort = 8080,
            enabled = true,
            detailCaptureEnabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var tunnel = await create.Content.ReadFromJsonAsync<TunnelBody>(JsonOptions);
        Assert.NotNull(tunnel);
        Assert.Equal(45123, tunnel!.ListenPort);
        Assert.True(tunnel.DetailCaptureEnabled);

        var list = await client.GetFromJsonAsync<List<TunnelBody>>(
            $"/api/admin/tunnels?clientId={demo.Id}", JsonOptions);
        Assert.Contains(list!, row => row.Id == tunnel.Id);

        var update = await client.PutAsJsonAsync($"/api/admin/tunnels/{tunnel.Id}", new
        {
            listenPort = 45124,
            targetAddress = "localhost",
            targetPort = 9090,
            enabled = false,
            detailCaptureEnabled = false,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<TunnelBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal(45124, updated!.ListenPort);
        Assert.False(updated.Enabled);
        Assert.False(updated.DetailCaptureEnabled);

        var push = await client.PostAsync($"/api/admin/clients/{demo.Id}/nat-control", content: null);
        Assert.Equal(HttpStatusCode.Conflict, push.StatusCode);

        var delete = await client.DeleteAsync($"/api/admin/tunnels/{tunnel.Id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
    }

    [Fact]
    public async Task HttpRouteCrudValidatesAndPersistsRoutes()
    {
        using var client = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(client);

        var invalid = await client.PostAsJsonAsync($"/api/admin/clients/{demo.Id}/http-routes", new
        {
            route = "bad/path",
            targetBaseUrl = "https://example.com",
        });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        var create = await client.PostAsJsonAsync($"/api/admin/clients/{demo.Id}/http-routes", new
        {
            route = "api",
            targetBaseUrl = "https://example.com/base",
            enabled = true,
            detailCaptureEnabled = true,
            pathRewriteEnabled = true,
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var route = await create.Content.ReadFromJsonAsync<HttpRouteBody>(JsonOptions);
        Assert.NotNull(route);
        Assert.Equal("api", route!.Route);
        Assert.True(route.DetailCaptureEnabled);
        Assert.True(route.PathRewriteEnabled);

        var list = await client.GetFromJsonAsync<List<HttpRouteBody>>(
            $"/api/admin/http-routes?clientId={demo.Id}", JsonOptions);
        Assert.Contains(list!, row => row.Id == route.Id);

        var update = await client.PutAsJsonAsync($"/api/admin/http-routes/{route.Id}", new
        {
            route = "admin",
            targetBaseUrl = "http://localhost:5000",
            enabled = false,
            detailCaptureEnabled = false,
            pathRewriteEnabled = false,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<HttpRouteBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal("admin", updated!.Route);
        Assert.False(updated.Enabled);
        Assert.False(updated.DetailCaptureEnabled);
        Assert.False(updated.PathRewriteEnabled);

        var delete = await client.DeleteAsync($"/api/admin/http-routes/{route.Id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
    }

    [Fact]
    public async Task ConnectionTrafficAndStatReadModelsMatchAdminShape()
    {
        using var client = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(client);
        await SeedReadModelRowsAsync(demo);

        var connections = await client.GetFromJsonAsync<ConnectionPageBody>(
            $"/api/admin/connections?clientId={demo.Id}&success=true&page=0&size=10", JsonOptions);
        Assert.NotNull(connections);
        Assert.True(connections!.Total >= 1);
        var connection = Assert.Single(connections.Items, row => row.ChannelId == "admin-api-test");
        Assert.True(connection.Success);
        Assert.Equal("CLIENT_CLOSED", connection.DisconnectReason);
        Assert.Equal("客户端正常断开", connection.DisconnectReasonText);

        var traffic = await client.GetFromJsonAsync<List<TrafficBody>>(
            $"/api/admin/traffic?clientId={demo.Id}&limit=10", JsonOptions);
        Assert.Contains(traffic!, row => row.ClientId == demo.Id
            && row.UploadBytes == 1234
            && row.DownloadBytes == 5678);

        var stats = await client.GetFromJsonAsync<List<ConnectionStatBody>>(
            $"/api/admin/connection-stats?clientName={Uri.EscapeDataString(demo.ClientName)}&limit=10",
            JsonOptions);
        Assert.Contains(stats!, row => row.ClientName == demo.ClientName
            && row.Month == "2026-06"
            && row.Total == 3
            && row.Success == 2
            && row.Failure == 1);
    }

    [Fact]
    public async Task HttpTrafficSearchMatchesJavaFieldSemantics()
    {
        using var client = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(client);
        await SeedReadModelRowsAsync(demo);

        var summary = await client.GetFromJsonAsync<HttpExchangePageBody>(
            $"/api/admin/traffic/http-exchanges?q={Uri.EscapeDataString("POST api")}&page=0&size=20",
            JsonOptions);
        Assert.NotNull(summary);
        Assert.Equal(1, summary!.Total);
        Assert.Equal("POST", Assert.Single(summary.Items).Method);

        var method = await client.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?field=method&q=POST&page=0&size=20",
            JsonOptions);
        Assert.NotNull(method);
        Assert.Equal(1, method!.Total);
        Assert.Equal("POST", Assert.Single(method.Items).Method);

        var status = await client.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?field=status&q=201&page=0&size=20",
            JsonOptions);
        Assert.NotNull(status);
        Assert.Equal(1, status!.Total);
        Assert.Equal(201, Assert.Single(status.Items).StatusCode);

        var responseType = await client.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?field=responseDataType&q=json&page=0&size=20",
            JsonOptions);
        Assert.NotNull(responseType);
        Assert.Equal(1, responseType!.Total);
        Assert.Equal("json", Assert.Single(responseType.Items).ResponseBodyType);

        var imageType = await client.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?route=legacy-image&responseBodyType=image&page=0&size=20",
            JsonOptions);
        Assert.NotNull(imageType);
        Assert.Equal(1, imageType!.Total);
        Assert.Equal("image", Assert.Single(imageType.Items).ResponseBodyType);

        var emptyType = await client.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?route=legacy-empty&responseBodyType=empty&page=0&size=20",
            JsonOptions);
        Assert.NotNull(emptyType);
        Assert.Equal(1, emptyType!.Total);
        Assert.Equal("empty", Assert.Single(emptyType.Items).ResponseBodyType);

        var unsupportedType = await client.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?route=legacy-image&responseBodyType=unknown&page=0&size=20",
            JsonOptions);
        Assert.NotNull(unsupportedType);
        Assert.Equal(1, unsupportedType!.Total);
    }

    [Fact]
    public async Task DirectHttpTunnelRejectsOfflineClientAndOversizedBody()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var create = await admin.PostAsJsonAsync($"/api/admin/clients/{demo.Id}/http-routes", new
        {
            route = "oversize",
            targetBaseUrl = "https://example.com",
            enabled = true,
            detailCaptureEnabled = true,
            pathRewriteEnabled = false,
        });
        create.EnsureSuccessStatusCode();

        using var client = _server!.CreateClient();
        var offline = await client.GetAsync($"/http/{Uri.EscapeDataString("Demo client")}/oversize/ping");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, offline.StatusCode);

        var offlineDetails = await admin.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?route=oversize&field=status&q=503&page=0&size=20&flush=true",
            JsonOptions);
        Assert.NotNull(offlineDetails);
        var offlineRow = Assert.Single(offlineDetails!.Items);
        Assert.Equal("GET", offlineRow.Method);
        Assert.Equal(503, offlineRow.StatusCode);
        Assert.Contains("Content-Type:text/plain;charset=UTF-8", offlineRow.ResponseHeaders);
        Assert.Equal("客户端不在线: Demo client", offlineRow.ResponsePreviewText);

        var oversized = new StringContent(new string('x', 128), Encoding.UTF8, "text/plain");
        var tooLarge = await client.PostAsync($"/http/{Uri.EscapeDataString("Demo client")}/oversize/ping", oversized);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooLarge.StatusCode);

        var details = await admin.GetFromJsonAsync<HttpExchangePageBody>(
            "/api/admin/traffic/http-exchanges?route=oversize&field=status&q=413&page=0&size=20&flush=true",
            JsonOptions);
        Assert.NotNull(details);
        var row = Assert.Single(details!.Items);
        Assert.Equal("POST", row.Method);
        Assert.Equal(413, row.StatusCode);
        Assert.Contains("Content-Type:text/plain;charset=UTF-8", row.ResponseHeaders);
        Assert.Equal("HTTP 请求体超过限制", row.ResponsePreviewText);

        var registry = _server!.HostServices.GetRequiredService<SessionRegistry>();
        using var lifetime = new CancellationTokenSource();
        var failingContext = new TunnelConnectionContext(
            "direct-http-write-failure-test",
            "127.0.0.1:12345",
            new FailingFrameWriter(),
            lifetime.Token,
            () => { },
            new ReadGate(lifetime.Token),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        failingContext.OnLoginSuccess(demo.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            clientSessionId: 1);
        registry.Replace(demo.ClientName, failingContext);
        try
        {
            var writeFailed = await client.PostAsync(
                $"/http/{Uri.EscapeDataString("Demo client")}/oversize/write-fail",
                new StringContent("abc", Encoding.UTF8, "text/plain"));
            Assert.Equal(HttpStatusCode.BadGateway, writeFailed.StatusCode);

            var writeFailedDetails = await admin.GetFromJsonAsync<HttpExchangePageBody>(
                "/api/admin/traffic/http-exchanges?route=oversize&field=status&q=502&page=0&size=20&flush=true",
                JsonOptions);
            Assert.NotNull(writeFailedDetails);
            var writeFailedRow = Assert.Single(writeFailedDetails!.Items);
            Assert.Equal("POST", writeFailedRow.Method);
            Assert.Equal(502, writeFailedRow.StatusCode);
            Assert.Contains("Content-Type:text/plain;charset=UTF-8", writeFailedRow.ResponseHeaders);
            Assert.Equal("HTTP 转发请求发送失败", writeFailedRow.ResponsePreviewText);

            await _server.FlushTrafficAsync();
            var totals = await _server.ReadTrafficTotalsAsync(demo.ClientName);
            Assert.Equal(3, totals.Upload);
            Assert.Equal(0, totals.Download);
        }
        finally
        {
            registry.Unbind(demo.ClientName, failingContext);
        }
    }

    [Fact]
    public async Task DirectHttpTunnelPreservesEncodedRelativePathLikeJava()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var dispatcher = _server!.HostServices.GetRequiredService<DirectHttpDispatcher>();
        var registry = _server.HostServices.GetRequiredService<SessionRegistry>();
        using var lifetime = new CancellationTokenSource();
        var writer = new CapturingDirectHttpResponder(dispatcher);
        var context = new TunnelConnectionContext(
            "direct-http-encoded-path-test",
            "127.0.0.1:12345",
            writer,
            lifetime.Token,
            () => { },
            new ReadGate(lifetime.Token),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        context.OnLoginSuccess(demo.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), clientSessionId: 1);
        registry.Replace(demo.ClientName, context);

        try
        {
            using var publicClient = _server.CreateClient();
            var response = await publicClient.GetAsync(
                $"/http/{Uri.EscapeDataString(demo.ClientName)}/encoded/%E4%BD%A0%2Fok?x=%2F");

            response.EnsureSuccessStatusCode();
            Assert.NotNull(writer.Captured);
            Assert.Equal("/%E4%BD%A0%2Fok", writer.Captured!.RelativePath);
            Assert.Equal("x=%2F", writer.Captured.RawQuery);
        }
        finally
        {
            registry.Unbind(demo.ClientName, context);
        }
    }

    [Fact]
    public async Task DirectHttpRewriteKeepsOriginalResponseHeadersInTrafficDetailLikeJava()
    {
        using var admin = await AuthenticatedClientAsync();
        var demo = await ReadDemoClientAsync(admin);
        var create = await admin.PostAsJsonAsync($"/api/admin/clients/{demo.Id}/http-routes", new
        {
            route = "rewrite-capture",
            targetBaseUrl = "https://example.com",
            enabled = true,
            detailCaptureEnabled = true,
            pathRewriteEnabled = true,
        });
        create.EnsureSuccessStatusCode();

        var dispatcher = _server!.HostServices.GetRequiredService<DirectHttpDispatcher>();
        var registry = _server.HostServices.GetRequiredService<SessionRegistry>();
        using var lifetime = new CancellationTokenSource();
        var writer = new DirectHttpResponder(dispatcher);
        var context = new TunnelConnectionContext(
            "direct-http-capture-test",
            "127.0.0.1:12345",
            writer,
            lifetime.Token,
            () => { },
            new ReadGate(lifetime.Token),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        context.OnLoginSuccess(demo.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), clientSessionId: 1);
        registry.Replace(demo.ClientName, context);

        try
        {
            using var publicClient = _server.CreateClient();
            var response = await publicClient.GetAsync(
                $"/http/{Uri.EscapeDataString(demo.ClientName)}/rewrite-capture/index.html");
            response.EnsureSuccessStatusCode();
            var responseText = await response.Content.ReadAsStringAsync();

            Assert.Contains("src=\"/http/Demo%20client/rewrite-capture/img/logo.png\"", responseText);
            Assert.DoesNotContain("gzip", response.Content.Headers.ContentEncoding);
            if (response.Content.Headers.ContentLength is { } contentLength)
            {
                Assert.NotEqual(999L, contentLength);
            }

            var details = await admin.GetFromJsonAsync<HttpExchangePageBody>(
                "/api/admin/traffic/http-exchanges?field=responseHeaders&q=Content-Encoding&page=0&size=20&flush=true",
                JsonOptions);
            Assert.NotNull(details);
            var row = Assert.Single(details!.Items, item => item.Route == "rewrite-capture");
            Assert.NotNull(row.ResponseHeaders);
            Assert.NotNull(row.ResponsePreviewText);
            Assert.Contains("Content-Encoding:gzip", row.ResponseHeaders);
            Assert.Contains("Content-Length:999", row.ResponseHeaders);
            Assert.Contains("/http/Demo%20client/rewrite-capture/img/logo.png", row.ResponsePreviewText);
        }
        finally
        {
            registry.Unbind(demo.ClientName, context);
        }
    }

    [Fact]
    public async Task ConnectionWebSocketReceivesCreatedAndUpdatedEvents()
    {
        using var client = _server!.CreateClient();
        var token = await LoginAsync(client);
        var wsClient = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await wsClient.ConnectAsync(
            new Uri($"ws://localhost/ws/connections?token={Uri.EscapeDataString(token.AccessToken)}"),
            cts.Token);

        long recordId;
        await using (var scope = _server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
            var account = await db.ClientAccounts.AsNoTracking()
                .SingleAsync(a => a.ClientName == "Demo client", cts.Token);
            var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
            recordId = await records.RecordConnectionAsync(AuthenticationResult.Pass(account), account.ClientName,
                "ws-created-test", "127.0.0.1:51000", cts.Token);
        }

        var createdJson = await ReceiveWebSocketTextAsync(socket, cts.Token);
        Assert.Contains("\"tenantId\":\"default\"", createdJson, StringComparison.Ordinal);
        Assert.Contains("\"type\":\"created\"", createdJson, StringComparison.Ordinal);
        Assert.Contains("\"connection\":", createdJson, StringComparison.Ordinal);
        Assert.DoesNotContain("\"record\":", createdJson, StringComparison.Ordinal);
        Assert.Contains("\"channelId\":\"ws-created-test\"", createdJson, StringComparison.Ordinal);

        await using (var scope = _server.HostServices.CreateAsyncScope())
        {
            var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
            await records.RecordDisconnectAsync(recordId, DisconnectReason.ClientClosed, cts.Token);
        }

        var updatedJson = await ReceiveWebSocketTextAsync(socket, cts.Token);
        Assert.Contains("\"tenantId\":\"default\"", updatedJson, StringComparison.Ordinal);
        Assert.Contains("\"type\":\"updated\"", updatedJson, StringComparison.Ordinal);
        Assert.Contains("\"connection\":", updatedJson, StringComparison.Ordinal);
        Assert.DoesNotContain("\"record\":", updatedJson, StringComparison.Ordinal);
        Assert.Contains("\"channelId\":\"ws-created-test\"", updatedJson, StringComparison.Ordinal);
        Assert.Contains("\"disconnectReason\":\"CLIENT_CLOSED\"", updatedJson, StringComparison.Ordinal);
        Assert.Contains("\"disconnectedAt\":", updatedJson, StringComparison.Ordinal);
    }

    private static async Task<string> ReceiveWebSocketTextAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        var received = await socket.ReceiveAsync(buffer, cancellationToken);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        Assert.True(received.EndOfMessage);
        return Encoding.UTF8.GetString(buffer.AsSpan(0, received.Count));
    }

    private static byte[] GzipText(string text)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            gzip.Write(bytes, 0, bytes.Length);
        }
        return output.ToArray();
    }

    private static async Task<TokenBody> LoginAsync(HttpClient client, string username = "admin",
        string password = "admin")
    {
        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username,
            password,
        });
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions);
        Assert.NotNull(token);
        Assert.Equal("Bearer", token!.TokenType);
        Assert.True(token.ExpiresIn > 0);
        return token;
    }

    private async Task<HttpClient> AuthenticatedClientAsync()
    {
        var client = _server!.CreateClient();
        var token = await LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        return client;
    }

    private static async Task<ClientBody> ReadDemoClientAsync(HttpClient client)
    {
        var clients = await client.GetFromJsonAsync<List<ClientBody>>("/api/admin/clients", JsonOptions);
        Assert.NotNull(clients);
        return Assert.Single(clients!, row => row.ClientName == "Demo client");
    }

    private async Task SeedReadModelRowsAsync(ClientBody demo)
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.ConnectionRecords.Add(new ConnectionRecord
        {
            TenantId = "default",
            ClientId = demo.Id,
            ClientName = demo.ClientName,
            ChannelId = "admin-api-test",
            RemoteAddress = "127.0.0.1:50000",
            ConnectedAt = now,
            DisconnectedAt = now,
            Success = true,
            DisconnectReason = DisconnectReason.ClientClosed.ToWireString(),
        });
        db.TrafficUsages.Add(new TrafficUsage
        {
            ClientId = demo.Id,
            ClientName = demo.ClientName,
            UsageDate = "2026-06-20",
            UploadBytes = 1234,
            DownloadBytes = 5678,
            UpdatedAt = now,
        });
        db.ConnectionStats.Add(new ConnectionStat
        {
            TenantId = "default",
            ClientId = demo.Id,
            ClientName = demo.ClientName,
            StatMonth = "2026-06",
            TotalCount = 3,
            SuccessCount = 2,
            FailureCount = 1,
            UpdatedAt = now,
        });
        db.HttpTrafficExchanges.AddRange(
            new HttpTrafficExchange
            {
                TenantId = "default",
                ClientId = demo.Id,
                ClientName = demo.ClientName,
                Route = "api",
                ResourceName = "api -> https://example.com/base",
                Method = "POST",
                RelativePath = "/items",
                RawQuery = "page=1",
                StatusCode = 201,
                Success = true,
                RemoteAddress = "127.0.0.1:62000",
                RequestBytes = 14,
                ResponseBytes = 11,
                ElapsedMs = 12,
                RequestContentType = "application/json",
                ResponseContentType = "application/json",
                ResponseBodyType = "json",
                RequestHeaders = "Content-Type: application/json",
                ResponseHeaders = "Content-Type: application/json",
                RequestPreviewText = "{\"hello\":true}",
                ResponsePreviewText = "{\"ok\":true}",
                CapturedAt = now,
            },
            new HttpTrafficExchange
            {
                TenantId = "default",
                ClientId = demo.Id,
                ClientName = demo.ClientName,
                Route = "assets",
                Method = "GET",
                RelativePath = "/vendor.js",
                StatusCode = 200,
                Success = true,
                RequestBytes = 0,
                ResponseBytes = 1024,
                ElapsedMs = 6,
                ResponseBodyType = "script",
                RequestHeaders = "X-Debug-Method: POST",
                ResponseHeaders = "Content-Type: text/javascript",
                ResponsePreviewText = "console.log('ready')",
                CapturedAt = now.AddSeconds(1),
            },
            new HttpTrafficExchange
            {
                TenantId = "default",
                ClientId = demo.Id,
                ClientName = demo.ClientName,
                Route = "legacy-image",
                Method = "GET",
                RelativePath = "/logo.png",
                StatusCode = 200,
                Success = true,
                ResponseBytes = 42,
                ResponseContentType = "image/png;charset=UTF-8",
                ResponseBodyType = "",
                CapturedAt = now.AddSeconds(2),
            },
            new HttpTrafficExchange
            {
                TenantId = "default",
                ClientId = demo.Id,
                ClientName = demo.ClientName,
                Route = "legacy-empty",
                Method = "GET",
                RelativePath = "/empty",
                StatusCode = 204,
                Success = true,
                ResponseBytes = 0,
                ResponseBodyType = "",
                CapturedAt = now.AddSeconds(3),
            });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    private sealed class DirectHttpResponder : IFrameWriter
    {
        private readonly DirectHttpDispatcher _dispatcher;

        public DirectHttpResponder(DirectHttpDispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            var request = Assert.IsType<DirectHttpRequestPacket>(packet);
            Assert.False(string.IsNullOrWhiteSpace(request.RequestId));
            var body = GzipText("<html><head></head><body><img src=\"/img/logo.png\"></body></html>");
            _dispatcher.Ack(new DirectHttpResponsePacket
            {
                RequestId = request.RequestId,
                StatusCode = StatusCodes.Status200OK,
                Headers =
                [
                    "Content-Type:text/html;charset=UTF-8",
                    "Content-Encoding:gzip",
                    "Content-Length:999",
                ],
                Body = body,
            });
            return ValueTask.CompletedTask;
        }
    }

    private sealed class CapturingDirectHttpResponder : IFrameWriter
    {
        private readonly DirectHttpDispatcher _dispatcher;

        public CapturingDirectHttpResponder(DirectHttpDispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public DirectHttpRequestPacket? Captured { get; private set; }

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            Captured = Assert.IsType<DirectHttpRequestPacket>(packet);
            Assert.False(string.IsNullOrWhiteSpace(Captured.RequestId));
            _dispatcher.Ack(new DirectHttpResponsePacket
            {
                RequestId = Captured.RequestId,
                StatusCode = StatusCodes.Status200OK,
                Headers = ["Content-Type:text/plain"],
                Body = Encoding.UTF8.GetBytes("ok"),
            });
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FailingFrameWriter : IFrameWriter
    {
        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new IOException("socket closed"));
    }

    private sealed record TokenBody(string AccessToken, string TokenType, long ExpiresIn);

    private sealed record ManagementUserBody(
        string Username,
        string TenantId,
        string Role,
        bool Admin,
        bool BuiltIn,
        bool Enabled,
        string CreatedAt,
        string UpdatedAt);

    private sealed record ClientResultBody(ClientBody Client);

    private sealed record CredentialBody(CredentialViewBody Credential, string? Secret);

    private sealed record CredentialViewBody(
        long Id,
        string ApiKey,
        string? OwnerUsername,
        bool Enabled,
        int MaxOnlineInstances,
        string CreatedAt,
        string UpdatedAt);

    private sealed record ClientDownloadLinkBody(
        long Id,
        string Implementation,
        string Platform,
        string Arch,
        string DisplayName,
        string DownloadUrl,
        string? Description,
        int DisplayOrder,
        bool Enabled,
        string CreatedAt,
        string UpdatedAt);

    private sealed record OverviewBody(
        int Clients,
        int OnlineClients,
        long SuccessfulConnections,
        long FailedConnections,
        long UploadBytes,
        long DownloadBytes,
        int ExternalConnections,
        long RejectedExternalConnections);

    private sealed record ClientBody(
        long Id,
        string ClientName,
        string? OwnerUsername,
        bool Enabled,
        int ConnectionRateLimitPerMinute,
        bool Online,
        long? ConnectedSinceMs,
        long UploadBytes,
        long DownloadBytes,
        string CreatedAt,
        string UpdatedAt);

    private sealed record TunnelBody(
        long Id,
        long ClientId,
        string ClientName,
        int ListenPort,
        string TargetAddress,
        int TargetPort,
        bool Enabled,
        bool DetailCaptureEnabled,
        string CreatedAt,
        string UpdatedAt);

    private sealed record HttpRouteBody(
        long Id,
        long ClientId,
        string ClientName,
        string Route,
        string TargetBaseUrl,
        bool Enabled,
        bool DetailCaptureEnabled,
        bool PathRewriteEnabled,
        string CreatedAt,
        string UpdatedAt);

    private sealed record ConnectionPageBody(
        List<ConnectionBody> Items,
        long Total,
        int Page,
        int Size,
        int TotalPages);

    private sealed record ConnectionBody(
        long Id,
        long? ClientId,
        string ClientName,
        string? ChannelId,
        string? RemoteAddress,
        string ConnectedAt,
        string? DisconnectedAt,
        bool Success,
        string? FailureReason,
        string? DisconnectReason,
        string? DisconnectReasonText);

    private sealed record TrafficBody(
        long Id,
        long ClientId,
        string ClientName,
        string UsageDate,
        long UploadBytes,
        long DownloadBytes,
        string UpdatedAt);

    private sealed record ConnectionStatBody(
        long Id,
        long? ClientId,
        string ClientName,
        string Month,
        long Total,
        long Success,
        long Failure,
        string UpdatedAt);

    private sealed record HttpExchangePageBody(
        List<HttpExchangeBody> Items,
        long Total,
        int Page,
        int Size,
        int TotalPages);

    private sealed record HttpExchangeBody(
        string Id,
        string Route,
        string Method,
        int StatusCode,
        string ResponseBodyType,
        string? ResponseHeaders,
        string? ResponsePreviewText);
}
