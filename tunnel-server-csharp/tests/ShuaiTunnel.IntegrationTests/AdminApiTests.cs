using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.IntegrationTests;

public sealed class AdminApiTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

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
    public async Task ClientCrudReturnsCredentialAndUpdatesList()
    {
        using var client = await AuthenticatedClientAsync();

        var create = await client.PostAsJsonAsync("/api/admin/clients", new
        {
            clientName = "Phase4 CRUD",
            enabled = true,
            connectionRateLimitPerMinute = 12,
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var created = await create.Content.ReadFromJsonAsync<CredentialBody>(JsonOptions);
        Assert.NotNull(created);
        Assert.Equal("Phase4 CRUD", created!.Client.ClientName);
        Assert.False(string.IsNullOrWhiteSpace(created.Password));

        var update = await client.PutAsJsonAsync($"/api/admin/clients/{created.Client.Id}", new
        {
            clientName = "Phase4 CRUD renamed",
            password = "new-secret",
            enabled = false,
            connectionRateLimitPerMinute = 0,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<CredentialBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal("Phase4 CRUD renamed", updated!.Client.ClientName);
        Assert.False(updated.Client.Enabled);
        Assert.Equal("new-secret", updated.Password);

        var delete = await client.DeleteAsync($"/api/admin/clients/{created.Client.Id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
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
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var tunnel = await create.Content.ReadFromJsonAsync<TunnelBody>(JsonOptions);
        Assert.NotNull(tunnel);
        Assert.Equal(45123, tunnel!.ListenPort);

        var list = await client.GetFromJsonAsync<List<TunnelBody>>(
            $"/api/admin/tunnels?clientId={demo.Id}", JsonOptions);
        Assert.Contains(list!, row => row.Id == tunnel.Id);

        var update = await client.PutAsJsonAsync($"/api/admin/tunnels/{tunnel.Id}", new
        {
            listenPort = 45124,
            targetAddress = "localhost",
            targetPort = 9090,
            enabled = false,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<TunnelBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal(45124, updated!.ListenPort);
        Assert.False(updated.Enabled);

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
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var route = await create.Content.ReadFromJsonAsync<HttpRouteBody>(JsonOptions);
        Assert.NotNull(route);
        Assert.Equal("api", route!.Route);

        var list = await client.GetFromJsonAsync<List<HttpRouteBody>>(
            $"/api/admin/http-routes?clientId={demo.Id}", JsonOptions);
        Assert.Contains(list!, row => row.Id == route.Id);

        var update = await client.PutAsJsonAsync($"/api/admin/http-routes/{route.Id}", new
        {
            route = "admin",
            targetBaseUrl = "http://localhost:5000",
            enabled = false,
        });
        update.EnsureSuccessStatusCode();
        var updated = await update.Content.ReadFromJsonAsync<HttpRouteBody>(JsonOptions);
        Assert.NotNull(updated);
        Assert.Equal("admin", updated!.Route);
        Assert.False(updated.Enabled);

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
    public async Task DirectHttpTunnelRejectsOfflineClientAndOversizedBody()
    {
        using var client = _server!.CreateClient();
        var offline = await client.GetAsync($"/http/{Uri.EscapeDataString("Demo client")}/api/ping");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, offline.StatusCode);

        var oversized = new StringContent(new string('x', 128), Encoding.UTF8, "text/plain");
        var tooLarge = await client.PostAsync($"/http/{Uri.EscapeDataString("Demo client")}/api/ping", oversized);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooLarge.StatusCode);
    }

    [Fact]
    public async Task ConnectionWebSocketReceivesCreatedEvents()
    {
        using var client = _server!.CreateClient();
        var token = await LoginAsync(client);
        var wsClient = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await wsClient.ConnectAsync(
            new Uri($"ws://localhost/ws/connections?token={Uri.EscapeDataString(token.AccessToken)}"),
            cts.Token);

        await using (var scope = _server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
            var account = await db.ClientAccounts.AsNoTracking()
                .SingleAsync(a => a.ClientName == "Demo client", cts.Token);
            var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
            await records.RecordConnectionAsync(AuthenticationResult.Pass(account), account.ClientName,
                "ws-created-test", "127.0.0.1:51000", cts.Token);
        }

        var buffer = new byte[4096];
        var received = await socket.ReceiveAsync(buffer, cts.Token);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        var json = Encoding.UTF8.GetString(buffer.AsSpan(0, received.Count));
        Assert.Contains("\"type\":\"created\"", json, StringComparison.Ordinal);
        Assert.Contains("\"channelId\":\"ws-created-test\"", json, StringComparison.Ordinal);
    }

    private static async Task<TokenBody> LoginAsync(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
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
            ClientId = demo.Id,
            ClientName = demo.ClientName,
            StatMonth = "2026-06",
            TotalCount = 3,
            SuccessCount = 2,
            FailureCount = 1,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    private sealed record TokenBody(string AccessToken, string TokenType, long ExpiresIn);

    private sealed record CredentialBody(ClientBody Client, string? Password);

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
        string CreatedAt,
        string UpdatedAt);

    private sealed record HttpRouteBody(
        long Id,
        long ClientId,
        string ClientName,
        string Route,
        string TargetBaseUrl,
        bool Enabled,
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
}
