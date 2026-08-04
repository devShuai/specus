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
using Specus.Server.Security;

namespace Specus.IntegrationTests;

public sealed class DiagramAndTransferRoomApiTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:PeerMesh:StandaloneStunAddress"] = "stun1.example.com",
            ["Specus:PeerMesh:StandaloneStunPort"] = "3478",
            ["Specus:PeerMesh:StandaloneStunAlternateAddress"] = "stun2.example.com",
            ["Specus:PeerMesh:StandaloneStunAlternatePort"] = "3479",
            ["Specus:PublicTransfer:PairingCodeRedeemRateLimitPerIp"] = "20",
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
    public async Task ClientNameAvailabilityAndNatProbeConfigMatchJavaApi()
    {
        using var admin = await AuthenticatedClientAsync();
        long demoId;
        long foreignClientId;
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            demoId = await db.ClientAccounts.AsNoTracking()
                .Where(row => row.ClientName == "Demo client")
                .Select(row => row.Id)
                .SingleAsync();
            foreignClientId = ClientIdGenerator.NewId();
            db.ClientAccounts.Add(new ClientAccount
            {
                Id = foreignClientId,
                TenantId = "other-tenant",
                OwnerUsername = "other-user",
                ClientName = $"other-{Guid.NewGuid():N}",
                PasswordHash = "unused",
                Enabled = true,
                ConnectionRateLimitPerMinute = 30,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        var unavailable = await admin.GetFromJsonAsync<JsonElement>(
            "/api/admin/clients/name-availability?clientName=Demo%20client", JsonOptions);
        Assert.False(unavailable.GetProperty("available").GetBoolean());
        Assert.Equal("Demo client", unavailable.GetProperty("clientName").GetString());

        var excluded = await admin.GetFromJsonAsync<JsonElement>(
            $"/api/admin/clients/name-availability?clientName=Demo%20client&excludeClientId={demoId}",
            JsonOptions);
        Assert.True(excluded.GetProperty("available").GetBoolean());

        using var missingName = await admin.GetAsync("/api/admin/clients/name-availability?clientName=%20");
        Assert.Equal(HttpStatusCode.BadRequest, missingName.StatusCode);
        using var hiddenExclude = await admin.GetAsync(
            $"/api/admin/clients/name-availability?clientName=unused&excludeClientId={foreignClientId}");
        Assert.Equal(HttpStatusCode.BadRequest, hiddenExclude.StatusCode);

        using var anonymous = _server.CreateClient();
        var nat = await anonymous.GetFromJsonAsync<JsonElement>(
            "/api/public/peer-mesh/nat-probe-config", JsonOptions);
        Assert.True(nat.GetProperty("available").GetBoolean());
        Assert.Equal("RFC8489", nat.GetProperty("protocol").GetString());
        Assert.Equal("RFC5780", nat.GetProperty("discoveryMethod").GetString());
        Assert.Equal(4, nat.GetProperty("endpoints").GetArrayLength());
        Assert.Equal("stun:stun1.example.com:3478",
            nat.GetProperty("endpoints")[0].GetProperty("url").GetString());
        Assert.True(nat.GetProperty("capabilities").GetProperty("changeRequest").GetBoolean());
    }

    [Fact]
    public async Task DiagramCrudEnforcesOwnerAndOptimisticRevision()
    {
        using var admin = await AuthenticatedClientAsync();
        var initial = Convert.ToBase64String(Encoding.UTF8.GetBytes("diagram-v1"));
        using var create = await admin.PostAsJsonAsync("/api/admin/diagrams", new
        {
            name = "My diagram",
            update = initial,
        });
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var created = await ReadJsonAsync(create);
        var id = created.GetProperty("id").GetInt64();
        Assert.Equal(0, created.GetProperty("revision").GetInt64());

        var detail = await admin.GetFromJsonAsync<JsonElement>($"/api/admin/diagrams/{id}", JsonOptions);
        Assert.Equal(initial, detail.GetProperty("update").GetString());
        Assert.Equal(id, detail.GetProperty("document").GetProperty("id").GetInt64());

        var next = Convert.ToBase64String(Encoding.UTF8.GetBytes("diagram-v2"));
        using var update = await admin.PutAsJsonAsync($"/api/admin/diagrams/{id}", new
        {
            name = "My diagram 2",
            update = next,
            revision = 0,
        });
        update.EnsureSuccessStatusCode();
        var updated = await ReadJsonAsync(update);
        Assert.Equal(1, updated.GetProperty("revision").GetInt64());

        using var stale = await admin.PutAsJsonAsync($"/api/admin/diagrams/{id}", new
        {
            name = "stale",
            update = initial,
            revision = 0,
        });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);

        long foreignId;
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            foreignId = ClientIdGenerator.NewId();
            db.UserDiagramDocuments.Add(new UserDiagramDocument
            {
                Id = foreignId,
                TenantId = "default",
                OwnerUsername = "someone-else",
                Name = "hidden",
                SnapshotData = [1],
                SizeBytes = 1,
                Revision = 0,
                CreatedAt = DateTimeOffset.UtcNow,
                UpdatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using var hidden = await admin.GetAsync($"/api/admin/diagrams/{foreignId}");
        Assert.Equal(HttpStatusCode.NotFound, hidden.StatusCode);

        using var delete = await admin.DeleteAsync($"/api/admin/diagrams/{id}");
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
        using var gone = await admin.GetAsync($"/api/admin/diagrams/{id}");
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
    }

    [Fact]
    public async Task RoomTokensPairingCodesAndVersionsEnforceRolesAndRevocation()
    {
        using var client = _server!.CreateClient();
        var roomId = $"room-{Guid.NewGuid():N}";
        var ownerToken = $"owner-{Guid.NewGuid():N}";

        using var createEditor = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/access-tokens", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
                role = "EDITOR",
                label = "Editor",
                expiresInSeconds = 3600,
            });
        createEditor.EnsureSuccessStatusCode();
        Assert.Contains("no-store", createEditor.Headers.CacheControl?.ToString() ?? string.Empty,
            StringComparison.OrdinalIgnoreCase);
        var editorCreated = await ReadJsonAsync(createEditor);
        var editorId = editorCreated.GetProperty("access").GetProperty("id").GetInt64();
        var editorToken = editorCreated.GetProperty("token").GetString()
            ?? throw new InvalidOperationException("missing editor token");
        Assert.StartsWith("st-editor-", editorToken, StringComparison.Ordinal);

        using var createPairing = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/pairing-codes", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
                role = "VIEWER",
                maxUses = 1,
            });
        createPairing.EnsureSuccessStatusCode();
        var pairing = await ReadJsonAsync(createPairing);
        var pairingCode = pairing.GetProperty("code").GetString()
            ?? throw new InvalidOperationException("missing pairing code");
        Assert.Equal(8, pairingCode.Length);

        using var redeem = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/pairing-codes/redeem", new
            {
                code = pairingCode,
                peerId = "viewer-peer",
            });
        redeem.EnsureSuccessStatusCode();
        var redeemed = await ReadJsonAsync(redeem);
        var viewerToken = redeemed.GetProperty("roomToken").GetString()
            ?? throw new InvalidOperationException("missing viewer token");
        Assert.Equal("VIEWER", redeemed.GetProperty("role").GetString());

        using var redeemAgain = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/pairing-codes/redeem", new
            {
                code = pairingCode,
                peerId = "viewer-peer-2",
            });
        Assert.Equal(HttpStatusCode.BadRequest, redeemAgain.StatusCode);

        var snapshot = Convert.ToBase64String(Encoding.UTF8.GetBytes("shared diagram"));
        using var viewerCreate = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/diagram/versions", new
            {
                roomId,
                roomToken = viewerToken,
                peerId = "viewer-peer",
                name = "viewer version",
                update = snapshot,
            });
        Assert.Equal(HttpStatusCode.Forbidden, viewerCreate.StatusCode);

        using var editorCreate = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/diagram/versions", new
            {
                roomId,
                roomToken = editorToken,
                peerId = "editor-peer",
                name = "editor version",
                update = snapshot,
            });
        editorCreate.EnsureSuccessStatusCode();
        var version = await ReadJsonAsync(editorCreate);
        var versionId = version.GetProperty("id").GetInt64();

        using var getVersion = await client.PostAsJsonAsync(
            $"/api/public/transfer/rooms/diagram/versions/{versionId}", new
            {
                roomId,
                roomToken = viewerToken,
                peerId = "viewer-peer",
            });
        getVersion.EnsureSuccessStatusCode();
        var detail = await ReadJsonAsync(getVersion);
        Assert.Equal(snapshot, detail.GetProperty("update").GetString());

        using var crossRoom = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/diagram/versions/list", new
            {
                roomId = "different-room",
                roomToken = editorToken,
                peerId = "editor-peer",
            });
        Assert.Equal(HttpStatusCode.Forbidden, crossRoom.StatusCode);

        using var revoke = await client.PostAsJsonAsync(
            $"/api/public/transfer/rooms/access-tokens/{editorId}/revoke", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
            });
        revoke.EnsureSuccessStatusCode();
        var revoked = await ReadJsonAsync(revoke);
        Assert.Equal(editorId, revoked.GetProperty("id").GetInt64());
        Assert.NotEqual(JsonValueKind.Null, revoked.GetProperty("revokedAt").ValueKind);

        using var revokedUse = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/diagram/versions/list", new
            {
                roomId,
                roomToken = editorToken,
                peerId = "editor-peer",
            });
        Assert.Equal(HttpStatusCode.Forbidden, revokedUse.StatusCode);

        using var delete = await client.PostAsJsonAsync(
            $"/api/public/transfer/rooms/diagram/versions/{versionId}/delete", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
            });
        Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
    }

    [Fact]
    public async Task PublicWebSocketTicketsResolveRoomRolesAndDiscoverability()
    {
        using var client = _server!.CreateClient();
        var roomId = $"ticket-room-{Guid.NewGuid():N}";
        var ownerToken = $"owner-{Guid.NewGuid():N}";

        var owner = await IssueAndConsumeTicketAsync(client, new
        {
            roomId,
            roomToken = ownerToken,
            peerId = "owner-peer",
            displayName = "Owner",
            discoverable = false,
        });
        Assert.True(owner.SharedRoom);
        Assert.StartsWith("room:", owner.RoomKey, StringComparison.Ordinal);
        Assert.Equal("OWNER", owner.RoomRole);
        Assert.False(owner.Discoverable);

        using var createEditor = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/access-tokens", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
                role = "EDITOR",
            });
        createEditor.EnsureSuccessStatusCode();
        var editorToken = (await ReadJsonAsync(createEditor)).GetProperty("token").GetString();
        Assert.NotNull(editorToken);

        using var createViewer = await client.PostAsJsonAsync(
            "/api/public/transfer/rooms/access-tokens", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
                role = "VIEWER",
            });
        createViewer.EnsureSuccessStatusCode();
        var viewerToken = (await ReadJsonAsync(createViewer)).GetProperty("token").GetString();
        Assert.NotNull(viewerToken);

        var editor = await IssueAndConsumeTicketAsync(client, new
        {
            roomId,
            roomToken = editorToken,
            peerId = "editor-peer",
            discoverable = true,
        });
        Assert.Equal(owner.RoomKey, editor.RoomKey);
        Assert.Equal("EDITOR", editor.RoomRole);
        Assert.True(editor.Discoverable);

        var viewer = await IssueAndConsumeTicketAsync(client, new
        {
            roomId,
            roomToken = viewerToken,
            peerId = "viewer-peer",
        });
        Assert.Equal(owner.RoomKey, viewer.RoomKey);
        Assert.Equal("VIEWER", viewer.RoomRole);
        Assert.True(viewer.Discoverable);

        using var invalidInvite = await client.PostAsJsonAsync(
            "/api/public/transfer/ws-tickets", new
            {
                roomId,
                roomToken = "st-editor-unknown",
                peerId = "invalid-peer",
            });
        Assert.Equal(HttpStatusCode.Forbidden, invalidInvite.StatusCode);

        var addressScoped = await IssueAndConsumeTicketAsync(client, new
        {
            roomId = "nearby",
            peerId = "nearby-peer",
        });
        Assert.False(addressScoped.SharedRoom);
        Assert.StartsWith("public:", addressScoped.RoomKey, StringComparison.Ordinal);
        Assert.Equal("EDITOR", addressScoped.RoomRole);
        Assert.True(addressScoped.Discoverable);
    }

    private async Task<HttpClient> AuthenticatedClientAsync()
    {
        var client = _server!.CreateClient();
        using var response = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        response.EnsureSuccessStatusCode();
        var body = await ReadJsonAsync(response);
        var accessToken = body.GetProperty("accessToken").GetString()
            ?? throw new InvalidOperationException("missing login token");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    private async Task<WebSocketTicketClaims> IssueAndConsumeTicketAsync(HttpClient client,
        object request)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/public/transfer/ws-tickets", request);
        response.EnsureSuccessStatusCode();
        var issued = await response.Content.ReadFromJsonAsync<IssuedWebSocketTicket>(JsonOptions)
            ?? throw new InvalidOperationException("missing websocket ticket");
        var tickets = _server!.HostServices.GetRequiredService<WebSocketTicketService>();
        foreach (var address in new[] { "unknown", "127.0.0.1", "::1" })
        {
            var claims = await tickets.ConsumeAsync(issued.Ticket,
                WebSocketTicketService.PublicTransferScope, address, CancellationToken.None);
            if (claims is not null)
            {
                return claims;
            }
        }
        throw new InvalidOperationException("could not consume websocket ticket");
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
    {
        await using var stream = await response.Content.ReadAsStreamAsync();
        using var document = await JsonDocument.ParseAsync(stream);
        return document.RootElement.Clone();
    }
}
