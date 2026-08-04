using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Networking;
using Specus.Server.Security;
using Specus.Server.Sessions;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed class PublicTransferAndMessagingTests : IAsyncLifetime
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
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
    public async Task PublicDiscoveryUsesJavaPathAndReturnsHelloThenRoster()
    {
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "room-a", "secret", "peer-a", "A");

        using var hello = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        Assert.Equal("hello", hello.RootElement.GetProperty("type").GetString());
        Assert.Equal("peer-a", hello.RootElement.GetProperty("peerId").GetString());
        Assert.True(hello.RootElement.GetProperty("sharedRoom").GetBoolean());

        using var roster = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        Assert.Equal("roster", roster.RootElement.GetProperty("type").GetString());
        var peer = Assert.Single(roster.RootElement.GetProperty("peers").EnumerateArray());
        Assert.Equal("peer-a", peer.GetProperty("peerId").GetString());
    }

    [Fact]
    public async Task PublicDiscoveryHidesNonDiscoverablePeerFromRoster()
    {
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var visible = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "hidden-room", "hidden-secret", "visible-peer", "Visible");
        _ = await ReceiveTextAsync(visible, cts.Token);
        _ = await ReceiveTextAsync(visible, cts.Token);

        using var hidden = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "hidden-room", "hidden-secret", "hidden-peer", "Hidden", discoverable: false);
        using var hello = JsonDocument.Parse(await ReceiveTextAsync(hidden, cts.Token));
        Assert.Equal("hello", hello.RootElement.GetProperty("type").GetString());
        using var hiddenRoster = JsonDocument.Parse(await ReceiveTextAsync(hidden, cts.Token));
        var hiddenPeers = hiddenRoster.RootElement.GetProperty("peers").EnumerateArray().ToArray();
        var onlyVisible = Assert.Single(hiddenPeers);
        Assert.Equal("visible-peer", onlyVisible.GetProperty("peerId").GetString());

        using var visibleRoster = JsonDocument.Parse(await ReceiveTextAsync(visible, cts.Token));
        var visiblePeers = visibleRoster.RootElement.GetProperty("peers").EnumerateArray().ToArray();
        Assert.DoesNotContain(visiblePeers,
            peer => peer.GetProperty("peerId").GetString() == "hidden-peer");
    }

    [Fact]
    public async Task PublicDiscoveryViewerCannotPublishWritableRoomMessages()
    {
        var roomId = $"viewer-room-{Guid.NewGuid():N}";
        var ownerToken = $"owner-{Guid.NewGuid():N}";
        using var http = _server!.CreateClient();
        using var createViewer = await http.PostAsJsonAsync(
            "/api/public/transfer/rooms/access-tokens", new
            {
                roomId,
                roomToken = ownerToken,
                peerId = "owner-peer",
                role = "VIEWER",
            });
        createViewer.EnsureSuccessStatusCode();
        using var tokenBody = JsonDocument.Parse(await createViewer.Content.ReadAsStringAsync());
        var viewerToken = tokenBody.RootElement.GetProperty("token").GetString();
        Assert.NotNull(viewerToken);

        var webSockets = _server.Server.CreateWebSocketClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var viewer = await ConnectPublicDiscoveryAsync(webSockets, timeout.Token,
            roomId, viewerToken!, "viewer-peer", "Viewer");
        using var hello = JsonDocument.Parse(await ReceiveTextAsync(viewer, timeout.Token));
        Assert.Equal("VIEWER", hello.RootElement.GetProperty("roomRole").GetString());
        _ = await ReceiveTextAsync(viewer, timeout.Token);

        await viewer.SendAsync(Encoding.UTF8.GetBytes(
            "{\"type\":\"clipboard\",\"payload\":{\"text\":\"blocked\"}}"),
            WebSocketMessageType.Text, true, timeout.Token);
        using var error = JsonDocument.Parse(await ReceiveTextAsync(viewer, timeout.Token));
        Assert.Equal("error", error.RootElement.GetProperty("type").GetString());
        Assert.Equal("viewer is read-only", error.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task PublicDiscoveryRejectsDuplicatePeerIdInSameGroup()
    {
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var first = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "duplicate-room", "secret", "reused");
        _ = await ReceiveTextAsync(first, cts.Token);
        _ = await ReceiveTextAsync(first, cts.Token);

        using var duplicate = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "duplicate-room", "secret", "reused");
        using var error = JsonDocument.Parse(await ReceiveTextAsync(duplicate, cts.Token));
        Assert.Equal("error", error.RootElement.GetProperty("type").GetString());
        Assert.Equal("peer id is already connected", error.RootElement.GetProperty("error").GetString());

        var close = await duplicate.ReceiveAsync(new byte[16], cts.Token);
        Assert.Equal(WebSocketMessageType.Close, close.MessageType);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, close.CloseStatus);
        Assert.Equal("peer id is already connected", close.CloseStatusDescription);

        using var otherGroup = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "duplicate-room", "other", "reused", "reused-other-group");
        using var hello = JsonDocument.Parse(await ReceiveTextAsync(otherGroup, cts.Token));
        Assert.Equal("hello", hello.RootElement.GetProperty("type").GetString());
    }

    [Fact]
    public async Task PublicDiscoveryUsesJavaUtf16CharacterLimitRatherThanUtf8ByteLimit()
    {
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "room-unicode", string.Empty, "peer-unicode");
        _ = await ReceiveTextAsync(socket, cts.Token);
        _ = await ReceiveTextAsync(socket, cts.Token);

        var message = Encoding.UTF8.GetBytes(
            "{\"type\":\"ping\",\"payload\":\"" + new string('界', 30_000) + "\"}");
        Assert.True(message.Length > 64 * 1024);
        await socket.SendAsync(message, WebSocketMessageType.Text, true, cts.Token);

        using var pong = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        Assert.Equal("pong", pong.RootElement.GetProperty("type").GetString());
    }

    [Fact]
    public async Task PublicDiscoveryDefaultsNonObjectJsonToSignalAndPreservesExplicitNullPayload()
    {
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var receiver = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "json-shape", "secret", "receiver");
        _ = await ReceiveTextAsync(receiver, cts.Token);
        _ = await ReceiveTextAsync(receiver, cts.Token);

        using var sender = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "json-shape", "secret", "sender");
        _ = await ReceiveTextAsync(sender, cts.Token);
        _ = await ReceiveTextAsync(sender, cts.Token);
        _ = await ReceiveTextAsync(receiver, cts.Token);

        await sender.SendAsync(Encoding.UTF8.GetBytes("[]"), WebSocketMessageType.Text, true, cts.Token);
        using (var signal = JsonDocument.Parse(await ReceiveTextAsync(receiver, cts.Token)))
        {
            Assert.Equal("signal", signal.RootElement.GetProperty("type").GetString());
            Assert.Equal("sender", signal.RootElement.GetProperty("sourcePeerId").GetString());
            Assert.False(signal.RootElement.TryGetProperty("payload", out _));
        }

        await sender.SendAsync(Encoding.UTF8.GetBytes("{\"payload\":null}"),
            WebSocketMessageType.Text, true, cts.Token);
        using var explicitNull = JsonDocument.Parse(await ReceiveTextAsync(receiver, cts.Token));
        Assert.Equal("signal", explicitNull.RootElement.GetProperty("type").GetString());
        Assert.Equal(JsonValueKind.Null, explicitNull.RootElement.GetProperty("payload").ValueKind);
    }

    [Fact]
    public void PublicDiscoveryScalarTextConversionMatchesJavaJackson()
    {
        using var document = JsonDocument.Parse("""
            {
              "string": "  original value  ",
              "integer": 42,
              "decimal": 1.25,
              "truth": true,
              "falsehood": false,
              "nullValue": null,
              "objectValue": {}
            }
            """);
        var root = document.RootElement;

        Assert.Equal("  original value  ", PublicTransferDiscoveryHub.Text(root, "string", "fallback"));
        Assert.Equal("42", PublicTransferDiscoveryHub.Text(root, "integer", "fallback"));
        Assert.Equal("1.25", PublicTransferDiscoveryHub.Text(root, "decimal", "fallback"));
        Assert.Equal("true", PublicTransferDiscoveryHub.Text(root, "truth", "fallback"));
        Assert.Equal("false", PublicTransferDiscoveryHub.Text(root, "falsehood", "fallback"));
        Assert.Equal("fallback", PublicTransferDiscoveryHub.Text(root, "nullValue", "fallback"));
        Assert.Equal("fallback", PublicTransferDiscoveryHub.Text(root, "missing", "fallback"));
        Assert.Equal("fallback", PublicTransferDiscoveryHub.Text(root, "objectValue", "fallback"));
    }

    [Fact]
    public async Task PublicDiscoveryNumericTargetPeerIdIsDirectedInsteadOfBroadcast()
    {
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var target = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "numeric-target", "numeric-secret", "42");
        _ = await ReceiveTextAsync(target, cts.Token);
        _ = await ReceiveTextAsync(target, cts.Token);

        using var observer = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "numeric-target", "numeric-secret", "observer");
        _ = await ReceiveTextAsync(observer, cts.Token);
        _ = await ReceiveTextAsync(observer, cts.Token);
        _ = await ReceiveTextAsync(target, cts.Token);

        using var sender = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "numeric-target", "numeric-secret", "sender");
        _ = await ReceiveTextAsync(sender, cts.Token);
        _ = await ReceiveTextAsync(sender, cts.Token);
        _ = await ReceiveTextAsync(target, cts.Token);
        _ = await ReceiveTextAsync(observer, cts.Token);

        await sender.SendAsync(Encoding.UTF8.GetBytes(
            "{\"type\":123,\"targetPeerId\":42,\"payload\":{\"offer\":true}}"),
            WebSocketMessageType.Text, true, cts.Token);

        using var directed = JsonDocument.Parse(await ReceiveTextAsync(target, cts.Token));
        Assert.Equal("123", directed.RootElement.GetProperty("type").GetString());
        Assert.Equal("42", directed.RootElement.GetProperty("targetPeerId").GetString());
        Assert.Equal("sender", directed.RootElement.GetProperty("sourcePeerId").GetString());

        using var noBroadcast = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ReceiveTextAsync(observer, noBroadcast.Token));
    }

    [Fact]
    public async Task PublicDiscoveryQueryTruncationDoesNotSplitUtf16SurrogatePair()
    {
        var splitAtBoundary = new string('p', 119) + "😀tail";
        var fitsAtBoundary = new string('d', 118) + "😀tail";
        var webSockets = _server!.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await ConnectPublicDiscoveryAsync(webSockets, cts.Token,
            "surrogate-room", string.Empty, splitAtBoundary, fitsAtBoundary);
        using var hello = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        using var roster = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));

        Assert.Equal(new string('p', 119), hello.RootElement.GetProperty("peerId").GetString());
        var peer = Assert.Single(roster.RootElement.GetProperty("peers").EnumerateArray());
        Assert.Equal(new string('d', 118) + "😀", peer.GetProperty("displayName").GetString());
    }

    [Fact]
    public async Task PublicDiscoveryDoesNotExposeLegacyShortPath()
    {
        using var client = _server!.CreateClient();
        var response = await client.GetAsync("/ws/public-transfer");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task PublicIceConfigMatchesJavaShape()
    {
        using var client = _server!.CreateClient();
        using var response = await client.GetAsync("/api/public/transfer/ice-config");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.GetProperty("peerMeshEnabled").GetBoolean());
        Assert.Equal(3478, json.RootElement.GetProperty("stunTurnPort").GetInt32());
        Assert.Equal(JsonValueKind.Array, json.RootElement.GetProperty("iceServers").ValueKind);
        Assert.True(json.RootElement.GetProperty("turnAuthRequired").GetBoolean());
    }

    [Fact]
    public async Task PublicAttachmentUploadRequiresLoginThenReturnsConflictWhenStorageDisabled()
    {
        using var client = _server!.CreateClient();
        var anonymousResponse = await client.PostAsJsonAsync(
            "/api/public/transfer/attachments/presign-upload",
            new
            {
                fileName = "photo.png",
                mimeType = "image/png",
                sizeBytes = 10,
                roomId = "room-a",
                roomToken = "secret",
            });
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        var login = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        login.EnsureSuccessStatusCode();
        using var loginJson = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        client.DefaultRequestHeaders.Authorization = new(
            "Bearer", loginJson.RootElement.GetProperty("accessToken").GetString());

        var response = await client.PostAsJsonAsync(
            "/api/public/transfer/attachments/presign-upload",
            new
            {
                fileName = "photo.png",
                mimeType = "image/png",
                sizeBytes = 10,
                roomId = "room-a",
                roomToken = "secret",
            });
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task PeerMeshAclApiAcceptsAndReturnsDirection()
    {
        long sourceId;
        long targetId;
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            sourceId = ClientIdGenerator.NewId();
            targetId = ClientIdGenerator.NewId();
            db.ClientAccounts.AddRange(
                new ClientAccount
                {
                    Id = sourceId,
                    TenantId = "default",
                    OwnerUsername = "alice",
                    ClientName = "acl-api-source",
                    PasswordHash = "unused",
                    Enabled = true,
                    ConnectionRateLimitPerMinute = 30,
                    CreatedAt = now,
                    UpdatedAt = now,
                },
                new ClientAccount
                {
                    Id = targetId,
                    TenantId = "default",
                    OwnerUsername = "bob",
                    ClientName = "acl-api-target",
                    PasswordHash = "unused",
                    Enabled = true,
                    ConnectionRateLimitPerMinute = 30,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
            await db.SaveChangesAsync();
        }

        using var client = _server!.CreateClient();
        var token = _server.HostServices.GetRequiredService<LocalTokenService>()
            .IssueToken("admin", "default", ManagementRole.Admin);
        client.DefaultRequestHeaders.Authorization = new("Bearer", token);
        using var create = await client.PostAsJsonAsync("/api/admin/peer-mesh/acls", new
        {
            sourceClientId = sourceId,
            targetClientId = targetId,
            allowed = true,
            direction = "inbound",
        });

        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        using var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync());
        Assert.Equal("INBOUND", created.RootElement.GetProperty("direction").GetString());
        var aclId = created.RootElement.GetProperty("id").GetInt64();

        using var list = await client.GetAsync("/api/admin/peer-mesh/acls");
        list.EnsureSuccessStatusCode();
        using var listed = JsonDocument.Parse(await list.Content.ReadAsStringAsync());
        var acl = Assert.Single(listed.RootElement.EnumerateArray());
        Assert.Equal("INBOUND", acl.GetProperty("direction").GetString());

        using var delete = await client.DeleteAsync($"/api/admin/peer-mesh/acls/{aclId}");
        Assert.Equal(HttpStatusCode.OK, delete.StatusCode);
    }

    [Fact]
    public async Task ClientMessagesWebSocketUsesSingleUseTicket()
    {
        using var http = _server!.CreateClient();
        var login = await http.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        login.EnsureSuccessStatusCode();
        using var loginJson = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var token = loginJson.RootElement.GetProperty("accessToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(token));

        var webSockets = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await ConnectAdminWebSocketAsync(webSockets, cts.Token,
            token!, WebSocketTicketService.ClientMessagesScope, "/ws/client-messages");
        using var hello = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        Assert.Equal("hello", hello.RootElement.GetProperty("type").GetString());
        Assert.Equal("client-messages", hello.RootElement.GetProperty("channel").GetString());
        Assert.Equal("admin", hello.RootElement.GetProperty("username").GetString());
    }

    [Fact]
    public async Task ClientMessagesTicketSupportsJavaUtf16CharacterLimit()
    {
        using var http = _server!.CreateClient();
        var login = await http.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        login.EnsureSuccessStatusCode();
        using var loginJson = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var token = loginJson.RootElement.GetProperty("accessToken").GetString();

        var webSockets = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await ConnectAdminWebSocketAsync(webSockets, cts.Token,
            token!, WebSocketTicketService.ClientMessagesScope, "/ws/client-messages");
        _ = await ReceiveTextAsync(socket, cts.Token);

        var command = Encoding.UTF8.GetBytes(
            "{\"type\":\"message\",\"messageId\":\"unicode-limit\"," +
            "\"toClientName\":\"missing-unicode-client\",\"message\":\"" +
            new string('界', 30_000) + "\"}");
        Assert.True(command.Length > 64 * 1024);
        await socket.SendAsync(command, WebSocketMessageType.Text, true, cts.Token);

        using var response = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        Assert.Equal("error", response.RootElement.GetProperty("type").GetString());
        Assert.Equal("target-not-found", response.RootElement.GetProperty("error").GetString());
        Assert.Equal("unicode-limit", response.RootElement.GetProperty("messageId").GetString());
    }

    [Fact]
    public async Task ClientMessagesOwnerCheckIsCaseSensitiveLikeJava()
    {
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.ClientAccounts.Add(new ClientAccount
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = "default",
                OwnerUsername = "alice",
                ClientName = "case-sensitive-owner-client",
                PasswordHash = "unused",
                Enabled = true,
                ConnectionRateLimitPerMinute = 30,
                CreatedAt = now,
                UpdatedAt = now,
            });
            db.ManagementUsers.Add(new ManagementUser
            {
                Username = "Alice",
                TenantId = "default",
                PasswordHash = "unused",
                Role = ManagementRole.User,
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }

        var tokens = _server!.HostServices.GetRequiredService<LocalTokenService>();
        var token = tokens.IssueToken("Alice", "default", ManagementRole.User);
        var webSockets = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await ConnectAdminWebSocketAsync(webSockets, cts.Token,
            token, WebSocketTicketService.ClientMessagesScope, "/ws/client-messages");
        _ = await ReceiveTextAsync(socket, cts.Token);

        var command = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = "message",
            messageId = "case-check",
            toClientName = "case-sensitive-owner-client",
            message = "hello",
        }, JsonOptions);
        await socket.SendAsync(command, WebSocketMessageType.Text, true, cts.Token);

        using var response = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
        Assert.Equal("error", response.RootElement.GetProperty("type").GetString());
        Assert.Equal("target-not-found", response.RootElement.GetProperty("error").GetString());
        Assert.Equal("case-check", response.RootElement.GetProperty("messageId").GetString());
    }

    [Fact]
    public async Task ClientMessagesReportsWriteFailureWithoutBlockingWebSocket()
    {
        ClientAccount target;
        await using (var scope = _server!.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            target = await db.ClientAccounts.SingleAsync(account =>
                account.ClientName == DatabaseInitializer.DemoClientName);
            var now = DateTimeOffset.UtcNow;
            db.ClientSessions.Add(new ClientSession
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = target.TenantId,
                ClientId = target.Id,
                ClientName = target.ClientName,
                TokenHash = "message-ack-test",
                Status = ClientAccountService.StatusNettyOnline,
                MachineFingerprint = "message-ack-machine",
                OsUser = "test",
                MessageReceiveCapable = true,
                HttpLoginAt = now,
                NettyConnectedAt = now,
                ExpiresAt = now.AddHours(1),
            });
            await db.SaveChangesAsync();
        }

        var writer = new DelayedFailingFrameWriter();
        using var lifetime = new CancellationTokenSource();
        var targetContext = new SpecusConnectionContext(
            "message-ack-target",
            "127.0.0.1:12345",
            writer,
            lifetime.Token,
            static () => { },
            new ReadGate(lifetime.Token),
            new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        targetContext.OnLoginSuccess(target.ClientName,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var registry = _server.HostServices.GetRequiredService<SessionRegistry>();
        registry.Replace(target.ClientName, targetContext);

        try
        {
            var token = _server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken("admin", "default", ManagementRole.Admin);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var http = _server.CreateClient();
            http.DefaultRequestHeaders.Authorization = new("Bearer", token);
            using var ticketResponse = await http.PostAsJsonAsync("/api/admin/ws-tickets",
                new { endpoint = WebSocketTicketService.ClientMessagesScope }, cts.Token);
            ticketResponse.EnsureSuccessStatusCode();
            var ticket = await ticketResponse.Content.ReadFromJsonAsync<IssuedWebSocketTicket>(
                cancellationToken: cts.Token);
            Assert.NotNull(ticket);
            var webSockets = _server.Server.CreateWebSocketClient();
            using var socket = await webSockets.ConnectAsync(new Uri(
                "ws://localhost/ws/client-messages?ticket="
                + Uri.EscapeDataString(ticket.Ticket)), cts.Token);
            _ = await ReceiveTextAsync(socket, cts.Token);

            await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "message",
                messageId = "ack-before-flush",
                toClientName = target.ClientName,
                message = "hello",
            }, JsonOptions), WebSocketMessageType.Text, true, cts.Token);

            await writer.Started.WaitAsync(cts.Token);
            Assert.False(writer.Completion.IsCompleted);
            var packet = Assert.IsType<MessageResponsePacket>(writer.Packet);
            Assert.Equal(MessageType.ClientToClient, packet.MessageType);

            await socket.SendAsync(Encoding.UTF8.GetBytes("{\"type\":\"noop\"}"),
                WebSocketMessageType.Text, true, cts.Token);
            using var next = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
            Assert.Equal("error", next.RootElement.GetProperty("type").GetString());
            Assert.Equal("unsupported-type", next.RootElement.GetProperty("error").GetString());

            writer.Fail(new IOException("simulated asynchronous write failure"));
            using var failed = JsonDocument.Parse(await ReceiveTextAsync(socket, cts.Token));
            Assert.Equal("failed", failed.RootElement.GetProperty("type").GetString());
            Assert.Equal("ack-before-flush", failed.RootElement.GetProperty("messageId").GetString());
            Assert.Equal("target-write-failed", failed.RootElement.GetProperty("error").GetString());
        }
        finally
        {
            registry.Unbind(target.ClientName, targetContext);
        }
    }

    private static async Task<string> ReceiveTextAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, cancellationToken);
            Assert.True(result.MessageType == WebSocketMessageType.Text,
                $"Expected text, got {result.MessageType}; close={socket.CloseStatus} {socket.CloseStatusDescription}");
            stream.Write(buffer, 0, result.Count);
            if (result.EndOfMessage)
            {
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
    }

    private async Task<WebSocket> ConnectPublicDiscoveryAsync(WebSocketClient webSockets,
        CancellationToken cancellationToken, string roomId, string roomToken, string peerId,
        string? displayName = null, bool? discoverable = null)
    {
        using var http = _server!.CreateClient();
        using var response = await http.PostAsJsonAsync("/api/public/transfer/ws-tickets", new
        {
            roomId,
            roomToken,
            peerId,
            displayName = displayName ?? peerId,
            discoverable,
        }, cancellationToken);
        response.EnsureSuccessStatusCode();
        var ticket = await response.Content.ReadFromJsonAsync<IssuedWebSocketTicket>(
            cancellationToken: cancellationToken);
        Assert.NotNull(ticket);
        return await webSockets.ConnectAsync(new Uri(
            "ws://localhost/ws/public-transfer/discovery?ticket="
            + Uri.EscapeDataString(ticket!.Ticket)), cancellationToken);
    }

    private async Task<WebSocket> ConnectAdminWebSocketAsync(WebSocketClient webSockets,
        CancellationToken cancellationToken, string bearerToken, string endpoint, string path)
    {
        using var http = _server!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new("Bearer", bearerToken);
        using var response = await http.PostAsJsonAsync("/api/admin/ws-tickets", new
        {
            endpoint,
        }, cancellationToken);
        response.EnsureSuccessStatusCode();
        var ticket = await response.Content.ReadFromJsonAsync<IssuedWebSocketTicket>(
            cancellationToken: cancellationToken);
        Assert.NotNull(ticket);
        return await webSockets.ConnectAsync(new Uri(
            $"ws://localhost{path}?ticket={Uri.EscapeDataString(ticket!.Ticket)}"),
            cancellationToken);
    }

    private sealed class DelayedFailingFrameWriter : IFrameWriter
    {
        private readonly TaskCompletionSource<bool> _completion = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _started = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Packet? Packet { get; private set; }
        public Task Completion => _completion.Task;
        public Task Started => _started.Task;

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            Packet = packet;
            _started.TrySetResult(true);
            return new ValueTask(_completion.Task);
        }

        public void Fail(Exception exception) => _completion.TrySetException(exception);
    }
}
