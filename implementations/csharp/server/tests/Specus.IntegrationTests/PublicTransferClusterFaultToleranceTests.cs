using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Security;
using Specus.Server.WebSockets;
using StackExchange.Redis;

namespace Specus.IntegrationTests;

/// <summary>
/// Cluster-mode fault tolerance for public transfer discovery, aligned with the Java
/// handler: a Redis-side routing failure drops only the failed message or cluster event,
/// never the discovery connection. Each test boots a cluster-enabled fixture; without
/// SPECUS_TEST_REDIS_URI the tests skip like the other Redis-backed tests.
/// </summary>
public sealed class PublicTransferClusterFaultToleranceTests : IAsyncLifetime
{
    private readonly string? _redisUri = Environment.GetEnvironmentVariable("SPECUS_TEST_REDIS_URI");
    private readonly string _keyPrefix = "specus:test:" + Guid.NewGuid().ToString("N");
    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        if (string.IsNullOrWhiteSpace(_redisUri))
        {
            return;
        }
        _server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:PublicTransfer:ClusterEnabled"] = "true",
            ["Specus:PublicTransfer:RedisUri"] = _redisUri,
            ["Specus:PublicTransfer:RedisKeyPrefix"] = _keyPrefix,
            // Keep the periodic presence sweep out of these tests so it cannot race the
            // injected Redis failures (the lease must stay above twice the interval).
            ["Specus:PublicTransfer:PresenceLeaseSeconds"] = "601",
            ["Specus:PublicTransfer:PresenceRefreshIntervalMs"] = "300000",
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
    public async Task DirectedTextRoutingFailureRepliesErrorAndKeepsConnectionAlive()
    {
        if (_server is null)
        {
            return;
        }
        const string roomId = "fault-text-room";
        const string address = "203.0.113.60";
        var webSockets = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var alpha = await ConnectAsync(webSockets, roomId, "peer-a", address, cts.Token);
        Assert.Equal("hello", await ReadTypeAsync(alpha, cts.Token));
        // A merged-scope change publishes to the group and the net, so each join lands as
        // two roster frames on every visible peer.
        Assert.Equal(["peer-a"], await ReadRosterPeersAsync(alpha, cts.Token));
        Assert.Equal(["peer-a"], await ReadRosterPeersAsync(alpha, cts.Token));
        using var beta = await ConnectAsync(webSockets, roomId, "peer-b", address, cts.Token);
        Assert.Equal("hello", await ReadTypeAsync(beta, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(beta, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(beta, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(alpha, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(alpha, cts.Token));

        // Corrupt the nets index so the directed route lookup fails inside Redis.
        var netsKey = _keyPrefix + ":nets:"
            + PublicTransferCoordinationService.NetId(address);
        using var raw = await RawRedis.ConnectAsync(_redisUri!);
        await raw.GetDatabase().StringSetAsync(netsKey, "not-a-set");
        try
        {
            await SendTextAsync(alpha,
                """{"type":"signal","targetPeerId":"peer-b","payload":{"k":"v"}}""", cts.Token);
            using var error = JsonDocument.Parse(await ReceiveTextAsync(alpha, cts.Token));
            Assert.Equal("error", error.RootElement.GetProperty("type").GetString());
            Assert.Equal("invalid message", error.RootElement.GetProperty("error").GetString());

            // The connection survives the routing failure: ping still gets a pong.
            await SendTextAsync(alpha, """{"type":"ping"}""", cts.Token);
            Assert.Equal("pong", await ReadTypeAsync(alpha, cts.Token));
        }
        finally
        {
            // Restore the index so disconnect cleanup does not trip over the corrupt key.
            await raw.GetDatabase().KeyDeleteAsync(netsKey);
        }
    }

    [Fact]
    public async Task FailedClusterRosterEventIsDiscardedWithoutDroppingParticipants()
    {
        if (_server is null)
        {
            return;
        }
        const string roomId = "fault-roster-room";
        const string address = "203.0.113.61";
        var webSockets = _server.Server.CreateWebSocketClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var alpha = await ConnectAsync(webSockets, roomId, "peer-a", address, cts.Token);
        Assert.Equal("hello", await ReadTypeAsync(alpha, cts.Token));
        Assert.Equal(["peer-a"], await ReadRosterPeersAsync(alpha, cts.Token));
        Assert.Equal(["peer-a"], await ReadRosterPeersAsync(alpha, cts.Token));
        using var beta = await ConnectAsync(webSockets, roomId, "peer-b", address, cts.Token);
        Assert.Equal("hello", await ReadTypeAsync(beta, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(beta, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(beta, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(alpha, cts.Token));
        Assert.Equal(["peer-a", "peer-b"], await ReadRosterPeersAsync(alpha, cts.Token));

        // A non-integer revision makes the roster re-read fail deterministically.
        var groupId = PublicTransferCoordinationService.GroupId(roomId, "public:" + address);
        var revisionKey = _keyPrefix + ":revision:" + groupId;
        using var raw = await RawRedis.ConnectAsync(_redisUri!);
        await raw.GetDatabase().StringSetAsync(revisionKey, "1.5");
        try
        {
            var coordination = _server.HostServices
                .GetRequiredService<PublicTransferCoordinationService>();
            var dispatched = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            coordination.AddListener(clusterEvent =>
            {
                if (clusterEvent.Kind == PublicTransferClusterFrame.KindRoster
                    && clusterEvent.GroupId == groupId)
                {
                    dispatched.TrySetResult();
                }
                return Task.CompletedTask;
            });
            var rosterEvent = PublicTransferClusterFrame.Encode(new PublicTransferClusterEvent(
                PublicTransferClusterFrame.KindRoster, false, 0, groupId, string.Empty,
                string.Empty, []));
            await raw.GetSubscriber().PublishAsync(RedisChannel.Literal(_keyPrefix + ":events"),
                rosterEvent);
            // The hub's listener is registered before this one, so by the time the event
            // has been dispatched the failed roster refresh has already completed.
            await dispatched.Task.WaitAsync(cts.Token);

            // Both peers survive the failed roster refresh: ping still gets a pong.
            foreach (var socket in new[] { alpha, beta })
            {
                await SendTextAsync(socket, """{"type":"ping"}""", cts.Token);
                Assert.Equal("pong", await ReadTypeAsync(socket, cts.Token));
            }
        }
        finally
        {
            await raw.GetDatabase().KeyDeleteAsync(revisionKey);
        }
    }

    private async Task<WebSocket> ConnectAsync(WebSocketClient webSockets, string roomId,
        string peerId, string publicAddress, CancellationToken cancellationToken)
    {
        using var http = _server!.CreateClient();
        // The ticket is bound to the request address, so the WebSocket connect below must
        // present the same X-Real-IP.
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Real-IP", publicAddress);
        using var response = await http.PostAsJsonAsync("/api/public/transfer/ws-tickets", new
        {
            roomId,
            roomToken = "",
            peerId,
            displayName = peerId,
        }, cancellationToken);
        response.EnsureSuccessStatusCode();
        var ticket = await response.Content.ReadFromJsonAsync<IssuedWebSocketTicket>(
            cancellationToken: cancellationToken);
        Assert.NotNull(ticket);
        webSockets.ConfigureRequest = request => request.Headers["X-Real-IP"] = publicAddress;
        return await webSockets.ConnectAsync(new Uri(
            "ws://localhost/ws/public-transfer/discovery?ticket="
            + Uri.EscapeDataString(ticket!.Ticket)), cancellationToken);
    }

    private static async Task<string> ReadTypeAsync(WebSocket socket,
        CancellationToken cancellationToken)
    {
        using var frame = JsonDocument.Parse(await ReceiveTextAsync(socket, cancellationToken));
        return frame.RootElement.GetProperty("type").GetString()!;
    }

    private static async Task<string[]> ReadRosterPeersAsync(WebSocket socket,
        CancellationToken cancellationToken)
    {
        using var roster = JsonDocument.Parse(await ReceiveTextAsync(socket, cancellationToken));
        Assert.Equal("roster", roster.RootElement.GetProperty("type").GetString());
        return roster.RootElement.GetProperty("peers").EnumerateArray()
            .Select(peer => peer.GetProperty("peerId").GetString()!)
            .ToArray();
    }

    private static Task SendTextAsync(WebSocket socket, string text,
        CancellationToken cancellationToken) => socket.SendAsync(Encoding.UTF8.GetBytes(text),
            WebSocketMessageType.Text, true, cancellationToken);

    private static async Task<string> ReceiveTextAsync(WebSocket socket,
        CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[8192];
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
}

/// <summary>Raw Redis access for injecting failures the coordination API cannot produce.</summary>
internal static class RawRedis
{
    internal static Task<ConnectionMultiplexer> ConnectAsync(string redisUri)
    {
        var uri = new Uri(redisUri);
        var configuration = new ConfigurationOptions();
        configuration.EndPoints.Add(uri.Host, uri.Port > 0 ? uri.Port : 6379);
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            configuration.Password = Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[^1]);
        }
        // Honor the database index in the URI path like the coordination service does,
        // or fault injections land in DB 0 while the service under test reads another
        // database (pub/sub is the only database-agnostic part).
        var path = uri.AbsolutePath.Trim('/');
        if (path.Length > 0 && int.TryParse(path,
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var database))
        {
            configuration.DefaultDatabase = database;
        }
        return ConnectionMultiplexer.ConnectAsync(configuration);
    }
}
