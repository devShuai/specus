using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Security;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed class ConnectionEventPolicyCloseTests
{
    [Fact]
    public async Task RealTcpWebSocketReceivesPolicyCloseBeforeReceiveCancellationCanAbortTransport()
    {
        await using var server = await TestServerFixture.StartAsync();
        using var http = server.CreateClient();
        using var login = await http.PostAsJsonAsync("/auth/login", new { username = "admin", password = "admin" });
        login.EnsureSuccessStatusCode(); var json = await login.Content.ReadFromJsonAsync<JsonElement>();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", json.GetProperty("accessToken").GetString());
        using var response = await http.PostAsJsonAsync("/api/admin/ws-tickets", new { endpoint = WebSocketTicketService.ConnectionsScope });
        response.EnsureSuccessStatusCode(); var ticket = (await response.Content.ReadFromJsonAsync<IssuedWebSocketTicket>())!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct = timeout.Token;
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var clientTcp = new TcpClient();
        Task? accepting = null; Task? closing = null;
        try
        {
            await clientTcp.ConnectAsync((IPEndPoint)listener.LocalEndpoint, ct);
            using var serverTcp = await listener.AcceptTcpClientAsync(ct);
            using var client = WebSocket.CreateFromStream(clientTcp.GetStream(), false, null, Timeout.InfiniteTimeSpan);
            using var wire = WebSocket.CreateFromStream(serverTcp.GetStream(), true, null, Timeout.InfiniteTimeSpan);
            using var observed = new ReceiveObserver(wire);
            var context = new DefaultHttpContext { RequestAborted = ct };
            context.Connection.RemoteIpAddress = IPAddress.Loopback;
            context.Request.QueryString = new QueryString("?ticket=" + ticket.Ticket);
            context.Features.Set<IHttpWebSocketFeature>(new AcceptedFeature(observed));
            var hub = server.HostServices.GetRequiredService<ConnectionEventsHub>();
            accepting = hub.AcceptAsync(context);
            await observed.Receiving.Task.WaitAsync(ct);
            closing = hub.CloseIdentityAsync("default", "admin", "test policy close");
            var received = await client.ReceiveAsync(new ArraySegment<byte>(new byte[1024]), ct);
            Assert.Equal(WebSocketMessageType.Close, received.MessageType);
            Assert.Equal(WebSocketCloseStatus.PolicyViolation, received.CloseStatus);
            Assert.Equal("test policy close", received.CloseStatusDescription);
            await client.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "ack", ct);
            await closing.WaitAsync(ct); await accepting.WaitAsync(ct);
        }
        finally
        {
            timeout.Cancel(); clientTcp.Close(); listener.Stop();
            if (closing is not null) try { await closing.WaitAsync(TimeSpan.FromSeconds(10)); } catch (Exception) { }
            if (accepting is not null) try { await accepting.WaitAsync(TimeSpan.FromSeconds(10)); } catch (Exception) { }
        }
    }

    private sealed class AcceptedFeature(WebSocket socket) : IHttpWebSocketFeature
    {
        public bool IsWebSocketRequest => true;
        public Task<WebSocket> AcceptAsync(WebSocketAcceptContext context) => Task.FromResult(socket);
    }

    private sealed class ReceiveObserver(WebSocket inner) : WebSocket
    {
        internal TaskCompletionSource Receiving { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override WebSocketState State => inner.State;
        public override WebSocketCloseStatus? CloseStatus => inner.CloseStatus;
        public override string? CloseStatusDescription => inner.CloseStatusDescription;
        public override string? SubProtocol => inner.SubProtocol;
        public override void Abort() => inner.Abort();
        public override void Dispose() => inner.Dispose();
        public override Task CloseAsync(WebSocketCloseStatus status, string? reason, CancellationToken ct) => inner.CloseAsync(status, reason, ct);
        public override Task CloseOutputAsync(WebSocketCloseStatus status, string? reason, CancellationToken ct) => inner.CloseOutputAsync(status, reason, ct);
        public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool end, CancellationToken ct) => inner.SendAsync(buffer, type, end, ct);
        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct)
        {
            var pending = inner.ReceiveAsync(buffer, ct);
            // The actual ManagedWebSocket has registered cancellation before we signal.
            Receiving.TrySetResult(); return pending;
        }
    }
}
