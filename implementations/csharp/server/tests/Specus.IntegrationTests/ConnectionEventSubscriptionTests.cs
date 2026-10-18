using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Management;
using Specus.Server.Security;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed class ConnectionEventSubscriptionTests
{
    [Fact]
    public async Task AcceptedSocketRetainsEventProducedBeforeAcceptContinuation()
    {
        var gate = new AcceptContinuationGate();
        await using var server = await TestServerFixture.StartAsync(configureServices: services =>
            services.AddSingleton<IStartupFilter>(gate));
        using var http = server.CreateClient();
        using var login = await http.PostAsJsonAsync("/auth/login", new { username = "admin", password = "admin" });
        login.EnsureSuccessStatusCode();
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("accessToken").GetString());
        using var ticketResponse = await http.PostAsJsonAsync("/api/admin/ws-tickets", new { endpoint = WebSocketTicketService.ConnectionsScope });
        ticketResponse.EnsureSuccessStatusCode();
        var ticket = (await ticketResponse.Content.ReadFromJsonAsync<IssuedWebSocketTicket>())!;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var ct = timeout.Token;
        var connecting = server.Server.CreateWebSocketClient().ConnectAsync(new Uri("ws://localhost/ws/connections?ticket=" + Uri.EscapeDataString(ticket.Ticket)), ct);
        WebSocket? socket = null;
        Task? broadcast = null;
        try
        {
            await gate.Held.Task.WaitAsync(ct);
            socket = await connecting.WaitAsync(ct);
            Assert.Equal(WebSocketState.Open, socket.State);
            // The actual HTTP upgrade has completed, but the hub cannot yet resume
            // from AcceptWebSocketAsync. No sleeps or registration polling/retries.
            broadcast = server.HostServices.GetRequiredService<ConnectionEventsHub>().BroadcastAsync(Event("upgrade-boundary"));
            gate.Release();
            await broadcast.WaitAsync(ct);
            var data = new byte[8192];
            var received = await socket.ReceiveAsync(data, ct);
            Assert.Equal(WebSocketMessageType.Text, received.MessageType);
            Assert.True(received.EndOfMessage);
            Assert.Contains("upgrade-boundary", Encoding.UTF8.GetString(data.AsSpan(0, received.Count)), StringComparison.Ordinal);
        }
        finally
        {
            gate.Release();
            socket?.Abort(); socket?.Dispose();
            if (broadcast is not null) try { await broadcast; } catch (Exception) { }
            try { (await connecting).Dispose(); } catch (Exception) { }
        }
    }

    internal static ConnectionEvent Event(string marker) => new("default", "created", new ConnectionRecordView(
        810001, 1001, marker, marker, "127.0.0.1", DateTimeOffset.UtcNow.ToString("O"), null, true, null, null, null));

    private sealed class AcceptContinuationGate : IStartupFilter
    {
        internal TaskCompletionSource Held { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Release() => _release.TrySetResult();
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.UseWebSockets();
            app.Use(async (context, nextMiddleware) =>
            {
                if (context.Request.Path == "/ws/connections" && context.Features.Get<IHttpWebSocketFeature>() is { } feature)
                    context.Features.Set<IHttpWebSocketFeature>(new GatedFeature(feature, this, context.RequestAborted));
                await nextMiddleware();
            });
            next(app);
        };

        private sealed class GatedFeature(IHttpWebSocketFeature inner, AcceptContinuationGate gate, CancellationToken ct) : IHttpWebSocketFeature
        {
            public bool IsWebSocketRequest => inner.IsWebSocketRequest;
            public async Task<WebSocket> AcceptAsync(WebSocketAcceptContext context)
            {
                var socket = await inner.AcceptAsync(context);
                gate.Held.TrySetResult();
                await gate._release.Task.WaitAsync(ct);
                return socket;
            }
        }
    }
}
