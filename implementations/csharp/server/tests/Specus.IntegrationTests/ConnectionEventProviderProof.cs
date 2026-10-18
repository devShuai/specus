using System.Net.Http.Headers;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

// Same signed HTTP/ticket + actual TestServer WebSocket proof in every native DB.
// Independent SQL mutation deliberately does not notify this host's live socket.
internal static class ConnectionEventProviderProof
{
    internal static async Task VerifyAsync(TestServerFixture server)
    {
        using var diagnostics = new FailureLog();
        server.HostServices.GetRequiredService<ILoggerFactory>().AddProvider(diagnostics);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct = timeout.Token;
        await using (var seed = server.HostServices.CreateAsyncScope())
        {
            var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
            db.ManagementUsers.Add(new ManagementUser { Username = "native-ws-account", LoginName = "native-ws-user", TenantId = "default",
                PasswordHash = PasswordHasher.Hash("native-ws-fixture-password"), Enabled = true, Role = ManagementRole.User });
            db.ClientAccounts.Add(new ClientAccount { Id = 810011, TenantId = "default", ClientName = "native-ws-client",
                OwnerUsername = "native-ws-user", Enabled = true, PasswordHash = "unused-fixture" });
            await db.SaveChangesAsync(ct);
        }
        using var http = server.CreateClient();
        using var login = await http.PostAsJsonAsync("/auth/login", new { username = "native-ws-user", password = "native-ws-fixture-password", tenantId = "default" }, ct);
        login.EnsureSuccessStatusCode(); var body = await login.Content.ReadFromJsonAsync<JsonElement>(ct);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("accessToken").GetString());
        using var response = await http.PostAsJsonAsync("/api/admin/ws-tickets", new { endpoint = WebSocketTicketService.ConnectionsScope }, ct);
        Assert.True(response.IsSuccessStatusCode, $"WS ticket HTTP {(int)response.StatusCode}: {string.Join('\n', diagnostics.Errors)}");
        var ticket = (await response.Content.ReadFromJsonAsync<IssuedWebSocketTicket>(ct))!;
        using var socket = await server.Server.CreateWebSocketClient().ConnectAsync(
            new Uri("ws://localhost/ws/connections?ticket=" + Uri.EscapeDataString(ticket.Ticket)), ct);
        var hub = server.HostServices.GetRequiredService<ConnectionEventsHub>();
        ConnectionEvent Event(string marker) => new("default", "created", new ConnectionRecordView(810012, 810011,
            marker, marker, "127.0.0.1", DateTimeOffset.UtcNow.ToString("O"), null, true, null, null, null));
        await hub.BroadcastAsync(Event("native-ws-authorized"));
        var buffer = new byte[8192];
        var received = await socket.ReceiveAsync(buffer.AsMemory(), ct);
        Assert.Equal(WebSocketMessageType.Text, received.MessageType);
        Assert.Contains("native-ws-authorized", Encoding.UTF8.GetString(buffer.AsSpan(0, received.Count)), StringComparison.Ordinal);
        await using (var revoke = server.HostServices.CreateAsyncScope())
        {
            var db = revoke.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.Equal(1, await db.ManagementUsers.Where(u => u.Username == "native-ws-account")
                .ExecuteUpdateAsync(setters => setters.SetProperty(u => u.Enabled, false), ct));
        }
        await hub.BroadcastAsync(Event("native-ws-must-not-leak"));
        var closed = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
        Assert.Equal(WebSocketMessageType.Close, closed.MessageType);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, closed.CloseStatus);
        Assert.Equal(0, closed.Count);
    }

    private sealed class FailureLog : ILoggerProvider
    {
        internal ConcurrentQueue<string> Errors { get; } = new();
        public void Dispose() { }
        public ILogger CreateLogger(string categoryName) => new Capture(this);
        private sealed class Capture(FailureLog owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => level >= LogLevel.Error;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (level >= LogLevel.Error && exception is not null)
                {
                    var cause = exception.GetBaseException();
                    owner.Errors.Enqueue(cause.GetType().Name + ": " + cause.Message);
                }
            }
        }
    }
}
