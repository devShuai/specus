using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using Specus.Server.WebSockets;

namespace Specus.IntegrationTests;

public sealed partial class ManagementAccountLifecycleTests
{
    [Fact]
    public async Task ReplaysTheWebSocketRevocationVector()
    {
        using var document = LoadVector();
        var vector = document.RootElement.GetProperty("webSocketRevocation");
        await using var server = await TestServerFixture.StartAsync();
        await SeedVectorAccountsAsync(server, vector);
        using var actor = Bearer(server, Sign(vector.GetProperty("actor")));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = timeout.Token;
        var bystanders = new List<(WebSocket Socket, string Endpoint, string Tenant, string Username, Uri Ticket)>();
        try
        {
            foreach (var bystander in vector.GetProperty("bystanders").EnumerateArray())
            {
                var claims = bystander.GetProperty("claims");
                using var client = Bearer(server, Sign(claims));
                var endpoint = bystander.GetProperty("endpoint").GetString()!;
                var socket = await ConnectManagementSocketAsync(server, client, endpoint, ct);
                if (endpoint == "client-messages") await ReceiveTextAsync(socket, ct);
                var tenant = claims.GetProperty("tenant_id").GetString()!;
                var username = claims.GetProperty("sub").GetString()!;
                await AssertManagementSocketAliveAsync(server, socket, endpoint, tenant, username, ct);
                bystanders.Add((socket, endpoint, tenant, username, await IssueManagementTicketAsync(client, endpoint, ct)));
            }
            foreach (var testCase in vector.GetProperty("cases").EnumerateArray())
            {
                var target = testCase.GetProperty("target");
                var tenant = target.GetProperty("tenant_id").GetString()!;
                var username = target.GetProperty("sub").GetString()!;
                using var client = Bearer(server, Sign(target));
                using var messages = await ConnectManagementSocketAsync(server, client, "client-messages", ct);
                await ReceiveTextAsync(messages, ct);
                using var events = await ConnectManagementSocketAsync(server, client, "connections", ct);
                await AssertManagementSocketAliveAsync(server, events, "connections", tenant, username, ct);
                var messagesTicket = await IssueManagementTicketAsync(client, "client-messages", ct);
                var eventsTicket = await IssueManagementTicketAsync(client, "connections", ct);
                var request = testCase.GetProperty("request");
                using var mutation = new HttpRequestMessage(new HttpMethod(request.GetProperty("method").GetString()!),
                    "/api/admin/users/" + username);
                if (request.TryGetProperty("body", out var body)) mutation.Content = JsonContent.Create(body);
                using var response = await actor.SendAsync(mutation, ct);
                var expect = testCase.GetProperty("expect");
                Assert.Equal(expect.GetProperty("status").GetInt32(), (int)response.StatusCode);
                if (expect.GetProperty("revoked").GetBoolean())
                {
                    await AssertPolicyCloseAsync(messages, ct);
                    await AssertPolicyCloseAsync(events, ct);
                    await AssertTicketRefusedAsync(server, messagesTicket, ct);
                    await AssertTicketRefusedAsync(server, eventsTicket, ct);
                }
                else
                {
                    await AssertManagementSocketAliveAsync(server, messages, "client-messages", tenant, username, ct);
                    await AssertManagementSocketAliveAsync(server, events, "connections", tenant, username, ct);
                    using var extraMessages = await server.Server.CreateWebSocketClient().ConnectAsync(messagesTicket, ct);
                    Assert.Contains("hello", await ReceiveTextAsync(extraMessages, ct), StringComparison.Ordinal);
                    using var extraEvents = await server.Server.CreateWebSocketClient().ConnectAsync(eventsTicket, ct);
                    await AssertManagementSocketAliveAsync(server, extraEvents, "connections", tenant, username, ct);
                }
            }
            foreach (var bystander in bystanders)
            {
                await AssertManagementSocketAliveAsync(server, bystander.Socket, bystander.Endpoint,
                    bystander.Tenant, bystander.Username, ct);
                using var extra = await server.Server.CreateWebSocketClient().ConnectAsync(bystander.Ticket, ct);
                if (bystander.Endpoint == "client-messages") await ReceiveTextAsync(extra, ct);
                await AssertManagementSocketAliveAsync(server, extra, bystander.Endpoint, bystander.Tenant, bystander.Username, ct);
            }
        }
        finally { foreach (var bystander in bystanders) bystander.Socket.Dispose(); }
    }

    [Theory]
    [InlineData("connections", "disabled")]
    [InlineData("connections", "role-changed")]
    [InlineData("connections", "recreated")]
    [InlineData("connections", "unchanged")]
    [InlineData("client-messages", "disabled")]
    [InlineData("client-messages", "role-changed")]
    [InlineData("client-messages", "recreated")]
    [InlineData("client-messages", "unchanged")]
    public async Task TicketWhoseAccountChangedIsRefusedAtHandshake(string endpoint, string change)
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAsync(server, "original-key", "stale-ticket", "default", ManagementRole.User);
        using var client = Bearer(server, Sign(new Dictionary<string, string>
        { ["sub"] = "stale-ticket", ["tenant_id"] = "default", ["role"] = "USER", ["uid"] = "original-key" }));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var ct = timeout.Token;
        var address = await IssueManagementTicketAsync(client, endpoint, ct);
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ManagementUsers.SingleAsync(user => user.Username == "original-key", ct);
            switch (change)
            {
                case "disabled": account.Enabled = false; break;
                case "role-changed": account.Role = ManagementRole.Admin; break;
                case "recreated":
                    db.ManagementUsers.Remove(account);
                    await db.SaveChangesAsync(ct);
                    db.ChangeTracker.Clear();
                    account.Username = "replacement-key";
                    db.ManagementUsers.Add(account);
                    break;
            }
            await db.SaveChangesAsync(ct);
        }
        if (change == "unchanged")
        {
            using var socket = await server.Server.CreateWebSocketClient().ConnectAsync(address, ct);
            if (endpoint == "client-messages") await ReceiveTextAsync(socket, ct);
            await AssertManagementSocketAliveAsync(server, socket, endpoint, "default", "stale-ticket", ct);
        }
        else
        {
            await AssertTicketRefusedAsync(server, address, ct);
            // A refused identity check still consumes the one-time ticket.
            await using var scope = server.HostServices.CreateAsyncScope();
            Assert.Empty(await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().WebSocketTickets.ToListAsync(ct));
        }
    }

    [Fact]
    public async Task ManagementRevocationClosesBothHubsOnAnotherRedisInstance()
    {
        var redis = Environment.GetEnvironmentVariable("SPECUS_TEST_REDIS_URI");
        if (string.IsNullOrWhiteSpace(redis)) return;
        var sharedDatabase = Path.Combine(Path.GetTempPath(), $"specus-revocation-{Guid.NewGuid():N}.db");
        try
        {
            var settings = new Dictionary<string, string?>
            {
                ["Specus:PublicTransfer:ClusterEnabled"] = "true",
                ["Specus:PublicTransfer:RedisUri"] = redis,
                ["Specus:PublicTransfer:RedisKeyPrefix"] = "specus:test:revocation:" + Guid.NewGuid().ToString("N"),
                ["ConnectionStrings:Specus"] = "Data Source=" + sharedDatabase,
            };
            await using var first = await TestServerFixture.StartAsync(settings);
            await using var second = await TestServerFixture.StartAsync(settings);
            await SeedAsync(first, "cluster-account", "cluster-user", "default", ManagementRole.User);
            await SeedAsync(first, "other-account", "cluster-user", "other-tenant", ManagementRole.User);
            using var anonymous = first.CreateClient();
            using var admin = Bearer(first, await LoginAsync(anonymous, "admin", "admin", null));
            using var target = Bearer(second, Sign(new Dictionary<string, string>
            { ["sub"] = "cluster-user", ["tenant_id"] = "default", ["role"] = "USER", ["uid"] = "cluster-account" }));
            using var other = Bearer(second, Sign(new Dictionary<string, string>
            { ["sub"] = "cluster-user", ["tenant_id"] = "other-tenant", ["role"] = "USER", ["uid"] = "other-account" }));
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var ct = timeout.Token;
            using var events = await ConnectManagementSocketAsync(second, target, "connections", ct);
            using var messages = await ConnectManagementSocketAsync(second, target, "client-messages", ct);
            await ReceiveTextAsync(messages, ct);
            using var otherEvents = await ConnectManagementSocketAsync(second, other, "connections", ct);
            using var otherMessages = await ConnectManagementSocketAsync(second, other, "client-messages", ct);
            await ReceiveTextAsync(otherMessages, ct);
            await AssertManagementSocketAliveAsync(second, events, "connections", "default", "cluster-user", ct);
            await AssertManagementSocketAliveAsync(second, otherEvents, "connections", "other-tenant", "cluster-user", ct);
            var unused = await IssueManagementTicketAsync(target, "connections", ct);
            using var response = await admin.PutAsJsonAsync("/api/admin/users/cluster-user", new { enabled = false }, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            await AssertPolicyCloseAsync(events, ct);
            await AssertPolicyCloseAsync(messages, ct);
            await AssertTicketRefusedAsync(second, unused, ct);
            await AssertManagementSocketAliveAsync(second, otherEvents, "connections", "other-tenant", "cluster-user", ct);
            await AssertManagementSocketAliveAsync(second, otherMessages, "client-messages", "other-tenant", "cluster-user", ct);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            File.Delete(sharedDatabase);
        }
    }

    [Theory]
    [InlineData("connections")]
    [InlineData("client-messages")]
    public async Task RevocationBetweenHandshakeCheckAndRegistrationClosesTheSocket(string endpoint)
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAsync(server, "racing-account", "racing-user", "default", ManagementRole.User);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var context = new DefaultHttpContext { RequestAborted = timeout.Token };
        context.Connection.RemoteIpAddress = IPAddress.Loopback;
        var ticket = await server.HostServices.GetRequiredService<WebSocketTicketService>().IssueAsync(
            endpoint, "127.0.0.1", new WebSocketTicketClaims("racing-user", "default", AccountKey: "racing-account"),
            timeout.Token);
        context.Request.QueryString = new QueryString("?ticket=" + ticket.Ticket);
        using var socket = new RegistrationRaceSocket();
        var feature = new RegistrationRaceFeature(socket, async () =>
        {
            // Acceptance runs after the first authoritative check, but before hub registration.
            await using var scope = server.HostServices.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().ManagementUsers
                .Where(user => user.Username == "racing-account")
                .ExecuteUpdateAsync(setters => setters.SetProperty(user => user.Enabled, false), timeout.Token);
            // The notification deliberately completes before the new subscription exists.
            await server.HostServices.GetRequiredService<ManagementAccessRevocations>()
                .CommittedAsync("default", "racing-user", ManagementAccessRevocations.Disabled);
        });
        context.Features.Set<IHttpWebSocketFeature>(feature);
        if (endpoint == "connections")
            await server.HostServices.GetRequiredService<ConnectionEventsHub>().AcceptAsync(context);
        else
            await server.HostServices.GetRequiredService<ClientMessagesHub>().AcceptAsync(context);
        Assert.True(feature.Accepted);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, socket.CloseStatus);
        Assert.Equal("identity revoked", socket.CloseStatusDescription);
        Assert.Equal(0, socket.DataFrames);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TicketDeletionFailureRollsBackAccountMutationWithoutClosingSessions(bool delete)
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAsync(server, "rollback-account", "rollback-user", "default", ManagementRole.User);
        using var client = Bearer(server, Sign(new Dictionary<string, string>
        { ["sub"] = "rollback-user", ["tenant_id"] = "default", ["role"] = "USER", ["uid"] = "rollback-account" }));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var ct = timeout.Token;
        using var messages = await ConnectManagementSocketAsync(server, client, "client-messages", ct);
        await ReceiveTextAsync(messages, ct);
        using var events = await ConnectManagementSocketAsync(server, client, "connections", ct);
        await AssertManagementSocketAliveAsync(server, events, "connections", "default", "rollback-user", ct);
        var messageTicket = await IssueManagementTicketAsync(client, "client-messages", ct);
        var eventTicket = await IssueManagementTicketAsync(client, "connections", ct);
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            await db.Database.ExecuteSqlRawAsync("""
                CREATE TRIGGER fail_ticket_revocation BEFORE DELETE ON specus_websocket_ticket
                BEGIN SELECT RAISE(ABORT, 'forced ticket revocation failure'); END;
                """, ct);
            var users = scope.ServiceProvider.GetRequiredService<ManagementUserService>();
            var admin = new ManagementContext("default", "admin", ManagementRole.Admin, true);
            var error = await Assert.ThrowsAsync<Microsoft.Data.Sqlite.SqliteException>(async () =>
            {
                if (delete) await users.DeleteUserAsync(admin, "rollback-user", ct);
                else await users.UpdateUserAsync(admin, "rollback-user",
                    JsonSerializer.Deserialize<UserMutation>("{\"enabled\":false}", JsonOptions)!, ct);
            });
            Assert.Contains("forced ticket revocation failure", error.Message, StringComparison.Ordinal);
            await db.Database.ExecuteSqlRawAsync("DROP TRIGGER fail_ticket_revocation", ct);
        }
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            Assert.True((await db.ManagementUsers.SingleAsync(user => user.Username == "rollback-account", ct)).Enabled);
            Assert.Equal(2, await db.WebSocketTickets.CountAsync(ct));
        }
        await AssertManagementSocketAliveAsync(server, messages, "client-messages", "default", "rollback-user", ct);
        await AssertManagementSocketAliveAsync(server, events, "connections", "default", "rollback-user", ct);
        using var extraMessages = await server.Server.CreateWebSocketClient().ConnectAsync(messageTicket, ct);
        Assert.Contains("hello", await ReceiveTextAsync(extraMessages, ct), StringComparison.Ordinal);
        using var extraEvents = await server.Server.CreateWebSocketClient().ConnectAsync(eventTicket, ct);
        await AssertManagementSocketAliveAsync(server, extraEvents, "connections", "default", "rollback-user", ct);
    }

    private sealed class RegistrationRaceFeature(WebSocket socket, Func<Task> beforeRegistration) : IHttpWebSocketFeature
    {
        public bool IsWebSocketRequest => true;
        public bool Accepted { get; private set; }
        public async Task<WebSocket> AcceptAsync(WebSocketAcceptContext context)
        {
            Accepted = true;
            await beforeRegistration();
            return socket;
        }
    }

    private sealed class RegistrationRaceSocket : WebSocket
    {
        private WebSocketState _state = WebSocketState.Open;
        private WebSocketCloseStatus? _closeStatus;
        private string? _closeDescription;
        public int DataFrames { get; private set; }
        public override WebSocketState State => _state;
        public override WebSocketCloseStatus? CloseStatus => _closeStatus;
        public override string? CloseStatusDescription => _closeDescription;
        public override string? SubProtocol => null;
        public override void Abort() => _state = WebSocketState.Aborted;
        public override void Dispose() => _state = WebSocketState.Closed;
        public override Task CloseAsync(WebSocketCloseStatus status, string? description, CancellationToken ct) =>
            CloseOutputAsync(status, description, ct);
        public override Task CloseOutputAsync(WebSocketCloseStatus status, string? description, CancellationToken ct)
        {
            _closeStatus = status;
            _closeDescription = description;
            _state = WebSocketState.CloseSent;
            return Task.CompletedTask;
        }
        public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType type, bool end, CancellationToken ct)
        {
            DataFrames++;
            throw new InvalidOperationException("revoked subscription must not send application data");
        }
        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken ct) =>
            throw new InvalidOperationException("revoked subscription must not enter the receive loop");
    }

    private static async Task<Uri> IssueManagementTicketAsync(HttpClient client, string endpoint, CancellationToken ct)
    {
        using var response = await client.PostAsJsonAsync("/api/admin/ws-tickets", new { endpoint }, ct);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        return new Uri($"ws://localhost/ws/{endpoint}?ticket=" + Uri.EscapeDataString(document.RootElement.GetProperty("ticket").GetString()!));
    }

    private static async Task AssertTicketRefusedAsync(TestServerFixture server, Uri address, CancellationToken ct)
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => server.Server.CreateWebSocketClient().ConnectAsync(address, ct));
        Assert.Contains("403", error.Message, StringComparison.Ordinal);
    }

    private static async Task AssertPolicyCloseAsync(WebSocket socket, CancellationToken ct)
    {
        var buffer = new byte[16384];
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, ct);
            if (result.MessageType != WebSocketMessageType.Close) continue;
            Assert.Equal(WebSocketCloseStatus.PolicyViolation, result.CloseStatus);
            return;
        }
    }

    // Send an actual authorized event/message and read it back, proving registration and liveness.
    // Temporary client rows are removed before the mutation so account deletion is not blocked.
    private static async Task AssertManagementSocketAliveAsync(TestServerFixture server, WebSocket socket,
        string endpoint, string tenant, string username, CancellationToken ct)
    {
        var marker = "revocation-probe-" + Guid.NewGuid().ToString("N");
        if (endpoint == "client-messages")
        {
            Assert.True(await server.HostServices.GetRequiredService<ClientMessagesHub>().DeliverFromClientAsync(
                new ClientAccount { TenantId = tenant, ClientName = marker }, "admin:" + username, marker, ct));
            while (!(await ReceiveTextAsync(socket, ct)).Contains(marker, StringComparison.Ordinal)) { }
            return;
        }
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var id = ClientIdGenerator.NewId();
        db.ClientAccounts.Add(new ClientAccount { Id = id, TenantId = tenant, OwnerUsername = username,
            ClientName = marker, CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow });
        await db.SaveChangesAsync(ct);
        try
        {
            var read = ReceiveTextAsync(socket, ct);
            var hub = server.HostServices.GetRequiredService<ConnectionEventsHub>();
            do
            {
                await hub.BroadcastAsync(new ConnectionEvent(tenant, "created", new ConnectionRecordView(
                    id, id, marker, marker, "127.0.0.1", DateTimeOffset.UtcNow.ToString("O"), null, true, null, null, null)));
                await Task.WhenAny(read, Task.Delay(20, ct));
                ct.ThrowIfCancellationRequested();
            } while (!read.IsCompleted);
            while (!(await read).Contains(marker, StringComparison.Ordinal)) read = ReceiveTextAsync(socket, ct);
        }
        finally { await db.ClientAccounts.Where(client => client.Id == id).ExecuteDeleteAsync(ct); }
    }
}
