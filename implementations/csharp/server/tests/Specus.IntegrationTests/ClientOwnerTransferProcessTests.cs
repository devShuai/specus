using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Xunit.Abstractions;

namespace Specus.IntegrationTests;

public sealed class ClientOwnerTransferProcessTests(ITestOutputHelper output)
{
    private const string MemberPassword = "process-fixture-member-password";
    private const string Secret = "process-fixture-retained-secret";

    [Fact(Timeout = 90_000)]
    public async Task TwoActualProcessesTransferAcrossInstancesRetainWireAccessAndReplayAfterRestart()
    {
        await using var runtime = new OwnerTransferProcessFixture(output);
        var first = await runtime.StartAsync("node-a");
        var second = await runtime.StartAsync("node-b");
        Assert.NotEqual(first.Process.Id, second.Process.Id);
        Assert.NotEqual(Environment.ProcessId, first.Process.Id);
        var options = new DbContextOptionsBuilder<SpecusDbContext>().UseSqlite(runtime.ConnectionString).Options;
        await using var db = new SpecusDbContext(options);
        await OwnerTransferWriterProof.SeedAsync(db, "default");
        var bob = await db.ManagementUsers.SingleAsync();
        bob.PasswordHash = PasswordHasher.Hash(MemberPassword);
        db.ManagementUsers.Add(new ManagementUser { Username = "alice-key", LoginName = "alice", TenantId = "default",
            PasswordHash = PasswordHasher.Hash(MemberPassword), Enabled = true });
        var credential = await db.ClientCredentials.SingleAsync();
        credential.Enabled = true; credential.SecretHash = ClientStartupOwnershipTests.Hash(Secret); credential.MaxOnlineInstances = 8;
        (await db.ClientSessions.SingleAsync()).ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        db.ClientAccounts.Add(new ClientAccount { Id = 1004, TenantId = "default", ClientName = "process-legacy",
            OwnerUsername = "alice", Enabled = false });
        db.ClientCredentials.Add(new ClientCredential { Id = 502, TenantId = "default", ApiKey = "process-empty",
            OwnerUsername = "alice", SecretHash = "empty-retained-hash", Enabled = false });
        await db.SaveChangesAsync();
        var originalCredential = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        await AdminAsync(first.Http); await AdminAsync(second.Http);
        using var alice = Member(first.Http.BaseAddress!, await LoginAsync(first.Http, "alice", MemberPassword));
        using var target = Member(second.Http.BaseAddress!, await LoginAsync(second.Http, "bob", MemberPassword));
        using var refusedDelete = await first.Http.DeleteAsync("/api/admin/users/alice");
        Assert.Equal(HttpStatusCode.Conflict, refusedDelete.StatusCode);
        // Existing runtime tokens are process-local: issue on the same node as
        // CONTROL/DATA. The cross-instance contract here is A preview/B commit,
        // current authorization and journal replay, not new token portability.
        var access = await ClientLoginAsync(second.Http, "retained-machine1");
        Assert.Equal(1001, access.ClientId);
        using var control = await ConnectAsync(second.ControlPort, access, ConnectionRole.Control);
        using var data = await ConnectAsync(second.ControlPort, access, ConnectionRole.Data);
        await HeartbeatAsync(control); await HeartbeatAsync(data);
        using var conflict = await second.Http.PostAsJsonAsync("/api/admin/clients/1001/owner-transfer", new { scope = "single" });
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Equal("CREDENTIAL_SHARED", (await conflict.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("code").GetString());

        foreach (var (resource, scope, ids) in new[] {
            ("client-credentials/501", "credential-group", new long[] {1001,1002}),
            ("clients/1004", "single", new long[] {1004}),
            ("client-credentials/502", "credential-group", Array.Empty<long>()) })
        {
            var path = "/api/admin/" + resource + "/owner-transfer";
            var preview = await first.Http.GetFromJsonAsync<ClientOwnerTransferPreview>(path);
            Assert.NotNull(preview?.Revision);
            using var response = await second.Http.PostAsJsonAsync(path,
                new { scope, targetUsername = " BoB ", expectedRevision = preview.Revision });
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.True(result.GetProperty("accessRetained").GetBoolean());
            Assert.Equal("bob", result.GetProperty("targetUsername").GetString());
            Assert.Equal(ids, result.GetProperty("affectedClientIds").EnumerateArray().Select(v => v.GetInt64()).ToArray());
        }
        await WaitForReceiptsAsync(db, 2, 3);
        await HeartbeatAsync(control); await HeartbeatAsync(data); // Same physical channels, no login/reconnect.
        Assert.Equal("NETTY_ONLINE", (await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == access.ClientSessionId)).Status);
        var after = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 501);
        Assert.Equal(originalCredential.ApiKey, after.ApiKey); Assert.Equal(originalCredential.SecretHash, after.SecretHash);
        Assert.Equal(originalCredential.Enabled, after.Enabled);
        Assert.False((await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1002)).Enabled);
        Assert.False((await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1004)).Enabled);
        Assert.False((await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 502)).Enabled);
        using var oldScope = await alice.GetAsync("/api/admin/clients/1001");
        // Ordinary client details retain the existing ArgumentException -> 400
        // convention; ownership preview/write paths separately guarantee 404.
        Assert.Equal(HttpStatusCode.BadRequest, oldScope.StatusCode);
        Assert.Empty((await alice.GetFromJsonAsync<JsonElement>("/api/admin/clients")).EnumerateArray());
        using var newScope = await target.GetAsync("/api/admin/clients/1001");
        Assert.Equal(HttpStatusCode.OK, newScope.StatusCode);

        const string groupPath = "/api/admin/client-credentials/501/owner-transfer";
        var fresh = (await first.Http.GetFromJsonAsync<ClientOwnerTransferPreview>(groupPath))!;
        using var noop = await second.Http.PostAsJsonAsync(groupPath,
            new { scope = "credential-group", targetUsername = "bob", expectedRevision = fresh.Revision });
        Assert.Equal(HttpStatusCode.OK, noop.StatusCode);
        Assert.False((await noop.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("changed").GetBoolean());
        Assert.Equal(3, await db.ClientOwnerTransferAudits.CountAsync());
        using var deletedOwner = await first.Http.DeleteAsync("/api/admin/users/alice");
        Assert.True(deletedOwner.StatusCode is HttpStatusCode.OK or HttpStatusCode.NoContent);
        var newDevice = await ClientLoginAsync(second.Http, "process-new-device-after-transfer");
        Assert.NotEqual(access.ClientId, newDevice.ClientId);
        Assert.Equal("bob", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == newDevice.ClientId)).OwnerUsername);
        // The original pre-transfer token can still authenticate another DATA connection.
        await HeartbeatAsync(data);
        using var replacementData = await ConnectAsync(second.ControlPort, access, ConnectionRole.Data);
        await HeartbeatAsync(replacementData); await HeartbeatAsync(control);

        await first.StopAsync(); // Deliberate owned-process termination, not a graceful-shutdown assertion.
        var restarted = await runtime.StartAsync("node-a-restarted");
        await AdminAsync(restarted.Http);
        await WaitForReceiptsAsync(db, 3, 3);
        await HeartbeatAsync(control); await HeartbeatAsync(replacementData);
        Assert.Equal(3, await db.ClientOwnerTransferAudits.CountAsync());
        output.WriteLine("PASS actual two processes + restart: three public cross-node transfers, 9 receipts/3 incarnations, original CONTROL/DATA/token/secret retained, current REST scopes, disabled resources preserved, account delete 409 then success");
    }

    private static HttpClient Member(Uri baseAddress, string token)
    {
        var client = new HttpClient { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(10) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token); return client;
    }
    private static async Task AdminAsync(HttpClient client) => client.DefaultRequestHeaders.Authorization =
        new AuthenticationHeaderValue("Bearer", await LoginAsync(client, "process-admin", "process-fixture-admin-password"));
    private static async Task<string> LoginAsync(HttpClient client, string user, string password)
    {
        using var response = await client.PostAsJsonAsync("/auth/login", new AdminLoginRequest(user, password));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("accessToken").GetString()!;
    }
    private static async Task<ClientAuthLoginResponse> ClientLoginAsync(HttpClient client, string machine)
    {
        using var response = await client.PostAsJsonAsync("/api/client/auth/login",
            ClientStartupOwnershipTests.Signed("retained-api", Secret, Guid.NewGuid().ToString("N"), machine, "retained-user"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>())!;
    }
    private static async Task WaitForReceiptsAsync(SpecusDbContext db, int nodes, int events)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (await db.ClientOwnerTransferReceipts.CountAsync(timeout.Token) != nodes * events)
            await Task.Delay(20, timeout.Token);
        Assert.Equal(nodes, await db.ClientOwnerTransferReceipts.Select(r => r.NodeId).Distinct().CountAsync(timeout.Token));
        Assert.Equal(events, await db.ClientOwnerTransferAudits.CountAsync(timeout.Token));
    }
    private static async Task<TcpClient> ConnectAsync(int port, ClientAuthLoginResponse access, string role)
    {
        var client = new TcpClient { NoDelay = true };
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
            await client.GetStream().WriteAsync(PacketCodec.Encode(new LoginRequestPacket { ClientName = access.ClientName,
                ClientSessionId = access.ClientSessionId, AccessToken = access.AccessToken, ConnectionRole = role }), timeout.Token);
            var response = Assert.IsType<LoginResponsePacket>(await ReadAsync(client, timeout.Token));
            Assert.True(response.Success, response.Reason); return client;
        }
        catch { client.Dispose(); throw; }
    }
    private static async Task HeartbeatAsync(TcpClient client)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await client.GetStream().WriteAsync(PacketCodec.Encode(new HeartbeatRequestPacket()), timeout.Token);
        while (await ReadAsync(client, timeout.Token) is not HeartbeatResponsePacket) timeout.Token.ThrowIfCancellationRequested();
    }
    private static async Task<Packet> ReadAsync(TcpClient client, CancellationToken ct)
    {
        var header = new byte[PacketCodec.HeaderSize]; await client.GetStream().ReadExactlyAsync(header, ct);
        var (_, length) = PacketCodec.DecodeHeader(header); Assert.InRange(length, 0, PacketCodec.MaxFrameSize);
        var frame = new byte[PacketCodec.HeaderSize + length]; header.CopyTo(frame, 0);
        await client.GetStream().ReadExactlyAsync(frame.AsMemory(PacketCodec.HeaderSize), ct);
        return PacketCodec.DecodeExact(frame);
    }
}
