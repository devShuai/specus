using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

// Two independent hosts/caches and real database connections, not a claim of separate OS
// processes. The existing native waiter observer retains its original ten-second deadline.
internal static class ClientSessionAuthorityProviderProof
{
    private const string Secret = "native-session-authority-fixture";

    internal static async Task VerifyAsync(TestServerFixture firstHost, TestServerFixture secondHost, PeerDefinitionProviderProof.CommitGate gate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        await using var firstScope = firstHost.HostServices.CreateAsyncScope();
        await using var secondScope = secondHost.HostServices.CreateAsyncScope();
        await using var observerScope = firstHost.HostServices.CreateAsyncScope();
        var firstDb = firstScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var secondDb = secondScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(firstDb, "default");
        var credential = await firstDb.ClientCredentials.SingleAsync(ct);
        credential.Enabled = true; credential.SecretHash = Hash(Secret); credential.MaxOnlineInstances = 1;
        (await firstDb.ClientAccounts.SingleAsync(c => c.Id == 1002, ct)).Enabled = true;
        var historicalSeed = await firstDb.ClientSessions.SingleAsync(s => s.Id == 901, ct);
        historicalSeed.ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        await firstDb.SaveChangesAsync(ct);
        var machine1 = (await firstDb.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701, ct)).MachineFingerprint;
        var machine2 = (await firstDb.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 702, ct)).MachineFingerprint;
        using var firstHttp = firstHost.CreateClient(); using var secondHttp = secondHost.CreateClient();
        async Task<ClientAuthLoginResponse> LoginAsync(HttpClient http, string machine)
        {
            using var response = await http.PostAsJsonAsync("/api/client/auth/login", Signed(credential.ApiKey, machine), ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return (await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct))!;
        }
        var firstLogin = await LoginAsync(firstHttp, machine1);
        var otherClient = await LoginAsync(secondHttp, machine2);
        var remoteCachedOldClient = await LoginAsync(secondHttp, machine1);
        var firstStore = firstHost.HostServices.GetRequiredService<ClientAuthSessionStore>();
        var secondStore = secondHost.HostServices.GetRequiredService<ClientAuthSessionStore>();
        Assert.NotSame(firstStore, secondStore);
        foreach (var db in new[] { firstDb, secondDb, observer }) await db.Database.OpenConnectionAsync(ct);
        var postgres = firstDb.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var query = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        var firstPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(firstDb, query, ct));
        var secondPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(secondDb, query, ct));
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        var firstService = firstScope.ServiceProvider.GetRequiredService<ClientAccountService>();
        var secondService = secondScope.ServiceProvider.GetRequiredService<ClientAccountService>();
        Task<AuthenticationResult>? first = null; Task<AuthenticationResult>? second = null;
        gate.Arm(firstDb);
        try
        {
            first = firstService.AuthenticateAsync(Packet(firstLogin), "first-host-control", "127.0.0.1", ct);
            await Task.WhenAny(first, gate.Entered).WaitAsync(ct);
            if (!gate.Entered.IsCompleted) { await first; throw new InvalidOperationException("actual control admission did not reach commit gate"); }
            await gate.Entered;
            second = secondService.AuthenticateAsync(Packet(otherClient), "second-host-control", "127.0.0.1", ct);
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, secondPid, firstPid, postgres, maria, second, ct);
            Assert.Equal(0, firstStore.CountOnlineByCredential(501));
            Assert.Equal(0, secondStore.CountOnlineByCredential(501));
            gate.Release();
            Assert.True((await first).Success);
            var denied = await second; Assert.False(denied.Success); Assert.Equal("在线实例数已达上限", denied.Reason);
        }
        finally
        {
            gate.Release();
            if (first is not null) try { await first; } catch (Exception) { }
            if (second is not null) try { await second; } catch (Exception) { }
        }
        Assert.True((await firstService.AuthenticateDataAsync(Packet(firstLogin), "current-data", "127.0.0.1", ct)).Success);
        // A cached token alone cannot authorize a tampered persisted session on a native DB.
        var row = await observer.ClientSessions.SingleAsync(s => s.Id == firstLogin.ClientSessionId, ct);
        var originalHash = row.TokenHash; row.TokenHash = "changed-native-token-hash"; await observer.SaveChangesAsync(ct);
        Assert.False((await firstService.AuthenticateDataAsync(Packet(firstLogin), "stale-data", "127.0.0.1", ct)).Success);
        row.TokenHash = originalHash; await observer.SaveChangesAsync(ct);
        var actor = await OwnerTransferWriterProof.ActorAsync(firstHost, firstScope.ServiceProvider);
        await firstScope.ServiceProvider.GetRequiredService<ManagementMutationService>().DeleteClientAsync(actor.Context, 1001, ct);
        Assert.Null(firstStore.Find(firstLogin.ClientSessionId, firstLogin.AccessToken));
        Assert.Equal(0, firstStore.CountOnlineByCredential(501));
        // This host did not receive local cache eviction. Current SQL authority must reject
        // its still-cached old token, rather than relying on a shared singleton or callback.
        Assert.NotNull(secondStore.Find(remoteCachedOldClient.ClientSessionId, remoteCachedOldClient.AccessToken));
        Assert.False((await secondService.AuthenticateAsync(Packet(remoteCachedOldClient), "remote-old-token", "127.0.0.1", ct)).Success);
        Assert.True((await secondService.AuthenticateAsync(Packet(otherClient), "second-after-deletion", "127.0.0.1", ct)).Success);
        var historical = await observer.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == firstLogin.ClientSessionId, ct);
        Assert.Equal("laptop", historical.ClientName); Assert.True(historical.ExpiresAt <= DateTimeOffset.UtcNow);
        var remoteHistory = await observer.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == remoteCachedOldClient.ClientSessionId, ct);
        Assert.Equal(1001, remoteHistory.ClientId); Assert.True(remoteHistory.ExpiresAt <= DateTimeOffset.UtcNow);
        var fresh = await LoginAsync(secondHttp, machine1); Assert.NotEqual(1001, fresh.ClientId);
        Assert.Equal(Hash(Secret), (await observer.ClientCredentials.AsNoTracking().SingleAsync(ct)).SecretHash);
    }

    private static LoginRequestPacket Packet(ClientAuthLoginResponse login) => new()
    { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken, ClientName = "untrusted-supplied-name" };
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static ClientAuthLoginRequest Signed(string api, string machine)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Guid.NewGuid().ToString("N"); const string user = "retained-user";
        return new ClientAuthLoginRequest { ApiKey = api, Timestamp = timestamp, Nonce = nonce,
            Signature = Convert.ToHexStringLower(HMACSHA256.HashData(Convert.FromHexString(Hash(Secret)), Encoding.UTF8.GetBytes(string.Join('\n', api, timestamp, nonce, machine, user)))),
            Environment = new ClientEnvironmentInfo { MachineFingerprint = machine, OsUser = user, Hostname = "native-session-authority" } };
    }
}
