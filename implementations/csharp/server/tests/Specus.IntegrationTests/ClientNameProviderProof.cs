using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

internal static class ClientNameProviderProof
{
    private const string Secret = "native-client-name-fixture";

    internal static async Task VerifyAsync(TestServerFixture server, PeerDefinitionProviderProof.CommitGate gate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        await using var writerScope = server.HostServices.CreateAsyncScope();
        await using var loginScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var services = writerScope.ServiceProvider;
        var writer = services.GetRequiredService<SpecusDbContext>();
        var loginDb = loginScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await OwnerTransferWriterProof.SeedAsync(writer, "default");
        var credential = await writer.ClientCredentials.SingleAsync(ct);
        credential.Enabled = true; credential.SecretHash = Hash(Secret); credential.MaxOnlineInstances = 7;
        var identity = await writer.ClientIdentities.SingleAsync(i => i.Id == 701, ct);
        // Repair a legacy stale label using the actual signed HTTP endpoint first.
        identity.ClientName = "stale-name";
        writer.SpecusMappings.Add(new SpecusMapping { Id = 4201, TenantId = null, ClientId = 1001, ClientName = "laptop", ListenPort = 24861, TargetAddress = "127.0.0.1", TargetPort = 80 });
        writer.HttpRouteMappings.Add(new HttpRouteMapping { Id = 4301, TenantId = null, ClientId = 1001, ClientName = "laptop", Route = "name-proof", TargetBaseUrl = "http://127.0.0.1:8000" });
        writer.PeerMeshAcls.Add(new PeerMeshAcl { Id = 4801, TenantId = "default", SourceClientId = 1001, SourceClientName = "laptop", TargetClientId = 1002, TargetClientName = "offline" });
        writer.PeerMeshSharedServices.Add(new PeerMeshSharedService { Id = 4901, TenantId = "default", ClientId = 1001, ClientName = "laptop", ServiceId = "native-name", Name = "native-name", TargetPort = 8080, PublishedPort = 18080 });
        writer.PeerMeshEgressPolicies.Add(new PeerMeshEgressPolicy { Id = 4951, TenantId = "default", EgressClientId = 1001, EgressClientName = "laptop" });
        writer.TrafficUsages.Add(new TrafficUsage { Id = 5101, TenantId = "default", ClientId = 1001, ClientName = "laptop", UsageDate = "2026-10-01", UploadBytes = 13 });
        writer.ResourceTrafficUsages.Add(new ResourceTrafficUsage { Id = 5102, TenantId = "default", ClientId = 1001, ClientName = "laptop", ResourceType = "TCP", ResourceKey = "native-name", ResourceName = "fixture", UsageDate = "2026-10-01", DownloadBytes = 29 });
        writer.ClientIdentities.Add(new ClientIdentity { Id = 703, TenantId = "DEFAULT", ClientId = 1001, CredentialId = 501,
            ClientName = "foreign-name", MachineFingerprint = "foreign-native-machine", OsUser = "foreign-native-user" });
        await writer.SaveChangesAsync(ct);
        using var http = server.CreateClient();
        using var initialResponse = await http.PostAsJsonAsync("/api/client/auth/login", Signed(credential.ApiKey, identity.MachineFingerprint), ct);
        Assert.Equal(HttpStatusCode.OK, initialResponse.StatusCode);
        var initial = await initialResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct); Assert.NotNull(initial);
        Assert.Equal(1001, initial.ClientId); Assert.Equal("laptop", initial.ClientName);

        var actor = await OwnerTransferWriterProof.ActorAsync(server, services);
        foreach (var db in new[] { writer, loginDb, observer }) await db.Database.OpenConnectionAsync(ct);
        var postgres = writer.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var pidQuery = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        var writerPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(writer, pidQuery, ct));
        var loginPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(loginDb, pidQuery, ct));
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        var mutation = services.GetRequiredService<ManagementMutationService>();
        // Observe a real SQL waiter on the actual credential-first management transaction.
        // The concurrent caller uses the signed login service (not an HTTP transport claim).
        gate.Arm(writer);
        Task? rename = null; Task<ClientAuthLoginResponse>? login = null;
        try
        {
            rename = mutation.UpdateClientAsync(actor.Context, 1001, new ClientMutation("canonical-native-name", null, null), ct);
            await Task.WhenAny(rename, gate.Entered).WaitAsync(ct);
            if (!gate.Entered.IsCompleted) { await rename; throw new InvalidOperationException("rename did not reach commit gate"); }
            await gate.Entered;
            login = loginScope.ServiceProvider.GetRequiredService<ClientAccountService>().LoginAsync(Signed(credential.ApiKey, identity.MachineFingerprint), "localhost", ct);
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, loginPid, writerPid, postgres, maria, login, ct);
            Assert.Equal("laptop", (await observer.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001, ct)).ClientName);
            gate.Release(); await rename;
            var result = await login;
            Assert.Equal(1001, result.ClientId); Assert.Equal("canonical-native-name", result.ClientName);
        }
        finally
        {
            gate.Release();
            if (rename is not null) try { await rename; } catch (Exception) { }
            if (login is not null) try { await login; } catch (Exception) { }
        }
        Assert.Equal("canonical-native-name", (await observer.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 701, ct)).ClientName);
        Assert.Equal("canonical-native-name", (await observer.PeerMeshDevices.AsNoTracking().SingleAsync(ct)).ClientName);
        Assert.Equal("canonical-native-name", (await observer.SpecusMappings.AsNoTracking().SingleAsync(ct)).ClientName);
        Assert.Equal("canonical-native-name", (await observer.HttpRouteMappings.AsNoTracking().SingleAsync(ct)).ClientName);
        Assert.Equal("canonical-native-name", (await observer.PeerMeshAcls.AsNoTracking().SingleAsync(ct)).SourceClientName);
        Assert.Equal("canonical-native-name", (await observer.PeerMeshSharedServices.AsNoTracking().SingleAsync(ct)).ClientName);
        Assert.Equal("canonical-native-name", (await observer.PeerMeshEgressPolicies.AsNoTracking().SingleAsync(ct)).EgressClientName);
        Assert.Equal("canonical-native-name", (await observer.TrafficUsages.AsNoTracking().SingleAsync(ct)).ClientName);
        Assert.Equal("canonical-native-name", (await observer.ResourceTrafficUsages.AsNoTracking().SingleAsync(ct)).ClientName);
        Assert.Equal("laptop", (await observer.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == initial.ClientSessionId, ct)).ClientName);
        Assert.Equal("foreign-name", (await observer.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 703, ct)).ClientName);
        await mutation.DeleteClientAsync(actor.Context, 1001, ct);
        Assert.False(await observer.ClientIdentities.AsNoTracking().AnyAsync(i => i.Id == 701, ct));
        Assert.True(await observer.ClientIdentities.AsNoTracking().AnyAsync(i => i.Id == 702, ct));
        Assert.Equal("foreign-name", (await observer.ClientIdentities.AsNoTracking().SingleAsync(i => i.Id == 703, ct)).ClientName);
        using var freshResponse = await http.PostAsJsonAsync("/api/client/auth/login", Signed(credential.ApiKey, identity.MachineFingerprint), ct);
        Assert.Equal(HttpStatusCode.OK, freshResponse.StatusCode);
        var fresh = await freshResponse.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct); Assert.NotNull(fresh);
        Assert.NotEqual(1001, fresh.ClientId);
        var authentication = await observerScope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(
            new LoginRequestPacket { ClientSessionId = initial.ClientSessionId, AccessToken = initial.AccessToken, ClientName = fresh.ClientName }, "deleted-native-token", "127.0.0.1", ct);
        Assert.False(authentication.Success);
        Assert.True(await observer.ClientSessions.AnyAsync(s => s.Id == initial.ClientSessionId && s.ClientId == 1001, ct));
        Assert.Equal(13, (await observer.TrafficUsages.AsNoTracking().SingleAsync(ct)).UploadBytes);
        Assert.Equal(29, (await observer.ResourceTrafficUsages.AsNoTracking().SingleAsync(ct)).DownloadBytes);
    }

    private static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    private static ClientAuthLoginRequest Signed(string api, string machine)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Guid.NewGuid().ToString("N"); const string user = "retained-user";
        var signature = Convert.ToHexString(HMACSHA256.HashData(Convert.FromHexString(Hash(Secret)),
            Encoding.UTF8.GetBytes(string.Join('\n', api, timestamp, nonce, machine, user)))).ToLowerInvariant();
        return new ClientAuthLoginRequest { ApiKey = api, Timestamp = timestamp, Nonce = nonce, Signature = signature,
            Environment = new ClientEnvironmentInfo { MachineFingerprint = machine, OsUser = user, Hostname = "native-name-fixture" } };
    }
}
