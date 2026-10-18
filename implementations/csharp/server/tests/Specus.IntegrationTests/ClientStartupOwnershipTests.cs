using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class ClientStartupOwnershipTests
{
    [Fact]
    public async Task SignedHttpLoginDoesNotCreateOldOwnerAfterCommittedCredentialTransfer()
    {
        const string api = "ck_startup_owner", secret = "startup-fixture-secret";
        var nonce = Guid.NewGuid().ToString("N");
        var barrier = new NonceSavedBarrier(Hash(api), Hash(nonce));
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Database:SeedDemoClient"] = "false",
            ["Specus:PeerMesh:Enabled"] = "true",
            ["Specus:PeerMesh:StunTurnPort"] = "0",
            ["Specus:PeerMesh:NatProbeAlternatePort"] = "0",
        }, services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(barrier)));
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.ClientCredentials.Add(new ClientCredential { Id = 6101, TenantId = "default", OwnerUsername = "alice", ApiKey = api, SecretHash = Hash(secret), Enabled = true, MaxOnlineInstances = 7, CreatedAt = now, UpdatedAt = now });
            db.ManagementUsers.Add(new ManagementUser { Username = "startup-bob-key", LoginName = "bob", TenantId = "default", Enabled = true });
            await db.SaveChangesAsync();
        }
        using var client = server.CreateClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var pending = client.PostAsJsonAsync("/api/client/auth/login", Signed(api, secret, nonce), timeout.Token);
        try
        {
            await barrier.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await using (var scope = server.HostServices.CreateAsyncScope())
            {
                var actor = await OwnerTransferWriterProof.ActorAsync(server, scope.ServiceProvider);
                var preview = await scope.ServiceProvider.GetRequiredService<ClientOwnerTransferService>()
                    .PreviewCredentialAsync(actor.Context, "6101", timeout.Token);
                Assert.Empty(preview.AffectedClients);
                var outcome = await scope.ServiceProvider.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor,
                    PathScope.CredentialGroup, "6101", JsonSerializer.SerializeToElement(new { scope = "credential-group", targetUsername = "bob", expectedRevision = preview.Revision }), timeout.Token);
                Assert.True(outcome.Response.Changed); Assert.Empty(outcome.Response.AffectedClientIds);
            }
            barrier.Release.TrySetResult(true);
            using var response = await pending;
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(timeout.Token);
            Assert.NotNull(login);
            await using var verify = server.HostServices.CreateAsyncScope();
            var db = verify.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == login.ClientId, timeout.Token);
            Assert.Equal("bob", account.OwnerUsername);
            var peer = await db.PeerMeshDevices.AsNoTracking().SingleAsync(p => p.ClientId == account.Id, timeout.Token);
            Assert.Equal("bob", peer.OwnerUsername); Assert.False(peer.Enabled);
            var credential = await db.ClientCredentials.AsNoTracking().SingleAsync(c => c.Id == 6101, timeout.Token);
            Assert.Equal("bob", credential.OwnerUsername); Assert.Equal(Hash(secret), credential.SecretHash); Assert.True(credential.Enabled);
            Assert.Equal(7, login.MaxOnlineInstances);
            var row = await db.ClientSessions.AsNoTracking().SingleAsync(s => s.Id == login.ClientSessionId, timeout.Token);
            Assert.Equal(account.Id, row.ClientId); Assert.Equal(credential.Id, row.CredentialId);
            Assert.NotNull(verify.ServiceProvider.GetRequiredService<ClientAuthSessionStore>().Find(login.ClientSessionId, login.AccessToken));
        }
        finally
        {
            barrier.Release.TrySetResult(true);
            if (!pending.IsCompleted) { timeout.Cancel(); try { using var ignored = await pending; } catch (Exception) { } }
        }
    }

    internal static ClientAuthLoginRequest Signed(string api, string secret, string nonce, string machine = "startup-machine", string user = "startup-user")
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new ClientAuthLoginRequest
        {
            ApiKey = api, Timestamp = timestamp, Nonce = nonce,
            Signature = Convert.ToHexStringLower(HMACSHA256.HashData(SHA256.HashData(Encoding.UTF8.GetBytes(secret)), Encoding.UTF8.GetBytes(string.Join('\n', api, timestamp, nonce, machine, user)))),
            Environment = new ClientEnvironmentInfo { MachineFingerprint = machine, OsUser = user, Hostname = "startup-host", PeerPublicKey = "startup-public-key" },
        };
    }

    internal static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    internal sealed class NonceSavedBarrier(string apiHash, string nonceHash) : SaveChangesInterceptor
    {
        private int entered;
        internal TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context is { } db && db.ChangeTracker.Entries<ClientAuthNonce>().Any(e => e.Entity.ApiKeyHash == apiHash && e.Entity.NonceHash == nonceHash)
                && Interlocked.CompareExchange(ref entered, 1, 0) == 0)
            {
                Entered.TrySetResult(true);
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }
}
