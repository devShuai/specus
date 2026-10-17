using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;

namespace Specus.IntegrationTests;

public sealed class ClientStartupCommitFailureTests
{
    [Fact]
    public async Task ActualStartupCommitFailureDoesNotPublishPreparedTokenOrPersistPartialRows()
    {
        var saved = new ClientStartupAtomicityTests.SessionSaveProbe(false);
        var commit = new CommitFailure(saved);
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Database:SeedDemoClient"] = "false", ["Specus:PeerMesh:Enabled"] = "true",
            ["Specus:PeerMesh:StunTurnPort"] = "0", ["Specus:PeerMesh:NatProbeAlternatePort"] = "0",
        }, services => services.ConfigureDbContext<SpecusDbContext>((_, options) => options.AddInterceptors(saved, commit)));
        await ClientStartupAtomicityTests.SeedAsync(server);
        using var client = server.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/client/auth/login", ClientStartupOwnershipTests.Signed(
            "ck_startup_atomic", "startup-atomic-secret", Guid.NewGuid().ToString("N")));
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.True(commit.Triggered); Assert.NotNull(saved.SessionId);
        Assert.Null(server.HostServices.GetRequiredService<ClientAuthSessionStore>().FindById(saved.SessionId));
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        Assert.Equal(0, await db.ClientAccounts.CountAsync()); Assert.Equal(0, await db.ClientIdentities.CountAsync());
        Assert.Equal(0, await db.PeerMeshDevices.CountAsync()); Assert.Equal(0, await db.ClientSessions.CountAsync());
    }

    private sealed class CommitFailure(ClientStartupAtomicityTests.SessionSaveProbe saved) : DbTransactionInterceptor
    {
        internal bool Triggered { get; private set; }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,
            TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (saved.SessionId is not null)
            {
                Triggered = true;
                throw new InvalidOperationException("owned startup commit fixture failure");
            }
            return ValueTask.FromResult(result);
        }
    }
}
