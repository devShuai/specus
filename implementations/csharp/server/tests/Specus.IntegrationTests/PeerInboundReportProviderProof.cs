using System.Data;
using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

// Actual mandatory native databases and signed HTTP/control authentication. The two-host
// case intentionally leaves the original host's cache unaware; it is not a two-OS-process test.
internal static class PeerInboundReportProviderProof
{
    internal static async Task VerifyCredentialWaitAsync(TestServerFixture server)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45)); var ct = timeout.Token;
        var source = await BindAsync(server, ct);
        await using var reportScope = server.HostServices.CreateAsyncScope();
        await using var holderScope = server.HostServices.CreateAsyncScope();
        await using var observerScope = server.HostServices.CreateAsyncScope();
        var reporter = reportScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var holder = holderScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var observer = observerScope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        foreach (var db in new[] { reporter, holder, observer }) await db.Database.OpenConnectionAsync(ct);
        var postgres = reporter.Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL";
        var pidQuery = postgres ? "SELECT pg_backend_pid()" : "SELECT CONNECTION_ID()";
        var reporterPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(reporter, pidQuery, ct));
        var holderPid = Convert.ToInt64(await OwnerTransferWriterProof.ScalarAsync(holder, pidQuery, ct));
        var maria = Convert.ToString(await OwnerTransferWriterProof.ScalarAsync(observer, "SELECT VERSION()", ct))!.Contains("MariaDB", StringComparison.OrdinalIgnoreCase);
        await using var transaction = await holder.Database.BeginTransactionAsync(IsolationLevel.ReadCommitted, ct);
        var entity = holder.Model.FindEntityType(typeof(ClientCredential))!;
        var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        var sql = holder.GetService<Microsoft.EntityFrameworkCore.Storage.ISqlGenerationHelper>();
        var key = sql.DelimitIdentifier(entity.FindProperty("Id")!.GetColumnName(table)!);
        _ = await OwnerTransferWriterProof.ScalarAsync(holder, $"SELECT {key} FROM {sql.DelimitIdentifier(table.Name, table.Schema)} WHERE {key}=501 FOR UPDATE", ct);
        var pending = ReportAsync(reportScope.ServiceProvider, source, ct);
        var committed = false;
        try
        {
            await OwnerTransferWriterProof.WaitForBlockerAsync(observer, reporterPid, holderPid, postgres, maria, pending, ct);
            (await holder.ClientCredentials.SingleAsync(c => c.Id == 501, ct)).Enabled = false;
            await holder.SaveChangesAsync(ct); await transaction.CommitAsync(ct); committed = true;
            await Assert.ThrowsAsync<ArgumentException>(() => pending);
            Assert.Null((await observer.PeerMeshDevices.AsNoTracking().SingleAsync(d => d.ClientId == 1001, ct)).VirtualDeviceError);
            Assert.Null(reporter.Database.CurrentTransaction);
        }
        finally
        {
            if (!committed) await transaction.RollbackAsync(CancellationToken.None);
            if (!pending.IsCompleted) timeout.Cancel();
            try { await pending; } catch (Exception) { }
        }
    }

    internal static async Task VerifyStaleSourceHintAsync(TestServerFixture server, SourceHintGate gate, TestServerFixture? deletionHost = null)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60)); var ct = timeout.Token;
        var source = await BindAsync(server, ct);
        await using var reportScope = server.HostServices.CreateAsyncScope();
        gate.OwnReport.Value = true;
        var pending = ReportAsync(reportScope.ServiceProvider, source, ct);
        gate.OwnReport.Value = false;
        try
        {
            await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            Assert.False(pending.IsCompleted);
            await using var change = (deletionHost ?? server).HostServices.CreateAsyncScope();
            var services = change.ServiceProvider;
            var actor = await OwnerTransferWriterProof.ActorAsync(deletionHost ?? server, services);
            if (deletionHost is null)
            {
                var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, "501", ct);
                var result = await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, PathScope.CredentialGroup, "501",
                    OwnerTransferWriterProof.Body(PathScope.CredentialGroup, "bob", preview.Revision!), ct);
                Assert.True(result.Response.Changed);
            }
            else
            {
                await services.GetRequiredService<ManagementMutationService>().DeleteClientAsync(actor.Context, 1001, ct);
                await services.GetRequiredService<PeerMeshService>().DrainClientDeletionsAsync(ct);
                Assert.False(server.HostServices.GetRequiredService<ClientAuthSessionStore>().FindById(source.ClientSessionId!.Value)!.Revoked);
                Assert.Same(source, server.HostServices.GetRequiredService<SessionRegistry>().Find(source.ClientName!));
            }
            gate.Release();
            var db = services.GetRequiredService<SpecusDbContext>();
            if (deletionHost is null)
            {
                await pending.WaitAsync(ct);
                var device = await db.PeerMeshDevices.AsNoTracking().SingleAsync(d => d.ClientId == 1001, ct);
                Assert.Equal("bob", device.OwnerUsername); Assert.Equal("native-inbound-current", device.VirtualDeviceError);
                Assert.Equal("bob", (await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == 1001, ct)).OwnerUsername);
            }
            else
            {
                await Assert.ThrowsAsync<ArgumentException>(() => pending);
                Assert.False(await db.ClientAccounts.AsNoTracking().AnyAsync(c => c.Id == 1001, ct));
                Assert.False(await db.ClientIdentities.AsNoTracking().AnyAsync(i => i.ClientId == 1001, ct));
                Assert.False(await db.PeerMeshDevices.AsNoTracking().AnyAsync(d => d.ClientId == 1001, ct));
                Assert.False(await db.PeerMeshEgressActivities.AsNoTracking().AnyAsync(a => a.EgressClientId == 1001, ct));
                Assert.True(await db.ClientSessions.AsNoTracking().AnyAsync(s => s.Id == 901, ct));
            }
            Assert.Null(reportScope.ServiceProvider.GetRequiredService<SpecusDbContext>().Database.CurrentTransaction);
        }
        finally
        {
            gate.Release(); if (!pending.IsCompleted) timeout.Cancel();
            try { await pending; } catch (Exception) { }
        }
    }

    private static Task ReportAsync(IServiceProvider services, SpecusConnectionContext source, CancellationToken ct) =>
        services.GetRequiredService<PeerMeshService>().HandleSignalAsync(new MessageRequestPacket
            { MessageType = Specus.Protocol.MessageType.PeerControl, Message = "{\"type\":\"device-report\",\"virtualDeviceError\":\"native-inbound-current\"}" },
            source.ClientName!, ct, source.ClientSessionId, source);

    private static async Task<SpecusConnectionContext> BindAsync(TestServerFixture server, CancellationToken ct)
    {
        await using var scope = server.HostServices.CreateAsyncScope(); var services = scope.ServiceProvider;
        var db = services.GetRequiredService<SpecusDbContext>(); await OwnerTransferWriterProof.SeedAsync(db, "default");
        const string secret = "native-inbound-fixture-secret";
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
        var credential = await db.ClientCredentials.SingleAsync(c => c.Id == 501, ct);
        credential.Enabled = true; credential.MaxOnlineInstances = 7; credential.SecretHash = hash;
        (await db.ClientSessions.SingleAsync(s => s.Id == 901, ct)).ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1);
        await db.SaveChangesAsync(ct);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Guid.NewGuid().ToString("N");
        using var http = server.CreateClient();
        using var response = await http.PostAsJsonAsync("/api/client/auth/login", new ClientAuthLoginRequest
        {
            ApiKey = credential.ApiKey, Timestamp = timestamp, Nonce = nonce,
            Signature = Convert.ToHexStringLower(HMACSHA256.HashData(Convert.FromHexString(hash), Encoding.UTF8.GetBytes(string.Join('\n', credential.ApiKey, timestamp, nonce, "retained-machine1", "retained-user")))),
            Environment = new ClientEnvironmentInfo { MachineFingerprint = "retained-machine1", OsUser = "retained-user", Hostname = "native-inbound" },
        }, ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var login = (await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(ct))!;
        var source = new SpecusConnectionContext("native-inbound-" + Guid.NewGuid().ToString("N"), "127.0.0.1", new Sink(), CancellationToken.None,
            () => { }, new ReadGate(CancellationToken.None), new WriteBackpressureGate(65536, 1048576));
        Assert.True((await services.GetRequiredService<ClientAccountService>().AuthenticateAsync(new LoginRequestPacket
            { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken }, source.ChannelId, "127.0.0.1", ct)).Success);
        source.OnLoginSuccess(login.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), login.ClientSessionId, tenantId: "default", clientId: 1001);
        services.GetRequiredService<SessionRegistry>().Replace(login.ClientName, source);
        return source;
    }

    internal sealed class SourceHintGate : DbCommandInterceptor
    {
        internal AsyncLocal<bool> OwnReport { get; } = new();
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Release() => _release.TrySetResult();
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (OwnReport.Value && command.CommandText.Contains("client_account", StringComparison.OrdinalIgnoreCase)
                && command.Parameters.Cast<DbParameter>().Any(p => Equals(p.Value, "laptop")) && Entered.TrySetResult())
                await _release.Task.WaitAsync(cancellationToken);
            return result;
        }
    }

    private sealed class Sink : IFrameWriter
    { public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default) => ValueTask.CompletedTask; }
}
