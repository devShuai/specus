using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class PeerControlDeliveryAuthorityTests
{
    [Theory]
    [InlineData("config", "credential-disabled")]
    [InlineData("config", "credential-deleted")]
    [InlineData("config", "identity-deleted")]
    [InlineData("config", "session-expired")]
    [InlineData("config", "session-offline")]
    [InlineData("config", "session-channel")]
    [InlineData("config", "session-client")]
    [InlineData("config", "session-tenant")]
    [InlineData("config", "account-disabled")]
    [InlineData("roster", "credential-disabled")]
    [InlineData("roster", "credential-deleted")]
    [InlineData("roster", "identity-deleted")]
    [InlineData("roster", "session-expired")]
    [InlineData("roster", "session-offline")]
    [InlineData("roster", "session-channel")]
    [InlineData("roster", "session-client")]
    [InlineData("roster", "session-tenant")]
    [InlineData("roster", "account-disabled")]
    [InlineData("egress", "credential-disabled")]
    [InlineData("egress", "credential-deleted")]
    [InlineData("egress", "identity-deleted")]
    [InlineData("egress", "session-expired")]
    [InlineData("egress", "session-offline")]
    [InlineData("egress", "session-channel")]
    [InlineData("egress", "session-client")]
    [InlineData("egress", "session-tenant")]
    [InlineData("egress", "account-disabled")]
    public async Task PushDoesNotReachTheWriterWhenItsCurrentSqlReceiverAuthorityIsInvalid(string kind, string change)
    {
        await using var fixture = await RuntimeFixture.StartAsync();
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await db.ClientAccounts.SingleAsync(a => a.Id == fixture.Account.Id);
        await db.ClientSessions.SingleAsync(s => s.Id == fixture.Login.ClientSessionId);
        await using (var mutate = fixture.Server.HostServices.CreateAsyncScope())
        {
            var current = mutate.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var session = await current.ClientSessions.SingleAsync(s => s.Id == fixture.Login.ClientSessionId);
            switch (change)
            {
                case "credential-disabled": (await current.ClientCredentials.SingleAsync()).Enabled = false; break;
                case "credential-deleted": current.ClientCredentials.Remove(await current.ClientCredentials.SingleAsync()); break;
                case "identity-deleted": current.ClientIdentities.Remove(await current.ClientIdentities.SingleAsync(i => i.Id == 701)); break;
                case "session-expired": session.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1); break;
                case "session-offline": session.Status = ClientAccountService.StatusDisconnected; break;
                case "session-channel": session.ChannelId = "replaced-physical-channel"; break;
                case "session-client": session.ClientId = 1002; break;
                case "session-tenant": session.TenantId = "DEFAULT"; break;
                case "account-disabled": (await current.ClientAccounts.SingleAsync(a => a.Id == fixture.Account.Id)).Enabled = false; break;
            }
            await current.SaveChangesAsync();
        }
        await PushAsync(scope.ServiceProvider.GetRequiredService<PeerMeshService>(), fixture.Account, kind);
        Assert.Empty(fixture.Writer.Messages);
    }

    [Theory]
    [InlineData("config")]
    [InlineData("roster")]
    [InlineData("egress")]
    public async Task HealthyBoundControlStillReceivesItsRuntimeMessages(string kind)
    {
        await using var fixture = await RuntimeFixture.StartAsync();
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        await PushAsync(scope.ServiceProvider.GetRequiredService<PeerMeshService>(), fixture.Account, kind);
        Assert.NotEmpty(fixture.Writer.Messages);
    }

    [Fact]
    public async Task EgressPushCannotBorrowCapabilityFromAnotherOnlineSqlSession()
    {
        await using var fixture = await RuntimeFixture.StartAsync(egressVersion: 0);
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var obsolete = await db.ClientSessions.SingleAsync(s => s.Id == 901);
        obsolete.ClientEgressVersion = 1;
        await db.SaveChangesAsync();
        await scope.ServiceProvider.GetRequiredService<PeerMeshService>().PushEgressAsync(fixture.Account, CancellationToken.None);
        Assert.Empty(fixture.Writer.Messages);
    }

    [Fact]
    public async Task RevocationAfterTheFirstEgressWritePreventsTheSecondWriteToThatReceiver()
    {
        await using var fixture = await RuntimeFixture.StartAsync();
        fixture.Writer.AfterWrite = async () =>
        {
            if (fixture.Writer.Messages.Count != 1) return;
            await using var mutate = fixture.Server.HostServices.CreateAsyncScope();
            var db = mutate.ServiceProvider.GetRequiredService<SpecusDbContext>();
            (await db.ClientSessions.SingleAsync(s => s.Id == fixture.Login.ClientSessionId)).ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        };
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<PeerMeshService>().PushEgressAsync(fixture.Account, CancellationToken.None);
        Assert.Single(fixture.Writer.Messages); Assert.Equal("egress-config", fixture.Writer.Messages[0].Type);
    }

    [Fact]
    public async Task RosterUsesTheTransferredCurrentOwnerRatherThanTheCapturedAccount()
    {
        await using var fixture = await RuntimeFixture.StartAsync();
        await using var scope = fixture.Server.HostServices.CreateAsyncScope();
        var services = scope.ServiceProvider; var db = services.GetRequiredService<SpecusDbContext>();
        db.ClientAccounts.Add(new ClientAccount { Id = 3003, TenantId = "default", ClientName = "old-alice-peer", OwnerUsername = "alice", Enabled = true });
        db.PeerMeshDevices.Add(new PeerMeshDevice { Id = 3803, TenantId = "default", ClientId = 3003, ClientName = "old-alice-peer", OwnerUsername = "alice", Enabled = true, VirtualIp = "10.66.0.4", Cidr = "10.66.0.0/16" });
        await db.SaveChangesAsync();
        var actor = await OwnerTransferWriterProof.ActorAsync(fixture.Server, services);
        var preview = await services.GetRequiredService<ClientOwnerTransferService>().PreviewCredentialAsync(actor.Context, "501", CancellationToken.None);
        await services.GetRequiredService<ClientOwnerTransferWriter>().CommitAsync(actor, ClientOwnerTransferPlan.PathScope.CredentialGroup, "501",
            OwnerTransferWriterProof.Body(ClientOwnerTransferPlan.PathScope.CredentialGroup, "bob", preview.Revision!), CancellationToken.None);
        Assert.Equal("alice", fixture.Account.OwnerUsername);
        await services.GetRequiredService<PeerMeshService>().PushRosterAsync(fixture.Account, CancellationToken.None);
        var message = Assert.Single(fixture.Writer.Messages);
        Assert.Equal("roster", message.Type); Assert.DoesNotContain(message.Peers!, p => p.ClientId == 3003);
    }

    internal static Task PushAsync(PeerMeshService service, ClientAccount account, string kind) => kind switch
    {
        "config" => service.PushConfigAsync(account, CancellationToken.None),
        "roster" => service.PushRosterAsync(account, CancellationToken.None),
        "egress" => service.PushEgressAsync(account, CancellationToken.None),
        _ => throw new ArgumentException("unknown runtime fixture kind"),
    };

    internal sealed class RuntimeFixture(TestServerFixture server, ClientAuthLoginResponse login, ClientAccount account,
        RecordingWriter writer, SpecusConnectionContext context) : IAsyncDisposable
    {
        internal TestServerFixture Server { get; } = server;
        internal ClientAuthLoginResponse Login { get; } = login;
        internal ClientAccount Account { get; } = account;
        internal RecordingWriter Writer { get; } = writer;
        internal SpecusConnectionContext Context { get; } = context;
        internal static async Task<RuntimeFixture> StartAsync(int egressVersion = 1)
        {
            var server = await ClientNameReferenceTests.StartAsync();
            try
            {
                await using (var seed = server.HostServices.CreateAsyncScope())
                {
                    var db = seed.ServiceProvider.GetRequiredService<SpecusDbContext>();
                    await ClientNameReferenceTests.SeedAsync(db); await ClientNameReferenceTests.EnableCredentialAsync(db);
                }
                using var http = server.CreateClient(); var request = ClientNameReferenceTests.Request();
                request.Environment!.ClientEgressCapabilities.Version = egressVersion;
                request.Environment.ClientPeerServiceCapabilities.Version = 2;
                using var response = await http.PostAsJsonAsync("/api/client/auth/login", request);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var login = await response.Content.ReadFromJsonAsync<ClientAuthLoginResponse>(); Assert.NotNull(login);
                await using var scope = server.HostServices.CreateAsyncScope();
                var auth = await scope.ServiceProvider.GetRequiredService<ClientAccountService>().AuthenticateAsync(
                    new LoginRequestPacket { ClientSessionId = login.ClientSessionId, AccessToken = login.AccessToken }, "runtime-control", "127.0.0.1", CancellationToken.None);
                Assert.True(auth.Success, auth.Reason);
                var writer = new RecordingWriter();
                var context = new SpecusConnectionContext("runtime-control", "127.0.0.1", writer, CancellationToken.None, () => { },
                    new ReadGate(CancellationToken.None), new WriteBackpressureGate(64 * 1024, 1024 * 1024));
                context.OnLoginSuccess(login.ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), login.ClientSessionId,
                    tenantId: login.TenantId, clientId: login.ClientId);
                server.HostServices.GetRequiredService<SessionRegistry>().Replace(login.ClientName, context);
                return new RuntimeFixture(server, login, auth.Account!, writer, context);
            }
            catch { await server.DisposeAsync(); throw; }
        }
        public ValueTask DisposeAsync() => Server.DisposeAsync();
    }

    internal sealed class RecordingWriter : IFrameWriter
    {
        internal List<PeerControlMessage> Messages { get; } = [];
        internal Func<Task>? AfterWrite { get; set; }
        public async ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            if (packet is MessageResponsePacket message) Messages.Add(JsonSerializer.Deserialize<PeerControlMessage>(message.Message!)!);
            if (AfterWrite is not null) await AfterWrite();
        }
    }
}
