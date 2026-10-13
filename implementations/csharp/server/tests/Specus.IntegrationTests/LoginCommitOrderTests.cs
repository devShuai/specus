using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Nat;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

/// <summary>
/// A client reads the login response before any other frame on a connection, and may hand the
/// server a public request as soon as it does. So a login publishes its connection and writes the
/// response as one step: nothing the published state lets others send may overtake the response.
/// </summary>
public sealed class LoginCommitOrderTests
{
    private static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(10);

    // A frame another producer sends because of what the commit published (here an OPEN on the
    // connection it registered) must not overtake the packet CommitAndWriteAsync writes.
    [Fact(Timeout = 30_000)]
    public async Task CommitAndWriteKeepsFramesTheCommitPublishesBehindThePacket()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var socket = await listener.AcceptSocketAsync();
        await using var connection = new SpecusConnection(socket, new NetworkStream(socket),
            new IdleDispatcher(), NullLogger.Instance, new NettyServerOptions(), CancellationToken.None);

        Task? follower = null;
        await connection.CommitAndWriteAsync(
            () => follower = connection.WriteAsync(Open(1)).AsTask(),
            new LoginResponsePacket { ClientName = "demo", Success = true });

        var stream = client.GetStream();
        Assert.IsType<LoginResponsePacket>(await ReadPacketAsync(stream));
        var open = Assert.IsType<NatMessagePacket>(await ReadPacketAsync(stream));
        Assert.Equal(NatMessageType.Open, open.NatMessageType);
        await follower!.WaitAsync(StepTimeout);
    }

    // The data login used to list the connection in the registry before attaching its NAT
    // session, and wrote its response after both, so a public request could find the client
    // online with no stream namespace, or get its OPEN onto the wire ahead of the response.
    [Fact(Timeout = 60_000)]
    public async Task DataLoginAttachesBeforeListingAndAnswersBeforeAnyOpen()
    {
        await using var server = await TestServerFixture.StartAsync();
        var nat = server.HostServices.GetRequiredService<NatServerHandler>();
        var sessions = server.HostServices.GetRequiredService<SessionRegistry>();
        var clientName = DatabaseInitializer.DemoClientName;
        var session = await IssueSessionAsync(server, clientName);

        using var control = await ConnectAsync(server.ControlPort);
        await SendAsync(control, Login(clientName, session, ConnectionRole.Control));
        var controlResponse = Assert.IsType<LoginResponsePacket>(await ReadPacketAsync(control.GetStream()));
        Assert.True(controlResponse.Success, controlResponse.Reason);

        var attaching = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var listedAtAttach = false;
        Task<HttpSpecusStream>? opening = null;
        nat.AttachedForTests = context =>
        {
            listedAtAttach = ReferenceEquals(sessions.FindData(clientName), context);
            // What a public request does once the client's data connection is reachable.
            opening = nat.OpenHttpStreamAsync(clientName,
                new Dictionary<string, object?> { ["method"] = "GET", ["path"] = "/" }, CancellationToken.None);
            attaching.TrySetResult();
            release.Task.Wait(StepTimeout);
        };
        try
        {
            using var data = await ConnectAsync(server.ControlPort);
            await SendAsync(data, Login(clientName, session, ConnectionRole.Data));
            await attaching.Task.WaitAsync(StepTimeout);
            Assert.False(listedAtAttach, "the registry listed the data connection before its NAT session existed");

            // The commit has not returned, so neither the login response nor the OPEN is on the wire.
            Assert.False(data.Client.Poll(TimeSpan.FromMilliseconds(200), SelectMode.SelectRead),
                "a frame reached the data connection before its login commit finished");

            release.TrySetResult();
            var stream = data.GetStream();
            var response = Assert.IsType<LoginResponsePacket>(await ReadPacketAsync(stream));
            Assert.True(response.Success, response.Reason);
            var open = Assert.IsType<NatMessagePacket>(await ReadPacketAsync(stream));
            Assert.Equal(NatMessageType.Open, open.NatMessageType);
            await using var opened = await opening!.WaitAsync(StepTimeout);
            Assert.Equal(opened.StreamId, open.StreamId);
            Assert.NotNull(sessions.FindData(clientName));
        }
        finally
        {
            release.TrySetResult();
            nat.AttachedForTests = null;
        }
    }

    private static NatMessagePacket Open(uint streamId) => new()
    {
        NatMessageType = NatMessageType.Open,
        StreamId = streamId,
        MetaData = new Dictionary<string, object?> { ["method"] = "GET" },
    };

    private static LoginRequestPacket Login(string clientName, ClientAuthSession session, string role) => new()
    {
        ClientName = clientName,
        ClientSessionId = session.Id,
        AccessToken = session.AccessToken,
        ConnectionRole = role,
    };

    private static async Task<ClientAuthSession> IssueSessionAsync(TestServerFixture server, string clientName)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.ClientName == clientName);
        var credential = await db.ClientCredentials.AsNoTracking()
            .SingleAsync(c => c.ApiKey == DatabaseInitializer.DemoCredentialApiKey);
        var now = DateTimeOffset.UtcNow;
        var identity = new ClientIdentity
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = credential.TenantId,
            CredentialId = credential.Id,
            ClientId = account.Id,
            ClientName = account.ClientName,
            MachineFingerprint = "login-order-machine",
            OsUser = "login-order",
            Hostname = "login-order",
            FirstSeenAt = now,
            LastSeenAt = now,
        };
        return scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>().Create(credential, identity,
            account, TimeSpan.FromHours(1), new ClientEnvironmentInfo
            {
                MachineFingerprint = identity.MachineFingerprint,
                OsUser = identity.OsUser,
                Hostname = identity.Hostname,
            });
    }

    private static async Task<TcpClient> ConnectAsync(int port)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            return tcp;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private static async Task SendAsync(TcpClient tcp, Packet packet) =>
        await tcp.GetStream().WriteAsync(PacketCodec.Encode(packet));

    private static async Task<Packet> ReadPacketAsync(NetworkStream stream)
    {
        using var timeout = new CancellationTokenSource(StepTimeout);
        var header = new byte[PacketCodec.HeaderSize];
        await stream.ReadExactlyAsync(header, timeout.Token);
        var (_, length) = PacketCodec.DecodeHeader(header);
        var frame = new byte[PacketCodec.HeaderSize + length];
        header.CopyTo(frame, 0);
        await stream.ReadExactlyAsync(frame.AsMemory(PacketCodec.HeaderSize), timeout.Token);
        return PacketCodec.DecodeExact(frame);
    }

    private sealed class IdleDispatcher : IControlChannelDispatcher
    {
        public Task OnConnectionOpenedAsync(SpecusConnectionContext context) => Task.CompletedTask;
        public Task DispatchAsync(SpecusConnectionContext context, Packet packet) => Task.CompletedTask;
        public Task OnConnectionClosedAsync(SpecusConnectionContext context) => Task.CompletedTask;
    }
}
