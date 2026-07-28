using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public sealed class PeerMeshTurnAuthChallengeTests
{
    [Theory]
    [InlineData(401)]
    [InlineData(438)]
    public async Task AuthenticationChallengeRetriesExactlyOnceWithNewTransaction(int challengeCode)
    {
        using var clientSocket = BoundUdp();
        using var turnServer = BoundUdp();
        var turnEndpoint = (IPEndPoint)turnServer.Client.LocalEndPoint!;
        await using var client = Client(clientSocket, TurnLongTermAuthenticatorTests.Config("old-realm", "old-nonce"));
        var request = StunMessage.Of(
            StunMessage.AllocateRequest,
            TurnLongTermAuthenticatorTests.TransactionId(1),
            StunMessage.RequestedUdpTransportAttribute());

        await SendStunRequestAsync(client, request, turnEndpoint);
        var first = await ReceiveAsync(turnServer);
        Assert.Equal("old-nonce", first.Message.TextAttribute(StunMessage.AttrNonce));
        Assert.True(TurnLongTermAuthenticatorTests.VerifyMessageIntegrity(
            first.Bytes,
            TurnLongTermAuthenticatorTests.LongTermKey("old-realm")));
        Assert.Single(Pending(client));

        await HandleAsync(client, StunMessage.Of(
            StunMessage.AllocateError,
            first.Message.TransactionId,
            StunMessage.ErrorCode(challengeCode, "challenge"),
            StunMessage.Realm("new-realm"),
            StunMessage.Nonce("new-nonce")), turnEndpoint);

        var retry = await ReceiveAsync(turnServer);
        Assert.NotEqual(first.Message.TransactionIdHex, retry.Message.TransactionIdHex);
        Assert.Equal("new-realm", retry.Message.TextAttribute(StunMessage.AttrRealm));
        Assert.Equal("new-nonce", retry.Message.TextAttribute(StunMessage.AttrNonce));
        Assert.True(TurnLongTermAuthenticatorTests.VerifyMessageIntegrity(
            retry.Bytes,
            TurnLongTermAuthenticatorTests.LongTermKey("new-realm")));
        Assert.Single(Pending(client));

        await HandleAsync(client, StunMessage.Of(
            StunMessage.AllocateError,
            retry.Message.TransactionId,
            StunMessage.ErrorCode(challengeCode, "repeated-challenge"),
            StunMessage.Realm("newer-realm"),
            StunMessage.Nonce("newer-nonce")), turnEndpoint);

        Assert.False(await HasDatagramAsync(turnServer));
        Assert.Empty(Pending(client));
    }

    [Fact]
    public async Task PendingLookupRequiresBothTransactionAndEndpointAndSuccessClearsIt()
    {
        using var clientSocket = BoundUdp();
        using var turnServer = BoundUdp();
        var turnEndpoint = (IPEndPoint)turnServer.Client.LocalEndPoint!;
        var wrongEndpoint = new IPEndPoint(
            turnEndpoint.Address,
            turnEndpoint.Port == ushort.MaxValue ? turnEndpoint.Port - 1 : turnEndpoint.Port + 1);
        await using var client = Client(clientSocket, TurnLongTermAuthenticatorTests.Config("realm", "nonce"));

        await SendStunRequestAsync(client, StunMessage.Of(
            StunMessage.AllocateRequest,
            TurnLongTermAuthenticatorTests.TransactionId(20),
            StunMessage.RequestedUdpTransportAttribute()), turnEndpoint);
        var first = await ReceiveAsync(turnServer);

        await HandleAsync(client, StunMessage.Of(
            StunMessage.AllocateError,
            first.Message.TransactionId,
            StunMessage.ErrorCode(401, "unauthorized"),
            StunMessage.Realm("wrong-realm"),
            StunMessage.Nonce("wrong-nonce")), wrongEndpoint);

        Assert.False(await HasDatagramAsync(turnServer));
        Assert.Single(Pending(client));

        await HandleAsync(client, StunMessage.Of(
            StunMessage.AllocateSuccess,
            first.Message.TransactionId), turnEndpoint);
        Assert.Empty(Pending(client));
    }

    [Fact]
    public async Task NonChallengeErrorDoesNotRetryAndRemovesPendingRequest()
    {
        using var clientSocket = BoundUdp();
        using var turnServer = BoundUdp();
        var turnEndpoint = (IPEndPoint)turnServer.Client.LocalEndPoint!;
        await using var client = Client(clientSocket, TurnLongTermAuthenticatorTests.Config("realm", "nonce"));

        await SendStunRequestAsync(client, StunMessage.Of(
            StunMessage.RefreshRequest,
            TurnLongTermAuthenticatorTests.TransactionId(30),
            StunMessage.Lifetime(300)), turnEndpoint);
        var first = await ReceiveAsync(turnServer);
        await HandleAsync(client, StunMessage.Of(
            StunMessage.RefreshError,
            first.Message.TransactionId,
            StunMessage.ErrorCode(400, "bad-request")), turnEndpoint);

        Assert.False(await HasDatagramAsync(turnServer));
        Assert.Empty(Pending(client));
    }

    [Fact]
    public async Task PendingRequestsAreClearedOnTimeoutCredentialChangeAndStop()
    {
        using var clientSocket = BoundUdp();
        using var turnServer = BoundUdp();
        var turnEndpoint = (IPEndPoint)turnServer.Client.LocalEndPoint!;
        var client = Client(clientSocket, TurnLongTermAuthenticatorTests.Config("old-realm", "old-nonce"));

        await SendStunRequestAsync(client, StunMessage.Of(
            StunMessage.CreatePermissionRequest,
            TurnLongTermAuthenticatorTests.TransactionId(40)), turnEndpoint);
        await ReceiveAsync(turnServer);
        var pending = Assert.Single(Pending(client).Values.Cast<object>());
        SetProperty(pending, "SentAt", DateTimeOffset.UtcNow.AddMinutes(-1));
        InvokePrivate(client, "CleanupProbes");
        Assert.Empty(Pending(client));

        await SendStunRequestAsync(client, StunMessage.Of(
            StunMessage.AllocateRequest,
            TurnLongTermAuthenticatorTests.TransactionId(41),
            StunMessage.RequestedUdpTransportAttribute()), turnEndpoint);
        await ReceiveAsync(turnServer);
        Assert.Single(Pending(client));
        InvokePrivate(client, "UpdateTurnCredentials", TurnLongTermAuthenticatorTests.Config("new-realm", "new-nonce"));
        Assert.Empty(Pending(client));

        await SendStunRequestAsync(client, StunMessage.Of(
            StunMessage.AllocateRequest,
            TurnLongTermAuthenticatorTests.TransactionId(42),
            StunMessage.RequestedUdpTransportAttribute()), turnEndpoint);
        var updated = await ReceiveAsync(turnServer);
        Assert.Equal("new-realm", updated.Message.TextAttribute(StunMessage.AttrRealm));
        Assert.Equal("new-nonce", updated.Message.TextAttribute(StunMessage.AttrNonce));
        Assert.Single(Pending(client));

        await client.DisposeAsync();
        Assert.Empty(Pending(client));
    }

    private static PeerMeshClient Client(UdpClient socket, PeerMeshConfig config)
    {
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetField(client, "_udp", socket);
        SetField(client, "_runtime", new SpecusRuntimeState { PeerMesh = config });
        PrivateField<TurnLongTermAuthenticator>(client, "_turnAuthenticator").Update(config);
        return client;
    }

    private static UdpClient BoundUdp()
    {
        var socket = new UdpClient(AddressFamily.InterNetwork);
        socket.Client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return socket;
    }

    private static IDictionary Pending(PeerMeshClient client) =>
        PrivateField<IDictionary>(client, "_pendingTurn");

    private static async Task SendStunRequestAsync(PeerMeshClient client, StunMessage message, IPEndPoint endpoint)
    {
        var method = typeof(PeerMeshClient)
            .GetMethods(BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(candidate => candidate.Name == "SendStunRequestAsync" && candidate.GetParameters().Length == 2);
        await ((Task)method.Invoke(client, [message, endpoint])!).ConfigureAwait(false);
    }

    private static async Task HandleAsync(PeerMeshClient client, StunMessage message, IPEndPoint endpoint)
    {
        var method = typeof(PeerMeshClient).GetMethod(
            "HandleStunTurnMessageAsync",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        await ((Task)method.Invoke(client, [message, endpoint])!).ConfigureAwait(false);
    }

    private static async Task<CapturedStun> ReceiveAsync(UdpClient socket)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var result = await socket.ReceiveAsync(cts.Token).ConfigureAwait(false);
        return new CapturedStun(result.Buffer, StunMessage.Parse(result.Buffer)!);
    }

    private static async Task<bool> HasDatagramAsync(UdpClient socket)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
        try
        {
            await socket.ReceiveAsync(cts.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static T PrivateField<T>(object instance, string name) =>
        (T)instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(instance)!;

    private static void SetField(object instance, string name, object value) =>
        instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(instance, value);

    private static void SetProperty(object instance, string name, object value) =>
        instance.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
            .SetValue(instance, value);

    private static void InvokePrivate(object instance, string name, params object[] arguments) =>
        instance.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(instance, arguments);

    private sealed record CapturedStun(byte[] Bytes, StunMessage Message);
}
