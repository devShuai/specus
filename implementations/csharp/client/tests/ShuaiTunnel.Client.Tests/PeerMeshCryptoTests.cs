using System.Buffers.Binary;
using System.Collections;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.PeerMesh;

namespace ShuaiTunnel.Client.Tests;

public sealed class PeerMeshCryptoTests
{
    [Fact]
    public void DataFrameRoundTrips()
    {
        var key = Enumerable.Repeat((byte)7, 32).ToArray();
        var frame = PeerDataFrameCodec.Encode(key, 1001, 1, 2, 1, "hello peer mesh"u8);

        var decoded = PeerDataFrameCodec.Decode(key, frame);

        Assert.Equal(1001, decoded.SessionId);
        Assert.Equal(1, decoded.FromClientId);
        Assert.Equal(2, decoded.ToClientId);
        Assert.Equal(1, decoded.Sequence);
        Assert.Equal("hello peer mesh"u8.ToArray(), decoded.Payload);
    }

    [Fact]
    public void DataFrameRejectsWrongKey()
    {
        var frame = PeerDataFrameCodec.Encode(Enumerable.Repeat((byte)7, 32).ToArray(), 1001, 1, 2, 1, "payload"u8);

        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Decode(Enumerable.Repeat((byte)8, 32).ToArray(), frame));
    }

    [Fact]
    public void ReplayWindowRejectsDuplicatesAndOldPackets()
    {
        var window = new PeerReplayWindow();

        Assert.True(window.Accept(10));
        Assert.False(window.Accept(10));
        Assert.True(window.Accept(9));
        Assert.False(window.Accept(9));
        Assert.True(window.Accept(80));
        Assert.False(window.Accept(15));
    }

    [Fact]
    public void IPv4PacketDestinationAndFlowKeyAreParsed()
    {
        var packet = MinimalTcpPacket("100.103.117.15", 51000, "100.112.186.105", 8006);

        Assert.Equal("100.112.186.105", PeerIpPacket.DestinationIPv4(packet));
        Assert.Equal("100.103.117.15", PeerIpPacket.SourceIPv4(packet));
        Assert.Equal("100.103.117.15:51000->100.112.186.105:8006/6", PeerIpPacket.FlowKey(packet));
    }

    [Fact]
    public void IcmpEchoReplyMatchesJavaNoopFallback()
    {
        var request = MinimalIcmpEchoRequest("100.103.117.15", "100.112.186.105");

        var reply = PeerIpPacket.IcmpEchoReplyFor(request, "100.112.186.105");

        Assert.NotNull(reply);
        Assert.Equal("100.112.186.105", PeerIpPacket.SourceIPv4(reply));
        Assert.Equal("100.103.117.15", PeerIpPacket.DestinationIPv4(reply));
        Assert.Equal(0, reply[20]);
        Assert.Equal(64, reply[8]);
        Assert.Equal((ushort)0, PeerIpPacket.Checksum(reply.AsSpan(0, 20)));
        Assert.Equal((ushort)0, PeerIpPacket.Checksum(reply.AsSpan(20)));
        Assert.Null(PeerIpPacket.IcmpEchoReplyFor(request, "100.112.186.106"));
    }

    [Fact]
    public void PeerMeshCidrNetworkAddressIsCalculatedForRouteConfiguration()
    {
        Assert.Equal("100.96.0.0", PeerVirtualDeviceHelpers.IPv4NetworkAddress("100.96.1.2/11"));
        Assert.Equal("10.23.42.0", PeerVirtualDeviceHelpers.IPv4NetworkAddress("10.23.42.17/24"));
    }

    [Fact]
    public void DeriveAesKeyMatchesBothSidesWhenX25519IsAvailable()
    {
        using var alice = TryCreateX25519();
        using var bob = TryCreateX25519();
        if (alice is null || bob is null)
        {
            return;
        }

        var alicePrivate = Convert.ToBase64String(alice.ExportPkcs8PrivateKey());
        var alicePublic = Convert.ToBase64String(alice.ExportSubjectPublicKeyInfo());
        var bobPrivate = Convert.ToBase64String(bob.ExportPkcs8PrivateKey());
        var bobPublic = Convert.ToBase64String(bob.ExportSubjectPublicKeyInfo());

        var aliceKey = PeerCrypto.DeriveAes256Key(alicePrivate, bobPublic, 1001, "token", 1, 2);
        var bobKey = PeerCrypto.DeriveAes256Key(bobPrivate, alicePublic, 1001, "token", 2, 1);

        Assert.Equal(aliceKey, bobKey);
    }

    [Fact]
    public void NatTypeUsesJavaEnumNames()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var client = new PeerMeshClient(new TunnelClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        var natByRole = PrivateField<Dictionary<string, string>>(client, "_natByRole");

        natByRole["primary"] = "198.51.100.1:41000";
        natByRole["alternate"] = "198.51.100.1:42000";
        Assert.Equal("SYMMETRIC_NAT", InvokeNatType(client));

        natByRole["alternate"] = "198.51.100.1:41000";
        Assert.Equal("PORT_RESTRICTED_NAT", InvokeNatType(client));

        natByRole.Clear();
        natByRole["primary"] = "198.51.100.1:41000";
        natByRole["changed-port"] = "198.51.100.1:41000";
        Assert.Equal("FULL_CONE_OR_RESTRICTED_NAT", InvokeNatType(client));

        natByRole.Clear();
        natByRole["primary"] = $"198.51.100.1:{port}";
        Assert.Equal("PORT_PRESERVED_NAT", InvokeNatType(client));

        natByRole["primary"] = "198.51.100.1:41000";
        Assert.Equal("NAT", InvokeNatType(client));
    }

    [Fact]
    public void PendingPacketQueueIsCappedPerPeer()
    {
        var client = new PeerMeshClient(new TunnelClientConfig(), NullLogger<PeerMeshClient>.Instance);

        for (var i = 0; i < 35; i++)
        {
            InvokePrivate(client, "QueuePendingPacket", 42L, new[] { (byte)i });
        }

        var pendingPackets = PrivateField<IDictionary>(client, "_pendingPackets");
        var queue = Assert.IsAssignableFrom<ICollection>(pendingPackets[42L]);

        Assert.Equal(32, queue.Count);
    }

    [Fact]
    public async Task RelayCandidateRequestIsThrottledLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = RelayTestClient(udp, relay);

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        var first = await ReadRelayMessagesAsync(relay, 2);
        Assert.Equal("binding", JsonString(first[0], "type"));
        Assert.Equal("allocate", JsonString(first[1], "type"));

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        Assert.Empty(await ReadRelayMessagesAsync(relay, 1));
    }

    [Fact]
    public async Task RelayRefreshRequestIsThrottledLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = RelayTestClient(udp, relay);
        SetPrivateField(client, "_relayId", "alloc-a");
        SetPrivateField(client, "_relayTtl", DateTimeOffset.UtcNow.AddMinutes(2));

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        var first = await ReadRelayMessagesAsync(relay, 2);
        Assert.Equal("binding", JsonString(first[0], "type"));
        Assert.Equal("refresh", JsonString(first[1], "type"));
        Assert.Equal("alloc-a", JsonString(first[1], "allocationId"));

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        Assert.Empty(await ReadRelayMessagesAsync(relay, 1));
    }

    [Fact]
    public async Task AlternateProbeRequestIsThrottledLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var alternate = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = new PeerMeshClient(new TunnelClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_runtime", new TunnelRuntimeState { PeerMesh = new PeerMeshConfig { Cidr = "100.96.0.0/11" } });
        var response = PeerRelayMessage(
            probeRole: "primary",
            alternateAddress: "127.0.0.1",
            alternatePort: ((IPEndPoint)alternate.Client.LocalEndPoint!).Port);

        await InvokePrivateAsync(client, "RequestAlternateProbeAsync", response, new IPEndPoint(IPAddress.Loopback, 3478));
        var first = await ReadRelayMessagesAsync(alternate, 1);
        Assert.Equal("binding", JsonString(first[0], "type"));
        Assert.Equal("alternate", JsonString(first[0], "probeRole"));

        await InvokePrivateAsync(client, "RequestAlternateProbeAsync", response, new IPEndPoint(IPAddress.Loopback, 3478));
        Assert.Empty(await ReadRelayMessagesAsync(alternate, 1));
    }

    [Fact]
    public void PeerRelayMessageCarriesObservedByEndpointLikeJava()
    {
        var message = PeerRelayMessage(
            probeRole: "primary",
            alternateAddress: "203.0.113.10",
            alternatePort: 3479,
            observedByAddress: "203.0.113.20",
            observedByPort: 3480);
        var json = JsonSerializer.SerializeToElement(message);

        Assert.Equal("203.0.113.20", JsonString(json, "observedByAddress"));
        Assert.Equal(3480, JsonInt(json, "observedByPort"));

        var type = typeof(PeerMeshClient).GetNestedType("PeerRelayMessage", BindingFlags.NonPublic)!;
        var decoded = JsonSerializer.Deserialize(json.GetRawText(), type)!;
        Assert.Equal("203.0.113.20", type.GetProperty("ObservedByAddress")!.GetValue(decoded));
        Assert.Equal(3480, type.GetProperty("ObservedByPort")!.GetValue(decoded));
    }

    [Fact]
    public async Task SendEncryptedPayloadUsesRelayAllocationLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var direct = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = RelayTestClient(udp, relay);
        SetPrivateField(client, "_relayId", "alloc-local");
        var session = NewPeerMeshSession(
            id: 1001,
            peerId: 2,
            token: "token",
            remote: (IPEndPoint)direct.Client.LocalEndPoint!,
            relayTargetAllocationId: "alloc-peer",
            pathType: "DIRECT",
            lastDirectSuccess: DateTimeOffset.UtcNow);
        PrivateField<IDictionary>(client, "_sessions").Add(2L, session);

        var sent = await InvokePrivateAsync<bool>(client, "SendEncryptedPayloadAsync", 2L, "payload"u8.ToArray());

        Assert.True(sent);
        var relayMessages = await ReadRelayMessagesAsync(relay, 1);
        Assert.Single(relayMessages);
        Assert.Equal("send", JsonString(relayMessages[0], "type"));
        Assert.Equal("alloc-peer", JsonString(relayMessages[0], "toAllocationId"));
        Assert.Empty(await ReadUdpPayloadsAsync(direct, 1));
    }

    [Fact]
    public async Task RelayProbeDoesNotOverrideHealthyDirectLikeJava()
    {
        var client = new PeerMeshClient(new TunnelClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_runtime", new TunnelRuntimeState { PeerMesh = new PeerMeshConfig { Cidr = "100.96.0.0/11" } });
        var session = NewPeerMeshSession(
            id: 1001,
            peerId: 2,
            token: "token",
            remote: new IPEndPoint(IPAddress.Parse("192.0.2.10"), 51000),
            relayTargetAllocationId: "",
            pathType: "DIRECT",
            lastDirectSuccess: DateTimeOffset.UtcNow);
        PrivateField<IDictionary>(client, "_sessions").Add(2L, session);
        var pending = NewNested(client, "PendingProbe", 1001L, 2L, DateTimeOffset.UtcNow.AddMilliseconds(-10), true, "alloc-peer");
        PrivateField<IDictionary>(client, "_pending").Add("nonce-a", pending);
        var probe = NewNested(client, "PeerUdpProbe", "shuai-peer-mesh", "check-response", 1001L, 2L, 1L, "nonce-a", "token", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        await InvokePrivateAsync(client, "CompleteProbeAsync", probe, new IPEndPoint(IPAddress.Loopback, 7011), "alloc-peer");

        Assert.Equal("DIRECT", Property<string>(session, "PathType"));
        Assert.Equal("", Property<string>(session, "RelayTargetAllocationId"));
    }

    private static ECDiffieHellman? TryCreateX25519()
    {
        try
        {
            return PeerCrypto.CreateX25519();
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            return null;
        }
    }

    private static string InvokeNatType(PeerMeshClient client)
        => (string)typeof(PeerMeshClient)
            .GetMethod("NatType", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(client, [])!;

    private static T PrivateField<T>(object instance, string name)
        => (T)instance.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(instance)!;

    private static void SetPrivateField(object instance, string name, object value)
        => instance.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(instance, value);

    private static void InvokePrivate(object instance, string name, params object[] parameters)
        => instance.GetType()
            .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(instance, parameters);

    private static async Task InvokePrivateAsync(object instance, string name, params object[] parameters)
    {
        var task = (Task)instance.GetType()
            .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(instance, parameters)!;
        await task.ConfigureAwait(false);
    }

    private static async Task<T> InvokePrivateAsync<T>(object instance, string name, params object[] parameters)
    {
        var task = (Task<T>)instance.GetType()
            .GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(instance, parameters)!;
        return await task.ConfigureAwait(false);
    }

    private static object NewPeerMeshSession(
        long id,
        long peerId,
        string token,
        IPEndPoint remote,
        string relayTargetAllocationId,
        string pathType,
        DateTimeOffset lastDirectSuccess)
    {
        var session = NewNested(typeof(PeerMeshClient), "PeerMeshSession");
        SetProperty(session, "Id", id);
        SetProperty(session, "PeerId", peerId);
        SetProperty(session, "Token", token);
        SetProperty(session, "ExpiresAt", DateTimeOffset.UtcNow.AddMinutes(1));
        SetProperty(session, "RemoteEndpoint", remote);
        SetProperty(session, "RelayTargetAllocationId", relayTargetAllocationId);
        SetProperty(session, "PathType", pathType);
        SetProperty(session, "LastDirectSuccess", lastDirectSuccess);
        SetProperty(session, "AesKey", "0123456789abcdef0123456789abcdef"u8.ToArray());
        return session;
    }

    private static object NewNested(object instance, string name, params object?[] args) =>
        NewNested(instance.GetType(), name, args);

    private static object NewNested(Type owner, string name, params object?[] args)
    {
        var type = owner.GetNestedType(name, BindingFlags.NonPublic)!;
        return Activator.CreateInstance(
            type,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: args,
            culture: CultureInfo.InvariantCulture)!;
    }

    private static void SetProperty(object instance, string name, object? value) =>
        instance.GetType()
            .GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
            .SetValue(instance, value);

    private static T? Property<T>(object instance, string name) =>
        (T?)instance.GetType()
            .GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!
            .GetValue(instance);

    private static PeerMeshClient RelayTestClient(UdpClient udp, UdpClient relay)
    {
        var client = new PeerMeshClient(new TunnelClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_runtime", new TunnelRuntimeState
        {
            PeerMesh = new PeerMeshConfig
            {
                TurnHost = "127.0.0.1",
                TurnPort = ((IPEndPoint)relay.Client.LocalEndPoint!).Port,
            },
        });
        return client;
    }

    private static object PeerRelayMessage(
        string? probeRole = null,
        string? alternateAddress = null,
        int alternatePort = 0,
        string? observedByAddress = null,
        int observedByPort = 0)
    {
        var type = typeof(PeerMeshClient).GetNestedType("PeerRelayMessage", BindingFlags.NonPublic)!;
        var message = Activator.CreateInstance(type)!;
        type.GetProperty("ProbeRole")!.SetValue(message, probeRole);
        type.GetProperty("AlternateAddress")!.SetValue(message, alternateAddress);
        type.GetProperty("AlternatePort")!.SetValue(message, alternatePort);
        type.GetProperty("ObservedByAddress")!.SetValue(message, observedByAddress);
        type.GetProperty("ObservedByPort")!.SetValue(message, observedByPort);
        return message;
    }

    private static async Task<List<JsonElement>> ReadRelayMessagesAsync(UdpClient socket, int max)
    {
        var messages = new List<JsonElement>();
        for (var i = 0; i < max; i++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            try
            {
                var result = await socket.ReceiveAsync(cts.Token);
                using var document = JsonDocument.Parse(result.Buffer);
                messages.Add(document.RootElement.Clone());
            }
            catch (OperationCanceledException)
            {
                return messages;
            }
        }
        return messages;
    }

    private static async Task<List<byte[]>> ReadUdpPayloadsAsync(UdpClient socket, int max)
    {
        var messages = new List<byte[]>();
        for (var i = 0; i < max; i++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            try
            {
                var result = await socket.ReceiveAsync(cts.Token);
                messages.Add(result.Buffer);
            }
            catch (OperationCanceledException)
            {
                return messages;
            }
        }
        return messages;
    }

    private static string? JsonString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetString() : null;

    private static int? JsonInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? value.GetInt32() : null;

    private static byte[] MinimalTcpPacket(string source, ushort sourcePort, string target, ushort targetPort)
    {
        var packet = new byte[40];
        packet[0] = 0x45;
        packet[2] = 0;
        packet[3] = (byte)packet.Length;
        packet[8] = 64;
        packet[9] = 6;
        var sourceBytes = System.Net.IPAddress.Parse(source).GetAddressBytes();
        var targetBytes = System.Net.IPAddress.Parse(target).GetAddressBytes();
        sourceBytes.CopyTo(packet.AsSpan(12, 4));
        targetBytes.CopyTo(packet.AsSpan(16, 4));
        packet[20] = (byte)(sourcePort >> 8);
        packet[21] = (byte)sourcePort;
        packet[22] = (byte)(targetPort >> 8);
        packet[23] = (byte)targetPort;
        return packet;
    }

    private static byte[] MinimalIcmpEchoRequest(string source, string target)
    {
        var packet = new byte[32];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = 1;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet.AsSpan(12, 4));
        IPAddress.Parse(target).GetAddressBytes().CopyTo(packet.AsSpan(16, 4));
        packet[20] = 8;
        packet[21] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(24, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), 1);
        new byte[] { 1, 2, 3, 4 }.CopyTo(packet.AsSpan(28));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), PeerIpPacket.Checksum(packet.AsSpan(20)));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10, 2), PeerIpPacket.Checksum(packet.AsSpan(0, 20)));
        return packet;
    }
}
