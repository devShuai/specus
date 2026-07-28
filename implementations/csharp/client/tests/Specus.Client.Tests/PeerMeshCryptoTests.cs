using System.Buffers.Binary;
using System.Collections;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;

namespace Specus.Client.Tests;

public sealed class PeerMeshCryptoTests
{
    [Theory]
    [InlineData("192.0.2.20", true)]
    [InlineData("100.96.0.20", false)]
    [InlineData("2001:db8::20", true)]
    [InlineData("fd00::20", false)]
    [InlineData("fe80::20", false)]
    public void HostCandidateFilteringSupportsGlobalIpv6(string address, bool expected)
    {
        Assert.Equal(expected,
            PeerMeshClient.IsUsablePeerHostAddress(IPAddress.Parse(address), "100.96.0.0/11"));
    }

    [Fact]
    public void PeerUdpSocketUsesDualStackWhenAvailable()
    {
        using var udp = PeerMeshClient.CreatePeerUdpClient();
        Assert.NotNull(udp.Client.LocalEndPoint);
        if (Socket.OSSupportsIPv6 && udp.Client.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Assert.True(udp.Client.DualMode);
        }
    }

    [Fact]
    public void DataFrameRoundTrips()
    {
        var key = Enumerable.Repeat((byte)7, 32).ToArray();
        var frame = PeerDataFrameCodec.Encode(key, 1001, 1, 2, "epoch-a", 1, "hello peer mesh"u8);

        var decoded = PeerDataFrameCodec.Decode(key, 1, 2, "epoch-a", frame);

        Assert.Equal(1001, PeerDataFrameCodec.SessionId(frame));
        Assert.Equal(1001, decoded.SessionId);
        Assert.Equal(1, decoded.Sequence);
        Assert.Equal("hello peer mesh"u8.ToArray(), decoded.Payload);
    }

    [Fact]
    public void DataFrameRejectsWrongKey()
    {
        var frame = PeerDataFrameCodec.Encode(Enumerable.Repeat((byte)7, 32).ToArray(), 1001, 1, 2, "epoch-a", 1, "payload"u8);

        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Decode(Enumerable.Repeat((byte)8, 32).ToArray(), 1, 2, "epoch-a", frame));
    }

    [Fact]
    public void DataFrameRejectsTrailingBytes()
    {
        var key = Enumerable.Repeat((byte)7, 32).ToArray();
        var frame = PeerDataFrameCodec.Encode(key, 1001, 1, 2, "epoch-a", 1, "payload"u8);

        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Decode(key, 1, 2, "epoch-a", [.. frame, 0]));
    }

    [Fact]
    public void DataFrameMatchesCanonicalVectorWithDirectionalKey()
    {
        var vector = ProtocolVectorTestHelper.Read<PeerMeshVector>(
            "protocol/test-vectors/peer-mesh-spm2.json");
        var key = Convert.FromHexString(vector.SessionKeyHex);
        var frame = PeerDataFrameCodec.Encode(
            key,
            vector.SessionId,
            vector.FromClientId,
            vector.ToClientId,
            vector.SenderKeyEpoch,
            vector.Sequence,
            Encoding.UTF8.GetBytes(vector.PlaintextUtf8));

        Assert.Equal(Convert.FromHexString(vector.FrameHex), frame);
        var decoded = PeerDataFrameCodec.Decode(key, vector.FromClientId, vector.ToClientId, vector.SenderKeyEpoch, frame);

        Assert.True(PeerDataFrameCodec.LooksLikeDataFrame(frame));
        Assert.Equal(vector.SessionId, PeerDataFrameCodec.SessionId(frame));
        Assert.Equal(vector.Sequence, decoded.Sequence);
        Assert.Equal(Encoding.UTF8.GetBytes(vector.PlaintextUtf8), decoded.Payload);

        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Decode(key, vector.ToClientId, vector.FromClientId, vector.SenderKeyEpoch, frame));
        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Encode(
                key, vector.SessionId, vector.FromClientId, vector.ToClientId,
                vector.SenderKeyEpoch, 0, ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void KeyEpochIsolatesNonceSpaceAcrossRestarts()
    {
        // A restarted client may be handed back the same sessionId/token while its sequence
        // restarts at 1. The epoch must change the traffic key, otherwise the same nonce space
        // is replayed under the same AES-GCM key.
        var key = Enumerable.Repeat((byte)7, 32).ToArray();
        var before = PeerDataFrameCodec.Encode(key, 1001, 1, 2, "epoch-before-restart", 1, "payload"u8);
        var after = PeerDataFrameCodec.Encode(key, 1001, 1, 2, "epoch-after-restart", 1, "payload"u8);

        Assert.NotEqual(before, after);
        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Decode(key, 1, 2, "epoch-after-restart", before));
        Assert.ThrowsAny<CryptographicException>(() =>
            PeerDataFrameCodec.Encode(key, 1001, 1, 2, "  ", 1, "payload"u8));
    }

    [Fact]
    public void DataFrameSessionIdRejectsMalformedFrame()
    {
        Assert.Null(PeerDataFrameCodec.SessionId([1, 2, 3]));
    }

    [Fact]
    public void ReplayWindowRejectsDuplicatesAndOldPackets()
    {
        var window = new PeerReplayWindow();

        Assert.True(window.Accept(10));
        Assert.False(window.Accept(10));
        Assert.True(window.Accept(9));
        Assert.False(window.Accept(9));
        Assert.True(window.Accept(5000));
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
    public void TcpSynMssIsClampedToPathMtu()
    {
        var packet = TcpSynWithMss("100.103.117.15", 51000, "100.112.186.105", 8006, 1460);

        var clamped = PeerIpPacket.ClampTcpMss(packet, 1280);

        Assert.NotSame(packet, clamped);
        Assert.Equal((ushort)1240, BinaryPrimitives.ReadUInt16BigEndian(clamped.AsSpan(42, 2)));
        Assert.Equal(
            BinaryPrimitives.ReadUInt16BigEndian(clamped.AsSpan(36, 2)),
            TcpChecksum(clamped));
    }

    [Fact]
    public void OversizedIpv4PacketProducesIcmpFragmentationNeeded()
    {
        var packet = new byte[1400];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = 17;
        IPAddress.Parse("100.103.117.15").GetAddressBytes().CopyTo(packet.AsSpan(12, 4));
        IPAddress.Parse("100.112.186.105").GetAddressBytes().CopyTo(packet.AsSpan(16, 4));

        var response = PeerIpPacket.IcmpFragmentationNeededFor(packet, 1280);

        Assert.NotNull(response);
        Assert.Equal(3, response[20]);
        Assert.Equal(4, response[21]);
        Assert.Equal((ushort)1280, BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(26, 2)));
        Assert.Equal((ushort)0, PeerIpPacket.Checksum(response.AsSpan(0, 20)));
        Assert.Equal((ushort)0, PeerIpPacket.Checksum(response.AsSpan(20)));
    }

    [Fact]
    public void PeerMeshCidrNetworkAddressIsCalculatedForRouteConfiguration()
    {
        Assert.Equal("100.96.0.0", PeerVirtualDeviceHelpers.IPv4NetworkAddress("100.96.1.2/11"));
        Assert.Equal("10.23.42.0", PeerVirtualDeviceHelpers.IPv4NetworkAddress("10.23.42.17/24"));
    }

    [Fact]
    public void X25519RawMatchesRfc7748Vector()
    {
        var alicePrivate = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var alicePublic = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        var bobPrivate = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        var bobPublic = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        var shared = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        Assert.Equal(alicePublic, PeerCrypto.X25519Raw(alicePrivate, Convert.FromHexString("0900000000000000000000000000000000000000000000000000000000000000")));
        Assert.Equal(shared, PeerCrypto.X25519Raw(alicePrivate, bobPublic));
        Assert.Equal(shared, PeerCrypto.X25519Raw(bobPrivate, alicePublic));
    }

    [Fact]
    public void DeriveAesKeyMatchesBothSides()
    {
        var alice = PeerCrypto.GenerateKeyMaterial();
        var bob = PeerCrypto.GenerateKeyMaterial();

        var aliceKey = PeerCrypto.DeriveAes256Key(alice.PrivateKeyBase64, bob.PublicKeyBase64, 1001, "token", 1, 2);
        var bobKey = PeerCrypto.DeriveAes256Key(bob.PrivateKeyBase64, alice.PublicKeyBase64, 1001, "token", 2, 1);

        Assert.Equal(aliceKey, bobKey);
    }

    [Fact]
    public void NatTypeUsesJavaEnumNames()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
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
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);

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
        var first = await ReadStunMessagesAsync(relay, 2);
        Assert.Equal(StunMessage.BindingRequest, first[0].Type);
        Assert.Equal(StunMessage.AllocateRequest, first[1].Type);

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        Assert.Empty(await ReadStunMessagesAsync(relay, 1));
    }

    [Fact]
    public async Task RelayRefreshRequestIsThrottledLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = RelayTestClient(udp, relay);
        SetPrivateField(client, "_relayId", "127.0.0.1:50001");
        SetPrivateField(client, "_relayTtl", DateTimeOffset.UtcNow.AddMinutes(2));

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        var first = await ReadStunMessagesAsync(relay, 2);
        Assert.Equal(StunMessage.BindingRequest, first[0].Type);
        Assert.Equal(StunMessage.RefreshRequest, first[1].Type);

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        Assert.Empty(await ReadStunMessagesAsync(relay, 1));
    }

    [Fact]
    public async Task IndependentStunEndpointStartsRfc5780FilteringProbe()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var stun = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var turn = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var cancellation = new CancellationTokenSource();
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_cts", cancellation);
        SetPrivateField(client, "_runtime", new SpecusRuntimeState
        {
            PeerMesh = new PeerMeshConfig
            {
                StunHost = "127.0.0.1",
                StunPort = ((IPEndPoint)stun.Client.LocalEndPoint!).Port,
                TurnHost = "127.0.0.1",
                TurnPort = ((IPEndPoint)turn.Client.LocalEndPoint!).Port,
            },
        });

        await InvokePrivateAsync(client, "RequestRelayCandidatesAsync");
        var binding = Assert.Single(await ReadStunMessagesAsync(stun, 1));
        var allocate = Assert.Single(await ReadStunMessagesAsync(turn, 1));
        Assert.Equal(StunMessage.BindingRequest, binding.Type);
        Assert.Equal(StunMessage.AllocateRequest, allocate.Type);
        Assert.Empty(await ReadStunMessagesAsync(turn, 1));

        var primary = (IPEndPoint)stun.Client.LocalEndPoint!;
        var otherPort = primary.Port == 65535 ? primary.Port - 1 : primary.Port + 1;
        var mapped = new IPEndPoint(IPAddress.Parse("198.51.100.20"), 52000);
        var success = StunMessage.Of(
            StunMessage.BindingSuccess,
            binding.TransactionId,
            StunMessage.XorMappedAddress(mapped, binding.TransactionId),
            StunMessage.ResponseOrigin(primary, binding.TransactionId),
            StunMessage.OtherAddress(
                new IPEndPoint(IPAddress.Parse("127.0.0.2"), otherPort),
                binding.TransactionId));
        await InvokePrivateAsync(client, "HandleStunTurnMessageAsync", success, primary);

        var filter = Assert.Single(await ReadStunMessagesAsync(stun, 1));
        var change = Assert.IsType<StunChangeRequest>(filter.ChangeRequest());
        Assert.True(change.ChangeIp);
        Assert.True(change.ChangePort);
        await cancellation.CancelAsync();
    }

    [Fact]
    public async Task AlternateProbeRequestIsThrottledLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var alternate = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_runtime", new SpecusRuntimeState { PeerMesh = new PeerMeshConfig { Cidr = "100.96.0.0/11" } });
        var alternateEndpoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint)alternate.Client.LocalEndPoint!).Port);

        await InvokePrivateAsync(client, "RequestAlternateProbeAsync", "primary", alternateEndpoint, new IPEndPoint(IPAddress.Loopback, 3478));
        var first = await ReadStunMessagesAsync(alternate, 1);
        Assert.Equal(StunMessage.BindingRequest, first[0].Type);

        await InvokePrivateAsync(client, "RequestAlternateProbeAsync", "primary", alternateEndpoint, new IPEndPoint(IPAddress.Loopback, 3478));
        Assert.Empty(await ReadStunMessagesAsync(alternate, 1));
    }

    [Fact]
    public void StunBindingResponseCarriesMappedAndOtherAddressLikeJava()
    {
        var transactionId = StunMessage.NewTransactionId();
        var message = StunMessage.Of(
            StunMessage.BindingSuccess,
            transactionId,
            StunMessage.XorMappedAddress(new IPEndPoint(IPAddress.Parse("203.0.113.20"), 3480), transactionId),
            StunMessage.OtherAddress(new IPEndPoint(IPAddress.Parse("203.0.113.10"), 3479), transactionId));
        var decoded = StunMessage.Parse(message.ToBytes())!;

        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.20"), 3480), decoded.XorMappedAddress());
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.10"), 3479), decoded.OtherAddress());
    }

    [Fact]
    public void StunRfc5780AttributesRoundTrip()
    {
        var transactionId = StunMessage.NewTransactionId();
        var origin = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 3478);
        var other = new IPEndPoint(IPAddress.Parse("203.0.113.11"), 3479);
        var message = StunMessage.Of(
            StunMessage.BindingError,
            transactionId,
            StunMessage.ResponseOrigin(origin, transactionId),
            StunMessage.OtherAddress(other, transactionId),
            StunMessage.ChangeRequest(true, true),
            StunMessage.UnknownAttributes(StunMessage.AttrChangeRequest));
        var decoded = StunMessage.Parse(message.ToBytes())!;

        Assert.Equal(origin, decoded.ResponseOrigin());
        Assert.Equal(other, decoded.OtherAddress());
        var change = Assert.IsType<StunChangeRequest>(decoded.ChangeRequest());
        Assert.True(change.ChangeIp);
        Assert.True(change.ChangePort);
        Assert.Equal([StunMessage.AttrChangeRequest], decoded.UnknownAttributes());
    }

    [Fact]
    public async Task SendEncryptedPayloadUsesRelayAllocationLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var direct = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var client = RelayTestClient(udp, relay);
        SetPrivateField(client, "_relayId", "127.0.0.1:50001");
        SetPrivateField(client, "_relayTtl", DateTimeOffset.UtcNow.AddMinutes(2));
        var peerRelay = $"127.0.0.1:{((IPEndPoint)relay.Client.LocalEndPoint!).Port + 1}";
        var session = NewPeerMeshSession(
            id: 1001,
            peerId: 2,
            token: "token",
            remote: (IPEndPoint)direct.Client.LocalEndPoint!,
            relayTargetAllocationId: peerRelay,
            pathType: "DIRECT",
            lastDirectSuccess: DateTimeOffset.UtcNow);
        PrivateField<IDictionary>(client, "_sessions").Add(2L, session);

        var sent = await InvokePrivateAsync<bool>(client, "SendEncryptedPayloadAsync", 2L, "payload"u8.ToArray());

        Assert.True(sent);
        var relayMessages = await ReadStunMessagesAsync(relay, 3);
        Assert.Equal(3, relayMessages.Count);
        Assert.Equal(StunMessage.CreatePermissionRequest, relayMessages[0].Type);
        Assert.Equal(ParseEndpoint(peerRelay), relayMessages[0].XorPeerAddress());
        Assert.Equal(StunMessage.ChannelBindRequest, relayMessages[1].Type);
        Assert.Equal(ParseEndpoint(peerRelay), relayMessages[1].XorPeerAddress());
        Assert.Equal(StunMessage.SendIndication, relayMessages[2].Type);
        Assert.Equal(ParseEndpoint(peerRelay), relayMessages[2].XorPeerAddress());
        Assert.Empty(await ReadUdpPayloadsAsync(direct, 1));
    }

    [Fact]
    public async Task RelayProbeDoesNotOverrideHealthyDirectLikeJava()
    {
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_runtime", new SpecusRuntimeState { PeerMesh = new PeerMeshConfig { Cidr = "100.96.0.0/11" } });
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
        var probe = NewNested(client, "PeerUdpProbe", "specus-peer-mesh", "check-response", 1001L, 2L, 1L, "nonce-a", "token", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        await InvokePrivateAsync(client, "CompleteProbeAsync", probe, new IPEndPoint(IPAddress.Loopback, 7011), "alloc-peer");

        Assert.Equal("DIRECT", Property<string>(session, "PathType"));
        Assert.Equal("", Property<string>(session, "RelayTargetAllocationId"));
    }

    [Fact]
    public async Task DirectKeepaliveUsesNominatedEndpointLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var direct = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var cts = new CancellationTokenSource();
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_cts", cts);
        SetPrivateField(client, "_runtime", new SpecusRuntimeState
        {
            PeerMesh = new PeerMeshConfig
            {
                ClientId = 1,
                Cidr = "100.96.0.0/11",
            },
        });
        var session = NewPeerMeshSession(
            id: 1001,
            peerId: 2,
            token: "token",
            remote: (IPEndPoint)direct.Client.LocalEndPoint!,
            relayTargetAllocationId: "",
            pathType: "DIRECT",
            lastDirectSuccess: DateTimeOffset.UtcNow);
        PrivateField<IDictionary>(client, "_sessions").Add(2L, session);

        await InvokePrivateAsync(client, "KeepaliveDirectPathsAsync");

        var payloads = await ReadUdpPayloadsAsync(direct, 3);
        Assert.Equal(3, payloads.Count);
        var payload = payloads[0];
        using var json = JsonDocument.Parse(payload);
        Assert.Equal("specus-peer-mesh", json.RootElement.GetProperty("magic").GetString());
        Assert.Equal("check", json.RootElement.GetProperty("type").GetString());
        Assert.Equal(1001, json.RootElement.GetProperty("sessionId").GetInt64());
        Assert.Equal("token", json.RootElement.GetProperty("token").GetString());
        Assert.Single(PrivateField<IDictionary>(client, "_pending"));

        await InvokePrivateAsync(client, "KeepaliveDirectPathsAsync");
        Assert.Empty(await ReadUdpPayloadsAsync(direct, 1));
    }

    [Fact]
    public void MergeRosterToleratesMissingCandidateList()
    {
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        var peer = NewNested(
            typeof(PeerMeshClient),
            "PeerMeshPeer",
            2L,
            "peer-a",
            "100.112.0.2",
            "public-key",
            true,
            false,
            false,
            false,
            false,
            0L,
            null);

        InvokePrivate(client, "MergeRoster", NewPeerList(peer));

        var peers = PrivateField<IDictionary>(client, "_peers");
        var stored = peers[2L]!;
        var candidates = Assert.IsAssignableFrom<ICollection>(Property<object>(stored, "Candidates"));
        Assert.Empty(candidates);
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
        SetProperty(session, "LocalKeyEpoch", "epoch-local");
        session.GetType()
            .GetMethod("ApplyRemoteKeyEpoch", BindingFlags.Instance | BindingFlags.Public)!
            .Invoke(session, ["epoch-remote"]);
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

    private static object NewPeerList(params object[] peers)
    {
        var peerType = typeof(PeerMeshClient).GetNestedType("PeerMeshPeer", BindingFlags.NonPublic)!;
        var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(peerType))!;
        foreach (var peer in peers)
        {
            list.Add(peer);
        }
        return list;
    }

    private static PeerMeshClient RelayTestClient(UdpClient udp, UdpClient relay)
    {
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_runtime", new SpecusRuntimeState
        {
            PeerMesh = new PeerMeshConfig
            {
                ClientId = 1,
                TurnHost = "127.0.0.1",
                TurnPort = ((IPEndPoint)relay.Client.LocalEndPoint!).Port,
            },
        });
        return client;
    }

    private static async Task<List<StunMessage>> ReadStunMessagesAsync(UdpClient socket, int max)
    {
        var messages = new List<StunMessage>();
        for (var i = 0; i < max; i++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            try
            {
                var result = await socket.ReceiveAsync(cts.Token);
                var message = StunMessage.Parse(result.Buffer);
                if (message is not null)
                {
                    messages.Add(message);
                }
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

    private static IPEndPoint ParseEndpoint(string value)
    {
        var index = value.LastIndexOf(':');
        Assert.True(index > 0);
        return new IPEndPoint(IPAddress.Parse(value[..index]), int.Parse(value[(index + 1)..], CultureInfo.InvariantCulture));
    }

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

    private static byte[] TcpSynWithMss(
        string source,
        ushort sourcePort,
        string target,
        ushort targetPort,
        ushort mss)
    {
        var packet = new byte[44];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = 6;
        IPAddress.Parse(source).GetAddressBytes().CopyTo(packet.AsSpan(12, 4));
        IPAddress.Parse(target).GetAddressBytes().CopyTo(packet.AsSpan(16, 4));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), targetPort);
        packet[32] = 0x60;
        packet[33] = 0x02;
        packet[40] = 2;
        packet[41] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(42, 2), mss);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(36, 2), TcpChecksum(packet));
        return packet;
    }

    private static ushort TcpChecksum(byte[] packet)
    {
        var copy = packet.ToArray();
        copy[36] = 0;
        copy[37] = 0;
        var pseudo = new byte[12 + copy.Length - 20];
        copy.AsSpan(12, 8).CopyTo(pseudo);
        pseudo[9] = 6;
        BinaryPrimitives.WriteUInt16BigEndian(pseudo.AsSpan(10, 2), (ushort)(copy.Length - 20));
        copy.AsSpan(20).CopyTo(pseudo.AsSpan(12));
        return PeerIpPacket.Checksum(pseudo);
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

    /// <summary>通过反射构造私有嵌套 record PeerCandidate（8 个位置参数全部显式传入）。</summary>
    private static object NewPeerCandidate(
        string type, string transport, string address, int port, long priority, string foundation)
        => NewNested(typeof(PeerMeshClient), "PeerCandidate", type, transport, address, port, priority, foundation, "", null);

    /// <summary>读取 PeerCandidate 的 Priority 属性。</summary>
    private static long CandidatePriority(object candidate)
        => Property<long>(candidate, "Priority");

    /// <summary>读取 PeerCandidate 的 Address 属性。</summary>
    private static string? CandidateAddress(object candidate)
        => Property<string?>(candidate, "Address");

    /// <summary>调用私有方法 SortedConnectivityCandidates 并返回结果列表。</summary>
    private static IList InvokeSortedConnectivityCandidates(PeerMeshClient client, IList candidates)
    {
        var candidateType = typeof(PeerMeshClient).GetNestedType("PeerCandidate", BindingFlags.NonPublic)!;
        var listType = typeof(List<>).MakeGenericType(candidateType);
        var typedInput = (IList)Activator.CreateInstance(listType)!;
        foreach (var c in candidates)
        {
            typedInput.Add(c);
        }
        var result = typeof(PeerMeshClient)
            .GetMethod("SortedConnectivityCandidates", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(client, [typedInput])!;
        return (IList)result;
    }

    [Fact]
    public void SendConnectivityChecksSortsCandidatesByPriorityDescendingLikeJava()
    {
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        var input = new ArrayList
        {
            NewPeerCandidate("srflx", "udp", "203.0.113.10", 30001, 800, "standard-stun"),
            NewPeerCandidate("host", "udp", "192.168.1.5", 40000, 1000, "host"),
            NewPeerCandidate("srflx", "udp", "203.0.113.20", 30002, 900, "public-stun"),
        };
        var sorted = InvokeSortedConnectivityCandidates(client, input);
        Assert.Equal(3, sorted.Count);
        // 期望顺序：1000 (host) -> 900 (public-stun) -> 800 (srflx)
        Assert.Equal(1000, CandidatePriority(sorted[0]!));
        Assert.Equal(900, CandidatePriority(sorted[1]!));
        Assert.Equal(800, CandidatePriority(sorted[2]!));
    }

    [Fact]
    public void SameNatReflexiveCandidatesAreDemotedNotPrunedLikeJava()
    {
        var localAddr = "203.0.113.42";
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        var localSrflx = NewPeerCandidate("srflx", "udp", localAddr, 34567, 800, "standard-stun");
        SetPrivateField(client, "_srflx", localSrflx);
        var input = new ArrayList
        {
            // 同 NAT 的 srflx：应被降权到 priority=1
            NewPeerCandidate("srflx", "udp", localAddr, 34567, 800, "standard-stun"),
            // 不同地址的 srflx：保持原 priority
            NewPeerCandidate("srflx", "udp", "203.0.113.99", 35000, 800, "public-stun"),
            // host 候选：不受影响
            NewPeerCandidate("host", "udp", "192.168.1.5", 40000, 1000, "host"),
        };
        var sorted = InvokeSortedConnectivityCandidates(client, input);
        // 降权不剪除：数量不变
        Assert.Equal(3, sorted.Count);
        // 期望顺序：1000 (host) -> 800 (不同地址 srflx) -> 1 (同 NAT 被降权 srflx)
        Assert.Equal(1000, CandidatePriority(sorted[0]!));
        Assert.Equal(1, CandidatePriority(sorted[2]!));
        Assert.Equal(localAddr, CandidateAddress(sorted[2]!));
        // 不同地址的 srflx 必须保持原 priority=800
        Assert.Equal(800, CandidatePriority(sorted[1]!));
        Assert.Equal("203.0.113.99", CandidateAddress(sorted[1]!));
    }

    [Fact]
    public void SameNatPortMapCandidatesAreDemotedLikeJava()
    {
        var localAddr = "203.0.113.42";
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        var localSrflx = NewPeerCandidate("srflx", "udp", localAddr, 34567, 900, "standard-stun");
        SetPrivateField(client, "_srflx", localSrflx);
        var input = new ArrayList
        {
            // port-map 候选与本地 srflx 同地址：应被降权到 priority=1
            NewPeerCandidate("srflx", "udp", localAddr, 34567, 900, "port-map-1"),
            NewPeerCandidate("host", "udp", "192.168.1.5", 40000, 1000, "host"),
        };
        var sorted = InvokeSortedConnectivityCandidates(client, input);
        Assert.Equal(2, sorted.Count);
        // host (1000) 排前，被降权的 port-map (1) 排后
        Assert.Equal(1000, CandidatePriority(sorted[0]!));
        Assert.Equal(1, CandidatePriority(sorted[1]!));
    }

    [Fact]
    public async Task CandidateReciprocationThrottlesPerPeerLikeJava()
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        using var cancellation = new CancellationTokenSource();
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        SetPrivateField(client, "_udp", udp);
        SetPrivateField(client, "_cts", cancellation);
        SetPrivateField(client, "_runtime", new SpecusRuntimeState
        {
            PeerMesh = new PeerMeshConfig { ClientId = 1, ClientName = "cs-a", VirtualIp = "100.96.0.1" },
        });
        SetPrivateField(client, "_srflx", NewPeerCandidate("srflx", "udp", "203.0.113.10", 34567, 800, "standard-stun"));

        // 注入一个在线 peer，但无 session（无健康 direct 路径）-> 应触发回礼
        var peer = NewNested(
            typeof(PeerMeshClient),
            "PeerMeshPeer",
            2L,
            "java-b",
            "100.96.0.2",
            "peer-key",
            true,
            false,
            false,
            false,
            false,
            0L,
            null);
        InvokePrivate(client, "MergeRoster", NewPeerList(peer));

        // 第一次回礼：节流状态被记录（announceCandidatesToPeerAsync 无 writer 时静默返回，
        // 但 candidateReciprocateAt 已记录时间戳）。第二次立即调用：2s 内应被节流跳过，
        // 不会覆盖已记录的时间戳。
        var before = DateTimeOffset.UtcNow;
        await InvokePrivateAsync(client, "ReciprocateCandidatesAsync", 2L);
        await InvokePrivateAsync(client, "ReciprocateCandidatesAsync", 2L);

        // 验证节流：candidateReciprocateAt[2] 已记录，且时间戳是第一次（before 之后不久）
        var reciprocateAt = PrivateField<IDictionary>(client, "_candidateReciprocateAt");
        Assert.True(reciprocateAt.Contains(2L));
        var recorded = (DateTimeOffset)reciprocateAt[2L]!;
        Assert.InRange(recorded, before, before.AddSeconds(2));
    }

    [Fact]
    public async Task HolePunchRetriesStopOnHealthyDirectLikeJava()
    {
        var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        var session = NewPeerMeshSession(
            id: 7001,
            peerId: 2,
            token: "tok",
            remote: new IPEndPoint(IPAddress.Loopback, 9),
            relayTargetAllocationId: "",
            pathType: "",
            lastDirectSuccess: DateTimeOffset.MinValue); // 无健康 direct
        var sessionsById = PrivateField<IDictionary>(client, "_sessionsById");
        sessionsById[7001L] = session;

        // 无健康 direct：排程应成功标记
        InvokePrivate(client, "ScheduleHolePunchRetries", session);
        var scheduled = PrivateField<IDictionary>(client, "_holePunchRetryScheduled");
        Assert.True(scheduled.Contains(2L));

        // 建立健康 direct 路径后，RetryHolePunch 应清除标记并停止
        SetProperty(session, "PathType", "DIRECT");
        SetProperty(session, "LastDirectSuccess", DateTimeOffset.UtcNow);
        await InvokePrivateAsync(client, "RetryHolePunch", 2L, 7001L);

        scheduled = PrivateField<IDictionary>(client, "_holePunchRetryScheduled");
        Assert.False(scheduled.Contains(2L));
    }

    private sealed class PeerMeshVector
    {
        public required string SessionKeyHex { get; init; }
        public long SessionId { get; init; }
        public long FromClientId { get; init; }
        public long ToClientId { get; init; }
        public required string SenderKeyEpoch { get; init; }
        public long Sequence { get; init; }
        public required string PlaintextUtf8 { get; init; }
        public required string FrameHex { get; init; }
    }
}
