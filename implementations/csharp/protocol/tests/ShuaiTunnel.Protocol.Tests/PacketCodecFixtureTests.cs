using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Protocol.Tests;

public class PacketCodecFixtureTests
{
    private static readonly string[] MalformedFixtures =
    [
        "invalid_bad_magic.bin",
        "invalid_version_v1.bin",
        "invalid_serializer.bin",
        "invalid_unknown_command.bin",
        "invalid_truncated_header.bin",
        "invalid_truncated_body.bin",
        "invalid_trailing_body.bin",
        "invalid_heartbeat_body.bin",
        "invalid_oversized_length.bin",
    ];

    [Theory]
    [MemberData(nameof(GetMalformedFixtures))]
    public void MalformedCanonicalFrame_IsRejected(string fixtureName)
    {
        var bytes = Fixtures.Read(fixtureName);
        Assert.Throws<InvalidDataException>(() => PacketCodec.DecodeExact(bytes));
    }

    public static IEnumerable<object[]> GetMalformedFixtures() =>
        MalformedFixtures.Select(name => new object[] { name });

    [Fact]
    public void LoginRequest_Roundtrips()
    {
        var packet = new LoginRequestPacket
        {
            ClientName = "Demo client",
            ClientSessionId = 123456789L,
            AccessToken = "cs_fixture_token",
            ConnectionRole = ConnectionRole.Control,
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = decodedPacket as LoginRequestPacket;

        Assert.NotNull(decoded);
        Assert.Equal(packet.ClientName, decoded!.ClientName);
        Assert.Equal(packet.ClientSessionId, decoded.ClientSessionId);
        Assert.Equal(packet.AccessToken, decoded.AccessToken);
        Assert.Equal(packet.ConnectionRole, decoded.ConnectionRole);
    }

    [Fact]
    public void CanonicalLoginRequest_IncludesMandatoryControlRole()
    {
        Fixtures.DecodeAndAssertRoundtrip<LoginRequestPacket>("login_request.bin", packet =>
        {
            Assert.Equal("Demo client", packet.ClientName);
            Assert.Equal(1700000000000L, packet.ClientSessionId);
            Assert.Equal("cs_fixture_access_token", packet.AccessToken);
            Assert.Equal(ConnectionRole.Control, packet.ConnectionRole);
        });
    }

    [Fact]
    public void LoginRequest_ZeroClientSessionId_EncodesAsNonNullLongLikeJava()
    {
        var packet = new LoginRequestPacket
        {
            ClientName = "csharp-client",
            ClientSessionId = 0,
            AccessToken = "token",
            ConnectionRole = ConnectionRole.Control,
        };

        var encoded = PacketCodec.Encode(packet);
        var raw = encoded[PacketCodec.HeaderSize..];
        var nameLengthMarker = raw[0];
        var sessionMarkerIndex = 1 + nameLengthMarker - 1;

        Assert.Equal(1, raw[sessionMarkerIndex]);
        Assert.Equal(0, raw[sessionMarkerIndex + 1]);
    }

    [Fact]
    public void LoginResponse_Success_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<LoginResponsePacket>("login_response.bin", p =>
        {
            Assert.Equal("Demo client", p.ClientName);
            Assert.True(p.Success);
            Assert.Null(p.Reason);
        });
    }

    [Fact]
    public void LoginResponse_Failure_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<LoginResponsePacket>("login_response_fail.bin", p =>
        {
            Assert.Equal("Demo client", p.ClientName);
            Assert.False(p.Success);
            Assert.Equal("时间戳过期", p.Reason);
        });
    }

    [Fact]
    public void LogoutRequest_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<LogoutRequestPacket>("logout_request.bin", _ => { });
    }

    [Fact]
    public void LogoutResponse_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<LogoutResponsePacket>("logout_response.bin", p =>
        {
            Assert.True(p.Success);
            Assert.Null(p.Reason);
        });
    }

    [Fact]
    public void HeartbeatRequest_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<HeartbeatRequestPacket>("heartbeat_request.bin", _ => { });
    }

    [Fact]
    public void HeartbeatResponse_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<HeartbeatResponsePacket>("heartbeat_response.bin", _ => { });
    }

    [Fact]
    public void MessageRequest_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<MessageRequestPacket>("message_request.bin", p =>
        {
            Assert.Equal("Demo client", p.ClientName);
            Assert.Equal("admin", p.ToClientName);
            Assert.Equal(MessageType.ClientToServer, p.MessageType);
            Assert.Equal("hello, server", p.Message);
        });
    }

    [Fact]
    public void MessageRequest_PeerControl_Roundtrips()
    {
        var packet = new MessageRequestPacket
        {
            ClientName = "csharp-client",
            ToClientName = "",
            MessageType = MessageType.PeerControl,
            Message = "{\"type\":\"device-report\"}",
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = decodedPacket as MessageRequestPacket;

        Assert.NotNull(decoded);
        Assert.Equal(packet.ClientName, decoded!.ClientName);
        Assert.Equal(packet.ToClientName, decoded.ToClientName);
        Assert.Equal(packet.MessageType, decoded.MessageType);
        Assert.Equal(packet.Message, decoded.Message);
    }

    [Fact]
    public void MessageResponse_NatControl_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<MessageResponsePacket>("message_response.bin", p =>
        {
            Assert.Equal("admin", p.ClientName);
            Assert.Equal("Demo client", p.ToClientName);
            Assert.Equal(MessageType.NatControl, p.MessageType);
            Assert.Equal("{\"clientName\":\"Demo client\",\"remotePort\":7010}", p.Message);
        });
    }

    [Fact]
    public void MessageResponse_PeerControl_Roundtrips()
    {
        var packet = new MessageResponsePacket
        {
            ClientName = "server",
            ToClientName = "csharp-client",
            MessageType = MessageType.PeerControl,
            Message = "{\"type\":\"roster\",\"peers\":[]}",
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = decodedPacket as MessageResponsePacket;

        Assert.NotNull(decoded);
        Assert.Equal(packet.ClientName, decoded!.ClientName);
        Assert.Equal(packet.ToClientName, decoded.ToClientName);
        Assert.Equal(packet.MessageType, decoded.MessageType);
        Assert.Equal(packet.Message, decoded.Message);
    }

    [Theory]
    [InlineData((sbyte)5)]
    [InlineData((sbyte)-5)]
    [InlineData((sbyte)7)]
    [InlineData((sbyte)-7)]
    public void RemovedHttpCommands_AreRejected(sbyte removedCommand)
    {
        var frame = PacketCodec.Encode(new HeartbeatRequestPacket());
        frame[6] = unchecked((byte)removedCommand);

        Assert.Throws<InvalidDataException>(() => PacketCodec.DecodeExact(frame));
    }
}
