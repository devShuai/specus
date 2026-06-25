using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Protocol.Tests;

public class PacketCodecFixtureTests
{
    [Fact]
    public void LoginRequest_Roundtrips()
    {
        var packet = new LoginRequestPacket
        {
            ClientName = "Demo client",
            ClientSessionId = 123456789L,
            AccessToken = "cs_fixture_token",
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = decodedPacket as LoginRequestPacket;

        Assert.NotNull(decoded);
        Assert.Equal(packet.ClientName, decoded!.ClientName);
        Assert.Equal(packet.ClientSessionId, decoded.ClientSessionId);
        Assert.Equal(packet.AccessToken, decoded.AccessToken);
    }

    [Fact]
    public void LoginRequest_ZeroClientSessionId_EncodesAsNonNullLongLikeJava()
    {
        var packet = new LoginRequestPacket
        {
            ClientName = "csharp-client",
            ClientSessionId = 0,
            AccessToken = "token",
        };

        var encoded = PacketCodec.Encode(packet);
        var raw = CompactBinarySerializer.DecodePayload(encoded[PacketCodec.HeaderSize..]);
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

    [Fact]
    public void HttpRequest_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<HttpRequestPacket>("http_request.bin", p =>
        {
            Assert.Equal("Demo client", p.ClientName);
            Assert.Equal("upstream", p.ToClientName);
            Assert.Equal("123e4567-e89b-12d3-a456-426614174000", p.RequestId);
            Assert.Equal("POST", p.RequestMethod);
            Assert.Equal("http://127.0.0.1:8080/api/demo", p.RequestUrl);
            Assert.NotNull(p.HeaderMap);
            Assert.Equal(2, p.HeaderMap!.Count);
            Assert.Equal("application/json", p.HeaderMap["Content-Type"]);
            Assert.Equal("fixture-1", p.HeaderMap["X-Request-Id"]);
            Assert.NotNull(p.ParamMap);
            Assert.Equal("10", p.ParamMap!["limit"]);
            Assert.Equal("{\"hello\":\"world\"}", p.Body);
        });
    }

    [Fact]
    public void HttpResponse_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<HttpResponsePacket>("http_response.bin", p =>
        {
            Assert.Equal("upstream", p.ClientName);
            Assert.Equal("Demo client", p.ToClientName);
            Assert.Equal("123e4567-e89b-12d3-a456-426614174000", p.RequestId);
            Assert.Equal("{\"ok\":true}", p.Response);
        });
    }

    [Fact]
    public void DirectHttpRequest_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<DirectHttpRequestPacket>("direct_http_request.bin", p =>
        {
            Assert.Equal("11111111-2222-3333-4444-555555555555", p.RequestId);
            Assert.Equal("GET", p.RequestMethod);
            Assert.Equal("api", p.Route);
            Assert.Equal("/v1/items", p.RelativePath);
            Assert.Equal("limit=10&page=1", p.RawQuery);
            Assert.NotNull(p.Headers);
            Assert.Collection(p.Headers!,
                h => Assert.Equal("accept: application/json", h),
                h => Assert.Equal("x-fixture: 1", h));
            Assert.NotNull(p.Body);
            Assert.Empty(p.Body!);
        });
    }

    [Fact]
    public void DirectHttpResponse_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<DirectHttpResponsePacket>("direct_http_response.bin", p =>
        {
            Assert.Equal("11111111-2222-3333-4444-555555555555", p.RequestId);
            Assert.Equal(200, p.StatusCode);
            Assert.NotNull(p.Headers);
            Assert.Single(p.Headers!);
            Assert.Equal("content-type: application/json", p.Headers![0]);
            Assert.NotNull(p.Body);
            Assert.Equal("{\"ok\":true}", System.Text.Encoding.UTF8.GetString(p.Body!));
            Assert.Null(p.Error);
        });
    }

    [Fact]
    public void DirectHttpResponseEmptyErrorPreservesNonNullStringLikeJava()
    {
        var packet = new DirectHttpResponsePacket
        {
            RequestId = "8b284fef-0987-4948-ac66-7f2059336989",
            StatusCode = 502,
            Headers = new List<string>(),
            Body = Array.Empty<byte>(),
            Error = "",
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = Assert.IsType<DirectHttpResponsePacket>(decodedPacket);

        Assert.NotNull(decoded.Error);
        Assert.Equal("", decoded.Error);
    }

    [Fact]
    public void UuidCodec_PreservesNonCanonicalCaseLikeJava()
    {
        var packet = new DirectHttpResponsePacket
        {
            RequestId = "8B284FEF-0987-4948-AC66-7F2059336989",
            StatusCode = 204,
            Headers = new List<string>(),
            Body = Array.Empty<byte>(),
            Error = null,
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = Assert.IsType<DirectHttpResponsePacket>(decodedPacket);

        Assert.Equal(packet.RequestId, decoded.RequestId);
    }

    [Fact]
    public void HttpMethodCodec_PreservesNonCanonicalCaseLikeJava()
    {
        var packet = new DirectHttpRequestPacket
        {
            RequestId = "8b284fef-0987-4948-ac66-7f2059336989",
            RequestMethod = "get",
            Route = "api",
            RelativePath = "/socket",
            RawQuery = "",
            Headers = new List<string>(),
            Body = Array.Empty<byte>(),
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decodedPacket, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var decoded = Assert.IsType<DirectHttpRequestPacket>(decodedPacket);

        Assert.Equal(packet.RequestMethod, decoded.RequestMethod);
    }

    [Fact]
    public void EmptyUuidAndHttpMethod_EncodeAsStringsLikeJava()
    {
        var packet = new DirectHttpRequestPacket
        {
            RequestId = "",
            RequestMethod = "",
            Route = "api",
            RelativePath = "/socket",
            RawQuery = "",
            Headers = new List<string>(),
            Body = Array.Empty<byte>(),
        };

        var encoded = PacketCodec.Encode(packet);
        var raw = CompactBinarySerializer.DecodePayload(encoded[PacketCodec.HeaderSize..]);

        Assert.Equal(2, raw[0]);
        Assert.Equal(1, raw[1]);
        Assert.Equal(5, raw[2]);
        Assert.Equal(1, raw[3]);
    }
}
