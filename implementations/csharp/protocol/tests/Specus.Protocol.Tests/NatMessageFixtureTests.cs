using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;

namespace Specus.Protocol.Tests;

public class NatMessageFixtureTests
{
    [Fact]
    public void Register_Roundtrips()
    {
        var nat = Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_register.bin", p =>
        {
            Assert.Equal(NatMessageType.Register, p.NatMessageType);
            Assert.NotNull(p.MetaData);
            Assert.Equal("Demo client", (string?)p.MetaData!["clientName"]);
            Assert.Equal(18080L, (long?)p.MetaData!["port"]);
            Assert.Equal("127.0.0.1", (string?)p.MetaData!["specusAddress"]);
            Assert.Equal(80L, (long?)p.MetaData!["specusPort"]);
            Assert.Null(p.Data);
        });
        _ = nat;
    }

    [Fact]
    public void RegisterResult_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_register_result.bin", p =>
        {
            Assert.Equal(NatMessageType.RegisterResult, p.NatMessageType);
            Assert.NotNull(p.MetaData);
            Assert.Equal(18080L, (long?)p.MetaData!["port"]);
            Assert.Equal(true, p.MetaData!["success"]);
            Assert.Null(p.Data);
        });
    }

    [Fact]
    public void Open_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_open.bin", p =>
        {
            Assert.Equal(NatMessageType.Open, p.NatMessageType);
            Assert.Equal(1U, p.StreamId);
            Assert.Equal("00010203-aaaa-bbbb-cccc-ddddeeeeffff", (string?)p.MetaData!["channelId"]);
            Assert.Equal(18080L, (long?)p.MetaData!["port"]);
            Assert.Null(p.Data);
        });
    }

    [Fact]
    public void Fin_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_fin.bin", p =>
        {
            Assert.Equal(NatMessageType.Fin, p.NatMessageType);
            Assert.Equal(1U, p.StreamId);
            Assert.Empty(p.MetaData!);
        });
    }

    [Fact]
    public void Rst_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_rst.bin", p =>
        {
            Assert.Equal(NatMessageType.Rst, p.NatMessageType);
            Assert.Equal(1U, p.StreamId);
            Assert.Equal(7U, p.Value);
            Assert.Equal("upstream reset", (string?)p.MetaData!["reason"]);
        });
    }

    [Fact]
    public void WindowUpdate_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_window_update.bin", p =>
        {
            Assert.Equal(NatMessageType.WindowUpdate, p.NatMessageType);
            Assert.Equal(1U, p.StreamId);
            Assert.Equal(65536U, p.Value);
            Assert.Empty(p.MetaData!);
        });
    }

    [Fact]
    public void Keepalive_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_keepalive.bin", p =>
        {
            Assert.Equal(NatMessageType.Keepalive, p.NatMessageType);
            Assert.NotNull(p.MetaData);
            Assert.Empty(p.MetaData!);
            Assert.Null(p.Data);
        });
    }

    [Fact]
    public void Unregister_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_unregister.bin", p =>
        {
            Assert.Equal(NatMessageType.Unregister, p.NatMessageType);
            Assert.Equal(18080L, (long?)p.MetaData!["port"]);
        });
    }

    [Fact]
    public void Data_Small_Raw_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_data_small.bin", p =>
        {
            Assert.Equal(NatMessageType.Data, p.NatMessageType);
            Assert.Equal(1U, p.StreamId);
            Assert.Empty(p.MetaData!);
            Assert.NotNull(p.Data);
            Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(p.Data!));
        });
    }

    [Fact]
    public void Data_Large_RawFromJava_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_data_large.bin", packet =>
        {
            Assert.Equal(NatMessageType.Data, packet.NatMessageType);
            Assert.NotNull(packet.Data);
            Assert.Equal(256, packet.Data!.Length);
            Assert.All(packet.Data, value => Assert.Equal((byte)'A', value));
        });
    }

    [Fact]
    public void Data_Large_NetEncodesAndSelfRoundtrips()
    {
        var payload = new byte[256];
        Array.Fill(payload, (byte)'A');
        var packet = new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 1,
            Data = payload,
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decoded, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var roundtrip = Assert.IsType<NatMessagePacket>(decoded);
        Assert.Equal(payload, roundtrip.Data);
    }

    [Fact]
    public void HttpStream_ResponseHeadAndTrailers_RoundtripAcrossLanguages()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("http_stream_response_open.bin", packet =>
        {
            Assert.Equal(NatMessageType.Open, packet.NatMessageType);
            Assert.Equal(101U, packet.StreamId);
            Assert.Equal("http", packet.MetaData!["source"]);
            Assert.Equal("response", packet.MetaData["phase"]);
            Assert.Equal(200L, packet.MetaData["statusCode"]);
            var names = Assert.IsAssignableFrom<IEnumerable<object?>>(packet.MetaData["trailerNames"]);
            Assert.Equal("Digest", Assert.Single(names));
        });

        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("http_stream_response_fin.bin", packet =>
        {
            Assert.Equal(NatMessageType.Fin, packet.NatMessageType);
            var trailers = Assert.IsAssignableFrom<IEnumerable<object?>>(packet.MetaData!["trailers"]);
            Assert.Equal("Digest:sha-256=fixture", Assert.Single(trailers));
        });
    }
}
