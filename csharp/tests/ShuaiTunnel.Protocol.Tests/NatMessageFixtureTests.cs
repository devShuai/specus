using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Protocol.Tests;

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
            Assert.Equal("127.0.0.1", (string?)p.MetaData!["tunnelAddress"]);
            Assert.Equal(80L, (long?)p.MetaData!["tunnelPort"]);
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
    public void Connected_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_connected.bin", p =>
        {
            Assert.Equal(NatMessageType.Connected, p.NatMessageType);
            Assert.Equal("00010203-aaaa-bbbb-cccc-ddddeeeeffff", (string?)p.MetaData!["channelId"]);
            Assert.Equal(18080L, (long?)p.MetaData!["port"]);
            Assert.Null(p.Data);
        });
    }

    [Fact]
    public void Disconnected_Roundtrips()
    {
        Fixtures.DecodeAndAssertRoundtrip<NatMessagePacket>("nat_disconnected.bin", p =>
        {
            Assert.Equal(NatMessageType.Disconnected, p.NatMessageType);
            Assert.Equal("00010203-aaaa-bbbb-cccc-ddddeeeeffff", (string?)p.MetaData!["channelId"]);
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
            Assert.Equal("00010203-aaaa-bbbb-cccc-ddddeeeeffff", (string?)p.MetaData!["channelId"]);
            Assert.NotNull(p.Data);
            Assert.Equal("hello", System.Text.Encoding.UTF8.GetString(p.Data!));
        });
    }

    /// <summary>
    /// Decode-only check for the deflated DATA path. .NET's <c>DeflateStream</c> and Java's
    /// <c>Deflater</c> with <c>BEST_COMPRESSION</c> emit slightly different byte sequences for
    /// the same input, so byte equality on the encoded form would be brittle. The contract is
    /// that the inflated payload is identical, which is what we assert here.
    /// </summary>
    [Fact]
    public void Data_Large_DeflatedFromJava_DecodesCorrectly()
    {
        var bytes = Fixtures.Read("nat_data_large_deflated.bin");
        Assert.True(PacketCodec.TryDecode(bytes, out var decoded, out _));
        var packet = Assert.IsType<NatMessagePacket>(decoded);
        Assert.Equal(NatMessageType.Data, packet.NatMessageType);
        Assert.NotNull(packet.Data);
        Assert.Equal(256, packet.Data!.Length);
        foreach (var b in packet.Data!)
        {
            Assert.Equal((byte)'A', b);
        }
    }

    [Fact]
    public void Data_Large_NetEncodesAndSelfRoundtrips()
    {
        var payload = new byte[256];
        Array.Fill(payload, (byte)'A');
        var packet = new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            MetaData = new Dictionary<string, object?>
            {
                ["channelId"] = "00010203-aaaa-bbbb-cccc-ddddeeeeffff",
            },
            Data = payload,
        };

        var encoded = PacketCodec.Encode(packet);
        Assert.True(PacketCodec.TryDecode(encoded, out var decoded, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        var roundtrip = Assert.IsType<NatMessagePacket>(decoded);
        Assert.Equal(payload, roundtrip.Data);
    }
}
