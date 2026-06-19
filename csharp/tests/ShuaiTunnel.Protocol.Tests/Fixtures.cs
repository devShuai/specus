using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Protocol.Tests;

internal static class Fixtures
{
    private static readonly string FixtureDir =
        Path.Combine(AppContext.BaseDirectory, "fixtures");

    internal static byte[] Read(string name) => File.ReadAllBytes(Path.Combine(FixtureDir, name));

    /// <summary>Decode + assert a packet, then re-encode and compare bytes when the fixture is
    /// known to round-trip (no deflate involved). For deflated fixtures, callers should compare
    /// the decoded packet only.</summary>
    internal static T DecodeAndAssertRoundtrip<T>(string fixtureName, Action<T> assertions, bool compareEncoded = true)
        where T : Packet
    {
        var bytes = Read(fixtureName);
        Assert.True(PacketCodec.TryDecode(bytes, out var decoded, out var consumed),
            $"fixture {fixtureName} did not parse as a complete frame");
        Assert.Equal(bytes.Length, consumed);
        Assert.NotNull(decoded);
        var typed = Assert.IsType<T>(decoded);
        assertions(typed);

        if (compareEncoded)
        {
            var reEncoded = PacketCodec.Encode(typed);
            Assert.Equal(bytes, reEncoded);
        }
        return typed;
    }
}
