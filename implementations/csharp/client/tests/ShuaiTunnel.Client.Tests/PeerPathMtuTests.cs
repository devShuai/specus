using ShuaiTunnel.Client.PeerMesh;

namespace ShuaiTunnel.Client.Tests;

public sealed class PeerPathMtuTests
{
    [Fact]
    public void ProbeAndAckRoundTripWithStrictLengths()
    {
        var vector = ProtocolVectorTestHelper.Read<PeerPathMtuVector>(
            "protocol/test-vectors/peer-path-mtu-v2.json");

        var probe = PeerPathMtu.EncodeProbe(vector.Nonce, vector.InnerMtu);
        var ack = PeerPathMtu.EncodeAck(vector.Nonce, vector.InnerMtu);

        Assert.Equal(vector.ProbeLength, probe.Length);
        Assert.Equal(vector.AckLength, ack.Length);
        Assert.Equal(Convert.FromHexString(vector.ProbeHeaderHex), probe[..vector.AckLength]);
        Assert.Equal(Convert.FromHexString(vector.AckHex), ack);
        Assert.Equal(new PeerPathMtu.Message(true, vector.Nonce, vector.InnerMtu), PeerPathMtu.Decode(probe));
        Assert.Equal(new PeerPathMtu.Message(false, vector.Nonce, vector.InnerMtu), PeerPathMtu.Decode(ack));
        Assert.Null(PeerPathMtu.Decode(probe[..^1]));
        Assert.Null(PeerPathMtu.Decode([.. ack, 0]));
    }

    [Fact]
    public void DiscoveryRetriesThenSearchesBelowFailedCeiling()
    {
        var discovery = new PeerPathMtu.Discovery();
        var now = DateTimeOffset.UtcNow;
        var first = Assert.IsType<PeerPathMtu.Probe>(
            discovery.Activate("direct|192.0.2.1:3478", 1280, null, now).NextProbe);

        var retryOne = Assert.IsType<PeerPathMtu.Probe>(discovery.Timeout(first.Nonce, now).NextProbe);
        var retryTwo = Assert.IsType<PeerPathMtu.Probe>(discovery.Timeout(first.Nonce, now).NextProbe);
        var reduced = Assert.IsType<PeerPathMtu.Probe>(discovery.Timeout(first.Nonce, now).NextProbe);

        Assert.Equal(1280, retryOne.InnerMtu);
        Assert.Equal(1280, retryTwo.InnerMtu);
        Assert.InRange(reduced.InnerMtu, PeerPathMtu.MinInnerMtu, 1279);
        Assert.True(discovery.EffectiveMtu(1280) < 1280);
    }

    [Fact]
    public void CachedPathMtuSkipsAProbeUntilExpiry()
    {
        var discovery = new PeerPathMtu.Discovery();
        var now = DateTimeOffset.UtcNow;
        var cached = new PeerPathMtu.CacheEntry(1180, now + TimeSpan.FromMinutes(1));

        var transition = discovery.Activate("relay|allocation", 1280, cached, now);

        Assert.Null(transition.NextProbe);
        Assert.Equal(1180, discovery.EffectiveMtu(1280));
    }

    private sealed class PeerPathMtuVector
    {
        public ulong Nonce { get; init; }
        public int InnerMtu { get; init; }
        public int ProbeLength { get; init; }
        public required string ProbeHeaderHex { get; init; }
        public int AckLength { get; init; }
        public required string AckHex { get; init; }
    }
}
