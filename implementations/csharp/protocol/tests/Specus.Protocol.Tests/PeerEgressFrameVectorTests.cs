using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Replays <c>peer-egress-frame-v1.json</c> against the .NET SPEG1 codec.
/// </summary>
/// <remarks>
/// The rejection cases assert the returned code and not merely that the frame was refused: an
/// operator who only sees "rejected" cannot tell a malformed frame from an unsupported one.
/// </remarks>
public class PeerEgressFrameVectorTests
{
    private static JsonDocument ReadVector(string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException($"cannot locate {name}");
    }

    private static string Text(JsonElement parent, string property) =>
        parent.TryGetProperty(property, out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString() ?? ""
            : "";

    private static int Number(JsonElement parent, string property) =>
        parent.TryGetProperty(property, out var element) && element.ValueKind == JsonValueKind.Number
            ? element.GetInt32()
            : 0;

    private static string HexOf(byte[] data) =>
        data.Length == 0 ? "" : Convert.ToHexString(data).ToLowerInvariant();

    [Fact]
    public void AcceptedFramesMatchSharedVector()
    {
        using var vector = ReadVector("peer-egress-frame-v1.json");
        var accept = vector.RootElement.GetProperty("accept");
        Assert.True(accept.GetArrayLength() > 0, "frame vector carried no accept cases");

        foreach (var testCase in accept.EnumerateArray())
        {
            var name = Text(testCase, "name");
            var raw = Convert.FromHexString(Text(testCase, "frameHex"));

            Assert.True(PeerEgressFrame.LooksLikeFrame(raw), $"{name}: not recognised as SPEG1");
            var decoded = PeerEgressFrame.Parse(raw);
            Assert.True(decoded.Accepted, $"{name}: refused with {decoded.Code}");
            Assert.True(Number(testCase, "type") == decoded.Type, $"{name}: type");
            Assert.True(
                (Number(testCase, "flags") & PeerEgressFrame.FlagHop) != 0 == decoded.Hop,
                $"{name}: hop");

            var innerHex = Text(testCase, "innerPacketHex");
            if (innerHex.Length == 0)
            {
                continue;
            }
            Assert.Equal(innerHex, HexOf(decoded.Body));
            Assert.Equal(Text(testCase, "innerSourceIp"), decoded.Inner.SourceIp);
            Assert.Equal(Text(testCase, "innerDestinationIp"), decoded.Inner.DestinationIp);
            Assert.True(
                Number(testCase, "innerSourcePort") == decoded.Inner.SourcePort,
                $"{name}: inner source port");
            Assert.True(
                Number(testCase, "innerDestinationPort") == decoded.Inner.DestinationPort,
                $"{name}: inner destination port");

            var protocol = Text(testCase, "innerProtocol");
            if (protocol == "tcp")
            {
                Assert.True(decoded.Inner.Protocol == 6, $"{name}: inner protocol");
            }
            else if (protocol == "udp")
            {
                Assert.True(decoded.Inner.Protocol == 17, $"{name}: inner protocol");
            }
        }
    }

    [Fact]
    public void RejectedFramesMatchSharedVector()
    {
        using var vector = ReadVector("peer-egress-frame-v1.json");
        var reject = vector.RootElement.GetProperty("reject");
        Assert.True(reject.GetArrayLength() > 0, "frame vector carried no reject cases");

        foreach (var testCase in reject.EnumerateArray())
        {
            var name = Text(testCase, "name");
            var raw = Convert.FromHexString(Text(testCase, "frameHex"));
            var decoded = PeerEgressFrame.Parse(raw);
            Assert.True(Text(testCase, "code") == decoded.Code, $"{name}: code = {decoded.Code}");
            Assert.False(decoded.Accepted, $"{name}: was accepted");
        }
    }

    /// <summary>
    /// A round trip through the encoder has to come back out of the parser. Otherwise the two
    /// halves could each be self-consistently wrong.
    /// </summary>
    [Fact]
    public void EncodedFramesParseBack()
    {
        using var vector = ReadVector("peer-egress-frame-v1.json");
        foreach (var testCase in vector.RootElement.GetProperty("accept").EnumerateArray())
        {
            var innerHex = Text(testCase, "innerPacketHex");
            if (innerHex.Length == 0)
            {
                continue;
            }
            var body = Convert.FromHexString(innerHex);
            var frame = PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, body);
            Assert.Equal(Text(testCase, "frameHex"), HexOf(frame));
        }
    }

    /// <summary>
    /// The hop flag is refused at the frame layer, before anything looks at the packet inside it.
    /// There are no multi-hop egress chains, and a frame that claims one must not reach the
    /// authorization step at all.
    /// </summary>
    [Fact]
    public void HopFlaggedFramesAreRefusedBeforeTheBodyIsRead()
    {
        var frame = PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, true, [0x01]);
        Assert.Equal(PeerEgressCodes.HopNotAllowed, PeerEgressFrame.Parse(frame).Code);
    }

    /// <summary>A payload that is not SPEG1 at all is left for the mesh's own handling.</summary>
    [Fact]
    public void NonFramePayloadsAreNotClaimed()
    {
        Assert.False(PeerEgressFrame.LooksLikeFrame([]));
        Assert.False(PeerEgressFrame.LooksLikeFrame([0x45, 0x00, 0x00, 0x28]));
    }
}
