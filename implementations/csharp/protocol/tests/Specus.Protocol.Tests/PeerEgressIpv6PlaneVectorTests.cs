using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// The egress side of the IPv6 data plane against protocol/test-vectors/peer-egress-ipv6-v1.json: the
/// derived device address, the frames an egress that announces <c>ipv6PacketCapable</c> reads, and the
/// derived prefix on the forced-deny list.
/// </summary>
public sealed class PeerEgressIpv6PlaneVectorTests
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

    [Fact]
    public void MeshAddressMatchesSharedVector()
    {
        using var vector = ReadVector("peer-egress-ipv6-v1.json");
        var section = vector.RootElement.GetProperty("meshAddress");
        Assert.Equal(PeerEgressMeshAddress.Prefix, Text(section, "prefix"));
        var derive = section.GetProperty("derive").EnumerateArray().ToList();
        var underive = section.GetProperty("underive").EnumerateArray().ToList();
        Assert.NotEmpty(derive);
        Assert.NotEmpty(underive);
        foreach (var testCase in derive)
        {
            var meshIpv4 = Text(testCase, "meshIpv4");
            Assert.True(PeerEgressMeshAddress.TryDerive(meshIpv4, out var derived), meshIpv4);
            Assert.Equal(Text(testCase, "ipv6"), Ipv6Cidr.FormatAddress(derived));
        }
        foreach (var testCase in underive)
        {
            var text = Text(testCase, "ipv6");
            Assert.True(Ipv6Cidr.TryParseAddress(text, out var address), $"{text} does not parse");
            var inside = PeerEgressMeshAddress.TryUnderive(address, out var meshIpv4);
            var expected = testCase.GetProperty("meshIpv4");
            if (expected.ValueKind == JsonValueKind.Null)
            {
                Assert.False(inside, $"{text}: read back {Ipv4Cidr.FormatAddress(meshIpv4)}, but it is outside the prefix");
            }
            else
            {
                Assert.True(inside, $"{text}: read back nothing");
                Assert.Equal(expected.GetString(), Ipv4Cidr.FormatAddress(meshIpv4));
            }
        }
    }

    /// <summary>
    /// A parser with the data plane reads every accepted frame's tuple; without it, the same frame is
    /// refused as before.
    /// </summary>
    [Fact]
    public void AcceptedFramesMatchSharedVector()
    {
        using var vector = ReadVector("peer-egress-ipv6-v1.json");
        var accept = vector.RootElement.GetProperty("frames").GetProperty("accept").EnumerateArray().ToList();
        Assert.NotEmpty(accept);
        foreach (var testCase in accept)
        {
            var name = Text(testCase, "name");
            var raw = Convert.FromHexString(Text(testCase, "frameHex"));
            var decoded = PeerEgressFrame.Parse(raw, ipv6: true);
            Assert.True(decoded.Accepted, $"{name}: refused with {decoded.Code}");
            Assert.Equal(PeerEgressFrame.TypeIpPacket, decoded.Type);
            var inner = decoded.Inner;
            Assert.True(inner.Ipv6, $"{name}: not read as IPv6");
            Assert.Equal(Text(testCase, "innerSourceIp"), inner.SourceIp);
            Assert.Equal(Text(testCase, "innerDestinationIp"), inner.DestinationIp);
            Assert.Equal(testCase.GetProperty("innerNextHeader").GetInt32(), inner.Protocol);
            Assert.Equal(testCase.GetProperty("innerSourcePort").GetInt32(), inner.SourcePort);
            Assert.Equal(testCase.GetProperty("innerDestinationPort").GetInt32(), inner.DestinationPort);
            Assert.Equal(raw[PeerEgressFrame.HeaderBytes..], decoded.Body);

            Assert.Equal(PeerEgressCodes.Ipv6Unsupported, PeerEgressFrame.Parse(raw).Code);
        }
    }

    [Fact]
    public void RejectedFramesMatchSharedVector()
    {
        using var vector = ReadVector("peer-egress-ipv6-v1.json");
        var reject = vector.RootElement.GetProperty("frames").GetProperty("reject").EnumerateArray().ToList();
        Assert.NotEmpty(reject);
        foreach (var testCase in reject)
        {
            var name = Text(testCase, "name");
            var decoded = PeerEgressFrame.Parse(Convert.FromHexString(Text(testCase, "frameHex")), ipv6: true);
            Assert.False(decoded.Accepted, $"{name}: was accepted");
            Assert.True(Text(testCase, "code") == decoded.Code, $"{name}: code = {decoded.Code}");
        }
    }

    /// <summary>
    /// Turning the data plane on changes nothing for a frame that is not IPv6: every case of
    /// peer-egress-frame-v1.json comes out the same, except the IPv6 body that the vector pins for a
    /// parser without it (ipv6-packet-in-v1).
    /// </summary>
    [Fact]
    public void FrameVectorHoldsWithTheDataPlaneForEverythingButIpv6()
    {
        using var vector = ReadVector("peer-egress-frame-v1.json");
        var compared = 0;
        foreach (var section in new[] { "accept", "reject" })
        {
            foreach (var testCase in vector.RootElement.GetProperty(section).EnumerateArray())
            {
                var raw = Convert.FromHexString(Text(testCase, "frameHex"));
                var without = PeerEgressFrame.Parse(raw);
                var with = PeerEgressFrame.Parse(raw, ipv6: true);
                var carriesIpv6 = raw.Length > PeerEgressFrame.HeaderBytes && raw[5] == PeerEgressFrame.TypeIpPacket
                    && raw[PeerEgressFrame.HeaderBytes] >> 4 == 6 && without.Code == PeerEgressCodes.Ipv6Unsupported;
                if (carriesIpv6)
                {
                    Assert.Equal("ipv6-packet-in-v1", Text(testCase, "name"));
                    continue;
                }
                Assert.True(without.Code == with.Code, $"{Text(testCase, "name")}: {without.Code} became {with.Code}");
                Assert.Equal(without.Inner, with.Inner);
                compared++;
            }
        }
        Assert.True(compared > 0);
    }

    /// <summary>
    /// The derived prefix is the mesh to IPv6: however broad the policy, a destination inside it is a
    /// forced-deny, ahead of the scope and the destination rules.
    /// </summary>
    [Theory]
    [InlineData("fd53:7065:6375:7300::6460:2", PeerEgressCodes.ForbiddenDestination)]
    [InlineData("fd53:7065:6375:7300::", PeerEgressCodes.ForbiddenDestination)]
    [InlineData("fd53:7065:6375:7300::ffff:ffff", PeerEgressCodes.ForbiddenDestination)]
    [InlineData("fd53:7065:6375:7301::1", PeerEgressCodes.Allowed)]
    [InlineData("fd53:7065:6375:7300:1::1", PeerEgressCodes.Allowed)]
    public void TheDerivedPrefixIsForcedDeny(string destination, string code)
    {
        var policy = new PeerEgressPolicy
        {
            Enabled = true,
            Scope = PeerEgressAuthorization.ScopeLan,
            AllowedConsumerClientIds = [7L],
            DestinationRules =
            [
                new PeerEgressDestinationRule { Cidr = "::/0", Protocols = ["tcp", "udp"], PortRanges = [[1, 65535]] },
            ],
        };
        var decision = PeerEgressAuthorization.Authorize(
            new PeerEgressRequest { ConsumerClientId = 7, DestinationIp = destination, DestinationPort = 443, Protocol = "tcp" },
            policy, peerAclAllows: true, PeerEgressContext.Default);
        Assert.Equal(code, decision.Code);
    }
}
